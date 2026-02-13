//! ztun.router - Transparent proxy forwarding engine
//!
//! A fixed forwarding engine with libxev-based async I/O.
//! All routing logic is provided by the application layer via callbacks.
//!
//! # Architecture
//!
//! ```
//! Application (tests/tun2sock.zig)
//!   ├── TUN config (name, ip, mtu, fd)
//!   ├── Egress config (name, ip, ifindex)
//!   ├── Proxy config (type, addr, auth)
//!   └── Route callback (decides how to forward each packet)
//!                     │
//!                     ▼
//! Router.init(config)
//!   ┌─────────────────────────────────────┐
//!   │  libxev Loop                       │
//!   │  ├── TUN async reader (IO)        │
//!   │  ├── TCP async connect (IO)       │
//!   │  ├── UDP async send/recv (IO)     │
//!   │  └── NAT cleanup timer            │
//!   └─────────────────────────────────────┘
//!                     │
//!         ┌───────────┴───────────┐
//!         ▼                       ▼
//!   TUN write              Proxy write
//! ```
//!
//! # Usage
//!
//! ```zig
//! const router = @import("router");
//!
//! // Application defines routing callback
//! fn myRouteCallback(
//!     src_ip: u32, src_port: u16,
//!     dst_ip: u32, dst_port: u16,
//!     protocol: u8,
//! ) router.RouteDecision {
//!     if (isPrivateIp(dst_ip)) return .Direct;
//!     return .Socks5;
//! }
//!
//! // Initialize router
//! var r = try router.Router.init(.{
//!     .tun = .{ ... },
//!     .egress = .{ ... },
//!     .proxy = .{ .type = .socks5, .addr = "127.0.0.1:1080" },
//!     .route_cb = myRouteCallback,
//! });
//! defer r.deinit();
//!
//! // Run event loop
//! r.run();
//! ```

const std = @import("std");
const builtin = @import("builtin");

// Import libxev for async I/O
const xev = @import("xev");

// Socket constants
const AF_INET = 2; // IPv4
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const SOCK_RAW = 3;
const SOL_SOCKET = 0xffff;
const SO_REUSEADDR = 0x0004;
const O_NONBLOCK = 0x4000; // Non-blocking socket
const F_GETFL = 3;
const F_SETFL = 4;

// TCP flag constants
const TCP_FIN = 0x01;
const TCP_SYN = 0x02;
const TCP_RST = 0x04;
const TCP_PSH = 0x08;
const TCP_ACK = 0x10;
const TCP_URG = 0x20;

/// sockaddr_in for IPv4 (macOS/Linux compatible)
const sockaddr_in = extern struct {
    sin_len: u8 = 0,
    sin_family: u8,
    sin_port: u16,
    sin_addr: [4]u8,
    sin_zero: [8]u8 = [_]u8{0} ** 8,
};

// Re-export config types
pub const TunConfig = @import("route.zig").TunConfig;
pub const EgressConfig = @import("route.zig").EgressConfig;
pub const ProxyConfig = @import("route.zig").ProxyConfig;
pub const RouteCallback = @import("route.zig").RouteCallback;
pub const RouteDecision = @import("route.zig").RouteDecision;
pub const ProxyType = @import("route.zig").ProxyType;
pub const NatSession = @import("nat.zig").NatSession;
pub const NatTable = @import("nat.zig").NatTable;
pub const NatConfig = @import("nat.zig").NatConfig;

// Re-export connection module for TCP state machine
pub const connection = @import("connection.zig");

// Re-export SOCKS5 module
pub const socks5 = @import("proxy/socks5.zig");

// Type alias for backward compatibility - Socks5Conn is now socks5.Socks5Client
pub const Socks5Conn = socks5.Socks5Client;

// Import checksum from ipstack
const ipstack = @import("ipstack");

// Import network monitor for cross-platform network change detection
const monitor = @import("monitor");

/// Parse proxy address (ip:port string)
fn parseProxyAddr(addr: [:0]const u8) !struct { ip: u32, port: u16 } {
    const colon_idx = std.mem.lastIndexOf(u8, addr, ":") orelse return error.InvalidProxyAddr;

    const ip_str = addr[0..colon_idx];
    const port_str = addr[colon_idx + 1 ..];

    const ip = try parseIpv4(ip_str);
    const port = try std.fmt.parseInt(u16, port_str, 10);

    if (port == 0) return error.InvalidPort;

    return .{ .ip = ip, .port = port };
}

/// Helper function to print packet as hex dump for debugging
fn dumpPacket(label: []const u8, data: []const u8) void {
    std.debug.print("[DUMP] {s} (len={})\n", .{ label, data.len });

    // Print first 32 bytes as hex
    const dump_len = @min(data.len, 32);
    var i: usize = 0;
    while (i < dump_len) : (i += 1) {
        std.debug.print("{x}", .{data[i]});
    }
    std.debug.print("\n", .{});
}

/// Helper function to format IP address for logging
fn fmtIp(ip: u32) [15]u8 {
    var buf: [15]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{}.{}.{}.{}", .{
        @as(u8, @truncate(ip >> 24)),
        @as(u8, @truncate(ip >> 16)),
        @as(u8, @truncate(ip >> 8)),
        @as(u8, @truncate(ip)),
    }) catch unreachable;
    return buf;
}

/// Parse IPv4 address string to u32 (network byte order)
fn parseIpv4(ip_str: []const u8) !u32 {
    var parts: [4]u8 = undefined;
    var part_idx: usize = 0;
    var val: u32 = 0;
    var dot_count: usize = 0;

    for (ip_str) |c| {
        if (c == '.') {
            if (part_idx >= 4) return error.InvalidIp;
            parts[part_idx] = @as(u8, @truncate(val));
            val = 0;
            part_idx += 1;
            dot_count += 1;
        } else if (c >= '0' and c <= '9') {
            val = val * 10 + (c - '0');
            if (val > 255) return error.InvalidIp;
        } else {
            return error.InvalidIp;
        }
    }

    // Last part
    if (part_idx >= 4) return error.InvalidIp;
    parts[part_idx] = @as(u8, @truncate(val));

    if (dot_count != 3) return error.InvalidIp;

    // Combine to u32 (network byte order: parts[0] is most significant)
    return @as(u32, parts[0]) << 24 | @as(u32, parts[1]) << 16 | @as(u32, parts[2]) << 8 | @as(u32, parts[3]);
}

/// Packet buffer for forwarding
pub const Packet = struct {
    /// Raw packet data
    data: []const u8,

    /// Source 4-tuple
    src_ip: u32,
    src_port: u16,

    /// Destination 4-tuple
    dst_ip: u32,
    dst_port: u16,

    /// IP protocol (6=TCP, 17=UDP)
    protocol: u8,
};

/// Router statistics
pub const RouterStats = struct {
    tcp_connections: u64 = 0,
    udp_sessions: u64 = 0,
    dns_queries: u64 = 0,
    dns_responses: u64 = 0,
    dns_timeouts: u64 = 0,
    packets_forwarded: u64 = 0,
    packets_dropped: u64 = 0,
    bytes_rx: u64 = 0,
    bytes_tx: u64 = 0,
    network_changes: u64 = 0,
    route_updates: u64 = 0,
};

/// Router configuration
pub const RouterConfig = struct {
    /// TUN device configuration (from application)
    tun: TunConfig,

    /// Egress network interface configuration (from application)
    egress: EgressConfig,

    /// Proxy configuration (optional)
    proxy: ?ProxyConfig = null,

    /// Mock HTTP server for testing (bypasses SOCKS5 proxy)
    mock_enabled: bool = false,
    mock_port: u16 = 0,

    /// Routing decision callback (required, from application)
    route_cb: RouteCallback,

    /// TCP connection pool size
    tcp_pool_size: usize = 4096,

    /// UDP NAT session table size
    udp_nat_size: usize = 8192,

    /// Connection idle timeout in seconds
    idle_timeout: u32 = 300,

    /// UDP session timeout in seconds
    udp_timeout: u32 = 30,

    /// NAT configuration (for UDP forwarding)
    nat_config: ?NatConfig = null,
};

/// Router state machine
const RouterState = enum {
    init,
    running,
    stopping,
    stopped,
};

/// Userdata for callbacks
const RouterContext = struct {
    router: *Router,
    completion: xev.Completion,
};

/// UDP session for NAT forwarding
const UdpSession = struct {
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    local_ip: u32,
    local_port: u16,
    last_active: i64,
};

/// TCP connection tracking entry (defined before Router to avoid container field ordering issues)
const TcpConnEntry = struct {
    /// Connection 4-tuple
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,

    /// Associated SOCKS5 client (null if still connecting)
    socks5_client: ?*Socks5Conn,

    /// TCP state from connection.zig
    tcp_state: connection.State,

    /// Activity timestamp
    last_active: i64,

    /// Whether this entry is in use
    used: bool,
};

/// Pending TCP connection (waiting for SOCKS5 handshake)
const PendingTcpConn = struct {
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,

    /// Client's initial sequence number
    client_seq: u32,

    /// When this pending connection was created (for timeout)
    created_at: i64,
};

/// UDP session for SOCKS5 UDP Associate forwarding
const Socks5UdpSession = struct {
    /// Original source 4-tuple
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,

    /// Activity timestamp
    last_active: i64,

    /// Whether this entry is in use
    used: bool,
};

/// DNS request tracking for timeout detection
const DnsRequest = struct {
    /// Original source 4-tuple
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,

    /// DNS transaction ID (from DNS header)
    tx_id: u16,

    /// When this request was made
    created_at: i64,

    /// Whether this entry is in use
    used: bool,
};

/// Router - Transparent proxy forwarding engine with libxev
pub const Router = struct {
    /// libxev event loop
    loop: xev.Loop,

    /// libxev completion for TUN reading
    tun_completion: xev.Completion,

    /// libxev completion for TUN writing
    tun_write_completion: xev.Completion,

    /// libxev timer for NAT cleanup
    nat_timer: xev.Completion,

    /// libxev completion for SOCKS5 TCP
    socks5_completion: xev.Completion,

    /// libxev completion for UDP socket
    udp_completion: xev.Completion,

    /// Configuration
    config: RouterConfig,

    /// NAT session table (for UDP forwarding)
    nat_table: ?*NatTable,

    /// SOCKS5 proxy connection pool for concurrent connections
    socks5_pool: []*Socks5Conn,

    /// TCP connection table (4-tuple -> connection state)
    tcp_conn_pool: []TcpConnEntry,

    /// Pending TCP connections (waiting for SOCKS5 handshake)
    pending_tcp_pool: []PendingTcpConn,

    /// UDP session table for SOCKS5 UDP Associate
    udp_sessions: []Socks5UdpSession,

    /// DNS request tracking table (for timeout detection)
    dns_requests: []DnsRequest,

    /// UDP Associate client (single shared client for all UDP flows)
    udp_associate: ?*socks5.Socks5UdpAssociate,

    /// UDP socket for NAT forwarding
    udp_sock: ?std.posix.socket_t = null,

    /// Raw socket for direct packet forwarding (Direct route decision)
    raw_sock: ?std.posix.socket_t = null,

    /// UDP send buffer
    udp_send_buf: [65536]u8 = undefined,

    /// UDP recv buffer
    udp_recv_buf: [65536]u8 = undefined,

    /// Current state
    state: RouterState,

    /// Packet buffer for TUN reads
    packet_buf: [65536]u8,

    /// Write buffer for TUN writes
    write_buf: [65536]u8,

    /// ICMP reply buffer (dedicated to avoid race conditions)
    icmp_buf: [65536]u8,

    /// Mock HTTP state for testing (tracks TCP handshake)
    mock_state: ?*MockState = null,

    /// Current egress interface name (updated on network change)
    egress_iface: [64]u8 = undefined,

    /// Network monitor for cross-platform change detection (platform-specific type)
    net_monitor: ?*monitor.NetworkMonitor = null,

    /// Network state
    is_paused: bool = false,

    /// Statistics
    _stats: RouterStats,

    /// Allocator for allocations
    allocator: std.mem.Allocator,

    /// Get TUN file descriptor (from device_ops or raw fd)
    inline fn tunFd(router: *Router) std.posix.fd_t {
        if (router.config.tun.device_ops) |dev| {
            return dev.fd();
        }
        return router.config.tun.fd;
    }

    /// Write to TUN device (uses device_ops if available)
    fn writeToTunDevice(router: *Router, data: []const u8) !void {
        if (router.config.tun.device_ops) |dev| {
            // Use device operations (handles platform-specific headers)
            const written = dev.write(data) catch return error.WriteFailed;
            router._stats.bytes_tx += written;
        } else {
            // Raw fd - may need platform-specific header (e.g., macOS utun 4-byte header)
            const header_len = router.config.tun.header_len;
            const total_len = header_len + data.len;

            std.debug.print("[TUN-WRITE] header_len={}, data.len={}, total_len={}\n", .{ header_len, data.len, total_len });

            if (router.write_buf.len < total_len) {
                return error.BufferTooSmall;
            }

            // Add macOS utun header if needed (4-byte AF_INET header)
            // macOS format: bytes 0-3 = AF_INET family in LITTLE-ENDIAN (from tcpdump observation)
            if (header_len > 0) {
                // AF_INET = 2 in little-endian format (02 00 00 00)
                router.write_buf[0] = 2;
                router.write_buf[1] = 0;
                router.write_buf[2] = 0;
                router.write_buf[3] = 0;

                // Debug: dump first 4 bytes of data being copied
                std.debug.print("[TUN-WRITE-DBG] data[0..4] before copy: {x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{ data[0], data[1], data[2], data[3] });
            }

            // Always copy data to write_buf if not already there (avoid aliasing)
            if (data.ptr != &router.write_buf) {
                @memcpy(router.write_buf[header_len..total_len], data);
            }

            // Debug: verify copied data
            std.debug.print("[TUN-WRITE-DBG] write_buf[{}..{}] after copy: {x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{ header_len, header_len + 4, router.write_buf[header_len], router.write_buf[header_len + 1], router.write_buf[header_len + 2], router.write_buf[header_len + 3] });

            // Debug: dump what we're writing
            std.debug.print("[TUN-WRITE] writing ", .{});
            for (0..@min(total_len, 24)) |i| std.debug.print("{x:0>2} ", .{router.write_buf[i]});
            std.debug.print("... (total={})\n", .{total_len});

            const tun = router.config.tun.fd;
            // Ensure we write exactly total_len bytes
            var bytes_written: usize = 0;
            while (bytes_written < total_len) {
                const slice = router.write_buf[bytes_written..total_len];
                const written = std.posix.write(tun, slice) catch return error.WriteFailed;
                if (written == 0) return error.WriteFailed;
                bytes_written += written;
            }
            std.debug.print("[TUN-WRITE] wrote {} bytes (expected {})\n", .{ bytes_written, total_len });
            router._stats.bytes_tx += bytes_written;

            // Final verification: dump first 12 bytes of what was written
            std.debug.print("[TUN-WRITE-DBG] final verify: {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{ router.write_buf[0], router.write_buf[1], router.write_buf[2], router.write_buf[3], router.write_buf[4], router.write_buf[5], router.write_buf[6], router.write_buf[7], router.write_buf[8], router.write_buf[9], router.write_buf[10], router.write_buf[11] });
        }
    }

    /// Create a new Router instance
    pub fn init(allocator: std.mem.Allocator, config: RouterConfig) !Router {
        // Initialize NAT table if configured
        var nat_table: ?*NatTable = null;
        if (config.nat_config) |nat_cfg| {
            nat_table = try NatTable.init(allocator, nat_cfg, config.udp_nat_size);
        }

        // Create UDP socket for NAT forwarding
        var udp_sock: ?std.posix.socket_t = null;
        if (config.nat_config != null) {
            udp_sock = std.posix.socket(AF_INET, SOCK_DGRAM, 0) catch null;
            if (udp_sock) |sock| {
                // Allow address reuse for NAT - use C API to avoid EINVAL panic on macOS
                const yes: c_int = 1;
                _ = std.c.setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, @sizeOf(c_int));
            }
        }

        // Create raw socket for direct packet forwarding
        var raw_sock: ?std.posix.socket_t = null;
        // On Darwin, use IPPROTO_IP (0) instead of IPPROTO_RAW which doesn't exist
        const raw_protocol: c_int = if (builtin.os.tag == .macos) 0 else std.posix.IPPROTO.RAW;
        raw_sock = std.posix.socket(AF_INET, std.posix.SOCK.RAW, raw_protocol) catch null;

        // Create libxev loop first (needed for Socks5Client creation)
        var loop = try xev.Loop.init(.{});

        // Allocate SOCKS5 connection pool (lazy allocation - create on demand)
        const socks5_pool_size = config.tcp_pool_size;
        const socks5_pool = try allocator.alloc(*Socks5Conn, socks5_pool_size);
        @memset(socks5_pool, null);

        // Allocate TCP connection table
        const tcp_conn_pool = try allocator.alloc(TcpConnEntry, config.tcp_pool_size);
        for (tcp_conn_pool) |*entry| {
            entry.* = .{
                .src_ip = 0,
                .src_port = 0,
                .dst_ip = 0,
                .dst_port = 0,
                .socks5_client = null,
                .tcp_state = .Closed,
                .last_active = 0,
                .used = false,
            };
        }

        // Allocate pending TCP connection pool
        const pending_pool_size = @divExact(config.tcp_pool_size, 4);
        const pending_tcp_pool = try allocator.alloc(PendingTcpConn, pending_pool_size);
        for (pending_tcp_pool) |*entry| {
            entry.* = .{
                .src_ip = 0,
                .src_port = 0,
                .dst_ip = 0,
                .dst_port = 0,
                .client_seq = 0,
                .created_at = 0,
            };
        }

        // Allocate UDP session table for SOCKS5 UDP Associate
        const udp_sessions = try allocator.alloc(Socks5UdpSession, config.udp_nat_size);
        for (udp_sessions) |*entry| {
            entry.* = .{
                .src_ip = 0,
                .src_port = 0,
                .dst_ip = 0,
                .dst_port = 0,
                .last_active = 0,
                .used = false,
            };
        }

        // Allocate DNS request tracking table
        const dns_request_size = @divExact(config.udp_nat_size, 4);
        const dns_requests = try allocator.alloc(DnsRequest, dns_request_size);
        for (dns_requests) |*entry| {
            entry.* = .{
                .src_ip = 0,
                .src_port = 0,
                .dst_ip = 0,
                .dst_port = 0,
                .tx_id = 0,
                .created_at = 0,
                .used = false,
            };
        }

        // Initialize egress interface name from config
        var egress_iface_init: [64]u8 = undefined;
        const name_len = @min(config.egress.name.len, 63);
        @memcpy(egress_iface_init[0..name_len], config.egress.name[0..name_len]);

        // Create Router as local variable first
        var router = Router{
            .loop = loop,
            .tun_completion = .{},
            .tun_write_completion = .{},
            .nat_timer = .{},
            .socks5_completion = .{},
            .udp_completion = .{},
            .config = config,
            .nat_table = nat_table,
            .socks5_pool = socks5_pool,
            .tcp_conn_pool = tcp_conn_pool,
            .pending_tcp_pool = pending_tcp_pool,
            .udp_sessions = udp_sessions,
            .dns_requests = dns_requests,
            .udp_associate = null,
            .udp_sock = udp_sock,
            .raw_sock = raw_sock,
            .state = .init,
            .packet_buf = undefined,
            .write_buf = undefined,
            .icmp_buf = undefined,
            .egress_iface = egress_iface_init,
            .is_paused = false,
            .net_monitor = null,
            ._stats = .{},
            .allocator = allocator,
        };

        // Create network monitor for cross-platform change detection (macOS only for now)
        if (builtin.os.tag == .macos) {
            router.net_monitor = monitor.createNetworkMonitor(allocator) catch null;
            if (router.net_monitor) |mon| {
                mon.register(onNetworkChangeCallback, &router) catch {
                    std.debug.print("[ROUTER] Warning: Failed to register network change callback\n", .{});
                };
            } else {
                std.debug.print("[ROUTER] Warning: Failed to create network monitor\n", .{});
            }
        }

        return router;
    }

    /// Stop the router gracefully
    pub fn stop(router: *Router) void {
        std.debug.print("[ROUTER] Stopping gracefully...\n", .{});

        // Signal event loop to stop
        router.state = .stopping;

        // Send FIN to all active TCP connections
        for (router.tcp_conn_pool) |*entry| {
            if (entry.used) {
                std.debug.print("[ROUTER] Closing TCP connection: {s}:{} -> {s}:{}\n", .{
                    fmtIp(entry.src_ip), entry.src_port,
                    fmtIp(entry.dst_ip), entry.dst_port,
                });

                // Send FIN to client
                router.sendFin(
                    entry.dst_ip,
                    entry.dst_port,
                    entry.src_ip,
                    entry.src_port,
                ) catch {
                    std.debug.print("[ROUTER] Failed to send FIN\n", .{});
                };

                entry.used = false;
            }
        }

        // Close UDP associate
        if (router.udp_associate) |ua| {
            ua.close();
        }

        // Stop the event loop
        router.loop.stop();
        router.state = .stopped;

        std.debug.print("[ROUTER] Stopped.\n", .{});
    }

    /// Destroy a Router instance
    pub fn deinit(router: *Router) void {
        router.stop();

        // Stop and cleanup network monitor
        if (router.net_monitor) |mon| {
            monitor.destroyNetworkMonitor(mon);
        }

        // Close all SOCKS5 connections in the pool
        for (router.socks5_pool) |*conn_ptr| {
            if (conn_ptr.*) |conn| {
                conn.close();
                Socks5Conn.destroy(conn, router.allocator);
                conn_ptr.* = null;
            }
        }
        router.allocator.free(router.socks5_pool);

        // Free TCP connection pool
        router.allocator.free(router.tcp_conn_pool);

        // Free pending TCP pool
        router.allocator.free(router.pending_tcp_pool);

        // Free UDP session table
        router.allocator.free(router.udp_sessions);

        // Free DNS request tracking table
        router.allocator.free(router.dns_requests);

        // Destroy UDP associate
        if (router.udp_associate) |ua| {
            socks5.Socks5UdpAssociate.destroy(ua, router.allocator);
        }

        // Close UDP socket
        if (router.udp_sock) |sock| {
            std.posix.close(sock);
        }

        // Close raw socket
        if (router.raw_sock) |sock| {
            std.posix.close(sock);
        }

        // Cleanup NAT table
        if (router.nat_table) |nat| {
            nat.deinit();
        }

        router.loop.deinit();
    }

    /// Run the router event loop (blocking)
    pub fn run(router: *Router) void {
        router.state = .running;

        // Submit initial TUN read
        router.submitTunRead();

        // Submit UDP read if NAT is configured
        if (router.udp_sock != null) {
            router.submitUdpRead();
        }

        // Submit NAT cleanup timer if configured
        if (router.config.nat_config != null) {
            router.submitNatTimer();
        }

        // Run event loop - use no_wait in loop to keep running
        std.debug.print("[ROUTER] Starting event loop...\n", .{});
        while (router.state == .running) {
            router.loop.run(.no_wait) catch {
                std.debug.print("[ROUTER] Event loop error!\n", .{});
                break;
            };
            // Small sleep to prevent busy loop and allow signal handling
            std.time.sleep(10 * std.time.ns_per_ms);
        }
        std.debug.print("[ROUTER] Event loop exited.\n", .{});
        router.state = .stopped;
    }

    /// Stop the router event loop
    pub fn stop(router: *Router) void {
        router.loop.stop();
        router.state = .stopped;
    }

    /// Get router statistics
    pub fn stats(router: *Router) RouterStats {
        return router._stats;
    }

    /// Submit TUN read operation
    fn submitTunRead(router: *Router) void {
        router.tun_completion = .{
            .op = .{
                .read = .{
                    .fd = router.tunFd(),
                    .buffer = .{ .slice = &router.packet_buf },
                },
            },
            .userdata = router,
            .callback = onTunReadable,
        };
        router.loop.add(&router.tun_completion);
    }

    /// Submit NAT cleanup timer
    fn submitNatTimer(router: *Router) void {
        router.loop.timer(&router.nat_timer, 30000, router, onNatTimer);
    }

    /// Submit UDP read operation for NAT responses
    fn submitUdpRead(router: *Router) void {
        const sock = router.udp_sock orelse return;

        router.udp_completion = .{
            .op = .{
                .read = .{
                    .fd = sock,
                    .buffer = .{ .slice = &router.udp_recv_buf },
                },
            },
            .userdata = router,
            .callback = onUdpReadable,
        };
        router.loop.add(&router.udp_completion);
    }

    /// UDP socket readable callback - handle NAT responses
    fn onUdpReadable(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;

        const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));

        // Handle read result
        const n = result.read catch {
            router.submitUdpRead();
            return .disarm;
        };

        if (n == 0) {
            router.submitUdpRead();
            return .disarm;
        }

        // Get source address from recvmsg
        // For simplicity, assume response comes from the original destination
        // This is a simplified NAT response handler

        // Parse the UDP response and forward to TUN
        if (n >= 28) { // Minimum IP + UDP header
            // Extract source IP from IP header
            const src_ip = std.mem.readInt(u32, router.udp_recv_buf[12..16], .big);
            const src_port = std.mem.readInt(u16, router.udp_recv_buf[20..22], .big);

            // Handle the NAT response
            router.handleNatUdp(router.udp_recv_buf[0..n], src_ip, src_port);
        }

        // Continue reading
        router.submitUdpRead();

        return .disarm;
    }

    /// Forward packet based on route decision
    fn forwardPacket(router: *Router, packet: *const Packet) !void {
        const decision = router.config.route_cb(
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol,
        );

        switch (decision) {
            .Direct => {
                std.debug.print("[FWD] Direct: {s}:{} -> {s}:{}\n", .{ fmtIp(packet.src_ip), packet.src_port, fmtIp(packet.dst_ip), packet.dst_port });
                try router.forwardToEgress(packet);
                router._stats.packets_forwarded += 1;
            },
            .Socks5 => {
                std.debug.print("[FWD] Socks5: {s}:{} -> {s}:{} proto={}\n", .{ fmtIp(packet.src_ip), packet.src_port, fmtIp(packet.dst_ip), packet.dst_port, packet.protocol });
                if (router.config.mock_enabled) {
                    try router.handleMockHttp(packet);
                } else if (packet.protocol == 17) {
                    // UDP packet - forward via SOCKS5 UDP Associate
                    try router.forwardUdpToSocks5(packet);
                } else {
                    // TCP packet - forward via SOCKS5 TCP tunnel
                    try router.forwardToProxy(packet);
                }
                router._stats.packets_forwarded += 1;
            },
            .Drop => {
                router._stats.packets_dropped += 1;
            },
            .Local => {
                std.debug.print("[FWD] Local: {s}:{} -> {s}:{}\n", .{ fmtIp(packet.src_ip), packet.src_port, fmtIp(packet.dst_ip), packet.dst_port });
                try router.writeToTun(packet);
                router._stats.packets_forwarded += 1;
            },
            .Nat => {
                try router.forwardWithNat(packet);
                router._stats.packets_forwarded += 1;
            },
            else => {},
        }
    }

    /// Forward packet through SOCKS5 proxy (TCP)
    /// Uses connection pool for concurrent connections to different destinations
    fn forwardToProxy(router: *Router, packet: *const Packet) !void {
        std.debug.print("\n[SOCKS5-PATH] ============================================\n", .{});
        std.debug.print("[SOCKS5-PATH] forwardToProxy called\n", .{});
        std.debug.print("[SOCKS5-PATH] Packet: {s}:{} -> {s}:{} proto={}\n", .{ fmtIp(packet.src_ip), packet.src_port, fmtIp(packet.dst_ip), packet.dst_port, packet.protocol });

        // Extract TCP flags
        const tcp_flags = if (packet.data.len >= 34) packet.data[33] else 0;
        const is_syn = (tcp_flags & TCP_SYN) != 0 and (tcp_flags & TCP_ACK) == 0;
        const is_fin = (tcp_flags & TCP_FIN) != 0;
        const is_rst = (tcp_flags & TCP_RST) != 0;

        std.debug.print("[SOCKS5-PATH] TCP flags: 0x{X:0>2} SYN={} FIN={} RST={}\n", .{ tcp_flags, is_syn, is_fin, is_rst });

        // Look up existing connection by 4-tuple
        const tcp_conn = router.lookupTcpConnection(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port);

        if (tcp_conn) |conn| {
            // Existing connection found
            std.debug.print("[SOCKS5-PATH] Found existing connection: state={s}\n", .{connection.stateToString(conn.tcp_state)});

            // Handle connection closure
            if (is_rst or is_fin) {
                std.debug.print("[SOCKS5-PATH] Connection closing (RST/FIN)\n", .{});
                router.removeTcpConnection(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port);
            }

            // Forward data if connection is established
            if (conn.tcp_state == .Established and conn.socks5_client) |client| {
                if (!is_syn) { // Don't forward SYN on established connection
                    try router.forwardTcpData(client, packet);
                }
            }
        } else {
            // No existing connection
            if (is_syn) {
                // New connection - initiate SOCKS5 connection
                std.debug.print("[SOCKS5-PATH] New connection, initiating SOCKS5 tunnel\n", .{});
                try router.initiateSocks5Tunnel(packet);
            } else {
                // Non-SYN packet for non-existent connection - drop
                std.debug.print("[SOCKS5-PATH-WARN] Dropping non-SYN packet for non-existent connection\n", .{});
                router._stats.packets_dropped += 1;
            }
        }

        std.debug.print("[SOCKS5-PATH-EXIT] ============================================\n\n", .{});
    }

    /// Look up TCP connection by 4-tuple
    fn lookupTcpConnection(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) ?*TcpConnEntry {
        for (router.tcp_conn_pool) |*entry| {
            if (entry.used and
                entry.src_ip == src_ip and entry.src_port == src_port and
                entry.dst_ip == dst_ip and entry.dst_port == dst_port)
            {
                return entry;
            }
        }
        return null;
    }

    /// Find or create pending TCP connection
    fn findOrCreatePending(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) !*PendingTcpConn {
        // Check for existing pending connection
        for (router.pending_tcp_pool) |*entry| {
            if (entry.src_ip == src_ip and entry.src_port == src_port and
                entry.dst_ip == dst_ip and entry.dst_port == dst_port)
            {
                return entry;
            }
        }

        // Find empty slot
        for (router.pending_tcp_pool) |*entry| {
            if (entry.src_ip == 0 and entry.dst_ip == 0) {
                entry.* = .{
                    .src_ip = src_ip,
                    .src_port = src_port,
                    .dst_ip = dst_ip,
                    .dst_port = dst_port,
                    .client_seq = 0,
                    .created_at = std.time.timestamp(),
                };
                return entry;
            }
        }

        return error.PendingConnectionPoolFull;
    }

    /// Initiate SOCKS5 tunnel for new TCP connection (async)
    fn initiateSocks5Tunnel(router: *Router, packet: *const Packet) !void {
        std.debug.print("[SOCKS5] initiateSocks5Tunnel for {s}:{} -> {s}:{}\n", .{ fmtIp(packet.src_ip), packet.src_port, fmtIp(packet.dst_ip), packet.dst_port });

        // Extract client's initial sequence number
        const client_seq = router.extractTcpSeqNum(packet);
        std.debug.print("[SOCKS5] Client SEQ: {}\n", .{client_seq});

        // Create pending connection entry
        const pending = try router.findOrCreatePending(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port);
        pending.client_seq = client_seq;

        // Find empty slot in SOCKS5 pool and create client
        const proxy_config = router.config.proxy orelse {
            std.debug.print("[SOCKS5-ERROR] No proxy configured\n", .{});
            return error.NoProxyConfigured;
        };

        const proxy_addr = parseProxyAddr(proxy_config.addr) catch {
            std.debug.print("[SOCKS5-ERROR] Failed to parse proxy address\n", .{});
            return error.InvalidProxyAddr;
        };

        const proxy_net_addr = std.net.Address.initIp4(
            .{ @as(u8, @truncate(proxy_addr.ip >> 24)), @as(u8, @truncate(proxy_addr.ip >> 16)), @as(u8, @truncate(proxy_addr.ip >> 8)), @as(u8, @truncate(proxy_addr.ip)) },
            proxy_addr.port,
        );

        // Find empty slot in pool
        var pool_idx: usize = 0;
        for (router.socks5_pool, 0..) |*conn_ptr, idx| {
            if (conn_ptr.* == null) {
                pool_idx = idx;
                break;
            }
        } else {
            return error.Socks5PoolFull;
        }

        // Create new SOCKS5 client
        const client = try Socks5Conn.create(router.allocator, &router.loop, proxy_net_addr);

        // Set the 4-tuple in the client for callback access
        client.src_ip = packet.src_ip;
        client.src_port = packet.src_port;
        client.dst_ip = packet.dst_ip;
        client.dst_port = packet.dst_port;

        // Set callbacks
        client.setCallbacks(router, onSocks5Data, onSocks5TunnelReady, onSocks5Ready, onSocks5Error);
        router.socks5_pool[pool_idx] = client;

        std.debug.print("[SOCKS5] Starting async connect to proxy...\n", .{});

        // Initiate async connection - will call back onSocks5TunnelReady when done
        client.connectAsync(packet.dst_ip, packet.dst_port) catch |err| {
            std.debug.print("[SOCKS5-ERROR] connectAsync failed: {}\n", .{err});
            router.socks5_pool[pool_idx] = null;
            Socks5Conn.destroy(client, router.allocator);
            return err;
        };

        std.debug.print("[SOCKS5] Async connect initiated\n", .{});
    }

    /// Forward TCP data through SOCKS5 connection
    fn forwardTcpData(router: *Router, client: *Socks5Conn, packet: *const Packet) !void {
        const payload = router.extractTcpPayload(packet);
        std.debug.print("[SOCKS5-DATA] Forwarding {} bytes\n", .{payload.len});

        if (payload.len > 0) {
            client.send(packet.data) catch |err| {
                std.debug.print("[SOCKS5-DATA-ERROR] send failed: {}\n", .{err});
                router._stats.packets_dropped += 1;
            };
        }
    }

    /// Register established TCP connection
    fn registerTcpConnection(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, client: *Socks5Conn) !void {
        for (router.tcp_conn_pool) |*entry| {
            if (!entry.used) {
                entry.* = .{
                    .src_ip = src_ip,
                    .src_port = src_port,
                    .dst_ip = dst_ip,
                    .dst_port = dst_port,
                    .socks5_client = client,
                    .tcp_state = .Established,
                    .last_active = std.time.timestamp(),
                    .used = true,
                };
                std.debug.print("[TCP] Registered connection: {s}:{} -> {s}:{}\n", .{ fmtIp(src_ip), src_port, fmtIp(dst_ip), dst_port });
                return;
            }
        }
        return error.TcpPoolFull;
    }

    /// Remove TCP connection
    fn removeTcpConnection(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) void {
        for (router.tcp_conn_pool) |*entry| {
            if (entry.used and
                entry.src_ip == src_ip and entry.src_port == src_port and
                entry.dst_ip == dst_ip and entry.dst_port == dst_port)
            {

                // Close associated SOCKS5 client
                if (entry.socks5_client) |client| {
                    // Remove from pool
                    for (router.socks5_pool, 0..) |*conn_ptr, idx| {
                        if (conn_ptr.* == client) {
                            conn_ptr.* = null;
                            break;
                        }
                    }
                    client.close();
                }

                entry.used = false;
                std.debug.print("[TCP] Removed connection: {s}:{} -> {s}:{}\n", .{ fmtIp(src_ip), src_port, fmtIp(dst_ip), dst_port });
                return;
            }
        }
    }

    /// Get pending connection info
    fn getPendingConnection(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) ?*PendingTcpConn {
        for (router.pending_tcp_pool) |*entry| {
            if (entry.src_ip == src_ip and entry.src_port == src_port and
                entry.dst_ip == dst_ip and entry.dst_port == dst_port)
            {
                return entry;
            }
        }
        return null;
    }

    /// Clear pending connection
    fn clearPendingConnection(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) void {
        for (router.pending_tcp_pool) |*entry| {
            if (entry.src_ip == src_ip and entry.src_port == src_port and
                entry.dst_ip == dst_ip and entry.dst_port == dst_port)
            {
                entry.src_ip = 0;
                entry.dst_ip = 0;
                return;
            }
        }
    }

    /// Extract TCP payload from packet
    fn extractTcpPayload(router: *Router, packet: *const Packet) []const u8 {
        const ip_header_len = ((packet.data[0] & 0x0F) * 4);
        const tcp_info = ipstack.tcp.parseHeader(
            packet.data.ptr + ip_header_len,
            packet.data.len - ip_header_len,
        ) orelse {
            return &[_]u8{};
        };
        return packet.data[ip_header_len + tcp_info.header_len ..];
    }

    /// Extract TCP sequence number from packet
    fn extractTcpSeqNum(router: *Router, packet: *const Packet) u32 {
        const ip_header_len = ((packet.data[0] & 0x0F) * 4);
        const tcp_info = ipstack.tcp.parseHeader(
            packet.data.ptr + ip_header_len,
            packet.data.len - ip_header_len,
        ) orelse {
            return 0;
        };
        return tcp_info.seq_num;
    }

    /// Forward packet with NAT translation (UDP)
    fn forwardWithNat(router: *Router, packet: *const Packet) !void {
        // UDP NAT forwarding
        // Create NAT session and forward packet

        if (router.udp_sock == null or router.nat_table == null) {
            router._stats.packets_dropped += 1;
            return;
        }

        const nat = router.nat_table.?;

        // Check if session exists
        const session = nat.lookup(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port);

        if (session) |sess| {
            // Session exists, rewrite and forward
            try router.sendNatUdp(sess.egress_ip, sess.mapped_port, packet);
        } else {
            // Create new session - insert() internally allocates port
            const new_session = nat.insert(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port) catch {
                router._stats.packets_dropped += 1;
                return;
            };

            try router.sendNatUdp(new_session.egress_ip, new_session.mapped_port, packet);
            router._stats.udp_sessions += 1;
        }

        router._stats.udp_sessions = nat.count();
    }

    /// Send UDP packet with NAT translation
    fn sendNatUdp(router: *Router, mapped_ip: u32, mapped_port: u16, packet: *const Packet) !void {
        _ = mapped_port;
        const sock = router.udp_sock orelse return error.NoSocket;

        // Parse IP header to get UDP payload
        const ip_header_len = ((packet.data[0] & 0x0F) * 4);
        if (packet.data.len < ip_header_len + 8) return; // Minimum UDP header is 8 bytes

        // Build new IP packet with rewritten source
        const new_ip_header_len = 20; // Standard IPv4 header

        // Copy packet to send buffer
        @memcpy(router.udp_send_buf[0..packet.data.len], packet.data);

        // Rewrite source IP
        std.mem.writeInt(u32, router.udp_send_buf[16..20], mapped_ip, .big);

        // Recalculate IP header checksum
        router.udp_send_buf[10] = 0;
        router.udp_send_buf[11] = 0;

        const ip_sum = ipstack.checksum.checksum(router.udp_send_buf[0..new_ip_header_len], 0);
        std.mem.writeInt(u16, router.udp_send_buf[10..12], ip_sum, .big);

        // Destination address
        var dst_addr = sockaddr_in{
            .sin_len = @sizeOf(sockaddr_in),
            .sin_family = AF_INET,
            .sin_port = std.mem.nativeToBig(u16, packet.dst_port),
            .sin_addr = .{
                @as(u8, @truncate(packet.dst_ip >> 24)),
                @as(u8, @truncate(packet.dst_ip >> 16)),
                @as(u8, @truncate(packet.dst_ip >> 8)),
                @as(u8, @truncate(packet.dst_ip)),
            },
        };

        const sent = std.posix.sendto(sock, router.udp_send_buf[0..packet.data.len], 0, @as(*const std.posix.sockaddr, @ptrCast(&dst_addr)), @sizeOf(sockaddr_in)) catch {
            router._stats.packets_dropped += 1;
            return;
        };

        if (sent != packet.data.len) {
            router._stats.packets_dropped += 1;
            return;
        }

        router._stats.bytes_tx += sent;
    }

    /// Handle UDP response from NAT
    fn handleNatUdp(router: *Router, data: []const u8, src_ip: u32, src_port: u16) void {
        if (router.nat_table == null) return;

        const nat = router.nat_table.?;

        // Find NAT session by mapped port and egress IP
        // For UDP response: src_ip=dst_ip, src_port=mapped_port
        const session = nat.lookupByMapped(src_ip, src_port) orelse {
            // No session found, might be unsolicited packet
            return;
        };

        // Copy to write buffer
        @memcpy(router.write_buf[0..data.len], data);

        // Rewrite destination to original source
        std.mem.writeInt(u32, router.write_buf[16..20], session.src_ip, .big);
        std.mem.writeInt(u16, router.write_buf[22..24], session.src_port, .big);

        // Recalculate checksum
        router.write_buf[10] = 0;
        router.write_buf[11] = 0;
        const ip_sum = ipstack.checksum.checksum(router.write_buf[0..20], 0);
        std.mem.writeInt(u16, router.write_buf[10..12], ip_sum, .big);

        // Write back to TUN
        router.writeToTunBuf(router.write_buf[0..data.len]) catch {};
    }

    // ============ SOCKS5 UDP Associate Methods ============

    /// Forward UDP packet through SOCKS5 proxy (UDP Associate)
    fn forwardUdpToSocks5(router: *Router, packet: *const Packet) !void {
        std.debug.print("\n[UDP-SOCKS5] ============================================\n", .{});
        std.debug.print("[UDP-SOCKS5] forwardUdpToSocks5 called\n", .{});
        std.debug.print("[UDP-SOCKS5] Packet: {s}:{} -> {s}:{}\n", .{ fmtIp(packet.src_ip), packet.src_port, fmtIp(packet.dst_ip), packet.dst_port });

        // Check if this is a DNS query
        const is_dns = router.isDnsQuery(packet.dst_port);
        if (is_dns) {
            std.debug.print("[UDP-SOCKS5] DNS query detected (port 53)\n", .{});
            router._stats.dns_queries += 1;

            // Extract DNS transaction ID and track request
            const ip_header_len = ((packet.data[0] & 0x0F) * 4);
            const udp_header_offset = ip_header_len;
            const udp_payload_offset = udp_header_offset + 8;
            if (packet.data.len >= udp_payload_offset) {
                const udp_payload = packet.data[udp_payload_offset..];
                const tx_id = router.extractDnsTxId(udp_payload);
                router.trackDnsRequest(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, tx_id);
            }
        }

        // Check if UDP associate is ready
        if (router.udp_associate) |ua| {
            if (ua.isReady()) {
                // Extract UDP payload
                const ip_header_len = ((packet.data[0] & 0x0F) * 4);
                const udp_header_offset = ip_header_len;
                const udp_payload_offset = udp_header_offset + 8; // UDP header is 8 bytes

                if (packet.data.len >= udp_payload_offset) {
                    const udp_payload = packet.data[udp_payload_offset..];

                    // Send through SOCKS5 UDP associate
                    ua.sendDatagram(udp_payload, packet.dst_ip, packet.dst_port) catch |err| {
                        std.debug.print("[UDP-SOCKS5-ERROR] sendDatagram failed: {}\n", .{err});
                        router._stats.packets_dropped += 1;
                        return;
                    };

                    // Create/update UDP session for response lookup
                    router.upsertUdpSession(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port);

                    std.debug.print("[UDP-SOCKS5] Sent {} bytes to proxy\n", .{udp_payload.len});
                }
            } else {
                std.debug.print("[UDP-SOCKS5-WARN] UDP associate not ready, state={s}\n", .{@tagName(ua.state)});
                router._stats.packets_dropped += 1;
            }
        } else {
            std.debug.print("[UDP-SOCKS5-WARN] No UDP associate configured\n", .{});
            router._stats.packets_dropped += 1;
        }

        std.debug.print("[UDP-SOCKS5-EXIT] ============================================\n\n", .{});
    }

    /// Create or update UDP session for SOCKS5 UDP Associate
    fn upsertUdpSession(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) void {
        // Check for existing session
        for (router.udp_sessions) |*entry| {
            if (entry.used and
                entry.src_ip == src_ip and entry.src_port == src_port and
                entry.dst_ip == dst_ip and entry.dst_port == dst_port)
            {
                entry.last_active = std.time.timestamp();
                return;
            }
        }

        // Find empty slot
        for (router.udp_sessions) |*entry| {
            if (!entry.used) {
                entry.* = .{
                    .src_ip = src_ip,
                    .src_port = src_port,
                    .dst_ip = dst_ip,
                    .dst_port = dst_port,
                    .last_active = std.time.timestamp(),
                    .used = true,
                };
                return;
            }
        }

        // Table full, drop oldest session
        var oldest_idx: usize = 0;
        var oldest_time: i64 = std.time.timestamp();
        for (router.udp_sessions, 0..) |*entry, idx| {
            if (entry.used and entry.last_active < oldest_time) {
                oldest_time = entry.last_active;
                oldest_idx = idx;
            }
        }

        const entry = &router.udp_sessions[oldest_idx];
        entry.* = .{
            .src_ip = src_ip,
            .src_port = src_port,
            .dst_ip = dst_ip,
            .dst_port = dst_port,
            .last_active = std.time.timestamp(),
            .used = true,
        };
    }

    /// Find UDP session by 4-tuple
    fn findUdpSession(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) ?*Socks5UdpSession {
        for (router.udp_sessions) |*entry| {
            if (entry.used and
                entry.src_ip == src_ip and entry.src_port == src_port and
                entry.dst_ip == dst_ip and entry.dst_port == dst_port)
            {
                return entry;
            }
        }
        return null;
    }

    /// Handle UDP datagram received from SOCKS5 proxy
    fn handleSocks5UdpResponse(router: *Router, data: []const u8, src_ip: u32, src_port: u16) void {
        std.debug.print("\n[UDP-SOCKS5-RESP] ============================================\n", .{});
        std.debug.print("[UDP-SOCKS5-RESP] Received {} bytes from {s}:{}\n", .{ data.len, fmtIp(src_ip), src_port });

        // Check if this is a DNS response
        const tx_id = router.extractDnsTxId(data);
        if (tx_id != 0) {
            // Check if response matches a pending request
            if (router.checkDnsResponse(src_ip, src_port, tx_id)) {
                std.debug.print("[UDP-SOCKS5-RESP] DNS response matched (tx_id={x:0>4})\n", .{tx_id});
                router._stats.dns_responses += 1;
            }
        }

        // Find matching UDP session
        // The response source is the original destination
        var found_session: ?*Socks5UdpSession = null;

        for (router.udp_sessions) |*entry| {
            if (entry.used and entry.dst_ip == src_ip and entry.dst_port == src_port) {
                found_session = entry;
                break;
            }
        }

        if (found_session) |session| {
            std.debug.print("[UDP-SOCKS5-RESP] Found session: {s}:{} -> {s}:{}\n", .{
                fmtIp(session.src_ip), session.src_port,
                fmtIp(session.dst_ip), session.dst_port,
            });

            // Build IP+UDP packet with original 4-tuple
            // IP header (20 bytes) + UDP header (8 bytes) + data
            const ip_header_len = 20;
            const udp_header_len = 8;
            const total_len = ip_header_len + udp_header_len + data.len;

            if (router.write_buf.len < total_len) {
                std.debug.print("[UDP-SOCKS5-RESP-ERROR] Buffer too small\n", .{});
                return;
            }

            // Build IP header
            router.write_buf[0] = 0x45; // Version + IHL
            router.write_buf[1] = 0; // TOS
            std.mem.writeInt(u16, router.write_buf[2..4], @as(u16, @intCast(total_len)), .big);
            router.write_buf[4] = 0; // ID
            router.write_buf[5] = 0;
            router.write_buf[6] = 0x40; // DF flag
            router.write_buf[7] = 0; // Fragment offset
            router.write_buf[8] = 64; // TTL
            router.write_buf[9] = 17; // Protocol = UDP
            router.write_buf[10] = 0; // Checksum (placeholder)
            router.write_buf[11] = 0;

            // Source IP = original destination
            std.mem.writeInt(u32, router.write_buf[12..16], session.dst_ip, .big);
            // Destination IP = original source
            std.mem.writeInt(u32, router.write_buf[16..20], session.src_ip, .big);

            // Calculate IP checksum
            const ip_sum = ipstack.checksum.checksum(router.write_buf[0..ip_header_len], 0);
            std.mem.writeInt(u16, router.write_buf[10..12], ip_sum, .big);

            // Build UDP header
            // Source port = original destination port
            std.mem.writeInt(u16, router.write_buf[ip_header_len .. ip_header_len + 2], session.dst_port, .big);
            // Destination port = original source port
            std.mem.writeInt(u16, router.write_buf[ip_header_len + 2 .. ip_header_len + 4], session.src_port, .big);
            // Length
            std.mem.writeInt(u16, router.write_buf[ip_header_len + 4 .. ip_header_len + 6], @as(u16, @intCast(udp_header_len + data.len)), .big);
            router.write_buf[ip_header_len + 6] = 0; // Checksum placeholder
            router.write_buf[ip_header_len + 7] = 0;

            // Copy data
            @memcpy(router.write_buf[ip_header_len + udp_header_len .. total_len], data);

            // Calculate UDP checksum
            const udp_sum = ipstack.checksum.checksumPseudoIPv4(
                session.dst_ip,
                session.src_ip,
                17,
                @as(u16, @intCast(udp_header_len + data.len)),
            );
            var sum: u32 = udp_sum;
            const udp_header_u16 = @as([*]const u16, @ptrCast(router.write_buf[ip_header_len .. ip_header_len + 8]));
            sum += udp_header_u16[0]; // src_port + dst_port
            sum += udp_header_u16[1]; // length
            sum += udp_header_u16[2]; // checksum (0) + padding

            var i: usize = 0;
            while (i + 1 < data.len) : (i += 2) {
                sum += @as(u16, data[i]) | (@as(u16, data[i + 1]) << 8);
            }
            if (i < data.len) {
                sum += @as(u16, data[i]);
            }

            while (sum >> 16 != 0) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            const udp_checksum = @as(u16, @bitCast(~sum));
            std.mem.writeInt(u16, router.write_buf[ip_header_len + 6 .. ip_header_len + 8], udp_checksum, .big);

            // Write to TUN
            router.writeToTunBuf(router.write_buf[0..total_len]) catch |err| {
                std.debug.print("[UDP-SOCKS5-RESP-ERROR] writeToTunBuf failed: {}\n", .{err});
            };

            std.debug.print("[UDP-SOCKS5-RESP] Wrote {} bytes to TUN\n", .{total_len});
        } else {
            std.debug.print("[UDP-SOCKS5-RESP-WARN] No matching session found for {s}:{}\n", .{ fmtIp(src_ip), src_port });
        }

        std.debug.print("[UDP-SOCKS5-RESP-EXIT] ============================================\n\n", .{});
    }

    /// Initialize UDP Associate with SOCKS5 proxy
    fn initUdpAssociate(router: *Router) !void {
        const proxy_config = router.config.proxy orelse {
            std.debug.print("[UDP-SOCKS5] No proxy configured\n", .{});
            return error.NoProxyConfigured;
        };

        if (proxy_config.type != .Socks5) {
            std.debug.print("[UDP-SOCKS5] Proxy type is not SOCKS5\n", .{});
            return error.NotSocks5Proxy;
        }

        const proxy_addr = parseProxyAddr(proxy_config.addr) catch {
            std.debug.print("[UDP-SOCKS5-ERROR] Failed to parse proxy address\n", .{});
            return error.InvalidProxyAddr;
        };

        const proxy_net_addr = std.net.Address.initIp4(
            .{ @as(u8, @truncate(proxy_addr.ip >> 24)), @as(u8, @truncate(proxy_addr.ip >> 16)), @as(u8, @truncate(proxy_addr.ip >> 8)), @as(u8, @truncate(proxy_addr.ip)) },
            proxy_addr.port,
        );

        // Create TCP connection to proxy (needed for UDP associate handshake)
        const tcp_client = try Socks5Conn.create(router.allocator, &router.loop, proxy_net_addr);
        errdefer Socks5Conn.destroy(tcp_client, router.allocator);

        // Store the TCP client for later
        var tcp_idx: usize = 0;
        for (router.socks5_pool, 0..) |*conn_ptr, idx| {
            if (conn_ptr.* == null) {
                tcp_idx = idx;
                break;
            }
        } else {
            return error.Socks5PoolFull;
        }

        // Connect to proxy
        tcp_client.setCallbacks(router, null, null, null, onSocks5Error);
        tcp_client.connect(0, 0, null) catch |err| {
            std.debug.print("[UDP-SOCKS5-ERROR] TCP connect failed: {}\n", .{err});
            return err;
        };

        // Wait for connection to establish (simplified - in production use async waiting)
        std.time.sleep(100 * std.time.ns_per_ms);

        if (tcp_client.getState() != .Ready) {
            return error.Socks5ConnectionFailed;
        }

        // Create UDP associate
        const udp_associate = try socks5.Socks5UdpAssociate.create(router.allocator, &router.loop, tcp_client);
        errdefer socks5.Socks5UdpAssociate.destroy(udp_associate, router.allocator);

        // Set callbacks
        udp_associate.setCallbacks(router, onSocks5UdpData, null);

        // Establish UDP associate
        udp_associate.associate() catch |err| {
            std.debug.print("[UDP-SOCKS5-ERROR] UDP associate failed: {}\n", .{err});
            return err;
        };

        // Start reading UDP datagrams from proxy
        udp_associate.submitRead();

        router.socks5_pool[tcp_idx] = tcp_client;
        router.udp_associate = udp_associate;

        std.debug.print("[UDP-SOCKS5] UDP associate established\n", .{});
    }

    /// Submit UDP associate read operation
    fn submitUdpAssociateRead(router: *Router) void {
        if (router.udp_associate) |ua| {
            ua.submitRead();
        }
    }

    /// Forward packet to egress interface using raw socket
    fn forwardToEgress(router: *Router, packet: *const Packet) !void {
        const raw_sock = router.raw_sock orelse {
            // No raw socket available - drop packet
            router._stats.packets_dropped += 1;
            return;
        };

        // Send packet via raw socket
        // The packet already contains the full IP header (from TUN device)
        // For raw sockets with IPPROTO_IP/RAW, destination is encoded in the IP header
        const written = std.posix.send(raw_sock, packet.data, 0) catch {
            router._stats.packets_dropped += 1;
            return;
        };

        if (written != packet.data.len) {
            router._stats.packets_dropped += 1;
            return;
        }

        router._stats.packets_forwarded += 1;
        router._stats.bytes_tx += @as(u64, @intCast(written));
    }

    /// Write packet back to TUN (for local handling)
    fn writeToTun(router: *Router, packet: *const Packet) !void {
        try router.writeToTunDevice(packet.data);
    }

    /// Write raw buffer to TUN
    /// Uses device_ops if available (handles platform-specific headers like macOS utun 4-byte header)
    fn writeToTunBuf(router: *Router, data: []const u8) !void {
        // Dump packet being written
        if (data.len >= 20) {
            const src_ip = std.mem.readInt(u32, data[12..16], .big);
            const dst_ip = std.mem.readInt(u32, data[16..20], .big);
            const protocol = data[9];
            std.debug.print("\n[TUN] WRITE: {} bytes to TUN\n", .{data.len});
            std.debug.print("[TUN]   src={s} dst={s} proto={}\n", .{ fmtIp(src_ip), fmtIp(dst_ip), protocol });
            dumpPacket("[TUN]   packet", data);
        } else {
            std.debug.print("\n[TUN] WRITE: {} bytes to TUN\n", .{data.len});
            dumpPacket("[TUN]   packet", data);
        }

        // Write using device_ops or raw fd
        try router.writeToTunDevice(data);
        std.debug.print("[TUN]   wrote {} bytes\n", .{data.len});
    }

    /// Send TCP SYN-ACK packet to complete three-way handshake
    /// Called after SOCKS5 tunnel is established
    /// Uses ipstack for IP/TCP header construction and checksum calculation
    fn sendSynAck(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, client_seq: u32) !void {
        std.debug.print("\n[SYNACK] ============================================\n", .{});
        std.debug.print("[SYNACK] sendSynAck called at {}\n", .{std.time.nanoTimestamp()});
        std.debug.print("[SYNACK] src_ip={s}:{} (server)\n", .{ fmtIp(src_ip), src_port });
        std.debug.print("[SYNACK] dst_ip={s}:{} (client)\n", .{ fmtIp(dst_ip), dst_port });
        std.debug.print("[SYNACK] client_seq={} ack_num={}\n", .{ client_seq, client_seq + 1 });

        std.debug.print("[SYNACK] Building SYN-ACK packet using ipstack...\n", .{});

        // Build IP header using ipstack
        const tcp_header_len = 20; // SYN packet, no options
        const ip_offset = ipstack.ipv4.buildHeader(
            router.write_buf[0..].ptr,
            src_ip,
            dst_ip,
            6, // TCP protocol
            tcp_header_len,
        );

        std.debug.print("[SYNACK] IP header built at offset {}\n", .{ip_offset});

        // Build TCP header with checksum using ipstack
        const tcp_offset = ip_offset;
        const tcp_len = ipstack.tcp.buildHeaderWithChecksum(
            router.write_buf[tcp_offset..].ptr,
            src_ip,
            dst_ip,
            src_port, // Server port
            dst_port, // Client port
            0, // Server's initial sequence number (will be random in real impl)
            client_seq + 1, // ACK number = client_seq + 1
            0x12, // Flags: SYN + ACK
            65535, // Window size
            &[0]u8{}, // No payload for SYN-ACK
        );

        std.debug.print("[SYNACK] TCP header built at offset {}, len={}\n", .{ tcp_offset, tcp_len });

        const total_len = ip_offset + tcp_len;
        std.debug.print("[SYNACK] Total packet length: {}\n", .{total_len});

        std.debug.print("[SYNACK] Writing {} bytes to TUN...\n", .{total_len});
        try router.writeToTunBuf(router.write_buf[0..total_len]);
        std.debug.print("[SYNACK] SYN-ACK sent successfully!\n", .{});
        std.debug.print("[SYNACK-EXIT] ============================================\n\n", .{});
    }

    /// Send TCP FIN packet to close connection gracefully
    fn sendFin(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) !void {
        std.debug.print("\n[FIN] ============================================\n", .{});
        std.debug.print("[FIN] Sending FIN to {s}:{} -> {s}:{}\n", .{ fmtIp(dst_ip), dst_port, fmtIp(src_ip), src_port });

        // Build IP header
        const tcp_header_len = 20;
        const ip_offset = ipstack.ipv4.buildHeader(
            router.write_buf[0..].ptr,
            src_ip,
            dst_ip,
            6, // TCP protocol
            tcp_header_len,
        );

        // Build TCP header with FIN flag
        const tcp_offset = ip_offset;
        const tcp_len = ipstack.tcp.buildHeaderWithChecksum(
            router.write_buf[tcp_offset..].ptr,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            0, // Sequence number (simplified)
            0, // ACK number
            0x11, // Flags: FIN + ACK
            0, // Window size
            &[0]u8{},
        );

        const total_len = ip_offset + tcp_len;
        try router.writeToTunBuf(router.write_buf[0..total_len]);
        std.debug.print("[FIN] FIN sent successfully!\n", .{});
        std.debug.print("[FIN-EXIT] ============================================\n\n", .{});
    }

    /// Mock connection state for TCP handshake tracking
    const MockState = struct {
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        client_seq: u32,
        stage: MockStage,
    };

    const MockStage = enum {
        syn_received, // Waiting for ACK
        established, // Connection established, can send data
    };

    /// Handle mock HTTP response (SYN -> SYN-ACK, then HTTP on ACK)
    fn handleMockHttp(router: *Router, packet: *const Packet) !void {
        const tcp_offset = 20; // IP header is 20 bytes
        if (packet.data.len < tcp_offset + 20) return;

        const tcp_flags = packet.data[tcp_offset + 13];
        const is_syn = (tcp_flags & 0x02) != 0;
        const is_ack = (tcp_flags & 0x10) != 0;

        std.debug.print("\n[MOCK] ============================================\n", .{});
        std.debug.print("[MOCK] handleMockHttp: SYN={} ACK={}\n", .{ is_syn, is_ack });

        // Store mock state for tracking
        if (router.mock_state == null) {
            router.mock_state = try router.allocator.create(MockState);
        }
        const mock = router.mock_state.?;
        mock.* = .{
            .src_ip = packet.dst_ip,
            .src_port = packet.dst_port,
            .dst_ip = packet.src_ip,
            .dst_port = packet.src_port,
            .client_seq = std.mem.readInt(u32, packet.data[tcp_offset + 4 .. tcp_offset + 8], .big),
            .stage = if (is_syn) .syn_received else .established,
        };

        if (is_syn) {
            // Send SYN-ACK
            std.debug.print("[MOCK] Sending SYN-ACK...\n", .{});
            try router.sendSynAck(
                mock.src_ip,
                mock.src_port,
                mock.dst_ip,
                mock.dst_port,
                mock.client_seq,
            );
        } else if (is_ack and mock.stage == .syn_received) {
            // ACK received, connection established - send HTTP 200 response
            mock.stage = .established;
            std.debug.print("[MOCK] Connection established, sending HTTP 200...\n", .{});
            try router.sendMockDataResponse(
                mock.src_ip,
                mock.src_port,
                mock.dst_ip,
                mock.dst_port,
                mock.client_seq + 1,
            );
        } else {
            std.debug.print("[MOCK] Ignoring packet (flags=0x{x:02})\n", .{tcp_flags});
        }
        std.debug.print("[MOCK-EXIT] ============================================\n\n", .{});
    }

    /// Send HTTP 200 data response (PSH+ACK with payload)
    /// Uses ipstack for IP/TCP header construction
    fn sendMockDataResponse(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, seq_num: u32) !void {
        // HTTP 200 response body
        const http_body = "Hello World!\r\n";
        const http_response =
            "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: 13\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            http_body;

        const tcp_header_len = 20;
        const payload_len = http_response.len;

        // Build IP header using ipstack
        const ip_offset = ipstack.ipv4.buildHeader(
            router.write_buf[0..].ptr,
            src_ip,
            dst_ip,
            6, // TCP protocol
            tcp_header_len + payload_len,
        );

        // Build TCP header with checksum using ipstack
        const tcp_offset = ip_offset;
        const tcp_len = ipstack.tcp.buildHeaderWithChecksum(
            router.write_buf[tcp_offset..].ptr,
            src_ip,
            dst_ip,
            src_port, // Server port
            dst_port, // Client port
            0, // Server's initial sequence number
            seq_num, // ACK number
            0x18, // Flags: PSH + ACK
            65535, // Window size
            http_response,
        );

        const total_len = ip_offset + tcp_len;

        std.debug.print("[MOCK-DATA] Sending HTTP 200 ({} bytes)...\n", .{total_len});
        try router.writeToTunBuf(router.write_buf[0..total_len]);
    }

    // ============ Network Change Detection ============

    /// Handle network pause (no default interface)
    fn handleNetworkPause(router: *Router) void {
        std.debug.print("[NET] Network paused\n", .{});
        router.is_paused = true;

        // Close all SOCKS5 connections in the pool
        for (router.socks5_pool, 0..) |*conn_ptr, idx| {
            if (conn_ptr.*) |conn| {
                conn.close();
                Socks5Conn.destroy(conn, router.allocator);
                conn_ptr.* = null;
            }
        }

        // Close UDP associate
        if (router.udp_associate) |ua| {
            ua.close();
            socks5.Socks5UdpAssociate.destroy(ua, router.allocator);
            router.udp_associate = null;
        }

        // Clear pending TCP connections
        for (router.pending_tcp_pool) |*entry| {
            entry.src_ip = 0;
            entry.dst_ip = 0;
        }
    }

    /// Handle network resume (after being paused)
    fn handleNetworkResume(router: *Router) void {
        std.debug.print("[NET] Network resumed\n", .{});
        router.is_paused = false;

        // Reselect egress interface
        router.reselectEgressInterface() catch |err| {
            std.debug.print("[NET] Failed to reselect egress: {}\n", .{err});
        };
    }

    /// Handle route changes (address added/removed)
    fn handleRoutesChanged(router: *Router) void {
        std.debug.print("[NET] Route changed\n", .{});
        router._stats.route_updates += 1;

        // Reselect egress interface on route changes
        router.reselectEgressInterface() catch |err| {
            std.debug.print("[NET] Failed to reselect egress on route change: {}\n", .{err});
        };
    }

    /// Re-select egress interface after network change
    fn reselectEgressInterface(router: *Router) !void {
        std.debug.print("[NET] Reselecting egress interface...\n", .{});

        // Close existing raw socket if any
        if (router.raw_sock) |sock| {
            std.posix.close(sock);
            router.raw_sock = null;
        }

        // Log current interface
        std.debug.print("[NET] Egress interface: {s}\n", .{router.config.egress.name});

        // Create new raw socket for egress interface
        router.raw_sock = std.posix.socket(
            AF_INET,
            SOCK_RAW | O_NONBLOCK,
            0,
        ) catch {
            std.debug.print("[NET] Failed to create raw socket, using TUN only\n", .{});
            router.raw_sock = null;
            return;
        };

        std.debug.print("[NET] Egress interface reselected successfully\n", .{});
    }

    /// Network change callback for monitor
    fn onNetworkChangeCallback(event: *const monitor.NetworkEvent, userdata: ?*anyopaque) void {
        const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return)));

        std.debug.print("[NET] Network change callback: {s}\n", .{@tagName(event.change)});

        switch (event.change) {
            .interface_down, .network_losing => {
                router.handleNetworkPause();
            },
            .interface_up, .address_added => {
                router.handleNetworkResume();
            },
            .address_removed => {
                // Address removed - pause and let resume handle it when address is added back
                router.handleNetworkPause();
            },
            .route_changed => {
                router.handleRoutesChanged();
            },
        }
    }

    /// Handle ICMP echo request - send echo reply
    fn handleIcmpEcho(router: *Router, packet_offset: usize, packet_len: usize, ip_header_len: usize) !void {
        // ICMP header is at ip_header_len in the packet (after packet_offset)
        // ICMP Echo Request: Type = 8, Code = 0
        // ICMP Echo Reply: Type = 0, Code = 0

        if (packet_len < 20) {
            std.debug.print("[ICMP] Packet too small for IP header\n", .{});
            return;
        }

        const packet = router.packet_buf[packet_offset .. packet_offset + packet_len];

        if (packet.len < ip_header_len + 8) {
            std.debug.print("[ICMP] Packet too small for ICMP\n", .{});
            return;
        }

        // Check if this is an echo request (type 8)
        const icmp_type = packet[ip_header_len];
        if (icmp_type != 8) {
            std.debug.print("[ICMP] Not an echo request (type={})\n", .{icmp_type});
            return;
        }

        std.debug.print("[ICMP] Echo request received, sending reply\n", .{});

        // Copy packet to ICMP buffer (use actual packet length)
        const copy_len = packet.len;
        @memcpy(router.icmp_buf[0..copy_len], packet);

        // Get src/dst IPs from original packet (in network byte order)
        const src_ip = std.mem.readInt(u32, packet[12..16], .big);
        const dst_ip = std.mem.readInt(u32, packet[16..20], .big);

        std.debug.print("[ICMP]   src={s} dst={s}\n", .{ fmtIp(src_ip), fmtIp(dst_ip) });

        // Swap IP addresses: reply goes back to original source
        // For ICMP echo reply:
        //   Source IP = original destination (dst_ip)
        //   Destination IP = original source (src_ip)
        // IPv4 header offsets:
        //   Offset 12-16: Source IP
        //   Offset 16-20: Destination IP
        std.mem.writeInt(u32, router.icmp_buf[12..16], dst_ip, .big);
        std.mem.writeInt(u32, router.icmp_buf[16..20], src_ip, .big);

        // Change ICMP type from 8 (Echo Request) to 0 (Echo Reply)
        router.icmp_buf[ip_header_len] = 0;

        // Zero out checksum field before recalculating (MUST be 0 for correct calculation)
        router.icmp_buf[ip_header_len + 2] = 0;
        router.icmp_buf[ip_header_len + 3] = 0;

        // Recalculate ICMP checksum (includes pseudo-header)
        // ICMP checksum = one's complement of sum(pseudo-header + ICMP header + data)
        // Pseudo-header: src_ip + dst_ip + zero + protocol (1) + ICMP length
        const icmp_len = copy_len - ip_header_len;

        var sum: u32 = 0;

        // Use the REPLY IPs (already swapped in icmp_buf) for pseudo-header
        // icmp_buf[12..16] = reply source IP (original dst_ip = 10.0.0.2)
        // icmp_buf[16..20] = reply destination IP (original src_ip = 10.0.0.1)
        const reply_src_ip = std.mem.readInt(u32, router.icmp_buf[12..16], .big);
        const reply_dst_ip = std.mem.readInt(u32, router.icmp_buf[16..20], .big);

        // Add pseudo-header: source IP (reply source)
        sum += reply_src_ip >> 16;
        sum += reply_src_ip & 0xFFFF;

        // Pseudo-header: destination IP (reply destination)
        sum += reply_dst_ip >> 16;
        sum += reply_dst_ip & 0xFFFF;

        // Pseudo-header: zero + protocol (1 = ICMP)
        sum += 1;

        // Pseudo-header: ICMP length
        sum += @as(u32, @intCast(icmp_len));

        // Add ICMP header + data
        var i: usize = ip_header_len;
        while (i + 1 < copy_len) : (i += 2) {
            sum += std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(&router.icmp_buf[i])), .big);
        }
        if (i < copy_len) {
            // Add last odd byte in high byte position
            sum += @as(u16, router.icmp_buf[i]) << 8;
        }

        // Fold 32-bit sum to 16-bit
        while (sum >> 16 != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        // Take one's complement (checksum = ~sum), then truncate to u16
        const checksum = @as(u16, @truncate(~sum));

        // Write checksum
        std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&router.icmp_buf[ip_header_len + 2])), checksum, .big);

        // Debug: verify IPs in icmp_buf
        std.debug.print("[ICMP-DBG] icmp_buf[12..20]=", .{});
        for (12..20) |j| std.debug.print("{x:0>2} ", .{router.icmp_buf[j]});
        std.debug.print("\n", .{});

        // Write reply back to TUN using dedicated ICMP buffer
        try router.writeToTunBuf(router.icmp_buf[0..copy_len]);
        std.debug.print("[ICMP] Reply sent successfully\n", .{});
    }

    /// Format IPv6 address for logging
    fn fmtIpv6(ip: *const [16]u8) [46]u8 {
        var buf: [46]u8 = undefined;
        const formatted = ipstack.ipv6.formatIp(ip, &buf);
        @memcpy(buf[0..formatted.len], formatted);
        if (formatted.len < buf.len) {
            buf[formatted.len] = 0;
        }
        return buf;
    }

    /// Handle IPv6 packet received from TUN
    fn onIpv6PacketReceived(router: *Router, packet_offset: usize, n: usize) xev.CallbackAction {
        _ = router;
        _ = packet_offset;
        _ = n;
        // TODO: Implement IPv6 packet handling
        // For now, drop IPv6 packets and resubmit read
        std.debug.print("[IPv6] IPv6 packet received, not yet implemented - dropping\n", .{});
        router.submitTunRead();
        return .disarm;
    }

    /// Parse IP packet and extract 4-tuple
    /// Uses ipstack for protocol parsing
    fn parsePacket(router: *Router, data: []const u8) !Packet {
        _ = router; // Reserved for future use (e.g., accessing config)
        // Use ipstack's IPv4 header parser
        const ip_info = ipstack.ipv4.parseHeader(data.ptr, data.len) orelse {
            return error.InvalidPacket;
        };

        var src_port: u16 = 0;
        var dst_port: u16 = 0;

        // Parse transport layer header for TCP/UDP using ipstack
        if (ip_info.protocol == 6) { // TCP
            const tcp_info = ipstack.tcp.parseHeader(
                data.ptr + ip_info.header_len,
                ip_info.payload_len,
            ) orelse {
                return error.InvalidPacket;
            };
            src_port = tcp_info.src_port;
            dst_port = tcp_info.dst_port;
        } else if (ip_info.protocol == 17) { // UDP
            const udp_info = ipstack.udp.parseHeader(
                data.ptr + ip_info.header_len,
                ip_info.payload_len,
            ) orelse {
                return error.InvalidPacket;
            };
            src_port = udp_info.src_port;
            dst_port = udp_info.dst_port;
        }

        return Packet{
            .data = data,
            .src_ip = ip_info.src_ip,
            .src_port = src_port,
            .dst_ip = ip_info.dst_ip,
            .dst_port = dst_port,
            .protocol = ip_info.protocol,
        };
    }
};

/// TUN readable callback (libxev callback) - ENTRY POINT FOR ALL INCOMING PACKETS
fn onTunReadable(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));
    std.debug.print("\n[TUN-CB-ENTRY] ============================================\n", .{});
    std.debug.print("[TUN-CB-ENTRY] onTunReadable called at {}\n", .{std.time.nanoTimestamp()});
    std.debug.print("[TUN-CB-ENTRY] result type: {s}\n", .{@tagName(result)});
    std.debug.print("[TUN-CB-ENTRY] router.state: {s}\n", .{@tagName(router.state)});

    // Check for read result (result.read is error union !usize)
    const n = result.read catch |err| {
        std.debug.print("[TUN-CB-ERROR] Read failed: {}\n", .{err});
        std.debug.print("[TUN-CB-ACTION] Resubmitting TUN read\n", .{});
        router.submitTunRead();
        return .disarm;
    };
    if (n == 0) {
        std.debug.print("[TUN-CB-WARN] EOF received (n=0)\n", .{});
        std.debug.print("[TUN-CB-ACTION] Resubmitting TUN read\n", .{});
        router.submitTunRead();
        return .disarm;
    }

    std.debug.print("[TUN-CB] Read {} bytes from TUN (fd={})\n", .{ n, router.tunFd() });
    router._stats.bytes_rx += n;

    // Check for macOS utun header (AF_INET=2 or AF_INET6=24 at byte 3 in network byte order)
    var packet_offset: usize = 0;
    var is_ipv6 = false;
    if (n >= 4) {
        const af_type = router.packet_buf[3];
        if (af_type == 2) {
            // IPv4
            std.debug.print("[TUN-CB] UTUN header detected (AF_INET=2), skipping 4 bytes\n", .{});
            packet_offset = 4;
        } else if (af_type == 24 or af_type == 0x18) {
            // IPv6 (AF_INET6 = 24 = 0x18)
            std.debug.print("[TUN-CB] UTUN header detected (AF_INET6={}), skipping 4 bytes\n", .{af_type});
            packet_offset = 4;
            is_ipv6 = true;
        }
    }

    // Check minimum size based on IP version
    const min_size = if (is_ipv6) 40 else 20; // IPv6 header is 40 bytes, IPv4 is 20
    if (n - packet_offset < min_size) {
        std.debug.print("[TUN-CB-WARN] Packet too small ({} < {}), dropping\n", .{ n - packet_offset, min_size });
        router.submitTunRead();
        return .disarm;
    }

    // Handle IPv6 packets
    if (is_ipv6) {
        return router.onIpv6PacketReceived(packet_offset, n);
    }

    // IPv4 packet handling continues below...

    // Extract packet info for logging
    const proto_byte = router.packet_buf[packet_offset + 9];
    const src_ip = std.mem.readInt(u32, router.packet_buf[packet_offset + 12 ..][0..4], .big);
    const dst_ip = std.mem.readInt(u32, router.packet_buf[packet_offset + 16 ..][0..4], .big);

    std.debug.print("[TUN-CB] Packet: {s} -> {s} proto={}\n", .{ fmtIp(src_ip), fmtIp(dst_ip), proto_byte });

    // Check for ICMP echo request (protocol=1, type=8)
    if (proto_byte == 1) {
        const ip_header_len = (@as(usize, router.packet_buf[packet_offset]) & 0x0F) * 4;
        if (n - packet_offset >= ip_header_len + 8) {
            const icmp_type = router.packet_buf[packet_offset + ip_header_len];
            if (icmp_type == 8) {
                std.debug.print("[TUN-CB] ICMP echo request detected, sending reply\n", .{});
                router.handleIcmpEcho(packet_offset, n, ip_header_len) catch {
                    std.debug.print("[TUN-CB-ERROR] handleIcmpEcho failed\n", .{});
                };
                router.submitTunRead();
                return .disarm;
            }
        }
    }

    // Parse and forward packet
    const raw_data = router.packet_buf[packet_offset..n];
    @memcpy(router.write_buf[0..raw_data.len], raw_data);
    const packet_copy = router.write_buf[0..raw_data.len];

    const packet = router.parsePacket(packet_copy) catch |err| {
        std.debug.print("[TUN-CB-ERROR] Parse packet failed: {}\n", .{err});
        router.submitTunRead();
        return .disarm;
    };

    std.debug.print("[TUN-CB] Parsed: {s}:{} -> {s}:{} proto={}\n", .{ fmtIp(packet.src_ip), packet.src_port, fmtIp(packet.dst_ip), packet.dst_port, packet.protocol });

    router.forwardPacket(&packet) catch |err| {
        std.debug.print("[TUN-CB-ERROR] forwardPacket failed: {}\n", .{err});
    };

    // Submit next TUN read
    router.submitTunRead();
    std.debug.print("[TUN-CB] Submitted next TUN read\n", .{});
    std.debug.print("[TUN-CB-EXIT] ============================================\n\n", .{});
    return .disarm;
}

/// NAT cleanup timer callback
fn onNatTimer(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));

    // Handle timer result (result.timer is error union !TimerTrigger)
    _ = result.timer catch {
        router.submitNatTimer();
        return .disarm;
    };
    // Timer fired, cleanup expired NAT sessions
    if (router.config.nat_config != null) {
        _ = router.nat_table.?.cleanup();
    }

    // Cleanup expired UDP sessions (60 second timeout)
    router.cleanupUdpSessions();

    // Resubmit timer
    router.submitNatTimer();

    return .disarm;
}

/// Cleanup expired UDP sessions
fn cleanupUdpSessions(router: *Router) void {
    const now = std.time.timestamp();
    const timeout: i64 = 60; // 60 seconds timeout

    var cleaned: usize = 0;
    for (router.udp_sessions) |*entry| {
        if (entry.used and now - entry.last_active > timeout) {
            entry.used = false;
            cleaned += 1;
        }
    }

    if (cleaned > 0) {
        std.debug.print("[UDP-SESSION] Cleaned {} expired sessions\n", .{cleaned});
    }

    // Also cleanup DNS requests
    router.cleanupDnsRequests();
}

/// Check if packet is a DNS query (UDP port 53)
/// Check if packet is a DNS query (UDP port 53)
fn isDnsQuery(router: *Router, dst_port: u16) bool {
    _ = router;
    return dst_port == 53;
}

/// Extract DNS transaction ID from UDP payload
fn extractDnsTxId(data: []const u8) u16 {
    if (data.len < 2) return 0;
    return std.mem.readInt(u16, data[0..2], .big);
}

/// Track DNS request for timeout detection
fn trackDnsRequest(router: *Router, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, tx_id: u16) void {
    // Check for existing request
    for (router.dns_requests) |*entry| {
        if (entry.used and
            entry.src_ip == src_ip and entry.src_port == src_port and
            entry.dst_ip == dst_ip and entry.dst_port == dst_port)
        {
            entry.tx_id = tx_id;
            entry.created_at = std.time.timestamp();
            return;
        }
    }

    // Find empty slot
    for (router.dns_requests) |*entry| {
        if (!entry.used) {
            entry.* = .{
                .src_ip = src_ip,
                .src_port = src_port,
                .dst_ip = dst_ip,
                .dst_port = dst_port,
                .tx_id = tx_id,
                .created_at = std.time.timestamp(),
                .used = true,
            };
            return;
        }
    }

    // Table full, log warning
    std.debug.print("[DNS-WARN] DNS request table full\n", .{});
}

/// Check if received DNS response matches a pending request
fn checkDnsResponse(router: *Router, src_ip: u32, src_port: u16, tx_id: u16) bool {
    for (router.dns_requests) |*entry| {
        if (entry.used and entry.dst_ip == src_ip and entry.dst_port == src_port) {
            // Found matching destination, check if tx_id matches
            if (entry.tx_id == tx_id) {
                // Mark as completed (clear the entry)
                entry.used = false;
                return true;
            }
        }
    }
    return false;
}

/// Cleanup expired DNS requests (for timeout detection)
fn cleanupDnsRequests(router: *Router) void {
    const now = std.time.timestamp();
    const timeout: i64 = 5; // 5 seconds for DNS

    var timed_out: usize = 0;
    for (router.dns_requests) |*entry| {
        if (entry.used and now - entry.created_at > timeout) {
            entry.used = false;
            timed_out += 1;
            router._stats.dns_timeouts += 1;
        }
    }

    if (timed_out > 0) {
        std.debug.print("[DNS] Cleaned {} timed out requests\n", .{timed_out});
    }
}

/// SOCKS5 data callback - forward received data from proxy to TUN
fn onSocks5Data(userdata: ?*anyopaque, data: []const u8, client: *Socks5Client) void {
    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return)));

    std.debug.print("\n[SOCKS5-DATA] ============================================\n", .{});
    std.debug.print("[SOCKS5-DATA] onSocks5Data called at {}\n", .{std.time.nanoTimestamp()});
    std.debug.print("[SOCKS5-DATA] Received {} bytes from proxy\n", .{data.len});

    std.debug.print("[SOCKS5-DATA] From target: {s}:{} (client src: {s}:{})\n", .{ fmtIp(client.dst_ip), client.dst_port, fmtIp(client.src_ip), client.src_port });

    // Build IP header at position 0-19
    const total_len = 20 + data.len; // IP header + payload

    // Copy payload to position after IP header (20 bytes)
    @memcpy(router.write_buf[20..total_len], data);

    router.write_buf[0] = 0x45; // Version (4) + IHL (5 = 20 bytes)
    router.write_buf[1] = 0; // TOS
    std.mem.writeInt(u16, router.write_buf[2..4], @as(u16, @intCast(total_len)), .big); // Total length
    router.write_buf[4] = 0; // ID
    router.write_buf[5] = 0;
    router.write_buf[6] = 0x40; // Flags (DF) + Fragment offset high
    router.write_buf[7] = 0; // Fragment offset low
    router.write_buf[8] = 64; // TTL
    router.write_buf[9] = 6; // Protocol (TCP)
    router.write_buf[10] = 0; // Checksum (will be calculated)
    router.write_buf[11] = 0;

    // Source IP: destination server IP (from SOCKS5 connection)
    std.mem.writeInt(u32, router.write_buf[12..16], client.dst_ip, .big);

    // Destination IP: original client IP (from 4-tuple)
    std.mem.writeInt(u32, router.write_buf[16..20], client.src_ip, .big);

    // Recalculate IP header checksum
    router.write_buf[10] = 0;
    router.write_buf[11] = 0;
    const ip_sum = ipstack.checksum.checksum(router.write_buf[0..20], 0);
    std.mem.writeInt(u16, router.write_buf[10..12], ip_sum, .big);

    std.debug.print("[SOCKS5-DATA] Writing {} bytes to TUN...\n", .{total_len});

    // Write to TUN
    router.writeToTunBuf(router.write_buf[0..total_len]) catch |err| {
        std.debug.print("[SOCKS5-DATA-ERROR] Failed to write to TUN: {}\n", .{err});
    };
    std.debug.print("[SOCKS5-DATA] Data written to TUN successfully\n", .{});
    std.debug.print("[SOCKS5-DATA-EXIT] ============================================\n\n", .{});
}

/// SOCKS5 tunnel ready callback - SOCKS5 CONNECT succeeded, send SYN-ACK to client
fn onSocks5TunnelReady(userdata: ?*anyopaque, client: *Socks5Client) void {
    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return)));

    std.debug.print("\n[SOCKS5-TUNNEL] ============================================\n", .{});
    std.debug.print("[SOCKS5-TUNNEL] onSocks5TunnelReady called\n", .{});
    std.debug.print("[SOCKS5-TUNNEL] SOCKS5 client state: {s}\n", .{@tagName(client.getState())});
    std.debug.print("[SOCKS5-TUNNEL] Client target: {s}:{} (src: {s}:{})\n", .{ fmtIp(client.dst_ip), client.dst_port, fmtIp(client.src_ip), client.src_port });

    // Look up pending connection
    const pending = router.getPendingConnection(client.src_ip, client.src_port, client.dst_ip, client.dst_port);

    if (pending) |syn| {
        std.debug.print("[SOCKS5-TUNNEL] Pending SYN found: client={s}:{} seq={}\n", .{ fmtIp(syn.src_ip), syn.src_port, syn.client_seq });

        // Send SYN-ACK to complete TCP handshake
        router.sendSynAck(
            client.dst_ip, // src_ip: server IP
            client.dst_port, // src_port: server port
            syn.src_ip, // dst_ip: client IP
            syn.src_port, // dst_port: client port
            syn.client_seq,
        ) catch |err| {
            std.debug.print("[SOCKS5-TUNNEL-ERROR] sendSynAck failed: {}\n", .{err});
            router.clearPendingConnection(client.src_ip, client.src_port, client.dst_ip, client.dst_port);
            return;
        };

        // Register the connection
        router.registerTcpConnection(client.src_ip, client.src_port, client.dst_ip, client.dst_port, client) catch {
            std.debug.print("[SOCKS5-TUNNEL-WARN] Failed to register connection\n", .{});
        };

        // Clear pending
        router.clearPendingConnection(client.src_ip, client.src_port, client.dst_ip, client.dst_port);
        std.debug.print("[SOCKS5-TUNNEL] SYN-ACK sent, connection registered!\n", .{});
    } else {
        std.debug.print("[SOCKS5-TUNNEL-WARN] No pending SYN found for this connection!\n", .{});
    }
    std.debug.print("[SOCKS5-TUNNEL-EXIT] ============================================\n\n", .{});
}

/// SOCKS5 ready callback - connection established
fn onSocks5Ready(userdata: ?*anyopaque, client: *Socks5Client) void {
    _ = client;
    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return)));
    router._stats.tcp_connections += 1;
    std.debug.print("[SOCKS5-READY] Connection established\n", .{});
}

/// SOCKS5 error callback - handle connection errors
fn onSocks5Error(userdata: ?*anyopaque, err: socks5.Socks5Error, client: *Socks5Client) void {
    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return)));
    std.debug.print("[SOCKS5-ERROR] Error occurred: {} for {s}:{}\n", .{ err, fmtIp(client.dst_ip), client.dst_port });

    // Clean up pending connection if any
    router.clearPendingConnection(client.src_ip, client.src_port, client.dst_ip, client.dst_port);

    // Remove from connection pool
    for (router.socks5_pool, 0..) |*conn_ptr, idx| {
        if (conn_ptr.* == client) {
            conn_ptr.* = null;
            break;
        }
    }

    // Close client
    client.close();
}

/// SOCKS5 UDP datagram callback - handle incoming UDP data from proxy
fn onSocks5UdpData(userdata: ?*anyopaque, data: []const u8, src_ip: u32, src_port: u16) void {
    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return)));

    std.debug.print("\n[SOCKS5-UDP-DATA] ============================================\n", .{});
    std.debug.print("[SOCKS5-UDP-DATA] Received {} bytes from {s}:{}\n", .{ data.len, fmtIp(src_ip), src_port });

    router.handleSocks5UdpResponse(data, src_ip, src_port);

    std.debug.print("[SOCKS5-UDP-DATA-EXIT] ============================================\n\n", .{});
}
