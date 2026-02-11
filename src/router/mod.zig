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
const AF_INET = 2;   // IPv4
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const SOL_SOCKET = 0xffff;
const SO_REUSEADDR = 0x0004;
const O_NONBLOCK = 0x4000; // Non-blocking socket

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

// Re-export SOCKS5 module
pub const socks5 = @import("proxy/socks5.zig");

// Type alias for backward compatibility - Socks5Conn is now socks5.Socks5Client
pub const Socks5Conn = socks5.Socks5Client;

// Import checksum from ipstack
const ipstack = @import("ipstack");

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
    packets_forwarded: u64 = 0,
    packets_dropped: u64 = 0,
    bytes_rx: u64 = 0,
    bytes_tx: u64 = 0,
};

/// Router configuration
pub const RouterConfig = struct {
    /// TUN device configuration (from application)
    tun: TunConfig,

    /// Egress network interface configuration (from application)
    egress: EgressConfig,

    /// Proxy configuration (optional)
    proxy: ?ProxyConfig = null,

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

    /// SOCKS5 proxy connection (using socks5.Socks5Client)
    socks5_conn: ?*Socks5Conn,

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
            if (header_len > 0) {
                // AF_INET = 2, followed by 3 zero bytes
                router.write_buf[0] = 2;
                router.write_buf[1] = 0;
                router.write_buf[2] = 0;
                router.write_buf[3] = 0;

                // Only copy if data is not already in the right place (avoid aliasing)
                if (data.ptr != &router.write_buf) {
                    @memcpy(router.write_buf[header_len..total_len], data);
                }
            }

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

        // Create SOCKS5 connection if proxy is configured
        var socks5_conn_ptr: ?*Socks5Conn = null;
        if (config.proxy) |proxy| {
            std.debug.print("[ROUTER] Creating SOCKS5 connection for proxy: {s}\n", .{proxy.addr});

            // Parse proxy address
            if (parseProxyAddr(proxy.addr)) |proxy_addr| {
                const proxy_net_addr = std.net.Address.initIp4(
                    .{ @as(u8, @truncate(proxy_addr.ip >> 24)), @as(u8, @truncate(proxy_addr.ip >> 16)), @as(u8, @truncate(proxy_addr.ip >> 8)), @as(u8, @truncate(proxy_addr.ip)) },
                    proxy_addr.port,
                );
                socks5_conn_ptr = try Socks5Conn.create(allocator, &loop, proxy_net_addr);

                std.debug.print("[ROUTER] SOCKS5 client created: {x:0>8}:{}\n", .{
                    proxy_addr.ip, proxy_addr.port });
            } else |_| {
                std.debug.print("[ROUTER] Failed to parse proxy address\n", .{});
            }
        }

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
            .socks5_conn = socks5_conn_ptr,
            .udp_sock = udp_sock,
            .raw_sock = raw_sock,
            .state = .init,
            .packet_buf = undefined,
            .write_buf = undefined,
            .icmp_buf = undefined,
            ._stats = .{},
            .allocator = allocator,
        };

        // Update Socks5Client callbacks to point to this Router
        if (router.socks5_conn) |client| {
            client.userdata = &router;
        }

        return router;
    }

    /// Destroy a Router instance
    pub fn deinit(router: *Router) void {
        if (router.state == .running) {
            router.loop.stop();
        }

        // Close SOCKS5 connection
        if (router.socks5_conn) |conn| {
            Socks5Conn.destroy(conn, router.allocator);
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

        // Run event loop
        std.debug.print("[ROUTER] Starting event loop...\n", .{});
        router.loop.run(.until_done) catch {
            std.debug.print("[ROUTER] Event loop error!\n", .{});
        };
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

        std.debug.print("[ROUTER] Route decision: {any}, dst={x:0>8}:{}\n", .{ decision, packet.dst_ip, packet.dst_port });

        switch (decision) {
            .Direct => {
                try router.forwardToEgress(packet);
                router._stats.packets_forwarded += 1;
            },
            .Socks5 => {
                try router.forwardToProxy(packet);
                router._stats.packets_forwarded += 1;
            },
            .Drop => {
                router._stats.packets_dropped += 1;
            },
            .Local => {
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
    fn forwardToProxy(router: *Router, packet: *const Packet) !void {
        // TCP packets are handled via SOCKS5 proxy

        if (router.socks5_conn == null) {
            router._stats.packets_dropped += 1;
            return;
        }

        const client = router.socks5_conn.?;

        // Extract payload
        const payload = extractTcpPayload(packet) catch {
            router._stats.packets_dropped += 1;
            return;
        };

        // Use Socks5Client's connect method with pending data
        // The client will queue the data and send after connection is established
        client.connect(packet.dst_ip, packet.dst_port, payload) catch {
            router._stats.packets_dropped += 1;
        };
    }

    /// Extract TCP payload from packet
    fn extractTcpPayload(packet: *const Packet) ![]const u8 {
        const ip_header_len = ((packet.data[0] & 0x0F) * 4);
        const tcp_header_len = 20; // Standard TCP header without options
        const payload_offset = ip_header_len + tcp_header_len;
        if (payload_offset >= packet.data.len or payload_offset + 20 > packet.data.len) {
            return error.NoPayload;
        }
        return packet.data[payload_offset..];
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

    /// Handle ICMP echo request - send echo reply
    fn handleIcmpEcho(router: *Router, packet_offset: usize, packet_len: usize, ip_header_len: usize) !void {
        // ICMP header is at ip_header_len in the packet (after packet_offset)
        // ICMP Echo Request: Type = 8, Code = 0
        // ICMP Echo Reply: Type = 0, Code = 0

        if (packet_len < 20) {
            std.debug.print("[ICMP] Packet too small for IP header\n", .{});
            return;
        }

        const packet = router.packet_buf[packet_offset..packet_offset + packet_len];

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

        // Add pseudo-header: source IP
        sum += src_ip >> 16;
        sum += src_ip & 0xFFFF;

        // Pseudo-header: destination IP
        sum += dst_ip >> 16;
        sum += dst_ip & 0xFFFF;

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

    /// Parse IP packet and extract 4-tuple
    fn parsePacket(_: *Router, data: []const u8) !Packet {
        // Parse IPv4 header (minimum 20 bytes)
        if (data.len < 20) return error.PacketTooSmall;

        const ver_ihl = data[0];
        const version = ver_ihl >> 4;
        const ihl = ver_ihl & 0x0F;

        if (version != 4) return error.NotIPv4;
        if (ihl < 5) return error.InvalidIhl;

        const header_len = @as(usize, ihl) * 4;
        if (data.len < header_len) return error.PacketTooSmall;

        const protocol = data[9];

        const src_ip = std.mem.readInt(u32, data[12..16], .big);
        const dst_ip = std.mem.readInt(u32, data[16..20], .big);

        var src_port: u16 = 0;
        var dst_port: u16 = 0;

        // Parse transport layer header for TCP/UDP
        if (protocol == 6 or protocol == 17) {
            if (data.len < header_len + 4) return error.PacketTooSmall;
            const src_port_bytes = data[header_len..header_len + 2];
            const dst_port_bytes = data[header_len + 2..header_len + 4];
            src_port = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(src_port_bytes.ptr)), .big);
            dst_port = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(dst_port_bytes.ptr)), .big);
        }

        // Return packet info - data is already in our buffer
        return Packet{
            .data = data,
            .src_ip = src_ip,
            .src_port = src_port,
            .dst_ip = dst_ip,
            .dst_port = dst_port,
            .protocol = protocol,
        };
    }
};

/// TUN readable callback (libxev callback)
fn onTunReadable(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));
    std.debug.print("[TUN-CB] onTunReadable called, result={any}\n", .{result});

    // Check for read result (result.read is error union !usize)
    const n = result.read catch {
        std.debug.print("[TUN] Read error, resubmitting\n", .{});
        router.submitTunRead();
        return .disarm;
    };
    if (n == 0) {
        // EOF, resubmit read
        std.debug.print("[TUN] EOF received, resubmitting\n", .{});
        router.submitTunRead();
        return .disarm;
    }
    std.debug.print("[TUN] Read {} bytes from TUN\n", .{n});

    router._stats.bytes_rx += n;

    // Check for macOS utun 4-byte AF_INET header
    // Observed: first 4 bytes are 0x00000002 (AF_INET family)
    // Byte 3 contains AF_INET=2 (bytes 0-2 are zero padding)
    // IP header starts at byte 4: 0x45 = IPv4 with 20-byte header
    var packet_offset: usize = 0;
    if (n >= 4 and router.packet_buf[3] == 2) {
        // UTUN header detected, skip 4 bytes
        packet_offset = 4;
    }

    if (n - packet_offset < 20) {
        router.submitTunRead();
        return .disarm;
    }

    // Packet data starts at packet_offset
    const packet_data = router.packet_buf[packet_offset..n];

    const protocol = packet_data[9];

    // ICMP protocol = 1
    if (protocol == 1) {
        const ver_ihl = packet_data[0];
        const ip_header_len = @as(usize, ver_ihl & 0x0F) * 4;
        router.handleIcmpEcho(packet_offset, n - packet_offset, ip_header_len) catch {};
        router.submitTunRead();
        return .disarm;
    }

    // Parse and forward packet
    // NOTE: Copy packet data to avoid buffer reuse issues with libxev
    const raw_data = router.packet_buf[packet_offset..n];
    @memcpy(router.write_buf[0..raw_data.len], raw_data);
    const packet_copy = router.write_buf[0..raw_data.len];

    const packet = router.parsePacket(packet_copy) catch {
        router.submitTunRead();
        return .disarm;
    };

    router.forwardPacket(&packet) catch {};

    // Resubmit read
    router.submitTunRead();
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

    // Resubmit timer
    router.submitNatTimer();

    return .disarm;
}

/// SOCKS5 data callback - forward received data from proxy to TUN
fn onSocks5Data(userdata: ?*anyopaque, data: []const u8) void {
    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return)));

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

    // Source IP (TUN interface IP)
    const src_ip = router.config.tun.ip;
    std.mem.writeInt(u32, router.write_buf[12..16], src_ip, .big);

    // Destination IP from Socks5Client
    if (router.socks5_conn) |conn| {
        std.mem.writeInt(u32, router.write_buf[16..20], conn.dst_ip, .big);

        // Recalculate IP header checksum
        router.write_buf[10] = 0;
        router.write_buf[11] = 0;
        const ip_sum = ipstack.checksum.checksum(router.write_buf[0..20], 0);
        std.mem.writeInt(u16, router.write_buf[10..12], ip_sum, .big);

        // Write to TUN
        router.writeToTunBuf(router.write_buf[0..total_len]) catch {};
    }
}

/// SOCKS5 ready callback - connection established
fn onSocks5Ready(userdata: ?*anyopaque) void {
    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return)));
    router._stats.tcp_connections += 1;
}

/// SOCKS5 error callback - handle connection errors
fn onSocks5Error(userdata: ?*anyopaque, err: socks5.Socks5Error) void {
    _ = err;
    _ = userdata;
    std.debug.print("[SOCKS5] Error occurred\n", .{});
}

