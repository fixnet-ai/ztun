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
pub const ProxyType = @import("proxy/socks5.zig").ProxyType;
pub const NatSession = @import("nat.zig").NatSession;
pub const NatTable = @import("nat.zig").NatTable;
pub const NatConfig = @import("nat.zig").NatConfig;

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

/// SOCKS5 connection state
const Socks5ConnState = enum(u8) {
    /// Initial state, need to connect
    Disconnected = 0,
    /// Connecting to proxy
    Connecting = 1,
    /// Sent greeting, waiting for ack
    Greeting = 2,
    /// Sent connect request, waiting for ack
    ConnectRequest = 3,
    /// Ready to forward data
    Ready = 4,
    /// Error state
    Error = 5,
};

/// SOCKS5 proxy connection
const Socks5Conn = struct {
    state: Socks5ConnState = .Disconnected,
    sock: ?std.posix.socket_t = null,
    dst_ip: u32 = 0,
    dst_port: u16 = 0,
    allocator: std.mem.Allocator,
    read_buf: [65536]u8 = undefined,
    read_offset: usize = 0,
    write_buf: [65536]u8 = undefined,
    write_offset: usize = 0,
    proxy_ip: u32 = 0,
    proxy_port: u16 = 0,
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

    /// SOCKS5 proxy connection (shared for all TCP connections)
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
            // Raw fd - write directly
            const tun = router.config.tun.fd;
            const written = std.posix.write(tun, data) catch return error.WriteFailed;
            router._stats.bytes_tx += written;
        }
    }

    /// Create a new Router instance
    pub fn init(allocator: std.mem.Allocator, config: RouterConfig) !Router {
        // Initialize NAT table if configured
        var nat_table: ?*NatTable = null;
        if (config.nat_config) |nat_cfg| {
            nat_table = try NatTable.init(allocator, nat_cfg, config.udp_nat_size);
        }

        // Create SOCKS5 connection if proxy is configured
        var socks5_conn_ptr: ?*Socks5Conn = null;
        if (config.proxy) |proxy| {
            const conn = try allocator.create(Socks5Conn);
            conn.* = .{
                .allocator = allocator,
                .state = .Disconnected,
                .sock = null,
            };
            socks5_conn_ptr = conn;

            // Parse proxy address
            if (parseProxyAddr(proxy.addr)) |proxy_addr| {
                conn.proxy_ip = proxy_addr.ip;
                conn.proxy_port = proxy_addr.port;
            } else |_| {
                allocator.destroy(conn);
                socks5_conn_ptr = null;
            }
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

        // Create libxev loop
        return .{
            .loop = try xev.Loop.init(.{}),
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
            ._stats = .{},
            .allocator = allocator,
        };
    }

    /// Destroy a Router instance
    pub fn deinit(router: *Router) void {
        if (router.state == .running) {
            router.loop.stop();
        }

        // Close SOCKS5 connection
        if (router.socks5_conn) |conn| {
            if (conn.sock) |sock| {
                std.posix.close(sock);
            }
            conn.allocator.destroy(conn);
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
        router.loop.run(.until_done) catch {};
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
        // For now, we'll send the TCP payload through the proxy
        // This is a simplified implementation

        if (router.socks5_conn == null) {
            router._stats.packets_dropped += 1;
            return;
        }

        const conn = router.socks5_conn.?;

        // Ensure we have a connected socket
        if (conn.sock == null) {
            try router.connectSocks5(conn, packet.dst_ip, packet.dst_port);
            return;
        }

        if (conn.state != .Ready) {
            // Still connecting, will forward when ready
            return;
        }

        // Extract TCP payload (skip IP + TCP headers)
        const ip_header_len = ((packet.data[0] & 0x0F) * 4);
        const tcp_header_len = ((packet.data[ip_header_len + 12] >> 4) * 4);
        const payload_offset = ip_header_len + tcp_header_len;

        if (payload_offset >= packet.data.len) {
            return; // No payload
        }

        const payload = packet.data[payload_offset..];

        // Send payload through SOCKS5 connection
        const sock = conn.sock.?;
        _ = std.posix.send(sock, payload, 0) catch {
            router._stats.packets_dropped += 1;
            return;
        };

        router._stats.bytes_tx += payload.len;
    }

    /// Connect to SOCKS5 proxy and establish tunnel
    fn connectSocks5(router: *Router, conn: *Socks5Conn, dst_ip: u32, dst_port: u16) !void {
        // Store destination for after connection
        conn.dst_ip = dst_ip;
        conn.dst_port = dst_port;

        // Create socket
        const sock = std.posix.socket(AF_INET, SOCK_STREAM, 0) catch {
            conn.state = .Error;
            return;
        };
        conn.sock = sock;

        // Non-blocking connect - set socket to non-blocking mode
        const flags = std.posix.fcntl(sock, std.posix.F.GETFL, 0) catch {
            conn.state = .Error;
            return;
        };
        _ = std.posix.fcntl(sock, std.posix.F.SETFL, flags | O_NONBLOCK) catch {};

        // Connect to proxy
        const proxy_addr = std.net.Address.initIp4(
            .{ @as(u8, @truncate(conn.proxy_ip >> 24)), @as(u8, @truncate(conn.proxy_ip >> 16)), @as(u8, @truncate(conn.proxy_ip >> 8)), @as(u8, @truncate(conn.proxy_ip)) },
            conn.proxy_port,
        );

        const result = std.posix.connect(sock, &proxy_addr.any, @sizeOf(std.posix.sockaddr.in));

        if (result) {
            // Connected immediately
            conn.state = .Greeting;
            try router.sendSocks5Greeting(conn);
        } else |err| {
            if (err != std.posix.ConnectError.WouldBlock) {
                conn.state = .Error;
                return;
            }
            // WouldBlock - wait for completion
            conn.state = .Connecting;

            // Setup async connect
            router.socks5_completion = .{
                .op = .{
                    .connect = .{
                        .socket = sock,
                        .addr = proxy_addr,
                    },
                },
                .userdata = router,
                .callback = onSocks5Connect,
            };
            router.loop.add(&router.socks5_completion);
        }
    }

    /// Send SOCKS5 greeting
    fn sendSocks5Greeting(router: *Router, conn: *Socks5Conn) !void {
        const sock = conn.sock orelse return error.NoSocket;

        // Build greeting: VER=5, NMETHODS=1, METHODS=[NO AUTH]
        var greeting: [3]u8 = undefined;
        greeting[0] = 0x05; // SOCKS5 version
        greeting[1] = 1;     // Number of auth methods
        greeting[2] = 0x00;  // No authentication

        const sent = std.posix.send(sock, &greeting, 0) catch {
            conn.state = .Error;
            return;
        };
        if (sent != 3) {
            conn.state = .Error;
            return;
        }

        conn.state = .Greeting;
        conn.read_offset = 0;

        // Wait for greeting ack
        router.socks5_completion = .{
            .op = .{
                .read = .{
                    .fd = sock,
                    .buffer = .{ .slice = &conn.read_buf },
                },
            },
            .userdata = router,
            .callback = onSocks5GreetingAck,
        };
        router.loop.add(&router.socks5_completion);
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
    fn handleIcmpEcho(router: *Router, icmp_offset: usize) !void {
        // ICMP header is at icmp_offset in the packet
        // ICMP Echo Request: Type = 8, Code = 0
        // ICMP Echo Reply: Type = 0, Code = 0

        const packet_len = router.packet_buf[2..4];
        const total_len = std.mem.readInt(u16, packet_len, .big);

        if (total_len < icmp_offset + 8) {
            std.debug.print("[ICMP] Packet too small for ICMP\n", .{});
            return;
        }

        // Check if this is an echo request (type 8)
        const icmp_type = router.packet_buf[icmp_offset];
        if (icmp_type != 8) {
            std.debug.print("[ICMP] Not an echo request (type={})\n", .{icmp_type});
            return;
        }

        std.debug.print("[ICMP] Echo request received, sending reply\n", .{});

        // Copy packet to write buffer
        @memcpy(router.write_buf[0..total_len], router.packet_buf[0..total_len]);

        // Get src/dst IPs from original packet (in network byte order)
        const src_ip = std.mem.readInt(u32, router.packet_buf[12..16], .big);
        const dst_ip = std.mem.readInt(u32, router.packet_buf[16..20], .big);

        std.debug.print("[ICMP]   src={s} dst={s}\n", .{ fmtIp(src_ip), fmtIp(dst_ip) });

        // Swap IP addresses: reply goes back to original source
        // Offset 12-16: destination IP in reply = original source IP
        // Offset 16-20: source IP in reply = original destination IP
        std.mem.writeInt(u32, router.write_buf[12..16], src_ip, .big);
        std.mem.writeInt(u32, router.write_buf[16..20], dst_ip, .big);

        // Change ICMP type from 8 (Echo Request) to 0 (Echo Reply)
        router.write_buf[icmp_offset] = 0;

        // Zero out checksum field before recalculating (MUST be 0 for correct calculation)
        router.write_buf[icmp_offset + 2] = 0;
        router.write_buf[icmp_offset + 3] = 0;

        // Recalculate ICMP checksum (includes pseudo-header)
        // ICMP checksum = one's complement of sum(pseudo-header + ICMP header + data)
        // Pseudo-header: src_ip + dst_ip + zero + protocol (1) + ICMP length
        const icmp_len = total_len - icmp_offset;

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
        var i: usize = icmp_offset;
        while (i + 1 < total_len) : (i += 2) {
            sum += std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(&router.write_buf[i])), .big);
        }
        if (i < total_len) {
            sum += @as(u16, router.write_buf[i]) << 8;
        }

        // Fold and complement
        while (sum >> 16 != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        const checksum = @as(u16, @truncate(~sum));

        // Write checksum
        std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&router.write_buf[icmp_offset + 2])), checksum, .big);

        // Write reply back to TUN
        try router.writeToTunBuf(router.write_buf[0..total_len]);
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

    router._stats.bytes_rx += n;

    // The packet buffer now contains a pure IP packet (no platform-specific headers)
    // DeviceOps.read() is responsible for stripping any platform-specific headers
    // (e.g., macOS utun 4-byte header) before returning
    if (n < 20) {
        std.debug.print("[TUN] Packet too small ({}) for IP header\n", .{n});
        router.submitTunRead();
        return .disarm;
    }

    // Use the packet directly - it's already a pure IP packet
    const packet_data = router.packet_buf[0..n];
    const src_ip = std.mem.readInt(u32, packet_data[12..16], .big);
    const dst_ip = std.mem.readInt(u32, packet_data[16..20], .big);
    const protocol = packet_data[9];
    std.debug.print("\n[TUN] READ: {} bytes from TUN\n", .{n});
    std.debug.print("[TUN]   src={s} dst={s} proto={}\n", .{ fmtIp(src_ip), fmtIp(dst_ip), protocol });
    dumpPacket("[TUN]   packet", packet_data);

    // Check if this is an ICMP packet - handle echo request immediately
    const ver_ihl = packet_data[0];
    const ihl = ver_ihl & 0x0F;
    const header_len = @as(usize, ihl) * 4;

    // ICMP protocol = 1
    if (protocol == 1) {
        std.debug.print("[TUN]   -> ICMP packet, handling echo\n", .{});
        // Handle ICMP echo request (ping)
        router.handleIcmpEcho(header_len) catch {};
        router.submitTunRead();
        return .disarm;
    }

    // Parse and forward packet
    const packet = router.parsePacket(packet_data) catch {
        std.debug.print("[TUN]   -> Failed to parse packet\n", .{});
        router.submitTunRead();
        return .disarm;
    };

    std.debug.print("[TUN]   -> Forwarding packet (src_port={}, dst_port={})\n", .{ packet.src_port, packet.dst_port });
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

/// SOCKS5 connect completion callback
fn onSocks5Connect(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));

    // Handle connect result
    _ = result.connect catch {
        // Connection failed
        if (router.socks5_conn) |conn| {
            conn.state = .Error;
        }
        return .disarm;
    };

    // Connected, send greeting
    if (router.socks5_conn) |conn| {
        if (conn.sock) |_| {
            conn.state = .Greeting;
            router.sendSocks5Greeting(conn) catch {
                conn.state = .Error;
            };
        }
    }

    return .disarm;
}

/// SOCKS5 greeting acknowledgment callback
fn onSocks5GreetingAck(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));

    if (router.socks5_conn == null) return .disarm;
    const conn = router.socks5_conn.?;

    // Handle read result
    const n = result.read catch {
        conn.state = .Error;
        return .disarm;
    };

    if (n == 0) {
        conn.state = .Error;
        return .disarm;
    }

    // Parse greeting acknowledgment
    if (conn.read_buf[0] != 0x05) {
        conn.state = .Error;
        return .disarm;
    }

    if (conn.read_buf[1] != 0x00) {
        conn.state = .Error;
        return .disarm;
    }

    // Greeting accepted, send connect request
    conn.state = .ConnectRequest;
    sendSocks5ConnectRequest(router, conn) catch {
        conn.state = .Error;
    };

    return .disarm;
}

/// Send SOCKS5 connect request
fn sendSocks5ConnectRequest(router: *Router, conn: *Socks5Conn) !void {
    const sock = conn.sock orelse return error.NoSocket;

    // Build connect request: VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, DST.ADDR, DST.PORT
    var request: [10]u8 = undefined;
    request[0] = 0x05; // SOCKS5 version
    request[1] = 0x01; // CONNECT command
    request[2] = 0x00; // Reserved
    request[3] = 0x01; // IPv4 address type

    // Destination IP (network byte order)
    std.mem.writeInt(u32, request[4..8], conn.dst_ip, .big);

    // Destination port (network byte order)
    const port_be = std.mem.nativeToBig(u16, conn.dst_port);
    std.mem.writeInt(u16, request[8..10], port_be, .big);

    const sent = std.posix.send(sock, &request, 0) catch {
        conn.state = .Error;
        return;
    };
    if (sent != 10) {
        conn.state = .Error;
        return;
    }

    conn.state = .ConnectRequest;
    conn.read_offset = 0;

    // Wait for connect ack
    router.socks5_completion = .{
        .op = .{
            .read = .{
                .fd = sock,
                .buffer = .{ .slice = &conn.read_buf },
            },
        },
        .userdata = router,
        .callback = onSocks5ConnectAck,
    };
    router.loop.add(&router.socks5_completion);
}

/// Submit SOCKS5 read operation
fn submitSocks5Read(router: *Router, conn: *Socks5Conn) void {
    const sock = conn.sock orelse return;

    router.socks5_completion = .{
        .op = .{
            .read = .{
                .fd = sock,
                .buffer = .{ .slice = &conn.read_buf },
            },
        },
        .userdata = router,
        .callback = onSocks5Readable,
    };
    router.loop.add(&router.socks5_completion);
}

/// SOCKS5 proxy data readable callback - read responses and forward to TUN
fn onSocks5Readable(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));
    const conn = router.socks5_conn orelse return .disarm;

    // Handle read result
    const n = result.read catch {
        conn.state = .Error;
        return .disarm;
    };

    if (n == 0) {
        // Connection closed
        conn.state = .Disconnected;
        conn.sock = null;
        return .disarm;
    }

    // Forward received data to TUN (build IP header)
    const payload = conn.read_buf[0..n];
    const total_len = 20 + payload.len; // IP header + payload

    // Build IP header
    @memcpy(router.write_buf[0..total_len], payload);

    // Set destination IP in IP header (conn.dst_ip was stored during connect)
    std.mem.writeInt(u32, router.write_buf[16..20], conn.dst_ip, .big);

    // Recalculate IP header checksum
    router.write_buf[10] = 0;
    router.write_buf[11] = 0;
    const ip_sum = ipstack.checksum.checksum(router.write_buf[0..20], 0);
    std.mem.writeInt(u16, router.write_buf[10..12], ip_sum, .big);

    // Write to TUN
    router.writeToTunBuf(router.write_buf[0..total_len]) catch {};

    // Continue reading
    submitSocks5Read(router, conn);

    return .disarm;
}

/// SOCKS5 connect acknowledgment callback
fn onSocks5ConnectAck(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    _ = completion;

    const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));

    if (router.socks5_conn == null) return .disarm;
    const conn = router.socks5_conn.?;

    // Handle read result
    const n = result.read catch {
        conn.state = .Error;
        return .disarm;
    };

    if (n == 0) {
        conn.state = .Error;
        return .disarm;
    }

    // Parse connect reply
    if (conn.read_buf[0] != 0x05) {
        conn.state = .Error;
        return .disarm;
    }

    if (conn.read_buf[1] != 0x00) {
        conn.state = .Error;
        return .disarm;
    }

    // Connection successful
    conn.state = .Ready;
    router._stats.tcp_connections += 1;

    // Start reading responses from SOCKS5 proxy
    submitSocks5Read(router, conn);

    return .disarm;
}

