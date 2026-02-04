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
const xev = @import("libxev");

// Re-export config types
pub const TunConfig = @import("route.zig").TunConfig;
pub const EgressConfig = @import("route.zig").EgressConfig;
pub const ProxyConfig = @import("route.zig").ProxyConfig;
pub const RouteCallback = @import("route.zig").RouteCallback;
pub const RouteDecision = @import("route.zig").RouteDecision;
pub const ProxyType = @import("proxy/socks5.zig").ProxyType;
pub const NatSession = @import("nat.zig").NatSession;
pub const NatTable = @import("nat.zig").NatTable;

/// Packet buffer for forwarding
pub const Packet = struct {
    /// Raw packet data
    data: []u8,

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

/// NAT configuration
pub const NatConfig = struct {
    /// NAT source IP (egress IP in network byte order)
    egress_ip: u32,

    /// Port range start
    port_range_start: u16 = 10000,

    /// Port range end
    port_range_end: u16 = 60000,

    /// Session timeout in seconds
    timeout: u32 = 30,
};

/// Router state machine
const RouterState = enum {
    init,
    running,
    stopped,
};

/// Router - Transparent proxy forwarding engine with libxev
pub const Router = struct {
    /// libxev event loop
    loop: *xev.Loop,

    /// libxev IO for TUN reading
    tun_io: xev.IO,

    /// libxev timer for NAT cleanup
    nat_timer: xev.Timer,

    /// Configuration
    config: RouterConfig,

    /// NAT session table (for UDP forwarding)
    nat_table: NatTable,

    /// Current state
    state: RouterState,

    /// Packet buffer for TUN reads
    packet_buf: [65536]u8,

    /// Statistics
    stats: RouterStats,

    /// Allocator for allocations
    allocator: std.mem.Allocator,

    /// Create a new Router instance
    pub fn init(allocator: std.mem.Allocator, config: RouterConfig) !*Router {
        const router = try allocator.create(Router);
        errdefer allocator.destroy(router);

        // Create libxev loop
        const loop = xev.Loop.new(.{});
        errdefer loop.deinit();

        // Initialize NAT table if configured
        var nat_table = NatTable{};
        if (config.nat_config) |nat_cfg| {
            nat_table = try NatTable.init(allocator, nat_cfg);
        }

        router.* = .{
            .loop = loop,
            .tun_io = undefined,
            .nat_timer = undefined,
            .config = config,
            .nat_table = nat_table,
            .state = .init,
            .packet_buf = undefined,
            .stats = .{},
            .allocator = allocator,
        };

        // Submit TUN read to event loop
        loop.io(&router.tun_io, config.tun.fd, .readable, onTunReadable, router);

        // Submit NAT cleanup timer (every 30 seconds)
        if (config.nat_config != null) {
            loop.timer(&router.nat_timer, 30000, onNatTimer, router);
        }

        return router;
    }

    /// Destroy a Router instance
    pub fn deinit(router: *Router) void {
        if (router.state == .running) {
            router.loop.stop();
        }

        // Cleanup NAT table
        if (router.config.nat_config != null) {
            router.nat_table.deinit(router.allocator);
        }

        router.loop.deinit();
        router.allocator.destroy(router);
    }

    /// Run the router event loop (blocking)
    pub fn run(router: *Router) void {
        router.state = .running;
        router.loop.run() catch {};
        router.state = .stopped;
    }

    /// Stop the router event loop
    pub fn stop(router: *Router) void {
        router.loop.stop();
        router.state = .stopped;
    }

    /// Get router statistics
    pub fn stats(router: *Router) RouterStats {
        return router.stats;
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
                router.stats.packets_forwarded += 1;
            },
            .Socks5 => {
                try router.forwardToProxy(packet);
                router.stats.packets_forwarded += 1;
            },
            .Drop => {
                router.stats.packets_dropped += 1;
            },
            .Local => {
                try router.writeToTun(packet);
                router.stats.packets_forwarded += 1;
            },
            .Nat => {
                try router.forwardWithNat(packet);
                router.stats.packets_forwarded += 1;
            },
        }
    }

    /// Forward packet to egress interface (raw socket)
    fn forwardToEgress(router: *Router, packet: *const Packet) !void {
        _ = router;
        _ = packet;
        // TODO: Implement raw socket forwarding with SO_BINDTODEVICE
    }

    /// Forward packet through SOCKS5 proxy
    fn forwardToProxy(router: *Router, packet: *const Packet) !void {
        _ = router;
        _ = packet;
        // TODO: Implement SOCKS5 proxy forwarding
    }

    /// Forward packet with NAT translation (UDP)
    fn forwardWithNat(router: *Router, packet: *const Packet) !void {
        _ = router;
        _ = packet;
        // TODO: Implement NAT forwarding
    }

    /// Write packet back to TUN (for local handling)
    fn writeToTun(router: *Router, packet: *const Packet) !void {
        const tun = router.config.tun.fd;
        const written = std.posix.write(tun, packet.data) catch return error.WriteFailed;
        if (written != packet.data.len) return error.PartialWrite;
        router.stats.bytes_tx += written;
    }

    /// Parse IP packet and extract 4-tuple
    fn parsePacket(router: *Router, data: []const u8) !Packet {
        // Parse IPv4 header (minimum 20 bytes)
        if (data.len < 20) return error.PacketTooSmall;

        const ver_ihl = data[0];
        const version = ver_ihl >> 4;
        const ihl = ver_ihl & 0x0F;

        if (version != 4) return error.NotIPv4;
        if (ihl < 5) return error.InvalidIhl;

        const header_len = @as(usize, ihl) * 4;
        if (data.len < header_len) return error.PacketTooSmall;

        const total_len = std.mem.readInt(u16, data[2..4], .big);
        const protocol = data[9];

        const src_ip = std.mem.readInt(u32, data[12..16], .big);
        const dst_ip = std.mem.readInt(u32, data[16..20], .big);

        var src_port: u16 = 0;
        var dst_port: u16 = 0;

        // Parse transport layer header for TCP/UDP
        if (protocol == 6 or protocol == 17) {
            if (data.len < header_len + 4) return error.PacketTooSmall;
            src_port = std.mem.readInt(u16, data[header_len..header_len + 2], .big);
            dst_port = std.mem.readInt(u16, data[header_len + 2..header_len + 4], .big);
        }

        return Packet{
            .data = router.packet_buf[0..@as(usize, total_len)],
            .len = @as(usize, total_len),
            .src_ip = src_ip,
            .src_port = src_port,
            .dst_ip = dst_ip,
            .dst_port = dst_port,
            .protocol = protocol,
        };
    }
};

/// TUN readable callback (libxev IO callback)
fn onTunReadable(self: *xev.IO, revents: u32) callconv(.C) void {
    const router = @as(*Router, @ptrCast(self.userdata orelse return));

    // Check for errors
    if ((revents & .ERR) != 0 or (revents & .HUP) != 0) {
        return;
    }

    const tun_fd = router.config.tun.fd;
    const n = std.posix.read(tun_fd, &router.packet_buf) catch {
        return;
    };

    if (n == 0) return;

    router.stats.bytes_rx += n;

    // Parse and forward packet
    const packet = router.parsePacket(router.packet_buf[0..n]) catch {
        return;
    };

    router.forwardPacket(&packet) catch {};

    // Resubmit read
    router.loop.io(self, tun_fd, .readable, onTunReadable, router);
}

/// NAT cleanup timer callback
fn onNatTimer(self: *xev.Timer, revents: u32) callconv(.C) void {
    const router = @as(*Router, @ptrCast(self.userdata orelse return));

    if ((revents & .TIMEOUT) == 0) return;

    // Cleanup expired NAT sessions
    if (router.config.nat_config) |_| {
        _ = router.nat_table.cleanup();
        // Resubmit timer
        router.loop.timer(self, 30000, onNatTimer, router);
    }
}
