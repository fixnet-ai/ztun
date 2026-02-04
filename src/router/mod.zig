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

    /// Configuration
    config: RouterConfig,

    /// NAT session table (for UDP forwarding)
    nat_table: ?*NatTable,

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

    /// Create a new Router instance
    pub fn init(allocator: std.mem.Allocator, config: RouterConfig) !Router {
        // Initialize NAT table if configured
        var nat_table: ?*NatTable = null;
        if (config.nat_config) |nat_cfg| {
            nat_table = try NatTable.init(allocator, nat_cfg, config.udp_nat_size);
        }

        // Create libxev loop
        return .{
            .loop = try xev.Loop.init(.{}),
            .tun_completion = .{},
            .tun_write_completion = .{},
            .nat_timer = .{},
            .config = config,
            .nat_table = nat_table,
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
                    .fd = router.config.tun.fd,
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
        router._stats.bytes_tx += written;
    }

    /// Write raw buffer to TUN
    fn writeToTunBuf(router: *Router, data: []const u8) !void {
        const tun = router.config.tun.fd;
        const written = std.posix.write(tun, data) catch return error.WriteFailed;
        if (written != data.len) return error.PartialWrite;
        router._stats.bytes_tx += written;
    }

    /// Handle ICMP echo request - send echo reply
    fn handleIcmpEcho(router: *Router, icmp_offset: usize) !void {
        // ICMP header is at icmp_offset in the packet
        // ICMP Echo Request: Type = 8, Code = 0
        // ICMP Echo Reply: Type = 0, Code = 0

        const packet_len = router.packet_buf[2..4];
        const total_len = std.mem.readInt(u16, packet_len, .big);

        if (total_len < icmp_offset + 8) return; // Need at least 8 bytes for ICMP header + identifier + sequence

        // Check if this is an echo request (type 8)
        const icmp_type = router.packet_buf[icmp_offset];
        if (icmp_type != 8) return; // Not an echo request

        // Copy packet to write buffer
        @memcpy(router.write_buf[0..total_len], router.packet_buf[0..total_len]);

        // Get src/dst IPs from original packet
        const src_ip = std.mem.readInt(u32, router.packet_buf[12..16], .big);
        const dst_ip = std.mem.readInt(u32, router.packet_buf[16..20], .big);

        // Swap IP addresses in IP header (offset 12-20)
        std.mem.writeInt(u32, router.write_buf[12..16], src_ip, .big);
        std.mem.writeInt(u32, router.write_buf[16..20], dst_ip, .big);

        // Change ICMP type from 8 (Echo Request) to 0 (Echo Reply)
        router.write_buf[icmp_offset] = 0;

        // Recalculate ICMP checksum
        const checksum_bytes = router.write_buf[icmp_offset + 2..icmp_offset + 4];
        const old_sum = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(checksum_bytes.ptr)), .big);
        var sum = ~old_sum & 0xFFFF; // one's complement
        // Adding 8 to checksum (since we changed 8 to 0)
        sum +%= 8;
        sum = ~sum & 0xFFFF;
        std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(checksum_bytes.ptr)), sum, .big);

        // Write reply back to TUN
        try router.writeToTunBuf(router.write_buf[0..total_len]);
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

        // Copy packet data to our buffer
        @memcpy(router.packet_buf[0..data.len], data);

        return Packet{
            .data = router.packet_buf[0..data.len],
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
        router.submitTunRead();
        return .disarm;
    };
    if (n == 0) {
        // EOF, resubmit read
        router.submitTunRead();
        return .disarm;
    }

    router._stats.bytes_rx += n;

    // Check if this is an ICMP packet - handle echo request immediately
    const ver_ihl = router.packet_buf[0];
    const ihl = ver_ihl & 0x0F;
    const header_len = @as(usize, ihl) * 4;
    const protocol = router.packet_buf[9];

    // ICMP protocol = 1
    if (protocol == 1) {
        // Handle ICMP echo request (ping)
        router.handleIcmpEcho(header_len) catch {};
        router.submitTunRead();
        return .disarm;
    }

    // Parse and forward packet
    const packet = router.parsePacket(router.packet_buf[0..n]) catch {
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
