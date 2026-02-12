//! outbound.zig - Outbound abstraction layer
//!
//! Provides a unified interface for different outbound implementations.
//! Integrates with existing Socks5Client and supports Direct connections.

const std = @import("std");
const builtin = @import("builtin");
const xev = @import("xev");

// Re-export for convenience
pub const OutboundType = enum(u8) {
    socks5 = 1,
    direct = 2,
};

/// Outbound configuration
pub const OutboundConfig = struct {
    /// SOCKS5 proxy address (e.g., "127.0.0.1:1080")
    socks5_addr: ?[:0]const u8 = null,

    /// Username for SOCKS5 authentication (optional)
    socks5_username: ?[:0]const u8 = null,

    /// Password for SOCKS5 authentication (optional)
    socks5_password: ?[:0]const u8 = null,

    /// Egress interface name for direct connections
    egress_iface: ?[*:0]const u8 = null,

    /// Connect timeout in milliseconds
    connect_timeout_ms: u32 = 5000,
};

/// Result of establishing a connection through an outbound
pub const ConnectResult = struct {
    /// Socket for proxy/server communication
    sock: std.posix.socket_t,
    /// Destination IP (network byte order)
    dst_ip: u32,
    /// Destination port (network byte order)
    dst_port: u16,
    /// Cleanup function
    cleanup: *const fn (userdata: ?*anyopaque) void,
    /// Userdata for cleanup
    userdata: ?*anyopaque,
};

/// Outbound interface
pub const Outbound = struct {
    /// Type of this outbound
    type: OutboundType,

    /// Opaque context
    ctx: *anyopaque,

    /// Destroy the outbound
    destroy: *const fn (ctx: *anyopaque) void,

    /// Connect to target through this outbound
    connect: *const fn (
        ctx: *anyopaque,
        dst_ip: u32,
        dst_port: u16,
    ) ConnectResult!void,

    /// Send data through the outbound
    send: *const fn (
        ctx: *anyopaque,
        sock: std.posix.socket_t,
        data: []const u8,
    ) void,

    /// Name for debugging
    name: *const fn (ctx: *anyopaque) [:0]const u8,
};

/// SOCKS5 outbound context
const Socks5Outbound = struct {
    allocator: std.mem.Allocator,
    loop: *xev.Loop,
    proxy_addr: std.net.Address,
    client: ?*Socks5Client,
    addr_str: [:0]const u8,
};

/// Direct outbound context
const DirectOutbound = struct {
    allocator: std.mem.Allocator,
    egress_iface: ?[*:0]const u8,
};

/// Create an outbound based on type
pub fn create(
    allocator: std.mem.Allocator,
    loop: *xev.Loop,
    outbound_type: OutboundType,
    config: OutboundConfig,
) !Outbound {
    switch (outbound_type) {
        .socks5 => {
            const addr = config.socks5_addr orelse return error.Socks5AddrRequired;
            const proxy_addr = try parseProxyAddr(addr);

            const proxy_net_addr = std.net.Address.initIp4(
                .{ @as(u8, @truncate(proxy_addr.ip >> 24)), @as(u8, @truncate(proxy_addr.ip >> 16)), @as(u8, @truncate(proxy_addr.ip >> 8)), @as(u8, @truncate(proxy_addr.ip)) },
                proxy_addr.port,
            );

            const client = try Socks5Client.create(allocator, loop, proxy_net_addr);

            const ctx = try allocator.create(Socks5Outbound);
            ctx.* = .{
                .allocator = allocator,
                .loop = loop,
                .proxy_addr = proxy_net_addr,
                .client = client,
                .addr_str = addr,
            };

            return Outbound{
                .type = .socks5,
                .ctx = ctx,
                .destroy = socks5Destroy,
                .connect = socks5Connect,
                .send = socks5Send,
                .name = socks5Name,
            };
        },
        .direct => {
            const ctx = try allocator.create(DirectOutbound);
            ctx.* = .{
                .allocator = allocator,
                .egress_iface = config.egress_iface,
            };

            return Outbound{
                .type = .direct,
                .ctx = ctx,
                .destroy = directDestroy,
                .connect = directConnect,
                .send = directSend,
                .name = directName,
            };
        },
    }
}

/// Destroy SOCKS5 outbound
fn socks5Destroy(ctx: *anyopaque) void {
    const s = @as(*Socks5Outbound, @ptrCast(@alignCast(ctx)));
    if (s.client) |client| {
        Socks5Client.destroy(client, s.allocator);
    }
    s.allocator.destroy(s);
}

/// Connect through SOCKS5
fn socks5Connect(ctx: *anyopaque, dst_ip: u32, dst_port: u16) ConnectResult!void {
    const s = @as(*Socks5Outbound, @ptrCast(@alignCast(ctx)));
    const client = s.client orelse return error.NoClient;

    client.connectBlocking(dst_ip, dst_port) catch {
        return error.ConnectionFailed;
    };

    return ConnectResult{
        .sock = client.sock,
        .dst_ip = dst_ip,
        .dst_port = dst_port,
        .cleanup = socks5Cleanup,
        .userdata = ctx,
    };
}

/// Send through SOCKS5
fn socks5Send(ctx: *anyopaque, sock: std.posix.socket_t, data: []const u8) void {
    _ = ctx;
    _ = std.posix.send(sock, data, 0) catch {};
}

/// SOCKS5 cleanup
fn socks5Cleanup(userdata: ?*anyopaque) void {
    _ = userdata;
}

/// SOCKS5 name
fn socks5Name(ctx: *anyopaque) [:0]const u8 {
    const s = @as(*Socks5Outbound, @ptrCast(@alignCast(ctx)));
    return s.addr_str;
}

/// Destroy Direct outbound
fn directDestroy(ctx: *anyopaque) void {
    const d = @as(*DirectOutbound, @ptrCast(@alignCast(ctx)));
    d.allocator.destroy(d);
}

/// Connect directly (socket creation only, actual connect happens on send)
fn directConnect(ctx: *anyopaque, dst_ip: u32, dst_port: u16) ConnectResult!void {
    const d = @as(*DirectOutbound, @ptrCast(@alignCast(ctx)));
    _ = d;

    const sock = std.posix.socket(2, 1, 0) catch {
        return error.ConnectionFailed;
    };

    // TODO: Bind to egress interface if specified

    return ConnectResult{
        .sock = sock,
        .dst_ip = dst_ip,
        .dst_port = dst_port,
        .cleanup = directCleanup,
        .userdata = ctx,
    };
}

/// Send directly
fn directSend(ctx: *anyopaque, sock: std.posix.socket_t, data: []const u8) void {
    _ = ctx;
    _ = std.posix.send(sock, data, 0) catch {};
}

/// Direct cleanup
fn directCleanup(userdata: ?*anyopaque) void {
    _ = userdata;
}

/// Direct name
fn directName(ctx: *anyopaque) [:0]const u8 {
    const d = @as(*DirectOutbound, @ptrCast(@alignCast(ctx)));
    if (d.egress_iface) |iface| {
        return std.mem.sliceTo(iface, 0);
    }
    return "direct";
}

// ============ Helper Functions ============

fn parseProxyAddr(addr: [:0]const u8) !struct { ip: u32, port: u16 } {
    const colon_idx = std.mem.lastIndexOf(u8, addr, ":") orelse return error.InvalidProxyAddr;

    const ip_str = addr[0..colon_idx];
    const port_str = addr[colon_idx + 1 ..];

    const ip = try parseIpv4(ip_str);
    const port = try std.fmt.parseInt(u16, port_str, 10);

    if (port == 0) return error.InvalidPort;

    return .{ .ip = ip, .port = port };
}

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

    if (part_idx >= 4) return error.InvalidIp;
    parts[part_idx] = @as(u8, @truncate(val));

    if (dot_count != 3) return error.InvalidIp;

    return @as(u32, parts[0]) << 24 | @as(u32, parts[1]) << 16 | @as(u32, parts[2]) << 8 | @as(u32, parts[3]);
}

// Import Socks5Client from proxy/socks5.zig
const Socks5Client = @import("proxy/socks5.zig").Socks5Client;

// Error set
const OutboundError = error{
    InvalidProxyAddr,
    InvalidPort,
    InvalidIp,
    NoClient,
    ConnectionFailed,
};
