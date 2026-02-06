//! options.zig - TUN device configuration options
//!
//! Configuration structures for creating and configuring TUN devices
//! across all supported platforms.

const std = @import("std");

/// IPv4 address representation (network byte order)
pub const Ipv4Address = [4]u8;

/// IPv6 address representation (network byte order)
pub const Ipv6Address = [16]u8;

/// IPv4 network address with prefix length
pub const Ipv4Network = struct {
    /// IPv4 address in network byte order
    address: Ipv4Address,
    /// CIDR prefix length (0-32)
    prefix: u8,
    /// Optional peer/destination address for point-to-point interfaces
    destination: ?Ipv4Address = null,
};

/// IPv6 network address with prefix length
pub const Ipv6Network = struct {
    /// IPv6 address in network byte order
    address: Ipv6Address,
    /// CIDR prefix length (0-128)
    prefix: u8,
};

/// Network address configuration for TUN device (backward compatible format)
pub const NetworkAddress = struct {
    /// IPv4 address in network byte order
    address: Ipv4Address,
    /// CIDR prefix length (0-32)
    prefix: u8,
    /// Optional peer/destination address
    destination: ?Ipv4Address = null,
};

/// Network configuration for TUN device (new format with both IPv4 and IPv6)
pub const NetworkConfig = struct {
    /// IPv4 configuration
    ipv4: ?Ipv4Network = null,
    /// IPv6 configuration
    ipv6: ?Ipv6Network = null,
};

/// TUN device configuration options
pub const Options = struct {
    /// Maximum transmission unit
    mtu: ?u16 = null,

    /// Network addresses for the interface (legacy format - use network instead)
    ipv4: ?NetworkAddress = null,
    /// IPv6 address (legacy format - use network instead)
    ipv6: ?Ipv6Address = null,
    /// IPv6 prefix length (legacy format - use network instead)
    ipv6_prefix: ?u8 = null,

    /// Network addresses for the interface
    network: ?NetworkConfig = null,

    /// Enable packet information (Linux-only, default: false)
    /// When true, packets include a 4-byte header with address family
    packet_info: bool = false,

    /// Enable generic segmentation offload (Linux-only, default: false)
    /// When true, supports sending packets with virtio_net_hdr
    gso: bool = false,

    /// User namespace for creating TUN in unprivileged mode (Linux-only)
    /// Not yet implemented
    user_namespace: bool = false,

    /// File descriptor for existing TUN device (Android VpnService)
    /// When set, the device is created from this fd instead of opening /dev/net/tun
    fd: ?std.posix.fd_t = null,

    /// DNS settings for network configuration
    dns: ?DnsConfig = null,

    /// Routing configuration
    routes: ?RouteConfig = null,
};

/// DNS configuration for the TUN interface
pub const DnsConfig = struct {
    /// DNS servers to add
    servers: []const Ipv4Address = &.{},
    /// DNS servers for IPv6
    servers6: []const Ipv6Address = &.{},
    /// Search domains
    search: []const []const u8 = &.{},
};

/// Route configuration
pub const RouteConfig = struct {
    /// Routes to add when device is created
    routes: []const RouteEntry = &.{},
    /// Enable interface-scoped routing (Darwin-only, default: true)
    interface_scoped: bool = true,
};

/// A single route entry
pub const RouteEntry = struct {
    /// Destination network
    destination: Ipv4Network,
    /// Gateway address (null for directly connected routes)
    gateway: ?Ipv4Address = null,
    /// Interface name to bind this route to
    interface: ?[]const u8 = null,
    /// Interface index (alternative to interface name)
    interface_index: ?u32 = null,
    /// Route metric (lower = preferred)
    metric: u32 = 0,
    /// Route flags (platform-specific)
    flags: u32 = 0,
};

/// Parse IPv4 address from string notation (e.g., "10.0.0.1")
pub fn parseIpv4(str: []const u8) !Ipv4Address {
    var result: Ipv4Address = undefined;
    var part_idx: usize = 0;
    var current: u32 = 0;
    var dot_count: usize = 0;

    for (str) |c| {
        if (c == '.') {
            if (part_idx >= 4) return error.InvalidAddress;
            if (current > 255) return error.InvalidAddress;
            result[part_idx] = @as(u8, @intCast(current));
            part_idx += 1;
            current = 0;
            dot_count += 1;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            if (current > 255) return error.InvalidAddress;
        } else {
            return error.InvalidAddress;
        }
    }

    // Last octet
    if (part_idx >= 4) return error.InvalidAddress;
    if (current > 255) return error.InvalidAddress;
    result[part_idx] = @as(u8, @intCast(current));
    part_idx += 1;

    if (part_idx != 4) return error.InvalidAddress;

    return result;
}

/// Format IPv4 address to string
pub fn formatIpv4(ip: Ipv4Address, buf: *[16]u8) []u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        ip[0], ip[1], ip[2], ip[3],
    }) catch unreachable;
}

/// Parse IPv6 address from string notation (e.g., "fd00::1")
pub fn parseIpv6(str: []const u8) !Ipv6Address {
    var result: Ipv6Address = undefined;
    @memset(result[0..], 0);

    // Simple parser for common formats - expand for full RFC 4291 compliance
    var parts: [8]u16 = undefined;
    var part_idx: usize = 0;
    var current: u32 = 0;
    var in_bracket: bool = false;
    var double_colon_idx: ?usize = null;

    var i: usize = 0;
    while (i < str.len and part_idx < 8) : (i += 1) {
        const c = str[i];

        if (c == ':') {
            if (part_idx >= 8) return error.InvalidAddress;
            if (current > 0xFFFF) return error.InvalidAddress;
            parts[part_idx] = @as(u16, @intCast(current));
            part_idx += 1;
            current = 0;

            if (i + 1 < str.len and str[i + 1] == ':') {
                double_colon_idx = part_idx;
                i += 1; // Skip second colon
            }
        } else if (c >= '0' and c <= '9') {
            current = current * 16 + (c - '0');
        } else if (c >= 'a' and c <= 'f') {
            current = current * 16 + (c - 'a' + 10);
        } else if (c >= 'A' and c <= 'F') {
            current = current * 16 + (c - 'A' + 10);
        } else if (c == '[') {
            in_bracket = true;
        } else if (c == ']') {
            in_bracket = false;
        }
    }

    // Last part
    if (part_idx < 8 and current <= 0xFFFF) {
        parts[part_idx] = @as(u16, @intCast(current));
        part_idx += 1;
    }

    // Handle :: expansion
    if (double_colon_idx) |dc_idx| {
        const before = dc_idx;
        const after = 8 - part_idx;
        var write_idx: usize = 0;

        // Copy parts before ::
        for (parts[0..before]) |p| {
            result[write_idx] = @as(u8, @intCast(p >> 8));
            result[write_idx + 1] = @as(u8, @intCast(p & 0xFF));
            write_idx += 2;
        }

        // Fill zeros
        for (0..after * 2) |_| {
            result[write_idx] = 0;
            write_idx += 1;
        }

        // Copy parts after ::
        for (parts[dc_idx..part_idx]) |p| {
            result[write_idx] = @as(u8, @intCast(p >> 8));
            result[write_idx + 1] = @as(u8, @intCast(p & 0xFF));
            write_idx += 2;
        }
    } else {
        // No :: expansion, just copy
        var write_idx: usize = 0;
        for (parts[0..part_idx]) |p| {
            result[write_idx] = @as(u8, @intCast(p >> 8));
            result[write_idx + 1] = @as(u8, @intCast(p & 0xFF));
            write_idx += 2;
        }
    }

    return result;
}

/// Format IPv6 address to string
pub fn formatIpv6(ip: *const Ipv6Address, buf: *[46]u8) []u8 {
    // Simple formatter - expand for full RFC 4291 compliance
    return std.fmt.bufPrint(buf, "{x:0>2x}{x:0>2x}:{x:0>2x}{x:0>2x}:{x:0>2x}{x:0>2x}:{x:0>2x}{x:0>2x}:{x:0>2x}{x:0>2x}:{x:0>2x}{x:0>2x}:{x:0>2x}{x:0>2x}", .{
        ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
        ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15],
    }) catch unreachable;
}

test "parseIpv4" {
    const ip = try parseIpv4("10.0.0.1");
    try std.testing.expectEqual(@as(u8, 10), ip[0]);
    try std.testing.expectEqual(@as(u8, 0), ip[1]);
    try std.testing.expectEqual(@as(u8, 0), ip[2]);
    try std.testing.expectEqual(@as(u8, 1), ip[3]);
}

test "parseIpv4 invalid" {
    try std.testing.expectError(error.InvalidAddress, parseIpv4("256.0.0.1"));
    try std.testing.expectError(error.InvalidAddress, parseIpv4("10.0.0"));
    try std.testing.expectError(error.InvalidAddress, parseIpv4("10.0.0.1.2"));
}

test "formatIpv4" {
    const ip: Ipv4Address = .{ 10, 0, 0, 1 };
    var buf: [16]u8 = undefined;
    const result = formatIpv4(ip, &buf);
    try std.testing.expectEqualStrings("10.0.0.1", result);
}

test "Options defaults" {
    const opts = Options{};
    try std.testing.expectEqual(@as(u16, 1500), opts.mtu);
    try std.testing.expectEqual(false, opts.packet_info);
    try std.testing.expectEqual(false, opts.gso);
    try std.testing.expectEqual(null, opts.network);
    try std.testing.expectEqual(null, opts.fd);
}
