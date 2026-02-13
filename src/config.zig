//! config.zig - JSON Configuration Parser
//!
//! Parses JSON configuration files for ztun/tun2socks.
//! Supports tun, outbound, and route sections.

const std = @import("std");

/// Main configuration structure
pub const Config = struct {
    /// TUN device configuration
    tun: ?TunConfig = null,

    /// Outbound configuration (proxy settings)
    outbound: ?OutboundConfig = null,

    /// Route configuration
    route: ?RouteConfig = null,

    /// DNS configuration
    dns: ?DnsConfig = null,
};

/// TUN device configuration
pub const TunConfig = struct {
    /// Interface name (e.g., "tun0")
    name: []const u8,

    /// TUN IPv4 address (e.g., "10.0.0.1")
    ip: []const u8,

    /// TUN peer address (e.g., "10.0.0.2")
    peer: []const u8 = "10.0.0.2",

    /// Prefix length
    prefix_len: u8 = 24,

    /// MTU
    mtu: u16 = 1500,
};

/// Outbound configuration
pub const OutboundConfig = struct {
    /// Type: socks5, http, direct
    type: []const u8 = "direct",

    /// Server address (e.g., "127.0.0.1:1080")
    server: []const u8 = "",

    /// Username for authentication
    username: ?[]const u8 = null,

    /// Password for authentication
    password: ?[]const u8 = null,
};

/// Route configuration
pub const RouteConfig = struct {
    /// Rules for routing decisions
    rules: []RuleConfig = &[_]RuleConfig{},

    /// Default outbound
    default: []const u8 = "direct",
};

/// Route rule configuration
pub const RuleConfig = struct {
    /// IP CIDR matches
    ip_cidr: ?[]const []const u8 = null,

    /// Protocol match (tcp, udp)
    protocol: ?[]const u8 = null,

    /// Port match
    port: ?u16 = null,

    /// Outbound to use
    outbound: []const u8 = "direct",
};

/// DNS configuration
pub const DnsConfig = struct {
    /// DNS server address
    server: []const u8 = "8.8.8.8",

    /// Strategy: udp, tcp, tls
    strategy: []const u8 = "udp",
};

/// Parse configuration from JSON string
pub fn parse(allocator: std.mem.Allocator, json_str: []const u8) !Config {
    var parser = std.json.Parser.init(allocator, .{});
    defer parser.deinit();

    var tree = try parser.parse(json_str);
    defer tree.deinit();

    return parseValue(allocator, &tree.root);
}

/// Parse JSON value to Config
fn parseValue(allocator: std.mem.Allocator, value: *const std.json.Value) !Config {
    if (value.* != .object) {
        return error.InvalidConfig;
    }

    var config: Config = .{};

    const obj = value.object;

    if (obj.get("tun")) |tun_value| {
        config.tun = try parseTunConfig(allocator, tun_value);
    }

    if (obj.get("outbound")) |outbound_value| {
        config.outbound = try parseOutboundConfig(allocator, outbound_value);
    }

    if (obj.get("route")) |route_value| {
        config.route = try parseRouteConfig(allocator, route_value);
    }

    if (obj.get("dns")) |dns_value| {
        config.dns = try parseDnsConfig(allocator, dns_value);
    }

    return config;
}

/// Parse TUN configuration
fn parseTunConfig(allocator: std.mem.Allocator, value: *const std.json.Value) !TunConfig {
    if (value.* != .object) {
        return error.InvalidTunConfig;
    }

    const obj = value.object;

    const name = obj.get("name") orelse return error.MissingName;
    const ip = obj.get("ip") orelse return error.MissingIp;

    return TunConfig{
        .name = try dupString(allocator, name),
        .ip = try dupString(allocator, ip),
        .peer = obj.get("peer") orelse "10.0.0.2",
        .prefix_len = obj.get("prefix_len") orelse 24,
        .mtu = obj.get("mtu") orelse 1500,
    };
}

/// Parse outbound configuration
fn parseOutboundConfig(allocator: std.mem.Allocator, value: *const std.json.Value) !OutboundConfig {
    if (value.* != .object) {
        return error.InvalidOutboundConfig;
    }

    const obj = value.object;

    return OutboundConfig{
        .type = obj.get("type") orelse "direct",
        .server = obj.get("server") orelse "",
        .username = obj.get("username"),
        .password = obj.get("password"),
    };
}

/// Parse route configuration
fn parseRouteConfig(allocator: std.mem.Allocator, value: *const std.json.Value) !RouteConfig {
    if (value.* != .object) {
        return error.InvalidRouteConfig;
    }

    const obj = value.object;

    return RouteConfig{
        .rules = &[_]RuleConfig{},
        .default = obj.get("default") orelse "direct",
    };
}

/// Parse DNS configuration
fn parseDnsConfig(allocator: std.mem.Allocator, value: *const std.json.Value) !DnsConfig {
    if (value.* != .object) {
        return error.InvalidDnsConfig;
    }

    const obj = value.object;

    return DnsConfig{
        .server = obj.get("server") orelse "8.8.8.8",
        .strategy = obj.get("strategy") orelse "udp",
    };
}

/// Duplicate JSON string to owned string
fn dupString(allocator: std.mem.Allocator, json_str: *const std.json.Value) ![]const u8 {
    const str = json_str.*;
    if (str != .string) {
        return error.InvalidString;
    }
    return try allocator.dupe(u8, str.string);
}

// Error set
pub const ConfigError = error{
    InvalidConfig,
    InvalidTunConfig,
    InvalidOutboundConfig,
    InvalidRouteConfig,
    InvalidDnsConfig,
    InvalidString,
    MissingName,
    MissingIp,
    OutOfMemory,
};
