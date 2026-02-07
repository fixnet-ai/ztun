//! route.zig - Route configuration and decision types
//!
//! Defines the types used for configuring the router and making routing decisions.

const std = @import("std");

/// TunError type for device operations
pub const TunError = error{ IoError, NotFound, PermissionDenied, NotSupported, InvalidArgument, Unknown };

/// Device operations interface for platform-specific TUN handling
/// Allows Router to work with different TUN implementations (macOS utun, Linux tun, etc.)
pub const DeviceOps = struct {
    /// Opaque pointer to device-specific state
    ctx: *anyopaque,

    /// Read a packet from the device
    /// Returns the number of bytes read (excluding any device-specific headers)
    readFn: *const fn (ctx: *anyopaque, buf: []u8) TunError!usize,

    /// Write a packet to the device
    /// Takes raw IP packet (without device headers), writes with proper headers
    writeFn: *const fn (ctx: *anyopaque, buf: []const u8) TunError!usize,

    /// Get the file descriptor for libxev polling
    fdFn: *const fn (ctx: *anyopaque) std.posix.fd_t,

    /// Destroy the device and cleanup resources
    destroyFn: *const fn (ctx: *anyopaque) void,

    /// Read packet from TUN device (wrapper that handles device-specific headers)
    pub fn read(self: *const DeviceOps, buf: []u8) TunError!usize {
        return self.readFn(self.ctx, buf);
    }

    /// Write packet to TUN device (wrapper that handles device-specific headers)
    pub fn write(self: *const DeviceOps, buf: []const u8) TunError!usize {
        return self.writeFn(self.ctx, buf);
    }

    /// Get file descriptor for event loop
    pub fn fd(self: *const DeviceOps) std.posix.fd_t {
        return self.fdFn(self.ctx);
    }

    /// Destroy device and cleanup
    pub fn destroy(self: *const DeviceOps) void {
        self.destroyFn(self.ctx);
    }
};

/// TUN device configuration provided by the application
pub const TunConfig = struct {
    /// TUN device name (e.g., "tun0")
    name: [:0]const u8,

    /// TUN interface index (from if_nametoindex())
    ifindex: u32,

    /// TUN IPv4 address (network byte order, e.g., 0x0A000001 = 10.0.0.1)
    ip: u32,

    /// IPv4 prefix length (e.g., 24 for /24 network)
    prefix_len: u8,

    /// Maximum Transmission Unit
    mtu: u16,

    /// TUN file descriptor (for libxev integration, when not using device_ops)
    fd: std.posix.fd_t = 0,

    /// Device operations (optional, for platforms with device-specific headers like macOS utun)
    /// When provided, Router uses these operations instead of raw fd
    device_ops: ?*const DeviceOps = null,

    /// Platform-specific header length for TUN write operations
    /// macOS utun: 4 bytes (AF_INET header added by kernel on read, required on write)
    /// Linux/Windows: 0 bytes
    /// This is used when writing packets via raw fd (non-device_ops path)
    header_len: usize = 0,
};

/// Egress network interface configuration provided by the application
pub const EgressConfig = struct {
    /// Egress interface name (e.g., "en0", "eth0")
    name: [:0]const u8,

    /// Egress interface index (from if_nametoindex())
    ifindex: u32,

    /// Egress IPv4 address (network byte order)
    /// Used as source IP for NAT and to prevent routing loops
    ip: u32,
};

/// Proxy configuration (optional)
pub const ProxyConfig = struct {
    /// Proxy protocol type
    type: ProxyType,

    /// Proxy server address (e.g., "127.0.0.1:1080")
    addr: [:0]const u8,

    /// Username for authentication (optional)
    username: ?[:0]const u8 = null,

    /// Password for authentication (optional)
    password: ?[:0]const u8 = null,
};

/// Proxy protocol type
pub const ProxyType = enum(u8) {
    /// No proxy (direct connection)
    None = 0,
    /// SOCKS5 proxy
    Socks5 = 1,
    /// HTTP proxy
    Http = 2,
    /// HTTPS proxy (HTTP over TLS)
    Https = 3,
};

/// Routing decision enum
/// Returned by the application's route callback
pub const RouteDecision = enum(u8) {
    /// Forward directly through egress interface (bypasses TUN)
    /// Uses SO_BINDTODEVICE to prevent routing loops
    Direct = 0,

    /// Forward through SOCKS5 proxy
    Socks5 = 1,

    /// Forward through HTTP proxy
    Http = 2,

    /// Drop the packet silently
    Drop = 3,

    /// Handle locally (write back to TUN)
    /// Used for packets addressed to the router itself
    Local = 4,

    /// NAT mode for UDP forwarding
    /// Rewrites source IP/port and tracks session
    Nat = 5,
};

/// Route callback function type
///
/// Called by the router for each incoming packet to determine
/// how the packet should be forwarded.
///
/// Parameters:
///   - src_ip: Source IP address (network byte order)
///   - src_port: Source port (host byte order)
///   - dst_ip: Destination IP address (network byte order)
///   - dst_port: Destination port (host byte order)
///   - protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP)
///
/// Returns:
///   - RouteDecision indicating how to forward the packet
pub const RouteCallback = *const fn (
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
) RouteDecision;

// ============================================================================
// Route Filtering Types
// ============================================================================

/// IP address matching mode
pub const IpMatcher = enum {
    Exact,      // Exact IP match
    Cidr,       // CIDR range match (e.g., 10.0.0.0/8)
    Private,    // RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    Loopback,   // 127.0.0.0/8
    Linklocal,  // 169.254.0.0/16
    Multicast,  // 224.0.0.0/4
    Any,        // Match any IP
};

/// IP matching rule configuration
pub const IpRule = struct {
    /// Matching mode
    matcher: IpMatcher,
    /// IP address for Exact or Cidr match (network byte order)
    ip: u32 = 0,
    /// Prefix length for Cidr match (0-32)
    prefix_len: u8 = 0,

    /// Create an Exact IP match rule
    pub fn exact(ip: u32) IpRule {
        return IpRule{
            .matcher = .Exact,
            .ip = ip,
            .prefix_len = 0,
        };
    }

    /// Create a CIDR range match rule
    pub fn cidr(ip: u32, prefix: u8) IpRule {
        return IpRule{
            .matcher = .Cidr,
            .ip = ip,
            .prefix_len = prefix,
        };
    }

    /// Create a Private IP match rule (RFC 1918)
    pub fn private() IpRule {
        return IpRule{
            .matcher = .Private,
            .ip = 0,
            .prefix_len = 0,
        };
    }

    /// Create a Loopback match rule (127.0.0.0/8)
    pub fn loopback() IpRule {
        return IpRule{
            .matcher = .Loopback,
            .ip = 0,
            .prefix_len = 0,
        };
    }

    /// Create a Link-local match rule (169.254.0.0/16)
    pub fn linklocal() IpRule {
        return IpRule{
            .matcher = .Linklocal,
            .ip = 0,
            .prefix_len = 0,
        };
    }

    /// Create a Multicast match rule (224.0.0.0/4)
    pub fn multicast() IpRule {
        return IpRule{
            .matcher = .Multicast,
            .ip = 0,
            .prefix_len = 0,
        };
    }

    /// Create an Any IP match rule
    pub fn any() IpRule {
        return IpRule{
            .matcher = .Any,
            .ip = 0,
            .prefix_len = 0,
        };
    }
};

/// Protocol matching configuration
pub const ProtocolRule = struct {
    /// Match specific protocol (0 = any)
    protocol: u8 = 0,
    /// Match specific port (0 = any)
    port: u16 = 0,

    /// Match any protocol
    pub fn anyProtocol() ProtocolRule {
        return ProtocolRule{ .protocol = 0, .port = 0 };
    }

    /// Match specific protocol
    pub fn proto(p: u8) ProtocolRule {
        return ProtocolRule{ .protocol = p, .port = 0 };
    }

    /// Match specific protocol and port
    pub fn protoPort(p: u8, port: u16) ProtocolRule {
        return ProtocolRule{ .protocol = p, .port = port };
    }

    /// Match TCP protocol
    pub fn tcp() ProtocolRule {
        return ProtocolRule{ .protocol = 6, .port = 0 };
    }

    /// Match UDP protocol
    pub fn udp() ProtocolRule {
        return ProtocolRule{ .protocol = 17, .port = 0 };
    }

    /// Match ICMP protocol
    pub fn icmp() ProtocolRule {
        return ProtocolRule{ .protocol = 1, .port = 0 };
    }
};

/// Filter rule combining IP, protocol, and port matching with action
pub const FilterRule = struct {
    /// IP matching rule
    ip_rule: IpRule,
    /// Protocol matching rule
    proto_rule: ProtocolRule,
    /// Action to take when rule matches
    action: RouteDecision,
    /// Rule priority (higher = checked first)
    priority: u8 = 0,

    /// Create a rule matching any IP and protocol with specified action
    pub fn any(action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.any(),
            .proto_rule = ProtocolRule.anyProtocol(),
            .action = action,
            .priority = 0,
        };
    }

    /// Create a rule for specific IP with specified action
    pub fn ip(ip_addr: u32, action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.exact(ip_addr),
            .proto_rule = ProtocolRule.anyProtocol(),
            .action = action,
            .priority = 10,
        };
    }

    /// Create a rule for CIDR range with specified action
    pub fn cidr(ip_addr: u32, prefix: u8, action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.cidr(ip_addr, prefix),
            .proto_rule = ProtocolRule.anyProtocol(),
            .action = action,
            .priority = 10,
        };
    }

    /// Create a rule for private IPs
    pub fn private(action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.private(),
            .proto_rule = ProtocolRule.anyProtocol(),
            .action = action,
            .priority = 20,
        };
    }

    /// Create a rule for loopback IPs
    pub fn loopback(action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.loopback(),
            .proto_rule = ProtocolRule.anyProtocol(),
            .action = action,
            .priority = 25,
        };
    }

    /// Create a rule for link-local IPs
    pub fn linklocal(action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.linklocal(),
            .proto_rule = ProtocolRule.anyProtocol(),
            .action = action,
            .priority = 25,
        };
    }

    /// Create a rule for multicast IPs
    pub fn multicast(action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.multicast(),
            .proto_rule = ProtocolRule.anyProtocol(),
            .action = action,
            .priority = 30,
        };
    }

    /// Create a rule for ICMP protocol
    pub fn icmp(action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.any(),
            .proto_rule = ProtocolRule.icmp(),
            .action = action,
            .priority = 40,
        };
    }

    /// Create a rule for UDP protocol
    pub fn udp(action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.any(),
            .proto_rule = ProtocolRule.udp(),
            .action = action,
            .priority = 35,
        };
    }

    /// Create a rule for TCP to specific destination
    pub fn tcpTo(dst_ip: u32, action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.exact(dst_ip),
            .proto_rule = ProtocolRule.tcp(),
            .action = action,
            .priority = 50,
        };
    }

    /// Create a rule for UDP to specific destination
    pub fn udpTo(dst_ip: u32, action: RouteDecision) FilterRule {
        return FilterRule{
            .ip_rule = IpRule.exact(dst_ip),
            .proto_rule = ProtocolRule.udp(),
            .action = action,
            .priority = 50,
        };
    }
};

/// Filter chain - ordered list of rules evaluated in priority order
pub const FilterChain = struct {
    /// List of rules (will be sorted by priority)
    rules: []const FilterRule,
    /// Default action when no rules match
    default_action: RouteDecision,

    /// Create a filter chain with rules and default action
    pub fn init(rules: []const FilterRule, default_action: RouteDecision) FilterChain {
        return FilterChain{
            .rules = rules,
            .default_action = default_action,
        };
    }

    /// Evaluate packet against filter chain
    /// Returns the action of the first matching rule, or default_action
    pub fn evaluate(
        chain: FilterChain,
        dst_ip: u32,
        dst_port: u16,
        protocol: u8,
    ) RouteDecision {
        // Rules are evaluated in priority order (higher priority first)
        // Since rules are stored as-is, caller should ensure they're sorted
        for (chain.rules) |rule| {
            if (matchRule(rule, dst_ip, dst_port, protocol)) {
                return rule.action;
            }
        }
        return chain.default_action;
    }
};

/// Check if a single rule matches the packet
fn matchRule(rule: FilterRule, dst_ip: u32, dst_port: u16, protocol: u8) bool {
    // Check protocol match
    if (rule.proto_rule.protocol != 0 and rule.proto_rule.protocol != protocol) {
        return false;
    }

    // Check port match
    if (rule.proto_rule.port != 0 and rule.proto_rule.port != dst_port) {
        return false;
    }

    // Check IP match
    return matchIp(rule.ip_rule, dst_ip);
}

/// Match IP address against IP rule (all IPs in network byte order)
fn matchIp(rule: IpRule, ip: u32) bool {
    switch (rule.matcher) {
        .Exact => {
            return ip == rule.ip;
        },
        .Cidr => {
            if (rule.prefix_len == 0) return true;
            if (rule.prefix_len >= 32) return ip == rule.ip;

            // Calculate mask for CIDR
            const mask: u32 = if (rule.prefix_len == 0) 0 else ~@as(u32, 0) << (32 - rule.prefix_len);
            return (ip & mask) == (rule.ip & mask);
        },
        .Private => {
            // 10.0.0.0/8
            const private_10 = (ip & 0xFF000000) == 0x0A000000;
            // 172.16.0.0/12
            const private_172 = (ip & 0xFFF00000) == 0xAC100000;
            // 192.168.0.0/16
            const private_192 = (ip & 0xFFFF0000) == 0xC0A80000;

            return private_10 or private_172 or private_192;
        },
        .Loopback => {
            // 127.0.0.0/8
            return (ip & 0xFF000000) == 0x7F000000;
        },
        .Linklocal => {
            // 169.254.0.0/16
            return (ip & 0xFFFF0000) == 0xA9FE0000;
        },
        .Multicast => {
            // 224.0.0.0/4 (224.0.0.0 to 239.255.255.255)
            return (ip & 0xF0000000) == 0xE0000000;
        },
        .Any => {
            return true;
        },
    }
}

// ============================================================================
// Standard Filter Chain Builders
// ============================================================================

/// Build the default transparent proxy filter chain
/// Rules:
///   1. ICMP -> Local (auto-reply)
///   2. Private IPs -> Local (normal routing)
///   3. UDP -> Nat (NAT all UDP)
///   4. TCP to target IP -> Socks5
///   5. Multicast -> Drop
///   6. Default -> Local (normal routing)
pub fn buildTransparentProxyChain(
    _: std.mem.Allocator,
    target_ip: u32,
    proxy_action: RouteDecision,
    nat_action: RouteDecision,
) FilterChain {
    const rules = &[_]FilterRule{
        // ICMP echo requests - handle locally (auto-reply)
        FilterRule.icmp(.Local),

        // Private IP ranges - handle locally (normal routing)
        FilterRule.private(.Local),
        FilterRule.loopback(.Local),
        FilterRule.linklocal(.Local),

        // All UDP traffic - NAT and forward
        FilterRule.udp(nat_action),

        // TCP to specific target IP - route through proxy
        FilterRule.tcpTo(target_ip, proxy_action),

        // Multicast - drop silently
        FilterRule.multicast(.Drop),
    };

    return FilterChain.init(rules, .Local);
}

/// Parse IPv4 address string to u32 (network byte order)
/// Supports: "10.0.0.1", "192.168.1.1", etc.
pub fn parseIpv4(ip_str: []const u8) !u32 {
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

    // Combine to u32 (network byte order)
    return @as(u32, parts[0]) << 24 | @as(u32, parts[1]) << 16 | @as(u32, parts[2]) << 8 | @as(u32, parts[3]);
}

/// Format IPv4 address (network byte order) to string
pub fn formatIpv4(ip: u32, buf: *[16]u8) []u8 {
    const b = @as(*const [4]u8, @ptrCast(&ip)).*;
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch unreachable;
}

// ============================================================================
// Common IP Address Constants (network byte order)
// ============================================================================

pub const IP_ANY = 0x00000000;           // 0.0.0.0
pub const IP_LOCALHOST = 0x7F000001;     // 127.0.0.1
pub const IP_MULTICAST = 0xE0000000;     // 224.0.0.0

// Private ranges (RFC 1918)
pub const IP_PRIVATE_10 = 0x0A000000;   // 10.0.0.0/8
pub const IP_PRIVATE_172 = 0xAC100000;  // 172.16.0.0/12
pub const IP_PRIVATE_192 = 0xC0A80000;  // 192.168.0.0/16

// Link-local
pub const IP_LINKLOCAL = 0xA9FE0000;    // 169.254.0.0/16

// Google DNS (for testing)
pub const IP_GOOGLE_DNS = 0x08080808;  // 8.8.8.8
pub const IP_GOOGLE_DNS_ALT = 0x08080804; // 8.8.8.4
