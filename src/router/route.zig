//! route.zig - Route configuration and decision types
//!
//! Defines the types used for configuring the router and making routing decisions.

const std = @import("std");

// Import DeviceOps and TunError from the tun module (single source of truth)
const tun = @import("../tun/device.zig");
pub const TunError = tun.TunError;
pub const DeviceOps = tun.DeviceOps;

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

    /// Device operations (for platforms with device-specific headers like macOS utun)
    /// When provided, Router uses these operations instead of raw fd
    /// The DeviceOps handles all platform-specific header processing internally
    device_ops: ?*const DeviceOps = null,
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
