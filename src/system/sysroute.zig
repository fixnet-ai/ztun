//! sysroute.zig - Cross-platform system routing management
//!
//! Provides cross-platform routing table operations using system APIs:
//! - Linux: Netlink sockets (NETLINK_ROUTE)
//! - macOS/iOS: Routing sockets (PF_ROUTE)
//! - Windows: IP Helper API (iphlpapi.dll)
//!
//! This module allows adding, deleting, and querying system routes.

const std = @import("std");
const builtin = @import("builtin");

// ==================== Platform Detection ====================

const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;
const is_ios = builtin.os.tag == .ios;
const is_windows = builtin.os.tag == .windows;
const is_bsd = is_macos or is_ios;

// ==================== C FFI Declarations ====================

// Common C functions - use Zig's built-in c_int from std.posix
extern "c" fn malloc(size: usize) *anyopaque;
extern "c" fn free(ptr: *anyopaque) callconv(.C) void;
extern "c" fn memcpy(dest: *anyopaque, src: *anyopaque, n: usize) *anyopaque;
extern "c" fn memset(ptr: *anyopaque, value: c_int, n: usize) *anyopaque;

// POSIX socket functions - use std.posix types
extern "c" fn socket(domain: c_int, type: c_int, protocol: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
extern "c" fn write(fd: c_int, buf: *const anyopaque, n: usize) isize;
extern "c" fn read(fd: c_int, buf: *anyopaque, n: usize) isize;
extern "c" fn send(fd: c_int, buf: *const anyopaque, n: usize, flags: c_int) isize;
extern "c" fn recv(fd: c_int, buf: *anyopaque, n: usize, flags: c_int) isize;
extern "c" fn bind(fd: c_int, addr: *const anyopaque, len: std.posix.socklen_t) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: std.posix.socklen_t) c_int;
extern "c" fn setsockopt(fd: c_int, level: c_int, optname: c_int, optval: *const anyopaque, optlen: std.posix.socklen_t) c_int;
extern "c" fn getsockopt(fd: c_int, level: c_int, optname: c_int, optval: *anyopaque, optlen: *std.posix.socklen_t) c_int;
extern "c" fn getpid() c_int;
extern "c" fn getuid() c_uint;
extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;
extern "c" fn getifaddrs(ifap: *?*ifaddrs) c_int;
extern "c" fn freeifaddrs(ifa: *ifaddrs) void;

// ==================== Type Definitions ====================

/// Address family
pub const AddressFamily = enum(u32) {
    ipv4 = 2,  // AF_INET
    ipv6 = if (is_bsd) 30 else 10, // AF_INET6 (BSD=30, Linux=10)
};

/// IPv6 address (128-bit)
pub const Ipv6Address = [16]u8;

/// IPv6 prefix (128-bit mask)
pub const Ipv6Prefix = [16]u8;

/// Route entry structure (cross-platform, supports IPv4/IPv6)
pub const RouteEntry = struct {
    family: AddressFamily,

    ipv4: struct {
        dst: u32,        // IPv4 destination address (network byte order)
        mask: u32,       // IPv4 subnet mask (network byte order)
        gateway: u32,    // IPv4 gateway (network byte order, 0 = direct)
    } = .{},

    ipv6: struct {
        dst: Ipv6Address,
        mask: Ipv6Prefix,
        gateway: Ipv6Address,
        prefix_len: u8, // IPv6 prefix length (0-128)
    } = .{},

    iface_idx: u32 = 0,
    metric: i32 = 0,
};

/// Error type for route operations
pub const RouteError = error{
    /// Invalid argument
    InvalidArgument,
    /// I/O error occurred
    IoError,
    /// Operation not supported on this platform
    NotSupported,
    /// Permission denied
    PermissionDenied,
    /// Route not found
    NotFound,
    /// Unknown error
    Unknown,
};

// ==================== C Types ====================

// BSD ifaddrs (used by macOS/iOS)
const ifaddrs = opaque {};
const ifaddrs_ptr = *ifaddrs;

// ==================== Helper Functions ====================

/// Convert CIDR prefix to subnet mask (network byte order)
fn cidrToMask(prefix_len: u5) u32 {
    if (prefix_len == 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFF;
    const host_mask = ~(@as(u32, 0) >> prefix_len);
    return @byteSwap(host_mask);
}

/// Calculate IPv6 prefix mask
fn ipv6PrefixToMaskInternal(prefix_len: u8, mask: *[16]u8) void {
    @memset(mask, 0);

    if (prefix_len == 0) return;
    const effective_prefix = if (prefix_len > 128) 128 else prefix_len;

    const full_bytes = effective_prefix / 8;
    const partial_bits = effective_prefix % 8;

    @memset(mask[0..full_bytes], 0xFF);

    if (partial_bits > 0) {
        mask[full_bytes] = 0xFF << @as(u3, 8 - partial_bits);
    }
}

/// Check if IPv6 address is all zeros
fn ipv6IsZero(addr: *const Ipv6Address) bool {
    for (addr) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

// ==================== Public API ====================

/// Add a route to the system routing table
pub fn routeAdd(route: *const RouteEntry) RouteError!void {
    if (route == null) return error.InvalidArgument;

    if (is_linux) {
        return linuxRouteAdd(route);
    } else if (is_bsd) {
        return bsdRouteAdd(route);
    } else if (is_windows) {
        return windowsRouteAdd(route);
    } else {
        return error.NotSupported;
    }
}

/// Delete a route from the system routing table
pub fn routeDelete(route: *const RouteEntry) RouteError!void {
    if (route == null) return error.InvalidArgument;

    if (is_linux) {
        return linuxRouteDelete(route);
    } else if (is_bsd) {
        return bsdRouteDelete(route);
    } else if (is_windows) {
        return windowsRouteDelete(route);
    } else {
        return error.NotSupported;
    }
}

/// Get the interface index by name
pub fn getIfaceIndex(ifname: [*:0]const u8) RouteError!u32 {
    if (is_linux) {
        return @as(u32, @intCast(linuxGetIfaceIndex(ifname)));
    } else if (is_bsd) {
        return bsdGetIfaceIndex(ifname);
    } else if (is_windows) {
        return @as(u32, @intCast(windowsGetIfaceIndex(ifname)));
    } else {
        return error.NotSupported;
    }
}

/// Create IPv4 route entry (convenience function)
pub fn createIpv4Route(
    dst: u32,
    prefix_len: u5,
    gateway: u32,
    iface_idx: u32,
    metric: i32,
) RouteEntry {
    return RouteEntry{
        .family = .ipv4,
        .ipv4 = .{
            .dst = dst,
            .mask = cidrToMask(prefix_len),
            .gateway = gateway,
        },
        .iface_idx = iface_idx,
        .metric = metric,
    };
}

/// Create IPv6 route entry (convenience function)
pub fn createIpv6Route(
    dst: *const Ipv6Address,
    prefix_len: u8,
    gateway: ?*const Ipv6Address,
    iface_idx: u32,
    metric: i32,
) RouteError!RouteEntry {
    if (dst == null) return error.InvalidArgument;

    var route = RouteEntry{
        .family = .ipv6,
        .ipv6 = .{
            .dst = dst.*,
            .prefix_len = prefix_len,
        },
        .iface_idx = iface_idx,
        .metric = metric,
    };

    ipv6PrefixToMaskInternal(prefix_len, &route.ipv6.mask);

    if (gateway) |gw| {
        route.ipv6.gateway = gw.*;
    }

    return route;
}

// ==================== Linux Netlink Implementation ====================

const AF_NETLINK = 16;
const NETLINK_ROUTE = 0;
const NLM_F_REQUEST = 1;
const NLM_F_CREATE = 0x100;
const NLM_F_EXCL = 0x200;
const NLM_F_ACK = 4;
const RTM_NEWROUTE = 24;
const RTM_DELROUTE = 25;
const RT_TABLE_MAIN = 254;
const RTPROT_BOOT = 3;
const RT_SCOPE_UNIVERSE = 0;
const RT_SCOPE_LINK = 253;
const RTN_UNICAST = 1;

const NLMSG_LENGTH = 16;
const RTA_LENGTH = 8;
const RTA_DATA = 8;

fn linuxRouteAdd(route: *const RouteEntry) RouteError!void {
    _ = route;
    std.debug.print("[sysroute] Linux route add not yet implemented\n", .{});
    return error.NotSupported;
}

fn linuxRouteDelete(route: *const RouteEntry) RouteError!void {
    _ = route;
    std.debug.print("[sysroute] Linux route delete not yet implemented\n", .{});
    return error.NotSupported;
}

fn linuxGetIfaceIndex(ifname: [*:0]const u8) c_int {
    _ = ifname;
    return -1;
}

// ==================== BSD Routing Socket Implementation ====================

const PF_ROUTE = 17;
const AF_UNSPEC = 0;
const SOCK_RAW = 3;
const RTM_VERSION = 5;
const RTM_ADD = 1;
const RTM_DELETE = 2;
const RTM_GET = 3;
const RTF_UP = 0x1;
const RTF_STATIC = 0x10;
const RTF_CLONING = 0x40;
const RTF_GATEWAY = 0x2;
const RTA_DST = 0x1;
const RTA_GATEWAY = 0x2;
const RTA_NETMASK = 0x4;
const RTA_IFP = 0x8;

const AF_INET = 2;
const AF_INET6 = 30;

// BSD sockaddr_in (IPv4)
const sockaddr_in = extern struct {
    sa_len: u8,
    sa_family: u8,
    sin_port: u16,
    sin_addr: [4]u8,
    sin_zero: [8]u8,
};

// BSD sockaddr_in6 (IPv6)
const sockaddr_in6 = extern struct {
    sa_len: u8,
    sa_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [16]u8,
    sin6_scope_id: u32,
};

// BSD sockaddr (generic)
const sockaddr = extern struct {
    sa_len: u8,
    sa_family: u8,
    sa_data: [14]u8,
};

// BSD route message header
const rt_msghdr = extern struct {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: u32,
    rtm_addrs: u32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    rtm_use: u32,
    rtm_inits: u32,
    rtm_rmx: [56]u8,
};

fn bsdRouteAdd(route: *const RouteEntry) RouteError!void {
    if (is_ios) {
        std.debug.print("[sysroute] Route operations not supported on iOS\n", .{});
        return error.NotSupported;
    }

    const sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (sock < 0) {
        return error.IoError;
    }
    defer close(sock);

    // Build the route message
    const msg = buildRouteMessage(route, RTM_ADD) catch {
        return error.InvalidArgument;
    };

    // Send the message
    const written = send(sock, &msg, msg.len, 0);
    if (written < 0) {
        std.debug.print("[sysroute] BSD route add failed to send\n", .{});
        return error.IoError;
    }

    std.debug.print("[sysroute] BSD route add completed\n", .{});
    return {};
}

fn bsdRouteDelete(route: *const RouteEntry) RouteError!void {
    if (is_ios) {
        std.debug.print("[sysroute] Route operations not supported on iOS\n", .{});
        return error.NotSupported;
    }

    const sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (sock < 0) {
        return error.IoError;
    }
    defer close(sock);

    // Build the route message
    const msg = buildRouteMessage(route, RTM_DELETE) catch {
        return error.InvalidArgument;
    };

    // Send the message
    const written = send(sock, &msg, msg.len, 0);
    if (written < 0) {
        std.debug.print("[sysroute] BSD route delete failed to send\n", .{});
        return error.IoError;
    }

    std.debug.print("[sysroute] BSD route delete completed\n", .{});
    return {};
}

/// Build a BSD routing socket message for adding/deleting routes
fn buildRouteMessage(route: *const RouteEntry, rtm_type: u8) ![]const u8 {
    const rtm_msglen = @sizeOf(rt_msghdr) + @sizeOf(sockaddr) * 3; // dst + gateway + netmask
    var buf: [256]u8 = undefined;

    // Build the message
    const rtm = @as(*rt_msghdr, @ptrCast(buf[0..@sizeOf(rt_msghdr)].ptr));
    rtm.rtm_msglen = @as(u16, @intCast(rtm_msglen));
    rtm.rtm_version = RTM_VERSION;
    rtm.rtm_type = rtm_type;
    rtm.rtm_index = @as(u16, @intCast(route.iface_idx));
    rtm.rtm_flags = RTF_UP | RTF_STATIC;
    rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    rtm.rtm_pid = getpid();
    rtm.rtm_seq = 0;
    rtm.rtm_errno = 0;

    // Build sockaddr structures (simplified IPv4)
    var offset = @sizeOf(rt_msghdr);

    // Destination address
    if (route.family == .ipv4) {
        const sa = @as(*sockaddr_in, @ptrCast(buf[offset..].ptr));
        sa.sa_len = @sizeOf(sockaddr_in);
        sa.sa_family = AF_INET;
        @memcpy(sa.sa_data[0..4], @as(*const [4]u8, @ptrCast(&route.ipv4.dst))[0..4]);
        offset += @sizeOf(sockaddr_in);

        // Gateway address
        const gw = @as(*sockaddr_in, @ptrCast(buf[offset..].ptr));
        gw.sa_len = @sizeOf(sockaddr_in);
        gw.sa_family = AF_INET;
        @memcpy(gw.sa_data[0..4], @as(*const [4]u8, @ptrCast(&route.ipv4.gateway))[0..4]);
        offset += @sizeOf(sockaddr_in);

        // Netmask
        const mask = @as(*sockaddr_in, @ptrCast(buf[offset..].ptr));
        mask.sa_len = @sizeOf(sockaddr_in);
        mask.sa_family = AF_INET;
        @memcpy(mask.sa_data[0..4], @as(*const [4]u8, @ptrCast(&route.ipv4.mask))[0..4]);
        offset += @sizeOf(sockaddr_in);
    }

    return buf[0..offset];
}

fn bsdGetIfaceIndex(ifname: [*:0]const u8) RouteError!u32 {
    const idx = if_nametoindex(ifname);
    if (idx == 0) {
        return error.NotFound;
    }
    return @as(u32, idx);
}

// ==================== Windows IP Helper Implementation ====================

fn windowsRouteAdd(route: *const RouteEntry) RouteError!void {
    _ = route;
    std.debug.print("[sysroute] Windows route add not yet implemented\n", .{});
    return error.NotSupported;
}

fn windowsRouteDelete(route: *const RouteEntry) RouteError!void {
    _ = route;
    std.debug.print("[sysroute] Windows route delete not yet implemented\n", .{});
    return error.NotSupported;
}

fn windowsGetIfaceIndex(ifname: [*:0]const u8) c_int {
    _ = ifname;
    return -1;
}

// ==================== Compile-time Checks ====================

comptime {
    if (@sizeOf(Ipv6Address) != 16) @compileError("Ipv6Address must be 16 bytes");
    if (@sizeOf(Ipv6Prefix) != 16) @compileError("Ipv6Prefix must be 16 bytes");
}
