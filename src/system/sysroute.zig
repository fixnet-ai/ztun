//! sysroute.zig - Cross-platform system routing management
//!
//! Provides cross-platform routing table operations using route commands:
//! - Linux: "ip route" command
//! - macOS/iOS: "route" command
//! - Windows: "route" command
//!
//! Reference: sing-tun (https://github.com/SagerNet/sing-tun)

const std = @import("std");
const builtin = @import("builtin");

// ==================== Platform Detection ====================

const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;
const is_ios = builtin.os.tag == .ios;
const is_windows = builtin.os.tag == .windows;
const is_bsd = is_macos or is_ios;

// ==================== Type Definitions ====================

/// Address family
pub const AddressFamily = enum(u32) {
    ipv4 = 2,
    ipv6 = if (is_bsd) 30 else 10,
};

/// IPv6 address (128-bit)
pub const Ipv6Address = [16]u8;

/// IPv6 prefix (128-bit mask)
pub const Ipv6Prefix = [16]u8;

/// Route entry for routing table operations
pub const RouteEntry = struct {
    /// Address family (AF_INET or AF_INET6)
    pub const AF = AddressFamily;

    /// IPv4-specific route data
    pub const Ipv4 = struct {
        /// Destination address (network byte order, big endian u32)
        dst: u32,
        /// Gateway address (network byte order, big endian u32)
        gateway: u32,
        /// Subnet mask (network byte order, big endian u32)
        mask: u32,
    };

    /// IPv6-specific route data
    pub const Ipv6 = struct {
        /// Destination address
        dst: Ipv6Address,
        /// Gateway address
        gateway: Ipv6Address,
        /// Prefix length (0-128)
        prefix: u8,
    };

    /// Address family
    af: AddressFamily,
    /// IPv4 route data (used when af = AF.ipv4)
    ipv4: Ipv4,
    /// IPv6 route data (used when af = AF.ipv6)
    ipv6: Ipv6,
    /// Interface index for interface-scoped routes
    iface_idx: u32,
    /// Interface name (null-terminated)
    iface_name: [*:0]const u8,
    /// Use interface scope (RTF_IFSCOPE on BSD)
    interface_scope: bool,
};

/// Error type for route operations
pub const RouteError = error{
    /// Invalid argument provided
    InvalidArgument,
    /// I/O error occurred
    IoError,
    /// Device not found
    NotFound,
    /// Permission denied
    PermissionDenied,
    /// Operation not supported
    NotSupported,
    /// Unknown error
    Unknown,
};

// ==================== Helper Functions ====================

/// Convert big-endian u32 to dotted decimal string
fn formatIpv4(address: u32, buf: *[16]u8) []const u8 {
    const b0 = @as(u8, @intCast((address >> 24) & 0xFF));
    const b1 = @as(u8, @intCast((address >> 16) & 0xFF));
    const b2 = @as(u8, @intCast((address >> 8) & 0xFF));
    const b3 = @as(u8, @intCast(address & 0xFF));
    return std.fmt.bufPrint(buf[0..], "{d}.{d}.{d}.{d}", .{b0, b1, b2, b3}) catch unreachable;
}

/// Parse IPv4 address string to big-endian u32
fn parseIpv4(str: []const u8) !u32 {
    var parts: [4]u32 = undefined;
    var count: usize = 0;
    var start: usize = 0;
    for (str, 0..) |c, i| {
        if (c == '.') {
            const part = std.fmt.parseInt(u32, str[start..i], 10) catch return error.InvalidArgument;
            if (part > 255) return error.InvalidArgument;
            parts[count] = part;
            count += 1;
            start = i + 1;
        }
    }
    // Last part
    const part = std.fmt.parseInt(u32, str[start..], 10) catch return error.InvalidArgument;
    if (part > 255) return error.InvalidArgument;
    parts[count] = part;
    count += 1;
    if (count != 4) return error.InvalidArgument;
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

/// Execute a command using libc system()
extern "c" fn system(cmd: [*:0]const u8) c_int;

/// Build command string and execute with system()
fn runRouteCommand(cmd: []const []const u8) RouteError!void {
    // Calculate required buffer size
    var cmd_len: usize = 0;
    for (cmd) |arg| {
        cmd_len += arg.len + 1; // +1 for space or null
    }

    // Allocate buffer on heap (need to use c_allocator for the temp buffer)
    const buf = std.heap.c_allocator.allocSentinel(u8, cmd_len, 0) catch {
        std.debug.print("[sysroute] Failed to allocate command buffer\n", .{});
        return error.IoError;
    };
    defer std.heap.c_allocator.free(buf);

    // Build command string
    var pos: usize = 0;
    for (cmd, 0..) |arg, i| {
        std.mem.copyForwards(u8, buf[pos..], arg);
        pos += arg.len;
        if (i < cmd.len - 1) {
            buf[pos] = ' ';
            pos += 1;
        }
    }
    buf[buf.len - 1] = 0; // Null terminate

    std.debug.print("[sysroute] Executing: {s}\n", .{buf[0..pos]});

    const result = system(buf.ptr);
    if (result != 0) {
        std.debug.print("[sysroute] Command failed with exit code {d}\n", .{result});
        return error.IoError;
    }

    return;
}

/// Create an IPv4 route entry
pub fn createIpv4Route(dst_ip: u32, prefix: u6, gateway_ip: u32, iface_idx: u32, _: u32) RouteEntry {
    // Calculate netmask from prefix using runtime computation to avoid type issues
    const all_ones: u32 = 0xFFFFFFFF;
    var mask: u32 = 0;
    if (prefix == 0) {
        mask = 0;
    } else if (prefix == 32) {
        mask = all_ones;
    } else {
        const shift: u5 = @intCast(32 - prefix);
        mask = all_ones << shift;
    }
    return .{
        .af = .ipv4,
        .ipv4 = .{
            .dst = dst_ip,
            .gateway = gateway_ip,
            .mask = @byteSwap(mask), // Host to network byte order
        },
        .ipv6 = undefined,
        .iface_idx = iface_idx,
        .iface_name = undefined,
        .interface_scope = false,
    };
}

// ==================== Route Operations ====================

/// Add a route to the system routing table
pub fn routeAdd(route: ?*const RouteEntry) RouteError!void {
    const r = route orelse return error.InvalidArgument;

    if (is_linux) {
        return linuxRouteAdd(r);
    } else if (is_bsd) {
        return bsdRouteAdd(r);
    } else if (is_windows) {
        return windowsRouteAdd(r);
    } else {
        return error.NotSupported;
    }
}

/// Delete a route from the system routing table
pub fn routeDelete(route: ?*const RouteEntry) RouteError!void {
    const r = route orelse return error.InvalidArgument;

    if (is_linux) {
        return linuxRouteDelete(r);
    } else if (is_bsd) {
        return bsdRouteDelete(r);
    } else if (is_windows) {
        return windowsRouteDelete(r);
    } else {
        return error.NotSupported;
    }
}

/// Get interface index from interface name
pub fn getIfaceIndex(ifname: [*:0]const u8) RouteError!u32 {
    const idx = if_nametoindex(ifname);
    if (idx == 0) {
        return error.NotFound;
    }
    return @as(u32, idx);
}

// ==================== BSD (macOS/iOS) Route Implementation ====================

fn bsdRouteAdd(route: *const RouteEntry) RouteError!void {
    if (route.af != .ipv4) {
        return error.NotSupported;
    }

    var addr_buf: [16]u8 = undefined;
    const dst_str = formatIpv4(route.ipv4.dst, &addr_buf);

    var mask_buf: [16]u8 = undefined;
    const mask_str = formatIpv4(route.ipv4.mask, &mask_buf);

    var gw_buf: [16]u8 = undefined;
    const gw_str = formatIpv4(route.ipv4.gateway, &gw_buf);

    std.debug.print("[sysroute] BSD route add: dst={s}, mask={s}, gw={s}\n", .{ dst_str, mask_str, gw_str });

    // route add -net <dst> -netmask <mask> <gw>
    const argv = &[_][]const u8{ "route", "add", "-net", dst_str, "-netmask", mask_str, gw_str };
    runRouteCommand(argv) catch {
        std.debug.print("[sysroute] BSD route add failed\n", .{});
        return error.IoError;
    };

    std.debug.print("[sysroute] BSD route add completed\n", .{});
    return {};
}

fn bsdRouteDelete(route: *const RouteEntry) RouteError!void {
    if (route.af != .ipv4) {
        return error.NotSupported;
    }

    var addr_buf: [16]u8 = undefined;
    const dst_str = formatIpv4(route.ipv4.dst, &addr_buf);

    var mask_buf: [16]u8 = undefined;
    const mask_str = formatIpv4(route.ipv4.mask, &mask_buf);

    std.debug.print("[sysroute] BSD route delete: dst={s}, mask={s}\n", .{ dst_str, mask_str });

    // route delete -net <dst> -netmask <mask>
    const argv = &[_][]const u8{ "route", "delete", "-net", dst_str, "-netmask", mask_str };
    runRouteCommand(argv) catch {
        std.debug.print("[sysroute] BSD route delete failed\n", .{});
        return error.IoError;
    };

    std.debug.print("[sysroute] BSD route delete completed\n", .{});
    return {};
}

// ==================== Linux Route Implementation ====================

fn linuxRouteAdd(route: *const RouteEntry) RouteError!void {
    if (route.af != .ipv4) {
        return error.NotSupported;
    }

    var addr_buf: [16]u8 = undefined;
    const dst_str = formatIpv4(route.ipv4.dst, &addr_buf);

    var gw_buf: [16]u8 = undefined;
    const gw_str = formatIpv4(route.ipv4.gateway, &gw_buf);

    std.debug.print("[sysroute] Linux route add: dst={s}, gw={s}\n", .{ dst_str, gw_str });

    // ip route add <dst> via <gateway>
    const argv = &[_][]const u8{ "/sbin/ip", "route", "add", dst_str, "via", gw_str };
    runRouteCommand(argv) catch {
        std.debug.print("[sysroute] Linux route add failed\n", .{});
        return error.IoError;
    };

    std.debug.print("[sysroute] Linux route add completed\n", .{});
    return {};
}

fn linuxRouteDelete(route: *const RouteEntry) RouteError!void {
    if (route.af != .ipv4) {
        return error.NotSupported;
    }

    var addr_buf: [16]u8 = undefined;
    const dst_str = formatIpv4(route.ipv4.dst, &addr_buf);

    std.debug.print("[sysroute] Linux route delete: dst={s}\n", .{dst_str});

    // ip route del <dst>
    const argv = &[_][]const u8{ "/sbin/ip", "route", "del", dst_str };
    runRouteCommand(argv) catch {
        std.debug.print("[sysroute] Linux route delete failed\n", .{});
        return error.IoError;
    };

    std.debug.print("[sysroute] Linux route delete completed\n", .{});
    return {};
}

// ==================== Windows Route Implementation ====================

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

// ==================== C FFI Declarations ====================

extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;

// ==================== Compile-time Checks ====================

comptime {
    if (@sizeOf(Ipv6Address) != 16) @compileError("Ipv6Address must be 16 bytes");
    if (@sizeOf(Ipv6Prefix) != 16) @compileError("Ipv6Prefix must be 16 bytes");
}
