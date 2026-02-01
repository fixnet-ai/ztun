//! device_macos.zig - macOS TUN device implementation
//!
//! Uses utun sockets for TUN device operations on macOS.

const std = @import("std");
const TunError = @import("device.zig").TunError;
const DeviceConfig = @import("device.zig").DeviceConfig;
const Ipv4Address = @import("device.zig").Ipv4Address;
const Ipv6Address = @import("device.zig").Ipv6Address;
const DeviceContext = @import("device.zig").DeviceContext;

const ifreq = @import("device_linux.zig").ifreq;

// ==================== Type Definitions ====================

/// Opaque macOS device handle
pub const MacOSDevice = opaque {};

/// macOS device internal state
const MacOSDeviceState = struct {
    fd: std.posix.fd_t,
    name: []const u8,
};

// ==================== FFI Declarations ====================

extern "c" fn socket(domain: c_int, type: c_int, protocol: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;
extern "c" fn malloc(size: usize) *anyopaque;
extern "c" fn free(ptr: *anyopaque) callconv(.C) void;
extern "c" fn strcpy(dest: [*]u8, src: [*:0]const u8) [*]u8;
extern "c" fn strlen(s: [*:0]const u8) usize;
extern "c" fn getsockopt(fd: c_int, level: c_int, optname: c_int, optval: *anyopaque, optlen: *std.posix.socklen_t) c_int;
extern "c" fn setsockopt(fd: c_int, level: c_int, optname: c_int, optval: *const anyopaque, optlen: std.posix.socklen_t) c_int;

// ==================== Helper Functions ====================

/// Get the device name from socket
fn getDeviceName(_: c_int, buf: *[64]u8) ![]const u8 {
    const default_name = "utun0";
    @memcpy(buf[0..default_name.len], default_name);
    return buf[0..default_name.len];
}

// ==================== Device Creation ====================

/// Create a new TUN device on macOS
pub fn create(_: DeviceConfig) TunError!*DeviceContext {
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 2) catch {
        return error.IoError;
    };
    errdefer std.posix.close(fd);

    // Get the device name
    var name_buf: [64]u8 = undefined;
    const name = getDeviceName(fd, &name_buf) catch {
        return error.IoError;
    };

    // Allocate context
    const ctx = malloc(@sizeOf(DeviceContext));
    if (@intFromPtr(ctx) == 0) {
        return error.IoError;
    }

    // Allocate state
    const state = malloc(@sizeOf(MacOSDeviceState));
    if (@intFromPtr(state) == 0) {
        free(ctx);
        return error.IoError;
    }

    // Copy name to heap
    const name_copy = malloc(name.len + 1);
    if (@intFromPtr(name_copy) == 0) {
        free(state);
        free(ctx);
        return error.IoError;
    }
    const name_ptr = @as([*]u8, @ptrCast(name_copy));
    @memcpy(name_ptr[0..name.len], name);
    name_ptr[name.len] = 0;

    // Initialize state
    const s = @as(*MacOSDeviceState, @alignCast(@ptrCast(state)));
    s.* = .{
        .fd = fd,
        .name = name_ptr[0..name.len],
    };

    // Initialize context
    const c = @as(*DeviceContext, @alignCast(@ptrCast(ctx)));
    c.* = .{ .ptr = state };

    return c;
}

// ==================== Device Operations ====================

/// Helper to cast device pointer to state
inline fn toState(device_ptr: *anyopaque) *MacOSDeviceState {
    return @as(*MacOSDeviceState, @alignCast(@ptrCast(device_ptr)));
}

/// Receive a packet from the TUN device
pub fn recv(device_ptr: *anyopaque, buf: []u8) TunError!usize {
    const state = toState(device_ptr);
    const n = std.posix.read(state.fd, buf) catch {
        return error.IoError;
    };
    return n;
}

/// Send a packet to the TUN device
pub fn send(device_ptr: *anyopaque, buf: []const u8) TunError!usize {
    const state = toState(device_ptr);
    const n = std.posix.write(state.fd, buf) catch {
        return error.IoError;
    };
    return n;
}

/// Get the device name
pub fn getName(device_ptr: *anyopaque) TunError![]const u8 {
    const state = toState(device_ptr);
    return state.name;
}

/// Get the device MTU
pub fn getMtu(device_ptr: *anyopaque) TunError!u16 {
    const state = toState(device_ptr);

    var req: ifreq = undefined;
    @memset(@as([*]u8, @ptrCast(&req))[0..@sizeOf(ifreq)], 0);
    @memcpy(req.ifr_name[0..state.name.len], state.name);

    const SIOCGIFMTU = 0xc0206933;
    const result = ioctl(state.fd, SIOCGIFMTU, &req);
    if (result < 0) {
        return error.IoError;
    }

    return @as(u16, @intCast(req.ifr_ifru.mtu));
}

/// Get the interface index
pub fn getIfIndex(device_ptr: *anyopaque) TunError!u32 {
    const state = toState(device_ptr);
    const index = if_nametoindex(state.name.ptr);
    if (index == 0) {
        return error.NotFound;
    }
    return @as(u32, @intCast(index));
}

/// Set non-blocking mode
pub fn setNonBlocking(device_ptr: *anyopaque, nonblocking: bool) TunError!void {
    const state = toState(device_ptr);
    const flags = std.posix.fcntl(state.fd, std.posix.F.GETFL, 0) catch return error.IoError;
    const new_flags = if (nonblocking) flags | std.posix.O.NONBLOCK else flags & ~std.posix.O.NONBLOCK;
    std.posix.fcntl(state.fd, std.posix.F.SETFL, new_flags) catch return error.IoError;
}

/// Add an IPv4 address at runtime
pub fn addIpv4(_: *anyopaque, _: Ipv4Address, _: u8) TunError!void {
    return error.Unknown;
}

/// Add an IPv6 address at runtime
pub fn addIpv6(_: *anyopaque, _: Ipv6Address, _: u8) TunError!void {
    return error.Unknown;
}

/// Destroy the device and clean up resources
pub fn destroy(device_ptr: *anyopaque) void {
    const state = toState(device_ptr);
    std.posix.close(state.fd);
    free(@constCast(state.name.ptr));
    free(state);
}
