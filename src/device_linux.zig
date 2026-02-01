//! device_linux.zig - Linux TUN device implementation
//!
//! Uses /dev/net/tun for TUN device operations.

const std = @import("std");
const TunError = @import("device.zig").TunError;
const DeviceConfig = @import("device.zig").DeviceConfig;
const Ipv4Address = @import("device.zig").Ipv4Address;
const Ipv6Address = @import("device.zig").Ipv6Address;
const DeviceContext = @import("device.zig").DeviceContext;

const EINVAL = std.posix.EINVAL;
const ENODEV = std.posix.ENODEV;
const EACCES = std.posix.EACCES;

// ==================== Type Definitions ====================

/// Opaque Linux device handle
pub const LinuxDevice = opaque {};

/// Linux device internal state
const LinuxDeviceState = struct {
    fd: std.posix.fd_t,
    name: []const u8,
};

/// Tunnel flags for /dev/net/tun
const IFF_TUN = std.os.linux.IFF_TUN;
const IFF_NO_PI = std.os.linux.IFF_NO_PI;

// ==================== FFI Declarations ====================

/// struct ifreq for ioctl operations
pub const ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_ifru: extern union {
        addr: [128]u8,  // Generic sockaddr storage
        mtu: c_int,
        flags: c_short,
        ifindex: c_int,
    },
};

extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int) c_int;
extern "c" fn malloc(size: usize) *anyopaque;
extern "c" fn c_free(ptr: *anyopaque) callconv(.C) void;

// ==================== Device Creation ====================

/// Create a new TUN device on Linux
pub fn create(config: DeviceConfig) TunError!*DeviceContext {
    // Open /dev/net/tun
    const tun_fd = std.posix.open("/dev/net/tun", std.posix.O.RDWR | std.posix.O.CLOEXEC, 0) catch |err| {
        return switch (err) {
            error.AccessDenied => .PermissionDenied,
            error.FileNotFound => .NotFound,
            else => .IoError,
        };
    };
    errdefer std.posix.close(tun_fd);

    // Prepare ifreq structure
    var req: ifreq = undefined;
    @memset(@as([*]u8, @ptrCast(&req))[0..@sizeOf(ifreq)], 0);

    // Set device name if provided
    const name_ptr = if (config.name) |name| name else "tun%d";
    const name_len = std.math.min(name_ptr.len, 15);
    @memcpy(req.ifr_name[0..name_len], name_ptr[0..name_len]);

    // Set TUN flags (IFF_TUN | IFF_NO_PI for pure IP packets)
    req.ifr_ifru.flags = @as(c_short, @intCast(IFF_TUN | IFF_NO_PI));

    // Configure TUN device
    const TUNSETIFF = 0x400454ca;
    const result = ioctl(tun_fd, TUNSETIFF, &req);
    if (result < 0) {
        return .IoError;
    }

    // Extract device name
    const dev_name = std.mem.sliceTo(&req.ifr_name, 0);

    // Allocate context
    const ctx = malloc(@sizeOf(DeviceContext));
    if (ctx == null) {
        return .IoError;
    }

    // Allocate state
    const state = malloc(@sizeOf(LinuxDeviceState));
    if (state == null) {
        c_free(ctx);
        return .IoError;
    }

    // Copy name to heap
    const name_copy = malloc(dev_name.len + 1);
    if (name_copy == null) {
        c_free(state);
        c_free(ctx);
        return .IoError;
    }
    @memcpy(name_copy[0..dev_name.len], dev_name);
    name_copy[dev_name.len] = 0;

    // Initialize state
    const s = @as(*LinuxDeviceState, @ptrCast(state));
    s.* = .{
        .fd = tun_fd,
        .name = name_copy[0..dev_name.len],
    };

    // Initialize context
    const c = @as(*DeviceContext, @ptrCast(ctx));
    c.* = .{ .ptr = state };

    return c;
}

// ==================== Device Operations ====================

/// Helper to cast device pointer to state
inline fn toState(device_ptr: *anyopaque) *LinuxDeviceState {
    return @as(*LinuxDeviceState, @alignCast(@ptrCast(device_ptr)));
}

/// Receive a packet from the TUN device
pub fn recv(device_ptr: *anyopaque, buf: []u8) TunError!usize {
    const state = toState(device_ptr);
    const n = std.posix.read(state.fd, buf) catch {
        return .IoError;
    };
    return @as(usize, @intCast(n));
}

/// Send a packet to the TUN device
pub fn send(device_ptr: *anyopaque, buf: []const u8) TunError!usize {
    const state = toState(device_ptr);
    const n = std.posix.write(state.fd, buf) catch {
        return .IoError;
    };
    return @as(usize, @intCast(n));
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
        return .IoError;
    }

    return @as(u16, @intCast(req.ifr_ifru.mtu));
}

/// Get the interface index
pub fn getIfIndex(device_ptr: *anyopaque) TunError!u32 {
    const state = toState(device_ptr);
    const index = std.posix.if_nametoindex(state.name.ptr);
    if (index == 0) {
        return .NotFound;
    }
    return @as(u32, @intCast(index));
}

/// Set non-blocking mode
pub fn setNonBlocking(device_ptr: *anyopaque, nonblocking: bool) TunError!void {
    const state = toState(device_ptr);
    const flags = std.posix.fcntl(state.fd, std.posix.F.GETFL, 0) catch return .IoError;
    const new_flags = if (nonblocking) flags | std.posix.O.NONBLOCK else flags & ~std.posix.O.NONBLOCK;
    std.posix.fcntl(state.fd, std.posix.F.SETFL, new_flags) catch return .IoError;
}

/// Add an IPv4 address at runtime
pub fn addIpv4(_: *anyopaque, _: Ipv4Address, _: u8) TunError!void {
    return .Unknown;
}

/// Add an IPv6 address at runtime
pub fn addIpv6(_: *anyopaque, _: Ipv6Address, _: u8) TunError!void {
    return .Unknown;
}

/// Destroy the device and clean up resources
pub fn destroy(device_ptr: *anyopaque) void {
    const state = toState(device_ptr);
    std.posix.close(state.fd);
    c_free(state.name.ptr);
    c_free(state);
}
