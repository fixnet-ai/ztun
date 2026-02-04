//! device.zig - TUN device abstraction
//!
//! Provides the core Device type for synchronous TUN operations.

const std = @import("std");
const builtin = @import("builtin");
const ringbuf = @import("ringbuf");

// Detect Android by ABI (works during cross-compilation)
const is_android = builtin.os.tag == .linux and builtin.abi == .android;
// Detect iOS by ABI (simulator uses different ABI)
const is_ios = builtin.os.tag == .ios or builtin.abi == .simulator;

// FFI declarations
extern "c" fn malloc(size: usize) *anyopaque;
extern "c" fn free(ptr: *anyopaque) callconv(.C) void;
extern "c" fn memset(ptr: *anyopaque, value: c_int, size: usize) callconv(.C) void;
extern "c" fn socket(domain: c_int, type: c_int, protocol: c_int) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, addrlen: std.posix.socklen_t) c_int;
extern "c" fn getsockopt(fd: c_int, level: c_int, optname: c_int, optval: *anyopaque, optlen: *std.posix.socklen_t) c_int;
extern "c" fn __error() *c_int;

// ==================== Platform-Specific Constants ====================

// Linux
const IFF_TUN = 0x0001;
const IFF_NO_PI = 0x1000;
const IFF_UP = 0x0001;
const IFF_RUNNING = 0x0040;
const O_RDWR = 2;
const O_NONBLOCK = 2048;
const TUNSETIFF = 0x400454ca;

// macOS
const PF_SYSTEM = 32;
const SYSPROTO_CONTROL = 2;
const CTLIOCGINFO = 0xc0644e03;
const UTUN_OPT_IFNAME = 2;

// ==================== Type Definitions ====================

/// Error type for TUN operations
pub const TunError = error{
    InvalidArgument,
    IoError,
    NotFound,
    PermissionDenied,
    NotSupported,
    Unknown,
};

/// IPv4 address representation
pub const Ipv4Address = [4]u8;

/// IPv6 address representation
pub const Ipv6Address = [16]u8;

/// Network address configuration
pub const NetworkAddress = struct {
    address: Ipv4Address,
    prefix: u8,
    destination: ?Ipv4Address = null,
};

/// TUN device configuration
pub const DeviceConfig = struct {
    mtu: ?u16 = null,
    ipv4: ?NetworkAddress = null,
    ipv6: ?Ipv6Address = null,
    ipv6_prefix: ?u8 = null,
};

/// Device context - holds platform-specific data
pub const DeviceContext = struct {
    ptr: *anyopaque,
};

// Linux device state
const LinuxDeviceState = struct {
    fd: std.posix.fd_t,
    name: []const u8,
    mtu: u16,
    ringbuf: ringbuf.RingBuffer,
    read_offset: usize,
};

// macOS device state
const MacOSDeviceState = struct {
    fd: std.posix.fd_t,
    name: []const u8,
    mtu: u16,
    index: u32,
    ringbuf: ringbuf.RingBuffer,
    read_offset: usize,
};

// macOS control socket structures
// From macOS kernel source (sys/socket.h):
const sockaddr_ctl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

const ctl_info = extern struct {
    ctl_id: u32,
    ctl_name: [96]u8,
};

const ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_ifru: extern union {
        addr: [128]u8,
        mtu: c_int,
        flags: c_short,
        ifindex: c_int,
    },
};

// ==================== Device Operations Interface ====================

pub const DeviceOps = struct {
    ctx: *anyopaque,
    readFn: *const fn (ctx: *anyopaque, buf: []u8) TunError!usize,
    writeFn: *const fn (ctx: *anyopaque, buf: []const u8) TunError!usize,
    fdFn: *const fn (ctx: *anyopaque) std.posix.fd_t,
    destroyFn: *const fn (ctx: *anyopaque) void,

    pub fn read(self: *const DeviceOps, buf: []u8) TunError!usize {
        return self.readFn(self.ctx, buf);
    }

    pub fn write(self: *const DeviceOps, buf: []const u8) TunError!usize {
        return self.writeFn(self.ctx, buf);
    }

    pub fn fd(self: *const DeviceOps) std.posix.fd_t {
        return self.fdFn(self.ctx);
    }

    pub fn destroy(self: *const DeviceOps) void {
        self.destroyFn(self.ctx);
    }
};

// ==================== Linux Implementation ====================

extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int) c_int;
extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;

inline fn linuxToState(device_ptr: *anyopaque) *LinuxDeviceState {
    return @as(*LinuxDeviceState, @alignCast(@ptrCast(device_ptr)));
}

fn linuxCreate(config: DeviceConfig) TunError!*DeviceContext {
    const tun_fd = open(@as([*:0]const u8, @ptrCast("/dev/net/tun")), O_RDWR);
    if (tun_fd < 0) return error.IoError;
    errdefer std.posix.close(tun_fd);

    var req: ifreq = undefined;
    memset(&req, 0, @sizeOf(ifreq));
    const name_ptr = "tun%d";
    const name_len = @min(name_ptr.len, 15);
    @memcpy(req.ifr_name[0..name_len], name_ptr[0..name_len]);
    req.ifr_ifru.flags = @as(c_short, @intCast(IFF_TUN | IFF_NO_PI));
    const result = ioctl(tun_fd, TUNSETIFF, &req);
    if (result < 0) return error.IoError;
    const dev_name = std.mem.sliceTo(&req.ifr_name, 0);

    const mtu = config.mtu orelse 1500;

    const name_copy = malloc(dev_name.len + 1);
    if (@intFromPtr(name_copy) == 0) return error.IoError;
    @memcpy(@as([*]u8, @ptrCast(name_copy))[0..dev_name.len], dev_name);
    @as([*]u8, @ptrCast(name_copy))[dev_name.len] = 0;

    const state = @as(*LinuxDeviceState, @alignCast(@ptrCast(malloc(@sizeOf(LinuxDeviceState)))));
    state.* = .{
        .fd = tun_fd,
        .name = @as([*]u8, @ptrCast(name_copy))[0..dev_name.len],
        .mtu = mtu,
        .ringbuf = undefined,
        .read_offset = 0,
    };

    const ctx = malloc(@sizeOf(DeviceContext));
    const c = @as(*DeviceContext, @alignCast(@ptrCast(ctx)));
    c.* = .{ .ptr = state };
    return c;
}

fn linuxRecv(device_ptr: *anyopaque, buf: []u8) TunError! usize {
    const state = linuxToState(device_ptr);
    const n = std.posix.read(state.fd, buf) catch return error.IoError;
    return @as(usize, @intCast(n));
}

fn linuxSend(device_ptr: *anyopaque, buf: []const u8) TunError! usize {
    const state = linuxToState(device_ptr);
    const n = std.posix.write(state.fd, buf) catch return error.IoError;
    return @as(usize, @intCast(n));
}

fn linuxGetName(device_ptr: *anyopaque) TunError![]const u8 {
    return linuxToState(device_ptr).name;
}

fn linuxGetMtu(device_ptr: *anyopaque) TunError!u16 {
    return linuxToState(device_ptr).mtu;
}

fn linuxGetIfIndex(device_ptr: *anyopaque) TunError!u32 {
    const state = linuxToState(device_ptr);
    const index = if_nametoindex(@as([*:0]const u8, @ptrCast(state.name.ptr)));
    if (index == 0) return error.NotFound;
    return @as(u32, @intCast(index));
}

fn linuxSetNonBlocking(device_ptr: *anyopaque, nonblocking: bool) TunError!void {
    const state = linuxToState(device_ptr);
    const flags = std.posix.fcntl(state.fd, std.posix.F.GETFL, 0) catch return error.IoError;
    const new_flags = if (nonblocking) flags | O_NONBLOCK else flags & ~@as(c_int, O_NONBLOCK);
    _ = std.posix.fcntl(state.fd, std.posix.F.SETFL, @as(c_int, @bitCast(@as(u32, @intCast(new_flags))))) catch return error.IoError;
}

fn linuxGetFd(device_ptr: *anyopaque) std.posix.fd_t {
    return linuxToState(device_ptr).fd;
}

fn linuxDestroy(device_ptr: *anyopaque) void {
    const state = linuxToState(device_ptr);
    std.posix.close(state.fd);
    free(@constCast(state.name.ptr));
    free(state);
}

fn linuxCreateOps(fd: std.posix.fd_t) DeviceOps {
    const state = @as(*LinuxDeviceState, @alignCast(@ptrCast(malloc(@sizeOf(LinuxDeviceState)))));
    state.* = .{
        .fd = fd,
        .name = "",
        .mtu = 1500,
        .ringbuf = undefined,
        .read_offset = 0,
    };
    return DeviceOps{
        .ctx = state,
        .readFn = linuxRecv,
        .writeFn = linuxSend,
        .fdFn = linuxGetFd,
        .destroyFn = linuxDestroy,
    };
}

// ==================== macOS Implementation ====================

inline fn macosToState(device_ptr: *anyopaque) *MacOSDeviceState {
    return @as(*MacOSDeviceState, @alignCast(@ptrCast(device_ptr)));
}

fn macosCreate(config: DeviceConfig) TunError!*DeviceContext {
    // On macOS, utun is accessed via a PF_SYSTEM socket with SYSPROTO_CONTROL
    const socket_fd = socket(PF_SYSTEM, 2, SYSPROTO_CONTROL);
    if (socket_fd < 0) return error.IoError;
    errdefer std.posix.close(socket_fd);

    // Get control info for utun
    var info: ctl_info = std.mem.zeroInit(ctl_info, .{});
    const ctl_name = "com.apple.net.utun_control";
    @memcpy(info.ctl_name[0..ctl_name.len], ctl_name);

    if (ioctl(socket_fd, CTLIOCGINFO, &info) < 0) return error.IoError;

    // Prepare sockaddr_ctl to connect to utun
    var addr: sockaddr_ctl = std.mem.zeroInit(sockaddr_ctl, .{});
    addr.sc_len = @sizeOf(sockaddr_ctl);
    addr.sc_family = 32; // AF_SYSTEM
    addr.ss_sysaddr = 2; // AF_SYS_CONTROL for utun
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0; // 0 = auto-assign unit number

    if (connect(socket_fd, @as(*const anyopaque, @ptrCast(&addr)), @sizeOf(sockaddr_ctl)) < 0) {
        return error.IoError;
    }

    // Get the assigned device name via getsockopt
    var name_buf: [64]u8 = undefined;
    var name_len: std.posix.socklen_t = 64;
    if (getsockopt(socket_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, @as(*anyopaque, @ptrCast(&name_buf)), &name_len) < 0) {
        return error.IoError;
    }

    const dev_name = std.mem.sliceTo(&name_buf, 0);
    const name_copy = malloc(dev_name.len + 1);
    @memcpy(@as([*]u8, @ptrCast(name_copy))[0..dev_name.len], dev_name);
    @as([*]u8, @ptrCast(name_copy))[dev_name.len] = 0;

    const state = @as(*MacOSDeviceState, @alignCast(@ptrCast(malloc(@sizeOf(MacOSDeviceState)))));
    state.* = .{
        .fd = socket_fd,
        .name = @as([*]u8, @ptrCast(name_copy))[0..dev_name.len],
        .mtu = config.mtu orelse 1500,
        .index = 0,
        .ringbuf = undefined,
        .read_offset = 0,
    };

    const ctx = malloc(@sizeOf(DeviceContext));
    const c = @as(*DeviceContext, @alignCast(@ptrCast(ctx)));
    c.* = .{ .ptr = state };
    return c;
}

fn macosRecv(device_ptr: *anyopaque, buf: []u8) TunError! usize {
    const state = macosToState(device_ptr);
    const header_buf = @as([*]u8, @ptrCast(malloc(buf.len + 4)));
    if (@intFromPtr(header_buf) == 0) return error.IoError;
    defer free(header_buf);

    const n = std.posix.read(state.fd, header_buf[0..buf.len + 4]) catch return error.IoError;
    if (n <= 4) return 0;
    @memcpy(buf[0..@as(usize, @intCast(n - 4))], header_buf[4..n]);
    return @as(usize, @intCast(n - 4));
}

fn macosSend(device_ptr: *anyopaque, buf: []const u8) TunError! usize {
    const state = macosToState(device_ptr);
    const packet_buf = @as([*]u8, @ptrCast(malloc(buf.len + 4)));
    if (@intFromPtr(packet_buf) == 0) return error.IoError;
    defer free(packet_buf);

    packet_buf[0] = 2; // AF_INET
    packet_buf[1] = 0;
    packet_buf[2] = 0;
    packet_buf[3] = 0;
    @memcpy(packet_buf[4..buf.len + 4], buf);

    const n = std.posix.write(state.fd, packet_buf[0..buf.len + 4]) catch return error.IoError;
    if (n <= 4) return 0;
    return @as(usize, @intCast(n - 4));
}

fn macosGetName(device_ptr: *anyopaque) TunError![]const u8 {
    return macosToState(device_ptr).name;
}

fn macosGetMtu(device_ptr: *anyopaque) TunError!u16 {
    return macosToState(device_ptr).mtu;
}

fn macosGetIfIndex(device_ptr: *anyopaque) TunError!u32 {
    return macosToState(device_ptr).index;
}

fn macosSetNonBlocking(_: *anyopaque, _: bool) TunError!void {
    // Non-blocking mode handled by libxev at the event loop level
}

fn macosGetFd(device_ptr: *anyopaque) std.posix.fd_t {
    return macosToState(device_ptr).fd;
}

fn macosDestroy(device_ptr: *anyopaque) void {
    const state = macosToState(device_ptr);
    std.posix.close(state.fd);
    free(@constCast(state.name.ptr));
    free(state);
}

fn macosCreateOps(fd: std.posix.fd_t) DeviceOps {
    const state = @as(*MacOSDeviceState, @alignCast(@ptrCast(malloc(@sizeOf(MacOSDeviceState)))));
    state.* = .{
        .fd = fd,
        .name = "",
        .mtu = 1500,
        .index = 0,
        .ringbuf = undefined,
        .read_offset = 0,
    };
    return DeviceOps{
        .ctx = state,
        .readFn = macosRecv,
        .writeFn = macosSend,
        .fdFn = macosGetFd,
        .destroyFn = macosDestroy,
    };
}

// ==================== Windows Stub ====================

fn windowsDummy(_: *anyopaque, _: []u8) TunError! usize {
    return error.NotSupported;
}

fn windowsDummyWrite(_: *anyopaque, _: []const u8) TunError! usize {
    return error.NotSupported;
}

fn windowsGetFd(_: *anyopaque) std.posix.fd_t {
    return -1;
}

fn windowsDestroy(_: *anyopaque) void {}

fn windowsCreateOps(_: std.posix.fd_t) DeviceOps {
    return DeviceOps{
        .ctx = undefined,
        .readFn = windowsDummy,
        .writeFn = windowsDummyWrite,
        .fdFn = windowsGetFd,
        .destroyFn = windowsDestroy,
    };
}

// ==================== Device Type ====================

pub const Device = struct {
    ctx: *DeviceContext,

    pub fn create(config: DeviceConfig) TunError!Device {
        const ctx_ptr = if (is_android or builtin.os.tag == .linux)
            try linuxCreate(config)
        else if (is_ios or builtin.os.tag == .macos)
            try macosCreate(config)
        else if (builtin.os.tag == .windows)
            error.NotSupported
        else
            unreachable;
        return Device{ .ctx = ctx_ptr };
    }

    pub fn recv(self: Device, buf: []u8) TunError! usize {
        return if (is_android or builtin.os.tag == .linux)
            linuxRecv(self.ctx.ptr, buf)
        else if (is_ios or builtin.os.tag == .macos)
            macosRecv(self.ctx.ptr, buf)
        else
            unreachable;
    }

    pub fn send(self: Device, buf: []const u8) TunError! usize {
        return if (is_android or builtin.os.tag == .linux)
            linuxSend(self.ctx.ptr, buf)
        else if (is_ios or builtin.os.tag == .macos)
            macosSend(self.ctx.ptr, buf)
        else
            unreachable;
    }

    pub fn name(self: Device) TunError![]const u8 {
        return if (is_android or builtin.os.tag == .linux)
            linuxGetName(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            macosGetName(self.ctx.ptr)
        else
            unreachable;
    }

    pub fn mtu(self: Device) TunError!u16 {
        return if (is_android or builtin.os.tag == .linux)
            linuxGetMtu(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            macosGetMtu(self.ctx.ptr)
        else
            unreachable;
    }

    pub fn ifIndex(self: Device) TunError!u32 {
        return if (is_android or builtin.os.tag == .linux)
            linuxGetIfIndex(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            macosGetIfIndex(self.ctx.ptr)
        else
            unreachable;
    }

    pub fn getFd(self: Device) std.posix.fd_t {
        return if (is_android or builtin.os.tag == .linux)
            linuxGetFd(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            macosGetFd(self.ctx.ptr)
        else
            unreachable;
    }

    pub fn setNonBlocking(self: Device, nonblocking: bool) TunError!void {
        return if (is_android or builtin.os.tag == .linux)
            linuxSetNonBlocking(self.ctx.ptr, nonblocking)
        else if (is_ios or builtin.os.tag == .macos)
            macosSetNonBlocking(self.ctx.ptr, nonblocking)
        else
            unreachable;
    }

    pub fn destroy(self: Device) void {
        if (is_android or builtin.os.tag == .linux)
            linuxDestroy(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            macosDestroy(self.ctx.ptr);
    }
};

// ==================== DeviceOps Factory ====================

pub fn createDeviceOps(fd: std.posix.fd_t) DeviceOps {
    if (is_ios or builtin.os.tag == .macos) {
        return macosCreateOps(fd);
    } else if (builtin.os.tag == .windows) {
        return windowsCreateOps(fd);
    } else {
        return linuxCreateOps(fd);
    }
}
