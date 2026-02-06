//! device_darwin.zig - Darwin/macOS/iOS TUN device implementation
//!
//! Implements TunDevice interface using utun sockets on Darwin-based systems.
//! Handles the 4-byte AF_INET header transparently on read/write.

const std = @import("std");
const builtin = @import("builtin");
const TunDevice = @import("device.zig").TunDevice;
const TunError = @import("device.zig").TunError;
const Options = @import("options.zig").Options;
const RouteEntry = @import("options.zig").RouteEntry;
const Ipv4Address = @import("options.zig").Ipv4Address;
const Ipv6Address = @import("options.zig").Ipv6Address;
const DeviceContext = @import("device.zig").DeviceContext;

// ==================== Constants ====================

/// Tunnel flags for utun
const IFF_TUN = 0x0001;
const IFF_NO_PI = 0x1000;
const IFF_UP = 0x0001;
const IFF_RUNNING = 0x0040;

/// Address family constants (BSD values)
const AF_INET = 2;
const AF_INET6 = 30;
const PF_SYSTEM = 32;
const SYSPROTO_CONTROL = 2;
const CTLIOCGINFO = 0xc0644e03;

/// File status flags
const O_NONBLOCK = 0x0004;

// C library declarations
extern "c" fn socket(domain: c_int, type: c_int, protocol: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: std.posix.socklen_t) c_int;
extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
extern "c" fn getsockopt(fd: c_int, level: c_int, optname: c_int, optval: *anyopaque, optlen: *std.posix.socklen_t) c_int;
extern "c" fn write(fd: c_int, buf: *const anyopaque, n: usize) isize;
extern "c" fn read(fd: c_int, buf: *anyopaque, n: usize) isize;
extern "c" fn malloc(size: usize) ?*anyopaque;
extern "c" fn free(ptr: *anyopaque) callconv(.C) void;
extern "c" fn memset(ptr: *anyopaque, value: c_int, size: usize) callconv(.C) void;
extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;
extern "c" fn getpid() c_int;

// BSD structures
const ctl_info = extern struct {
    ctl_id: u32,
    ctl_name: [96]u8,
};

const sockaddr_ctl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

const sockaddr = extern struct {
    sa_len: u8,
    sa_family: u8,
    sa_data: [14]u8,
};

const ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_ifru: extern union {
        addr: sockaddr,
        mtu: c_int,
        flags: c_short,
        ifindex: c_int,
    },
};

const sockaddr_in = extern struct {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: [4]u8,
    sin_zero: [8]u8,
};

const sockaddr_in6 = extern struct {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [16]u8,
    sin6_scope_id: u32,
};

// ==================== Device State ====================

/// Darwin device internal state
const DarwinDeviceState = struct {
    fd: std.posix.fd_t,
    name: []const u8,
    mtu: u16,
    index: u32,
    allocator: std.mem.Allocator,
};

// ==================== Device Implementation ====================

/// Create a new TUN device on Darwin/macOS/iOS
pub fn create(allocator: std.mem.Allocator, opts: Options) TunError!*TunDevice {
    const fd = std.posix.socket(PF_SYSTEM, std.posix.SOCK.DGRAM, SYSPROTO_CONTROL) catch {
        return error.IoError;
    };
    errdefer std.posix.close(fd);

    // Get control info for utun
    var info: ctl_info = undefined;
    @memset(@as([*]u8, @ptrCast(&info))[0..@sizeOf(ctl_info)], 0);
    const ctl_name = "com.apple.net.utun_control";
    @memcpy(info.ctl_name[0..ctl_name.len], ctl_name);

    const ioctl_result = ioctl(fd, CTLIOCGINFO, &info);
    if (ioctl_result < 0) {
        return error.IoError;
    }

    // Connect to utun
    var addr: sockaddr_ctl = undefined;
    @memset(@as([*]u8, @ptrCast(&addr))[0..@sizeOf(sockaddr_ctl)], 0);
    addr.sc_len = @sizeOf(sockaddr_ctl);
    addr.sc_family = 32;
    addr.ss_sysaddr = 2; // AF_SYS_CONTROL for utun
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;

    if (connect(fd, @as(*const anyopaque, @ptrCast(&addr)), @sizeOf(sockaddr_ctl)) < 0) {
        return error.IoError;
    }

    // Get device name
    var name_buf: [64]u8 = undefined;
    var name_len: std.posix.socklen_t = 64;
    const UTUN_OPT_IFNAME = 2;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, @as(*anyopaque, @ptrCast(&name_buf)), &name_len) < 0) {
        return error.IoError;
    }

    if (name_len >= name_buf.len) name_len = name_buf.len - 1;
    name_buf[name_len] = 0;

    const index = if_nametoindex(@as([*:0]const u8, @ptrCast(&name_buf)));
    const dev_name = std.mem.sliceTo(&name_buf, 0);

    // Allocate state
    const name_copy = allocator.dupe(u8, dev_name) catch {
        return error.OutOfMemory;
    };

    const state = allocator.create(DarwinDeviceState) catch {
        allocator.free(name_copy);
        return error.OutOfMemory;
    };

    state.* = .{
        .fd = fd,
        .name = name_copy,
        .mtu = opts.mtu orelse 1500,
        .index = index,
        .allocator = allocator,
    };

    // Configure addresses if provided
    if (opts.network) |net| {
        if (net.ipv4) |ipv4| {
            configureIpv4(fd, dev_name, ipv4.address, ipv4.prefix, state.mtu) catch {};
        }
        if (net.ipv6) |ipv6| {
            configureIpv6(fd, dev_name, ipv6.address, ipv6.prefix) catch {};
        }
    }

    // Bring interface up
    setInterfaceFlags(fd, dev_name, true) catch {};

    return createTunDevice(state);
}

/// Create a TUN device from an existing file descriptor
pub fn createFromFd(allocator: std.mem.Allocator, fd: std.posix.fd_t, name: []const u8, mtu: u16) TunError!*TunDevice {
    _ = name; // On Darwin, name is determined by the kernel

    const index = if_nametoindex("utun0");
    const name_copy = allocator.dupe(u8, "utun0") catch {
        return error.OutOfMemory;
    };

    const state = allocator.create(DarwinDeviceState) catch {
        allocator.free(name_copy);
        return error.OutOfMemory;
    };

    state.* = .{
        .fd = fd,
        .name = name_copy,
        .mtu = mtu,
        .index = index,
        .allocator = allocator,
    };

    return createTunDevice(state);
}

/// Create TunDevice interface from state
fn createTunDevice(state: *DarwinDeviceState) *TunDevice {
    const device = std.heap.c_allocator.create(TunDevice) catch unreachable;

    device.* = TunDevice{
        .ctx = state,
        .readFn = readFn,
        .writeFn = writeFn,
        .nameFn = nameFn,
        .mtuFn = mtuFn,
        .ifIndexFn = ifIndexFn,
        .fdFn = fdFn,
        .setNonBlockingFn = setNonBlockingFn,
        .closeFn = closeFn,
        .addRouteFn = addRouteFn,
        .deleteRouteFn = deleteRouteFn,
    };

    return device;
}

// ==================== Device Operations ====================

fn readFn(ctx: *anyopaque, buf: []u8) TunError!usize {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(ctx)));

    // Read with extra space for the 4-byte utun header
    const header_ptr = malloc(buf.len + 4) orelse return error.OutOfMemory;
    defer free(header_ptr);
    const header_buf = @as([*]u8, @ptrCast(header_ptr))[0..buf.len + 4];

    const n = read(state.fd, header_buf.ptr, buf.len + 4);
    if (n < 0) return error.IoError;
    if (n <= 4) return 0;

    // Strip the 4-byte utun header (first byte is address family)
    const bytes = @as(usize, @intCast(n));
    @memcpy(buf[0..bytes - 4], header_buf[4..bytes]);
    return bytes - 4;
}

fn writeFn(ctx: *anyopaque, buf: []const u8) TunError!usize {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(ctx)));

    // Allocate temp buffer for header + packet
    const packet_ptr = malloc(buf.len + 4) orelse return error.OutOfMemory;
    defer free(packet_ptr);
    const packet_buf = @as([*]u8, @ptrCast(packet_ptr))[0..buf.len + 4];

    // Add 4-byte utun header (AF_INET = 2 for IPv4)
    packet_buf[0] = 2;
    packet_buf[1] = 0;
    packet_buf[2] = 0;
    packet_buf[3] = 0;
    @memcpy(packet_buf[4..], buf);

    const n = write(state.fd, packet_buf.ptr, buf.len + 4);
    if (n < 0) return error.IoError;
    if (n <= 4) return 0;
    return @as(usize, @intCast(n - 4));
}

fn nameFn(ctx: *anyopaque) TunError![]const u8 {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(ctx)));
    return state.name;
}

fn mtuFn(ctx: *anyopaque) TunError!u16 {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(ctx)));
    return state.mtu;
}

fn ifIndexFn(ctx: *anyopaque) TunError!u32 {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(ctx)));
    return state.index;
}

fn fdFn(ctx: *anyopaque) std.posix.fd_t {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(ctx)));
    return state.fd;
}

fn setNonBlockingFn(ctx: *anyopaque, enabled: bool) TunError!void {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(ctx)));
    const flags = std.posix.fcntl(state.fd, std.posix.F.GETFL, 0) catch return error.IoError;
    const nonblock_flag = @as(@TypeOf(flags), O_NONBLOCK);
    const new_flags = if (enabled) flags | nonblock_flag else flags & ~nonblock_flag;
    _ = std.posix.fcntl(state.fd, std.posix.F.SETFL, new_flags) catch return error.IoError;
}

fn closeFn(ctx: *anyopaque) void {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(ctx)));
    std.posix.close(state.fd);
    state.allocator.free(state.name);
    state.allocator.destroy(state);
}

fn addRouteFn(ctx: *anyopaque, route: *const RouteEntry) TunError!void {
    _ = ctx;
    _ = route;
    // TODO: Implement BSD routing socket route addition
    return error.NotSupported;
}

fn deleteRouteFn(ctx: *anyopaque, route: *const RouteEntry) TunError!void {
    _ = ctx;
    _ = route;
    return error.NotSupported;
}

// ==================== Helper Functions ====================

fn configureIpv4(_: std.posix.fd_t, ifname: []const u8, address: Ipv4Address, prefix: u8, mtu: u16) TunError!void {
    const sock = std.posix.socket(AF_INET, std.posix.SOCK.DGRAM, 0) catch {
        return error.IoError;
    };
    defer std.posix.close(sock);

    var req: ifreq = undefined;
    @memset(@as([*]u8, @ptrCast(&req))[0..@sizeOf(ifreq)], 0);
    @memcpy(req.ifr_name[0..ifname.len], ifname);

    const addr = @as(*sockaddr_in, @alignCast(@ptrCast(&req.ifr_ifru.addr)));
    addr.sin_len = @sizeOf(sockaddr_in);
    addr.sin_family = AF_INET;
    @memset(addr.sin_zero[0..], 0);

    // SIOCSIFADDR
    addr.sin_addr = address;
    const SIOCSIFADDR: c_ulong = 0x8020690c;
    _ = ioctl(sock, SIOCSIFADDR, &req);

    // SIOCSIFDSTADDR (peer)
    const peer_addr = [4]u8{ address[0], address[1], address[2], address[3] + 1 };
    addr.sin_addr = peer_addr;
    const SIOCSIFDSTADDR: c_ulong = 0x8020690e;
    _ = ioctl(sock, SIOCSIFDSTADDR, &req);

    // SIOCSIFNETMASK
    const shift: u5 = @truncate(32 - prefix);
    const mask: u32 = if (prefix == 32) 0xFFFFFFFF else (~@as(u32, 0) << shift);
    const mask_be = @byteSwap(mask);
    @memcpy(addr.sin_addr[0..4], @as(*const [4]u8, @ptrCast(&mask_be))[0..4]);
    const SIOCSIFNETMASK: c_ulong = 0x80206916;
    _ = ioctl(sock, SIOCSIFNETMASK, &req);

    _ = mtu;
}

fn configureIpv6(_: std.posix.fd_t, ifname: []const u8, address: Ipv6Address, _: u32) TunError!void {
    const sock = std.posix.socket(AF_INET6, std.posix.SOCK.DGRAM, 0) catch {
        return error.IoError;
    };
    defer std.posix.close(sock);

    var req: ifreq = undefined;
    @memset(@as([*]u8, @ptrCast(&req))[0..@sizeOf(ifreq)], 0);
    @memcpy(req.ifr_name[0..ifname.len], ifname);

    const addr = @as(*sockaddr_in6, @alignCast(@ptrCast(&req.ifr_ifru.addr)));
    addr.sin6_len = @sizeOf(sockaddr_in6);
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = address;

    const SIOCSIFADDR: c_ulong = 0x8020690c;
    if (ioctl(sock, SIOCSIFADDR, &req) < 0) {
        return error.IoError;
    }
}

fn setInterfaceFlags(_: std.posix.fd_t, ifname: []const u8, up: bool) TunError!void {
    const sock = std.posix.socket(AF_INET, std.posix.SOCK.DGRAM, 0) catch {
        return error.IoError;
    };
    defer std.posix.close(sock);

    var req: ifreq = undefined;
    @memset(@as([*]u8, @ptrCast(&req))[0..@sizeOf(ifreq)], 0);
    @memcpy(req.ifr_name[0..ifname.len], ifname);

    const SIOCGIFFLAGS: c_ulong = 0xc0206911;
    if (ioctl(sock, SIOCGIFFLAGS, &req) < 0) {
        return error.IoError;
    }

    if (up) {
        req.ifr_ifru.flags |= @as(c_short, @intCast(IFF_UP | IFF_RUNNING));
    } else {
        req.ifr_ifru.flags &= ~@as(c_short, @intCast(IFF_UP));
    }

    const SIOCSIFFLAGS: c_ulong = 0x80206910;
    if (ioctl(sock, SIOCSIFFLAGS, &req) < 0) {
        return error.IoError;
    }
}

// ==================== Legacy API wrappers for Device interface ====================

/// Create a TUN device (legacy API for Device struct)
pub fn createLegacy(config: Options) TunError!*DeviceContext {
    const device = create(std.heap.c_allocator, config) catch {
        return error.IoError;
    };

    // Allocate DeviceContext
    const ctx = malloc(@sizeOf(DeviceContext));
    if (@intFromPtr(ctx) == 0) {
        // On error, cleanup device
        device.close();
        return error.IoError;
    }

    // Initialize context with device state
    const c = @as(*DeviceContext, @alignCast(@ptrCast(ctx)));
    c.* = .{ .ptr = device.ctx };

    // Note: device is leaked here, but its memory is managed through ctx
    // The caller must use destroy() to cleanup

    return c;
}

/// Receive a packet from the TUN device
pub fn recv(device_ptr: *anyopaque, buf: []u8) TunError!usize {
    return readFn(device_ptr, buf);
}

/// Send a packet to the TUN device
pub fn send(device_ptr: *anyopaque, buf: []const u8) TunError!usize {
    return writeFn(device_ptr, buf);
}

/// Get the device name
pub fn getName(device_ptr: *anyopaque) TunError![]const u8 {
    return nameFn(device_ptr);
}

/// Get the device MTU
pub fn getMtu(device_ptr: *anyopaque) TunError!u16 {
    return mtuFn(device_ptr);
}

/// Get the interface index
pub fn getIfIndex(device_ptr: *anyopaque) TunError!u32 {
    return ifIndexFn(device_ptr);
}

/// Set non-blocking mode
pub fn setNonBlocking(device_ptr: *anyopaque, enabled: bool) TunError!void {
    return setNonBlockingFn(device_ptr, enabled);
}

/// Add an IPv4 address at runtime
pub fn addIpv4(device_ptr: *anyopaque, address: Ipv4Address, prefix: u8) TunError!void {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(device_ptr)));
    return configureIpv4(state.fd, state.name, address, prefix, state.mtu);
}

/// Add an IPv6 address at runtime
pub fn addIpv6(device_ptr: *anyopaque, address: Ipv6Address, prefix: u8) TunError!void {
    const state = @as(*DarwinDeviceState, @ptrCast(@alignCast(device_ptr)));
    return configureIpv6(state.fd, state.name, address, prefix);
}

/// Add an IPv4 route (legacy API)
pub fn addRoute(device_ptr: *anyopaque, destination: Ipv4Address, gateway: Ipv4Address, prefix_len: u8) TunError!void {
    _ = device_ptr;
    _ = destination;
    _ = gateway;
    _ = prefix_len;
    // Routes are handled by the caller via sysroute
    return error.NotSupported;
}

/// Get the file descriptor
pub fn getFd(device_ptr: *anyopaque) std.posix.fd_t {
    return fdFn(device_ptr);
}

/// Destroy the device and clean up resources
pub fn destroy(device_ptr: *anyopaque) void {
    closeFn(device_ptr);
}
