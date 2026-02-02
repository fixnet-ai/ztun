//! device_linux.zig - Linux TUN device implementation
//!
//! Uses /dev/net/tun for TUN device operations with ioctl for IP configuration.
//! Uses RingBuffer internally for efficient batch packet handling.

const std = @import("std");
const builtin = @import("builtin");
const TunError = @import("device.zig").TunError;
const DeviceConfig = @import("device.zig").DeviceConfig;
const Ipv4Address = @import("device.zig").Ipv4Address;
const Ipv6Address = @import("device.zig").Ipv6Address;
const DeviceContext = @import("device.zig").DeviceContext;
const RingBuffer = @import("ringbuf.zig").RingBuffer;

// ==================== Type Definitions ====================

/// Opaque Linux device handle
pub const LinuxDevice = opaque {};

/// Linux device internal state
const LinuxDeviceState = struct {
    fd: std.posix.fd_t,
    name: []const u8,
    mtu: u16,
    ringbuf: RingBuffer,
    read_offset: usize,
};

/// Tunnel flags for /dev/net/tun
const IFF_TUN = 0x0001;
const IFF_NO_PI = 0x1000;
const IFF_UP = 0x0001;
const IFF_RUNNING = 0x0040;

/// Address family constants (Linux values)
const AF_INET = 2;   // IPv4
const AF_INET6 = 10; // IPv6
const SOCK_DGRAM = 2; // Datagram socket

// ==================== FFI Declarations ====================

/// struct ifreq for ioctl operations
pub const ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_ifru: extern union {
        addr: [128]u8,
        mtu: c_int,
        flags: c_short,
        ifindex: c_int,
    },
};

/// struct sockaddr_in for IPv4
const sockaddr_in = extern struct {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: [4]u8,
    sin_zero: [8]u8,
};

/// struct in6_ifreq for IPv6 address configuration
const in6_ifreq = extern struct {
    ifr6_addr: [16]u8,
    ifr6_prefixlen: u32,
    ifr6_ifindex: c_int,
    ifr6_name: [16]u8,
};

extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int) c_int;
extern "c" fn malloc(size: usize) *anyopaque;
extern "c" fn free(ptr: *anyopaque) callconv(.C) void;
extern "c" fn memset(ptr: *anyopaque, value: c_int, size: usize) callconv(.C) void;
extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;

// O flags from fcntl.h
const O_RDWR = 2;
const O_NONBLOCK = 2048;
const TUNSETIFF = 0x400454ca;

// ==================== Device Creation ====================

/// Create a new TUN device on Linux
pub fn create(config: DeviceConfig) TunError!*DeviceContext {
    // Open /dev/net/tun using C open() for cross-compilation compatibility
    // Use blocking mode by default (can be changed with setNonBlocking)
    const tun_fd = open(@as([*:0]const u8, @ptrCast("/dev/net/tun")), O_RDWR);
    if (tun_fd < 0) {
        return error.IoError;
    }
    errdefer std.posix.close(tun_fd);

    // Prepare ifreq structure
    var req: ifreq = undefined;
    memset(&req, 0, @sizeOf(ifreq));

    // Set device name if provided
    const name_ptr = if (config.name) |name| name else "tun%d";
    const name_len = @min(name_ptr.len, 15);
    @memcpy(req.ifr_name[0..name_len], name_ptr[0..name_len]);

    // Set TUN flags (IFF_TUN | IFF_NO_PI for pure IP packets)
    req.ifr_ifru.flags = @as(c_short, @intCast(IFF_TUN | IFF_NO_PI));

    // Configure TUN device
    const result = ioctl(tun_fd, TUNSETIFF, &req);
    if (result < 0) {
        return error.IoError;
    }

    // Extract device name
    const dev_name = std.mem.sliceTo(&req.ifr_name, 0);

    // Get MTU from config or use default
    const mtu = config.mtu orelse 1500;

    // Configure IPv4 address if provided
    if (config.ipv4) |ipv4| {
        if (configureIpv4(tun_fd, dev_name, ipv4.address, ipv4.prefix, mtu)) |_| {
            // Success, continue
        } else |_| {
            // Configuration failed, but continue anyway
        }
    }

    // Configure IPv6 address if provided
    if (config.ipv6) |ipv6| {
        const prefix = config.ipv6_prefix orelse 64;
        if (configureIpv6(tun_fd, dev_name, ipv6, prefix)) |_| {
            // Success, continue
        } else |_| {
            // Configuration failed, but continue anyway
        }
    }

    // Bring interface up
    if (setInterfaceFlags(tun_fd, dev_name, true, false)) |_| {
        // Interface up
    } else |_| {
        // Failed to bring up, but continue
    }

    // Allocate context
    const ctx = malloc(@sizeOf(DeviceContext));
    if (@intFromPtr(ctx) == 0) {
        return error.IoError;
    }

    // Allocate state
    const state = malloc(@sizeOf(LinuxDeviceState));
    if (@intFromPtr(state) == 0) {
        free(ctx);
        return error.IoError;
    }

    // Copy name to heap
    const name_copy = malloc(dev_name.len + 1);
    if (@intFromPtr(name_copy) == 0) {
        free(state);
        free(ctx);
        return error.IoError;
    }
    @memcpy(@as([*]u8, @ptrCast(name_copy))[0..dev_name.len], dev_name);
    @as([*]u8, @ptrCast(name_copy))[dev_name.len] = 0;

    // Initialize RingBuffer (large buffer for batch packet handling)
    const ringbuf_capacity = @as(usize, mtu) * 256; // 256 packets worth of buffer
    const ringbuf = RingBuffer.init(ringbuf_capacity) catch RingBuffer{
        .ptr = undefined,
        .capacity = 0,
        .owned = false,
    };

    // Initialize state
    const s = @as(*LinuxDeviceState, @alignCast(@ptrCast(state)));
    s.* = .{
        .fd = tun_fd,
        .name = @as([*]u8, @ptrCast(name_copy))[0..dev_name.len],
        .mtu = mtu,
        .ringbuf = ringbuf,
        .read_offset = 0,
    };

    // Initialize context
    const c = @as(*DeviceContext, @alignCast(@ptrCast(ctx)));
    c.* = .{ .ptr = state };

    return c;
}

// ==================== Helper Functions ====================

/// Helper to cast device pointer to state
inline fn toState(device_ptr: *anyopaque) *LinuxDeviceState {
    return @as(*LinuxDeviceState, @alignCast(@ptrCast(device_ptr)));
}

/// Convert IPv4 address to bytes
fn ipv4ToBytes(address: Ipv4Address) [4]u8 {
    return address;
}

/// Configure IPv4 address using ioctl
fn configureIpv4(_: std.posix.fd_t, ifname: []const u8, address: Ipv4Address, prefix: u8, mtu: u16) TunError!void {
    const sock = std.posix.socket(AF_INET, SOCK_DGRAM, 0) catch {
        return error.IoError;
    };
    defer std.posix.close(sock);

    var req: ifreq = undefined;
    memset(&req, 0, @sizeOf(ifreq));
    @memcpy(req.ifr_name[0..ifname.len], ifname);

    // Set IP address using SIOCSIFADDR
    const addr = @as(*sockaddr_in, @alignCast(@ptrCast(&req.ifr_ifru.addr)));
    addr.sin_family = AF_INET;
    const ip_bytes = ipv4ToBytes(address);
    addr.sin_addr = ip_bytes;

    const SIOCSIFADDR = 0x8916;
    if (ioctl(sock, SIOCSIFADDR, &req) < 0) {
        return error.IoError;
    }

    // Set netmask based on prefix
    const shift: u5 = @truncate(32 - prefix);
    const mask: u32 = if (prefix == 32) 0xFFFFFFFF else (~@as(u32, 0) << shift);
    addr.sin_addr = @as(*[4]u8, @ptrCast(@constCast(&mask))).*;

    const SIOCSIFNETMASK = 0x891c;
    if (ioctl(sock, SIOCSIFNETMASK, &req) < 0) {
        return error.IoError;
    }

    // Set MTU
    req.ifr_ifru.mtu = @as(c_int, @intCast(mtu));
    const SIOCSIFMTU = 0x8922;
    if (ioctl(sock, SIOCSIFMTU, &req) < 0) {
        return error.IoError;
    }
}

/// Configure IPv6 address using ioctl
fn configureIpv6(fd: std.posix.fd_t, ifname: []const u8, address: Ipv6Address, prefix: u32) TunError!void {
    _ = fd;

    const sock = std.posix.socket(AF_INET6, SOCK_DGRAM, 0) catch {
        return error.IoError;
    };
    defer std.posix.close(sock);

    // Get interface index
    const ifindex = if_nametoindex(@as([*:0]const u8, @ptrCast(ifname.ptr)));
    if (ifindex == 0) {
        return error.NotFound;
    }

    var req: in6_ifreq = undefined;
    memset(&req, 0, @sizeOf(in6_ifreq));
    @memcpy(req.ifr6_name[0..ifname.len], ifname);
    req.ifr6_ifindex = @as(c_int, @intCast(ifindex));
    req.ifr6_prefixlen = prefix;
    req.ifr6_addr = address;

    const SIOCSIFADDR = 0x892b;
    if (ioctl(sock, SIOCSIFADDR, &req) < 0) {
        return error.IoError;
    }
}

/// Set interface flags (up/down)
fn setInterfaceFlags(_: std.posix.fd_t, ifname: []const u8, up: bool, _: bool) TunError!void {
    const sock = std.posix.socket(AF_INET, SOCK_DGRAM, 0) catch {
        return error.IoError;
    };
    defer std.posix.close(sock);

    var req: ifreq = undefined;
    memset(&req, 0, @sizeOf(ifreq));
    @memcpy(req.ifr_name[0..ifname.len], ifname);

    // Get current flags
    const SIOCGIFFLAGS = 0x8913;
    if (ioctl(sock, SIOCGIFFLAGS, &req) < 0) {
        return error.IoError;
    }

    // Set new flags
    if (up) {
        req.ifr_ifru.flags |= @as(c_short, @intCast(IFF_UP | IFF_RUNNING));
    } else {
        req.ifr_ifru.flags &= ~@as(c_short, @intCast(IFF_UP));
    }

    const SIOCSIFFLAGS = 0x8914;
    if (ioctl(sock, SIOCSIFFLAGS, &req) < 0) {
        return error.IoError;
    }
}

// ==================== Device Operations ====================

/// Receive a packet from the TUN device
pub fn recv(device_ptr: *anyopaque, buf: []u8) TunError!usize {
    const state = toState(device_ptr);
    const n = std.posix.read(state.fd, buf) catch {
        return error.IoError;
    };
    return @as(usize, @intCast(n));
}

/// Send a packet to the TUN device
pub fn send(device_ptr: *anyopaque, buf: []const u8) TunError!usize {
    const state = toState(device_ptr);
    const n = std.posix.write(state.fd, buf) catch {
        return error.IoError;
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
    return state.mtu;
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
pub fn addIpv4(device_ptr: *anyopaque, address: Ipv4Address, prefix: u8) TunError!void {
    const state = toState(device_ptr);
    try configureIpv4(state.fd, state.name, address, prefix, state.mtu);
    // Bring interface up
    setInterfaceFlags(state.fd, state.name, true, false) catch {};
}

/// Add an IPv6 address at runtime
pub fn addIpv6(device_ptr: *anyopaque, address: Ipv6Address, prefix: u8) TunError!void {
    const state = toState(device_ptr);
    try configureIpv6(state.fd, state.name, address, prefix);
}

/// Destroy the device and clean up resources
pub fn destroy(device_ptr: *anyopaque) void {
    const state = toState(device_ptr);
    std.posix.close(state.fd);
    state.ringbuf.deinit();
    free(@constCast(state.name.ptr));
    free(state);
}
