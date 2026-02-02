//! device_macos.zig - macOS TUN device implementation
//!
//! Uses utun sockets for TUN device operations on macOS.
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

/// Opaque macOS device handle
pub const MacOSDevice = opaque {};

/// macOS device internal state
const MacOSDeviceState = struct {
    fd: std.posix.fd_t,
    name: []const u8,
    mtu: u16,
    index: u32,
    ringbuf: RingBuffer,
    read_offset: usize,
};

/// Tunnel flags for utun
const IFF_TUN = 0x0001;
const IFF_NO_PI = 0x1000;
const IFF_UP = 0x0001;
const IFF_RUNNING = 0x0040;

/// Address family constants (BSD values)
const AF_INET = 2;   // IPv4
const AF_INET6 = 30; // IPv6
const SOCK_DGRAM = 2; // Datagram socket
const PF_SYSTEM = 32; // System domain
const SYSPROTO_CONTROL = 2; // Control protocol
const CTLIOCGINFO = 0xc0644e03; // Get control info ioctl

// ==================== FFI Declarations ====================

extern "c" fn socket(domain: c_int, type: c_int, protocol: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: std.posix.socklen_t) c_int;
extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
extern "c" fn getsockopt(fd: c_int, level: c_int, optname: c_int, optval: *anyopaque, optlen: *std.posix.socklen_t) c_int;
extern "c" fn malloc(size: usize) *anyopaque;
extern "c" fn free(ptr: *anyopaque) callconv(.C) void;
extern "c" fn memset(ptr: *anyopaque, value: c_int, size: usize) callconv(.C) void;
extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;

/// struct ctl_info for CTLIOCGINFO
const ctl_info = extern struct {
    ctl_id: u32,
    ctl_name: [96]u8,
};

/// sockaddr_ctl for macOS control sockets
const sockaddr_ctl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

/// ifaliasreq for adding IP addresses on macOS
const ifaliasreq = extern struct {
    ifra_name: [16]u8,
    ifra_addr: sockaddr_in,
    ifra_broadaddr: sockaddr_in,
    ifra_mask: sockaddr_in,
};

/// struct ifreq for ioctl operations
const ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_ifru: extern union {
        addr: [128]u8,
        mtu: c_int,
        flags: c_short,
        ifindex: c_int,
    },
};

/// struct sockaddr_in for IPv4 (macOS has sin_len)
const sockaddr_in = extern struct {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: [4]u8,
    sin_zero: [8]u8,
};

/// struct sockaddr_in6 for IPv6 (macOS has sin6_len)
const sockaddr_in6 = extern struct {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [16]u8,
    sin6_scope_id: u32,
};

// ==================== Device Creation ====================

/// Create a new TUN device on macOS
pub fn create(config: DeviceConfig) TunError!*DeviceContext {
    // On macOS, utun is accessed via a PF_SYSTEM socket with SYSPROTO_CONTROL
    // Create a control socket for utun
    std.debug.print("[ztun] Creating socket(PF_SYSTEM={d}, SOCK_DGRAM={d}, SYSPROTO_CONTROL={d})...\n", .{PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL});
    const fd = std.posix.socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) catch {
        return error.IoError;
    };
    errdefer std.posix.close(fd);

    // Get control info for utun (key: "com.apple.net.utun_control")
    var info: ctl_info = undefined;
    @memset(@as([*]u8, @ptrCast(&info))[0..@sizeOf(ctl_info)], 0);
    const ctl_name = "com.apple.net.utun_control";
    @memcpy(info.ctl_name[0..ctl_name.len], ctl_name);

    const ioctl_result = ioctl(fd, CTLIOCGINFO, &info);
    if (ioctl_result < 0) {
        return error.IoError;
    }

    // Prepare sockaddr_ctl to connect to utun
    var addr: sockaddr_ctl = undefined;
    @memset(@as([*]u8, @ptrCast(&addr))[0..@sizeOf(sockaddr_ctl)], 0);
    addr.sc_len = @sizeOf(sockaddr_ctl);
    addr.sc_family = 32; // AF_SYSTEM
    addr.ss_sysaddr = 2; // AF_SYS_CONTROL for utun
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0; // 0 = auto-assign unit number

    if (connect(fd, @as(*const anyopaque, @ptrCast(&addr)), @sizeOf(sockaddr_ctl)) < 0) {
        return error.IoError;
    }

    // Get the assigned device name via getsockopt
    var name_buf: [64]u8 = undefined;
    var name_len: std.posix.socklen_t = 64;
    const UTUN_OPT_IFNAME = 2;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, @as(*anyopaque, @ptrCast(&name_buf)), &name_len) < 0) {
        return error.IoError;
    }

    // Ensure null termination for if_nametoindex
    if (name_len >= name_buf.len) name_len = name_buf.len - 1;
    name_buf[name_len] = 0;

    // Get interface index using the properly null-terminated name
    const index = if_nametoindex(@as([*:0]const u8, @ptrCast(&name_buf)));

    // Get the device name as a slice (for state)
    const dev_name = std.mem.sliceTo(&name_buf, 0);

    // Get MTU from config or use default
    const mtu = config.mtu orelse 1500;

    // Configure IPv4 address if provided
    if (config.ipv4) |ipv4| {
        if (configureIpv4(fd, dev_name, ipv4.address, ipv4.prefix, mtu)) |_| {
            // Success, continue
        } else |_| {
            // Configuration failed, but continue anyway
        }
    }

    // Configure IPv6 address if provided
    if (config.ipv6) |ipv6| {
        const prefix = config.ipv6_prefix orelse 64;
        if (configureIpv6(fd, dev_name, ipv6, prefix)) |_| {
            // Success, continue
        } else |_| {
            // Configuration failed, but continue anyway
        }
    }

    // Bring interface up
    if (setInterfaceFlags(fd, dev_name, true)) |_| {
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
    const state = malloc(@sizeOf(MacOSDeviceState));
    if (@intFromPtr(state) == 0) {
        free(ctx);
        return error.IoError;
    }

    // Copy name to heap
    const name_strlen = dev_name.len;
    const name_copy = @as([*]u8, @ptrCast(malloc(name_strlen + 1)));
    if (@intFromPtr(name_copy) == 0) {
        free(state);
        free(ctx);
        return error.IoError;
    }

    @memcpy(name_copy[0..name_strlen], dev_name);
    name_copy[name_strlen] = 0;

    // Initialize RingBuffer (large buffer for batch packet handling)
    const ringbuf_capacity = @as(usize, mtu) * 256; // 256 packets worth of buffer
    const ringbuf = RingBuffer.init(ringbuf_capacity) catch RingBuffer{
        .ptr = undefined,
        .capacity = 0,
        .owned = false,
    };

    // Initialize state
    const s = @as(*MacOSDeviceState, @alignCast(@ptrCast(state)));
    s.* = .{
        .fd = fd,
        .name = name_copy[0..name_strlen],
        .mtu = mtu,
        .index = index,
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
inline fn toState(device_ptr: *anyopaque) *MacOSDeviceState {
    return @as(*MacOSDeviceState, @alignCast(@ptrCast(device_ptr)));
}

/// Configure IPv4 address using ioctl (macOS)
/// Uses ifreq structure with SIOCSIFADDR/SIOCSIFDSTADDR like xtun does
fn configureIpv4(_: std.posix.fd_t, actual_ifname: []const u8, address: Ipv4Address, prefix: u8, mtu: u16) TunError!void {
    const sock = std.posix.socket(AF_INET, SOCK_DGRAM, 0) catch {
        return error.IoError;
    };
    defer std.posix.close(sock);

    // Use ifreq structure like xtun does (not ifaliasreq)
    var req: ifreq = undefined;
    @memset(@as([*]u8, @ptrCast(&req))[0..@sizeOf(ifreq)], 0);
    @memcpy(req.ifr_name[0..actual_ifname.len], actual_ifname);

    // Cast to sockaddr_in* for setting address fields
    const addr = @as(*sockaddr_in, @alignCast(@ptrCast(&req.ifr_ifru.addr)));
    addr.sin_len = @sizeOf(sockaddr_in);
    addr.sin_family = AF_INET;
    @memset(addr.sin_zero[0..], 0);

    // SIOCSIFADDR: set interface address (0x8020690c)
    addr.sin_addr = address;
    const SIOCSIFADDR: c_ulong = 0x8020690c;
    if (ioctl(sock, SIOCSIFADDR, &req) < 0) {
        std.debug.print("[ztun] SIOCSIFADDR failed for utun\n", .{});
    } else {
        std.debug.print("[ztun] SIOCSIFADDR succeeded\n", .{});
    }

    // SIOCSIFDSTADDR: set destination address (0x8020690e)
    // Only update sin_addr, keep other fields intact like xtun does
    var peer_addr = address;
    peer_addr[3] +|= 1;
    addr.sin_addr = peer_addr;
    const SIOCSIFDSTADDR: c_ulong = 0x8020690e;
    if (ioctl(sock, SIOCSIFDSTADDR, &req) < 0) {
        std.debug.print("[ztun] SIOCSIFDSTADDR failed for utun\n", .{});
    } else {
        std.debug.print("[ztun] SIOCSIFDSTADDR succeeded\n", .{});
    }

    // SIOCSIFNETMASK: set netmask (0x80206916)
    // Only update sin_addr, keep other fields intact like xtun does
    const shift: u5 = @truncate(32 - prefix);
    const mask: u32 = if (prefix == 32) 0xFFFFFFFF else (~@as(u32, 0) << shift);
    @memcpy(addr.sin_addr[0..4], @as(*const [4]u8, @ptrCast(&mask))[0..4]);

    const SIOCSIFNETMASK: c_ulong = 0x80206916;
    if (ioctl(sock, SIOCSIFNETMASK, &req) < 0) {
        std.debug.print("[ztun] SIOCSIFNETMASK failed for utun\n", .{});
    } else {
        std.debug.print("[ztun] SIOCSIFNETMASK succeeded\n", .{});
    }

    // Set MTU using ifreq
    var mtu_req: ifreq = undefined;
    @memset(@as([*]u8, @ptrCast(&mtu_req))[0..@sizeOf(ifreq)], 0);
    @memcpy(mtu_req.ifr_name[0..actual_ifname.len], actual_ifname);
    mtu_req.ifr_ifru.mtu = @as(c_int, @intCast(mtu));

    const SIOCSIFMTU: c_ulong = 0x80206934;
    _ = ioctl(sock, SIOCSIFMTU, &mtu_req);  // May fail for utun on macOS
}

/// Configure IPv6 address using ioctl (macOS)
fn configureIpv6(_: std.posix.fd_t, ifname: []const u8, address: Ipv6Address, _: u32) TunError!void {
    const sock = std.posix.socket(AF_INET6, SOCK_DGRAM, 0) catch {
        return error.IoError;
    };
    defer std.posix.close(sock);

    var req: ifreq = undefined;
    @memset(@as([*]u8, @ptrCast(&req))[0..@sizeOf(ifreq)], 0);
    @memcpy(req.ifr_name[0..ifname.len], ifname);

    // Set IPv6 address
    const addr = @as(*sockaddr_in6, @alignCast(@ptrCast(&req.ifr_ifru.addr)));
    addr.sin6_len = @sizeOf(sockaddr_in6);
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = address;

    const SIOCSIFADDR: c_ulong = 0x8020690c;
    if (ioctl(sock, SIOCSIFADDR, &req) < 0) {
        return error.IoError;
    }
}

/// Set interface flags (up/down)
fn setInterfaceFlags(_: std.posix.fd_t, ifname: []const u8, up: bool) TunError!void {
    const sock = std.posix.socket(AF_INET, SOCK_DGRAM, 0) catch {
        return error.IoError;
    };
    defer std.posix.close(sock);

    var req: ifreq = undefined;
    @memset(@as([*]u8, @ptrCast(&req))[0..@sizeOf(ifreq)], 0);
    @memcpy(req.ifr_name[0..ifname.len], ifname);

    // Get current flags
    const SIOCGIFFLAGS: c_ulong = 0xc0206911;
    if (ioctl(sock, SIOCGIFFLAGS, &req) < 0) {
        return error.IoError;
    }

    // Set new flags
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

// ==================== Device Operations ====================

/// Receive a packet from the TUN device
/// Note: macOS utun includes a 4-byte header (family + padding) that we strip
pub fn recv(device_ptr: *anyopaque, buf: []u8) TunError!usize {
    const state = toState(device_ptr);

    // Read with extra space for the 4-byte utun header
    const header_buf = @as([*]u8, @ptrCast(malloc(buf.len + 4)));
    if (@intFromPtr(header_buf) == 0) {
        return error.IoError;
    }
    defer free(header_buf);

    const n = std.posix.read(state.fd, header_buf[0..buf.len + 4]) catch {
        return error.IoError;
    };
    if (n <= 4) return 0;

    // Strip the 4-byte utun header (first byte is address family)
    @memcpy(buf[0..@as(usize, @intCast(n - 4))], header_buf[4..n]);
    return @as(usize, @intCast(n - 4));
}

/// Send a packet to the TUN device
/// Note: macOS utun requires a 4-byte header (family + padding) before the packet
pub fn send(device_ptr: *anyopaque, buf: []const u8) TunError!usize {
    const state = toState(device_ptr);

    // Allocate temp buffer for header + packet
    const packet_buf = @as([*]u8, @ptrCast(malloc(buf.len + 4)));
    if (@intFromPtr(packet_buf) == 0) {
        return error.IoError;
    }
    defer free(packet_buf);

    // Add 4-byte utun header (AF_INET = 2 for IPv4)
    packet_buf[0] = 2;  // Address family: AF_INET
    packet_buf[1] = 0;
    packet_buf[2] = 0;
    packet_buf[3] = 0;
    @memcpy(packet_buf[4..buf.len + 4], buf);

    const n = std.posix.write(state.fd, packet_buf[0..buf.len + 4]) catch {
        return error.IoError;
    };
    // Return bytes written minus the header
    if (n <= 4) return 0;
    return @as(usize, @intCast(n - 4));
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
    return state.index;
}

/// Set non-blocking mode
pub fn setNonBlocking(device_ptr: *anyopaque, nonblocking: bool) TunError!void {
    const state = toState(device_ptr);
    const flags = std.posix.fcntl(state.fd, std.posix.F.GETFL, 0) catch return error.IoError;
    const new_flags = if (nonblocking) flags | std.posix.O.NONBLOCK else flags & ~std.posix.O.NONBLOCK;
    std.posix.fcntl(state.fd, std.posix.F.SETFL, new_flags) catch return error.IoError;
}

/// Add an IPv4 address at runtime
pub fn addIpv4(device_ptr: *anyopaque, address: Ipv4Address, prefix: u8) TunError!void {
    const state = toState(device_ptr);
    try configureIpv4(state.fd, state.name, address, prefix, state.mtu);
    // Bring interface up
    setInterfaceFlags(state.fd, state.name, true) catch {};
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
