//! monitor_darwin.zig - macOS network change monitoring via BSD Routing Socket

const std = @import("std");
const builtin = @import("builtin");

// BSD Routing Socket constants
const AF_ROUTE = 32;
const SOCK_RAW = 3;
const RTM_VERSION = 5;
const RTM_ADD = 0x1;
const RTM_DELETE = 0x2;
const RTM_CHANGE = 0x3;
const RTM_GET = 0x4;
const RTM_LOSING = 0x5;
const RTM_IFINFO = 0x6;
const RTM_NEWMADDR = 0x7;
const RTM_DELMADDR = 0x8;
const RTM_OIFINFO = 0xd;
const RTM_IFINFO2 = 0xa;
const RTM_NEWADDR = 0xb;
const RTM_DELADDR = 0xc;

// fcntl constants
const F_GETFL = 3;
const F_SETFL = 4;
const O_NONBLOCK = 0x10;

// BSD Routing Socket message header
const rt_msghdr = extern struct {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: i32,
    rtm_addrs: i32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    rtm_use: i32,
    rtm_inits: i32,
    rtm_rmx: rtmetrics,
};

const rtmetrics = extern struct {
    rmx_locks: u32,
    rmx_mtu: u32,
    rmx_hopcount: i32,
    rmx_expire: i32,
    rmx_recvpipe: i32,
    rmx_sendpipe: i32,
    rmx_ssthresh: i32,
    rmx_rtt: i32,
    rmx_rttvar: i32,
    rmx_pksent: i32,
    rmx_filler: [4]i32,
};

/// Network change types
pub const NetworkChange = enum {
    interface_up,
    interface_down,
    address_added,
    address_removed,
    route_changed,
    network_losing,
};

/// Network change event
pub const NetworkEvent = struct {
    change: NetworkChange,
    interface_name: []const u8,
    interface_index: u32,
    timestamp: i64,
};

/// Observer callback type
pub const ObserverCallback = *const fn (event: *const NetworkEvent, userdata: ?*anyopaque) void;

const MAX_OBSERVERS: usize = 16;

const Observer = struct {
    callback: ObserverCallback,
    userdata: ?*anyopaque,
    active: bool,
};

/// Network monitor interface (darwin-specific implementation)
pub const NetworkMonitor = struct {
    observers: [MAX_OBSERVERS]Observer = undefined,
    observer_count: usize = 0,
    allocator: std.mem.Allocator,
    handle: *DarwinHandle,

    pub fn register(m: *NetworkMonitor, callback: ObserverCallback, userdata: ?*anyopaque) !void {
        if (m.observer_count >= MAX_OBSERVERS) return error.TooManyObservers;
        for (m.observers[0..m.observer_count]) |*obs| {
            if (obs.callback == callback) return error.AlreadyRegistered;
        }
        m.observers[m.observer_count] = .{
            .callback = callback,
            .userdata = userdata,
            .active = true,
        };
        m.observer_count += 1;
    }

    pub fn unregister(m: *NetworkMonitor, callback: ObserverCallback) void {
        for (m.observers[0..m.observer_count], 0..) |*obs, i| {
            if (obs.callback == callback) {
                obs.active = false;
                m.observers[i] = m.observers[m.observer_count - 1];
                m.observer_count -= 1;
                return;
            }
        }
    }

    pub fn notify(m: *NetworkMonitor, event: *const NetworkEvent) void {
        for (m.observers[0..m.observer_count]) |*obs| {
            if (obs.active) obs.callback(event, obs.userdata);
        }
    }
};

pub const DarwinHandle = struct {
    sock: i32,
    completion: *anyopaque,
    buffer: [4096]u8,
    monitor_ptr: *NetworkMonitor,
    callback: *const fn (userdata: ?*anyopaque, _: *anyopaque, _: *anyopaque, result: usize) void,
};

fn parseRtmMessage(buf: []const u8, event: *NetworkEvent) void {
    if (buf.len < @sizeOf(rt_msghdr)) return;
    const msg = @as(*const rt_msghdr, @ptrCast(@alignCast(buf.ptr)));
    event.timestamp = std.time.milliTimestamp();
    event.interface_index = msg.rtm_index;
    event.change = switch (msg.rtm_type) {
        RTM_IFINFO, RTM_IFINFO2 => .interface_up,
        RTM_NEWADDR => .address_added,
        RTM_DELADDR => .address_removed,
        RTM_LOSING => .network_losing,
        else => .route_changed,
    };
    event.interface_name = &[_]u8{};
}

fn darwinOnRoutingReadable(
    userdata: ?*anyopaque,
    _: *anyopaque,
    _: *anyopaque,
    result: usize,
) void {
    const dh = @as(*DarwinHandle, @ptrCast(@alignCast(userdata orelse return)));
    const mon = dh.monitor_ptr;
    const n = result;

    if (n == 0) return;

    var event: NetworkEvent = undefined;
    parseRtmMessage(dh.buffer[0..n], &event);
    mon.notify(&event);
}

fn darwinStart(dh: *DarwinHandle) !void {
    dh.sock = std.posix.socket(AF_ROUTE, SOCK_RAW, 0) catch |err| {
        std.debug.print("[MONITOR-DARWIN] Socket creation failed: {}\n", .{err});
        return error.SocketFailed;
    };
    if (dh.sock < 0) return error.SocketFailed;

    const flags = std.posix.fcntl(dh.sock, F_GETFL, 0) catch 0;
    _ = std.posix.fcntl(dh.sock, F_SETFL, flags | O_NONBLOCK) catch {};
}

fn darwinStop(dh: *DarwinHandle) void {
    if (dh.sock >= 0) {
        std.posix.close(@as(std.posix.fd_t, @intCast(dh.sock)));
        dh.sock = -1;
    }
}

pub fn createDarwinMonitor(allocator: std.mem.Allocator) !*NetworkMonitor {
    const monitor_ptr = try allocator.create(NetworkMonitor);
    monitor_ptr.* = .{ .observers = undefined, .observer_count = 0, .allocator = allocator, .handle = undefined };

    const dh = try allocator.create(DarwinHandle);
    dh.* = .{ .sock = -1, .completion = undefined, .buffer = undefined, .monitor_ptr = monitor_ptr, .callback = darwinOnRoutingReadable };
    monitor_ptr.handle = dh;

    try darwinStart(dh);
    return monitor_ptr;
}

pub fn destroyDarwinMonitor(monitor_ptr: *NetworkMonitor) void {
    const dh = monitor_ptr.handle;
    darwinStop(dh);
    const allocator = monitor_ptr.allocator;
    allocator.destroy(dh);
    allocator.destroy(monitor_ptr);
}
