//! monitor_linux.zig - Linux network change monitoring via rtnetlink

const std = @import("std");
const builtin = @import("builtin");

const NETLINK_ROUTE = 0;
const RTM_NEWLINK = 16;
const RTM_DELLINK = 17;
const RTM_NEWADDR = 20;
const RTM_DELADDR = 21;

const F_GETFL = 3;
const F_SETFL = 4;
const O_NONBLOCK = 0x400;

const nlmsghdr = packed struct {
    nlmsg_len: u32, nlmsg_type: u16, nlmsg_flags: u16, nlmsg_seq: u32, nlmsg_pid: u32,
};

pub const NetworkChange = enum {
    interface_up,
    interface_down,
    address_added,
    address_removed,
    route_changed,
    network_losing,
};

pub const NetworkEvent = struct {
    change: NetworkChange,
    interface_name: []const u8,
    interface_index: u32,
    timestamp: i64,
};

pub const ObserverCallback = *const fn (event: *const NetworkEvent, userdata: ?*anyopaque) void;

const MAX_OBSERVERS: usize = 16;

const Observer = struct { callback: ObserverCallback, userdata: ?*anyopaque, active: bool };

pub const NetworkMonitor = struct {
    observers: [MAX_OBSERVERS]Observer = undefined,
    observer_count: usize = 0,
    allocator: std.mem.Allocator,
    handle: *LinuxHandle,

    pub fn register(m: *NetworkMonitor, callback: ObserverCallback, userdata: ?*anyopaque) !void {
        if (m.observer_count >= MAX_OBSERVERS) return error.TooManyObservers;
        for (m.observers[0..m.observer_count]) |*obs| {
            if (obs.callback == callback) return error.AlreadyRegistered;
        }
        m.observers[m.observer_count] = .{ .callback = callback, .userdata = userdata, .active = true };
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

pub const LinuxHandle = struct {
    sock: i32,
    completion: *anyopaque,
    buffer: [8192]u8,
    monitor_ptr: *NetworkMonitor,
    callback: *const fn (userdata: ?*anyopaque, _: *anyopaque, _: *anyopaque, result: usize) void,
};

fn parseNlmsg(buf: []const u8, event: *NetworkEvent) void {
    if (buf.len < @sizeOf(nlmsghdr)) return;
    const nlh = @as(*const nlmsghdr, @ptrCast(@alignCast(buf.ptr)));
    event.timestamp = std.time.milliTimestamp();
    event.interface_index = @as(u32, @intCast(nlh.nlmsg_pid));
    event.change = switch (nlh.nlmsg_type) {
        RTM_NEWLINK => .interface_up, RTM_DELLINK => .interface_down,
        RTM_NEWADDR => .address_added, RTM_DELADDR => .address_removed, else => .route_changed,
    };
    event.interface_name = &[_]u8{};
}

fn linuxOnNetlinkReadable(userdata: ?*anyopaque, _: *anyopaque, _: *anyopaque, result: usize) void {
    const lh = @as(*LinuxHandle, @ptrCast(@alignCast(userdata orelse return)));
    const mon = lh.monitor_ptr;
    const n = result;

    if (n == 0) return;

    var event: NetworkEvent = undefined;
    parseNlmsg(lh.buffer[0..n], &event);
    mon.notify(&event);
}

fn linuxStart(lh: *LinuxHandle) !void {
    lh.sock = std.posix.socket(NETLINK_ROUTE, std.posix.SOCK.RAW, NETLINK_ROUTE) catch |err| {
        std.debug.print("[MONITOR-LINUX] Socket creation failed: {}\n", .{err});
        return error.SocketFailed;
    };
    if (lh.sock < 0) return error.SocketFailed;
    const flags = std.posix.fcntl(lh.sock, F_GETFL, 0) catch 0;
    _ = std.posix.fcntl(lh.sock, F_SETFL, flags | O_NONBLOCK) catch {};
}

fn linuxStop(lh: *LinuxHandle) void {
    if (lh.sock >= 0) {
        std.posix.close(@as(std.posix.fd_t, @intCast(lh.sock)));
        lh.sock = -1;
    }
}

pub fn createLinuxMonitor(allocator: std.mem.Allocator) !*NetworkMonitor {
    const monitor_ptr = try allocator.create(NetworkMonitor);
    monitor_ptr.* = .{ .observers = undefined, .observer_count = 0, .allocator = allocator, .handle = undefined };
    const lh = try allocator.create(LinuxHandle);
    lh.* = .{ .sock = -1, .completion = undefined, .buffer = undefined, .monitor_ptr = monitor_ptr, .callback = linuxOnNetlinkReadable };
    monitor_ptr.handle = lh;
    try linuxStart(lh);
    return monitor_ptr;
}

pub fn destroyLinuxMonitor(monitor_ptr: *NetworkMonitor) void {
    const lh = monitor_ptr.handle;
    linuxStop(lh);
    const allocator = monitor_ptr.allocator;
    allocator.destroy(lh);
    allocator.destroy(monitor_ptr);
}
