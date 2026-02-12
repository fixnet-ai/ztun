//! monitor_windows.zig - Windows network change monitoring

const std = @import("std");
const builtin = @import("builtin");

const OVERLAPPED = extern struct { Internal: usize, InternalHigh: usize, Offset: u32, OffsetHigh: u32, hEvent: ?*anyopaque };
const HANDLE = *anyopaque;

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
    handle: *WindowsHandle,

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

pub const WindowsHandle = struct {
    addr_event: ?*anyopaque,
    route_event: ?*anyopaque,
    addr_overlapped: OVERLAPPED,
    route_overlapped: OVERLAPPED,
    monitor_ptr: *NetworkMonitor,
    running: bool,
};

pub fn createWindowsMonitor(allocator: std.mem.Allocator) !*NetworkMonitor {
    const monitor_ptr = try allocator.create(NetworkMonitor);
    monitor_ptr.* = .{ .observers = undefined, .observer_count = 0, .allocator = allocator, .handle = undefined };
    const wh = try allocator.create(WindowsHandle);
    wh.* = .{ .addr_event = null, .route_event = null, .addr_overlapped = undefined, .route_overlapped = undefined, .monitor_ptr = monitor_ptr, .running = false };
    monitor_ptr.handle = wh;
    return monitor_ptr;
}

pub fn destroyWindowsMonitor(monitor_ptr: *NetworkMonitor) void {
    const wh = monitor_ptr.handle;
    const allocator = monitor_ptr.allocator;
    allocator.destroy(wh);
    allocator.destroy(monitor_ptr);
}
