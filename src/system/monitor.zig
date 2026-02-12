//! monitor.zig - Cross-platform network change monitoring

const std = @import("std");
const builtin = @import("builtin");

// Import platform-specific implementations
const darwin = @import("monitor_darwin.zig");
const linux = @import("monitor_linux.zig");
const windows = @import("monitor_windows.zig");

// Re-export types from the appropriate platform module based on current OS
pub const NetworkChange = darwin.NetworkChange;
pub const NetworkEvent = darwin.NetworkEvent;
pub const ObserverCallback = darwin.ObserverCallback;

/// Platform-specific monitor type
pub const NetworkMonitor = switch (builtin.os.tag) {
    .macos => darwin.NetworkMonitor,
    .linux => linux.NetworkMonitor,
    .windows => windows.NetworkMonitor,
    else => void,
};

/// Create platform-specific network monitor
pub fn createNetworkMonitor(allocator: std.mem.Allocator) !*NetworkMonitor {
    return switch (builtin.os.tag) {
        .macos => try darwin.createDarwinMonitor(allocator),
        .linux => try linux.createLinuxMonitor(allocator),
        .windows => try windows.createWindowsMonitor(allocator),
        else => error.UnsupportedPlatform,
    };
}

/// Cleanup platform-specific network monitor
pub fn destroyNetworkMonitor(monitor_ptr: *NetworkMonitor) void {
    return switch (builtin.os.tag) {
        .macos => darwin.destroyDarwinMonitor(monitor_ptr),
        .linux => linux.destroyLinuxMonitor(monitor_ptr),
        .windows => windows.destroyWindowsMonitor(monitor_ptr),
        else => {},
    };
}
