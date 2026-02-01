//! ztun - Cross-platform TUN device library in pure Zig
//!
//! A synchronous, cross-platform TUN device library providing:
//! - Device creation and configuration
//! - IPv4/IPv6 address management
//! - Packet send/receive operations
//! - Platform-specific optimizations (Linux, macOS, Windows)

pub const DeviceBuilder = @import("builder.zig").DeviceBuilder;
pub const Device = @import("device.zig").Device;
pub const TunError = @import("device.zig").TunError;
pub const Ipv4Address = @import("device.zig").Ipv4Address;
pub const Ipv6Address = @import("device.zig").Ipv6Address;
pub const NetworkAddress = @import("device.zig").NetworkAddress;
pub const DeviceConfig = @import("device.zig").DeviceConfig;

// Re-export platform module
pub const platform = @import("platform.zig");

// Re-export platform-specific types
pub usingnamespace switch (@import("builtin").os.tag) {
    .linux => @import("device_linux.zig"),
    .macos => @import("device_macos.zig"),
    .windows => @import("device_windows.zig"),
    else => struct {},
};
