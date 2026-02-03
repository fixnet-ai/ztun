//! ztun - Cross-platform TUN device library in pure Zig
//!
//! A synchronous, cross-platform TUN device library providing:
//! - Device creation and configuration
//! - IPv4/IPv6 address management
//! - Packet send/receive operations
//! - Platform-specific optimizations (Linux, macOS, Windows, Android, iOS)

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
// Note: using inline blocks because switch on os.tag doesn't include .android/.ios
const builtin = @import("builtin");

// Detect Android by ABI (works during cross-compilation)
const is_android = builtin.os.tag == .linux and builtin.abi == .android;
// Detect iOS by ABI (simulator uses different ABI)
const is_ios = builtin.os.tag == .ios or builtin.abi == .simulator;

pub usingnamespace if (is_android or builtin.os.tag == .linux)
    @import("device_linux.zig")
else if (is_ios or builtin.os.tag == .macos)
    @import("device_macos.zig")
else if (builtin.os.tag == .windows)
    @import("device_windows.zig")
else
    struct {};
