//! tun - Cross-platform TUN device library in pure Zig
//!
//! A synchronous, cross-platform TUN device library providing:
//! - Device creation and configuration
//! - IPv4/IPv6 address management
//! - Packet send/receive operations
//! - Platform-specific optimizations (Linux, macOS, Windows, Android, iOS)

pub const Device = @import("device.zig").Device;
pub const TunError = @import("device.zig").TunError;
pub const Ipv4Address = @import("device.zig").Ipv4Address;
pub const Ipv6Address = @import("device.zig").Ipv6Address;
pub const NetworkAddress = @import("device.zig").NetworkAddress;
pub const DeviceConfig = @import("device.zig").DeviceConfig;
pub const DeviceOps = @import("device.zig").DeviceOps;

// New interfaces (sing-tun inspired)
pub const TunDevice = @import("device.zig").TunDevice;
pub const Options = @import("options.zig").Options;
pub const TunStack = @import("stack.zig").TunStack;
pub const PacketHandler = @import("handler.zig").PacketHandler;
pub const PacketResult = @import("handler.zig").PacketResult;

// IP address conversion utilities
pub const ipv4ToU32 = @import("options.zig").ipv4ToU32;
pub const u32ToIpv4 = @import("options.zig").u32ToIpv4;
pub const parseIpv4 = @import("options.zig").parseIpv4;
pub const formatIpv4 = @import("options.zig").formatIpv4;

// Re-export iOS-specific types (PacketFlow wrapper)
pub const IosDevice = @import("device_ios.zig").IosDevice;
pub const PacketReadFn = @import("device_ios.zig").PacketReadFn;
pub const PacketWriteFn = @import("device_ios.zig").PacketWriteFn;

// Re-export platform-specific types
// Note: using inline blocks because switch on os.tag doesn't include .android/.ios
const builtin = @import("builtin");
const std = @import("std");

// Detect Android by ABI (works during cross-compilation)
const is_android = builtin.os.tag == .linux and builtin.abi == .android;
// Detect iOS by ABI (simulator uses different ABI)
const is_ios = builtin.os.tag == .ios or builtin.abi == .simulator;

pub usingnamespace if (is_android or builtin.os.tag == .linux)
    @import("device_linux.zig")
else if (is_ios or builtin.os.tag == .macos)
    @import("device_darwin.zig")
else if (builtin.os.tag == .windows)
    @import("device_windows.zig")
else
    struct {};
