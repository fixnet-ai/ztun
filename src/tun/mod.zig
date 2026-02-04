//! tun - Cross-platform TUN device library in pure Zig
//!
//! A synchronous, cross-platform TUN device library providing:
//! - Device creation and configuration
//! - IPv4/IPv6 address management
//! - Packet send/receive operations
//! - Platform-specific optimizations (Linux, macOS, Windows, Android, iOS)

const std = @import("std");
const device = @import("device");
const builder = @import("builder");
const ringbuf = @import("ringbuf");

pub const DeviceBuilder = builder.DeviceBuilder;
pub const Device = device.Device;
pub const TunError = device.TunError;
pub const Ipv4Address = device.Ipv4Address;
pub const Ipv6Address = device.Ipv6Address;
pub const NetworkAddress = device.NetworkAddress;
pub const DeviceConfig = device.DeviceConfig;
pub const DeviceOps = device.DeviceOps;
pub const RingBuffer = ringbuf.RingBuffer;

// Re-export iOS-specific types (PacketFlow wrapper)
pub const IosDevice = @import("device_ios.zig").IosDevice;
pub const PacketReadFn = @import("device_ios.zig").PacketReadFn;
pub const PacketWriteFn = @import("device_ios.zig").PacketWriteFn;

/// Create DeviceOps for the current platform
/// This factory function creates a DeviceOps that handles all platform-specific
/// header processing internally. The router receives pure IP packets.
pub fn createDeviceOps(fd: std.posix.fd_t) DeviceOps {
    return device.createDeviceOps(fd);
}
