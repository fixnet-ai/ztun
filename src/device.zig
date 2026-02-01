//! device.zig - TUN device abstraction
//!
//! Provides the core Device type for synchronous TUN operations.

const std = @import("std");
const builtin = @import("builtin");

// Import platform-specific implementation directly
const linux_impl = if (builtin.os.tag == .linux) @import("device_linux.zig") else struct {};
const macos_impl = if (builtin.os.tag == .macos) @import("device_macos.zig") else struct {};
const windows_impl = if (builtin.os.tag == .windows) @import("device_windows.zig") else struct {};

/// Error type for TUN operations
pub const TunError = error{
    /// Invalid argument provided
    InvalidArgument,
    /// I/O error occurred
    IoError,
    /// Device not found
    NotFound,
    /// Permission denied
    PermissionDenied,
    /// Unknown error
    Unknown,
};

/// IPv4 address representation
pub const Ipv4Address = [4]u8;

/// IPv6 address representation
pub const Ipv6Address = [16]u8;

/// Network address configuration
pub const NetworkAddress = struct {
    address: Ipv4Address,
    prefix: u8,
    destination: ?Ipv4Address = null,
};

/// TUN device configuration
pub const DeviceConfig = struct {
    name: ?[]const u8 = null,
    mtu: ?u16 = null,
    ipv4: ?NetworkAddress = null,
    ipv6: ?Ipv6Address = null,
    ipv6_prefix: ?u8 = null,
};

/// Device context - holds platform-specific data
pub const DeviceContext = struct {
    ptr: *anyopaque,
};

/// TUN device handle
///
/// Provides synchronous send/receive operations for TUN interfaces.
pub const Device = struct {
    ctx: *DeviceContext,

    /// Create a new TUN device with the given configuration
    pub fn create(config: DeviceConfig) TunError!Device {
        const ctx_ptr = switch (builtin.os.tag) {
            .linux => try linux_impl.create(config),
            .macos => try macos_impl.create(config),
            .windows => try windows_impl.create(config),
            else => unreachable,
        };
        return Device{ .ctx = ctx_ptr };
    }

    /// Receive a packet from the TUN device
    pub fn recv(self: Device, buf: []u8) TunError!usize {
        return switch (builtin.os.tag) {
            .linux => linux_impl.recv(self.ctx.ptr, buf),
            .macos => macos_impl.recv(self.ctx.ptr, buf),
            .windows => windows_impl.recv(self.ctx.ptr, buf),
            else => unreachable,
        };
    }

    /// Send a packet to the TUN device
    pub fn send(self: Device, buf: []const u8) TunError!usize {
        return switch (builtin.os.tag) {
            .linux => linux_impl.send(self.ctx.ptr, buf),
            .macos => macos_impl.send(self.ctx.ptr, buf),
            .windows => windows_impl.send(self.ctx.ptr, buf),
            else => unreachable,
        };
    }

    /// Get the device name
    pub fn name(self: Device) TunError![]const u8 {
        return switch (builtin.os.tag) {
            .linux => linux_impl.getName(self.ctx.ptr),
            .macos => macos_impl.getName(self.ctx.ptr),
            .windows => windows_impl.getName(self.ctx.ptr),
            else => unreachable,
        };
    }

    /// Get the device MTU
    pub fn mtu(self: Device) TunError!u16 {
        return switch (builtin.os.tag) {
            .linux => linux_impl.getMtu(self.ctx.ptr),
            .macos => macos_impl.getMtu(self.ctx.ptr),
            .windows => windows_impl.getMtu(self.ctx.ptr),
            else => unreachable,
        };
    }

    /// Get the interface index
    pub fn ifIndex(self: Device) TunError!u32 {
        return switch (builtin.os.tag) {
            .linux => linux_impl.getIfIndex(self.ctx.ptr),
            .macos => macos_impl.getIfIndex(self.ctx.ptr),
            .windows => windows_impl.getIfIndex(self.ctx.ptr),
            else => unreachable,
        };
    }

    /// Set non-blocking mode
    pub fn setNonBlocking(self: Device, nonblocking: bool) TunError!void {
        return switch (builtin.os.tag) {
            .linux => linux_impl.setNonBlocking(self.ctx.ptr, nonblocking),
            .macos => macos_impl.setNonBlocking(self.ctx.ptr, nonblocking),
            .windows => windows_impl.setNonBlocking(self.ctx.ptr, nonblocking),
            else => unreachable,
        };
    }

    /// Add an IPv4 address at runtime
    pub fn addIpv4(self: Device, address: Ipv4Address, prefix: u8) TunError!void {
        return switch (builtin.os.tag) {
            .linux => linux_impl.addIpv4(self.ctx.ptr, address, prefix),
            .macos => macos_impl.addIpv4(self.ctx.ptr, address, prefix),
            .windows => windows_impl.addIpv4(self.ctx.ptr, address, prefix),
            else => unreachable,
        };
    }

    /// Add an IPv6 address at runtime
    pub fn addIpv6(self: Device, address: Ipv6Address, prefix: u8) TunError!void {
        return switch (builtin.os.tag) {
            .linux => linux_impl.addIpv6(self.ctx.ptr, address, prefix),
            .macos => macos_impl.addIpv6(self.ctx.ptr, address, prefix),
            .windows => windows_impl.addIpv6(self.ctx.ptr, address, prefix),
            else => unreachable,
        };
    }

    /// Destroy the device and clean up resources
    pub fn destroy(self: Device) void {
        return switch (builtin.os.tag) {
            .linux => linux_impl.destroy(self.ctx.ptr),
            .macos => macos_impl.destroy(self.ctx.ptr),
            .windows => windows_impl.destroy(self.ctx.ptr),
            else => {},
        };
    }
};
