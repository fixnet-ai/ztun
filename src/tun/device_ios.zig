//! device_ios.zig - iOS PacketFlow wrapper
//!
//! iOS NEPacketTunnelProvider doesn't provide direct file descriptor access.
//! This module provides a callback-based interface for packet I/O.

const std = @import("std");
const device = @import("device");
const TunError = device.TunError;
const DeviceContext = device.DeviceContext;

/// iOS PacketFlow read callback
pub const PacketReadFn = *const fn (*anyopaque, []u8) usize;

/// iOS PacketFlow write callback
pub const PacketWriteFn = *const fn (*anyopaque, []const u8) usize;

/// Opaque iOS device handle
pub const IosDevice = opaque {};

/// iOS device internal state
const IosDeviceState = struct {
    ctx_ptr: *anyopaque,
    read_fn: PacketReadFn,
    write_fn: PacketWriteFn,
    mtu: u16,
};

/// Create an iOS device from packet flow callbacks
///
/// This is used with iOS NEPacketTunnelProvider where direct FD access
/// is not available. The callbacks forward packets to/from the VPN tunnel.
///
/// - context: Opaque context passed to callbacks
/// - read_fn: Called to read a packet (returns bytes read)
/// - write_fn: Called to write a packet (returns bytes written)
/// - mtu: MTU for the device
pub fn create(
    context: *anyopaque,
    read_fn: PacketReadFn,
    write_fn: PacketWriteFn,
    mtu: u16,
) TunError!*DeviceContext {
    // Allocate state using malloc (for cross-platform compatibility)
    const state = std.heap.c_allocator.create(IosDeviceState) catch {
        return error.IoError;
    };

    state.* = .{
        .ctx_ptr = context,
        .read_fn = read_fn,
        .write_fn = write_fn,
        .mtu = mtu,
    };

    const ctx = std.heap.c_allocator.create(DeviceContext) catch {
        std.heap.c_allocator.destroy(state);
        return error.IoError;
    };

    ctx.* = .{ .ptr = state };

    return ctx;
}

/// Receive a packet from the VPN tunnel
pub fn recv(device_ptr: *anyopaque, buf: []u8) TunError!usize {
    const state = @as(*IosDeviceState, @alignCast(@ptrCast(device_ptr)));
    return state.read_fn(state.ctx_ptr, buf);
}

/// Send a packet to the VPN tunnel
pub fn send(device_ptr: *anyopaque, buf: []const u8) TunError!usize {
    const state = @as(*IosDeviceState, @alignCast(@ptrCast(device_ptr)));
    return state.write_fn(state.ctx_ptr, buf);
}

/// Get the device name (not applicable on iOS)
pub fn getName(_: *anyopaque) TunError![]const u8 {
    return "ios-tun";
}

/// Get the device MTU
pub fn getMtu(device_ptr: *anyopaque) TunError!u16 {
    const state = @as(*IosDeviceState, @alignCast(@ptrCast(device_ptr)));
    return state.mtu;
}

/// Get the interface index (not applicable on iOS)
pub fn getIfIndex(_: *anyopaque) TunError!u32 {
    return 0;
}

/// Set non-blocking mode (not applicable on iOS)
pub fn setNonBlocking(_: *anyopaque, _: bool) TunError!void {
    // No-op on iOS - blocking mode is determined by callbacks
}

/// Add an IPv4 address at runtime (not applicable on iOS)
pub fn addIpv4(_: *anyopaque, _: [4]u8, _: u8) TunError!void {
    // No-op on iOS - address is configured by the system
}

/// Add an IPv6 address at runtime (not applicable on iOS)
pub fn addIpv6(_: *anyopaque, _: [16]u8, _: u8) TunError!void {
    // No-op on iOS - address is configured by the system
}

/// Destroy the device and clean up resources
pub fn destroy(device_ptr: *anyopaque) void {
    const state = @as(*IosDeviceState, @alignCast(@ptrCast(device_ptr)));
    std.heap.c_allocator.destroy(state);
}
