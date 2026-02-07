//! device.zig - TUN device abstraction
//!
//! Provides the TunDevice interface and Device type for synchronous TUN operations.
//! The TunDevice interface provides platform-independent operations for TUN devices.

const std = @import("std");
const builtin = @import("builtin");
const Options = @import("options.zig").Options;
const RouteEntry = @import("options.zig").RouteEntry;

// Detect Android by ABI (works during cross-compilation)
const is_android = builtin.os.tag == .linux and builtin.abi == .android;
// Detect iOS by ABI (simulator uses different ABI)
const is_ios = builtin.os.tag == .ios or builtin.abi == .simulator;

// Import platform-specific implementation directly
// Android uses Linux implementation (Android kernel)
const linux_impl = if (is_android or builtin.os.tag == .linux) @import("device_linux.zig") else struct {};
// iOS/macOS uses Darwin implementation (Darwin/XNU kernel)
const darwin_impl = if (is_ios or builtin.os.tag == .macos) @import("device_darwin.zig") else struct {};
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
    /// Operation not supported on this platform
    NotSupported,
    /// Resource exhaustion
    OutOfMemory,
    /// Invalid packet format
    InvalidPacket,
    /// Unknown error
    Unknown,
};

// Re-export types from options.zig for backward compatibility
pub const Ipv4Address = @import("options.zig").Ipv4Address;
pub const Ipv6Address = @import("options.zig").Ipv6Address;
pub const NetworkAddress = @import("options.zig").NetworkAddress;
pub const DeviceConfig = @import("options.zig").Options;

/// Device context - holds platform-specific data
pub const DeviceContext = struct {
    ptr: *anyopaque,
};

/// Device operations interface for platform-specific TUN handling
/// Allows Router to work with different TUN implementations (macOS utun, Linux tun, etc.)
pub const DeviceOps = struct {
    /// Opaque pointer to device-specific state
    ctx: *anyopaque,

    /// Read a packet from the device
    /// Returns the number of bytes read (excluding any device-specific headers)
    readFn: *const fn (ctx: *anyopaque, buf: []u8) TunError!usize,

    /// Write a packet to the device
    /// Takes raw IP packet (without device headers), writes with proper headers
    writeFn: *const fn (ctx: *anyopaque, buf: []const u8) TunError!usize,

    /// Get the file descriptor for libxev polling
    fdFn: *const fn (ctx: *anyopaque) std.posix.fd_t,

    /// Destroy the device and cleanup resources
    destroyFn: *const fn (ctx: *anyopaque) void,

    /// Read packet from TUN device (wrapper that handles device-specific headers)
    pub fn read(self: *const DeviceOps, buf: []u8) TunError!usize {
        return self.readFn(self.ctx, buf);
    }

    /// Write packet to TUN device (wrapper that handles device-specific headers)
    pub fn write(self: *const DeviceOps, buf: []const u8) TunError!usize {
        return self.writeFn(self.ctx, buf);
    }

    /// Get file descriptor for event loop
    pub fn fd(self: *const DeviceOps) std.posix.fd_t {
        return self.fdFn(self.ctx);
    }

    /// Destroy device and cleanup
    pub fn destroy(self: *const DeviceOps) void {
        self.destroyFn(self.ctx);
    }
};

/// TUN device handle
///
/// Provides synchronous send/receive operations for TUN interfaces.
pub const Device = struct {
    ctx: *DeviceContext,

    /// Create a TUN device from an existing file descriptor
    ///
    /// This is used by Android VpnService where the fd is obtained from
    /// ParcelFileDescriptor.getFd() via JNI.
    ///
    /// - fd: Existing file descriptor for the TUN device
    /// - dev_name: Optional device name (obtained from kernel if null)
    /// - dev_mtu: MTU for the device
    pub fn createFromFd(fd: std.posix.fd_t, dev_name: ?[:0]const u8, dev_mtu: u16) TunError!Device {
        const ctx_ptr = if (is_android or builtin.os.tag == .linux)
            linux_impl.createFromFd(fd, dev_name, dev_mtu)
        else if (is_ios or builtin.os.tag == .macos)
            error.NotSupported
        else if (builtin.os.tag == .windows)
            error.NotSupported
        else
            unreachable;
        return Device{ .ctx = ctx_ptr };
    }

    /// Create a new TUN device with the given configuration
    pub fn create(config: DeviceConfig) TunError!Device {
        const ctx_ptr = if (is_android or builtin.os.tag == .linux)
            try linux_impl.create(config)
        else if (is_ios or builtin.os.tag == .macos)
            try darwin_impl.createLegacy(config)
        else if (builtin.os.tag == .windows)
            try windows_impl.create(config)
        else
            unreachable;
        return Device{ .ctx = ctx_ptr };
    }

    /// Receive a packet from the TUN device
    pub fn recv(self: Device, buf: []u8) TunError!usize {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.recv(self.ctx.ptr, buf)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.recv(self.ctx.ptr, buf)
        else if (builtin.os.tag == .windows)
            windows_impl.recv(self.ctx.ptr, buf)
        else
            unreachable;
    }

    /// Send a packet to the TUN device
    pub fn send(self: Device, buf: []const u8) TunError!usize {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.send(self.ctx.ptr, buf)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.send(self.ctx.ptr, buf)
        else if (builtin.os.tag == .windows)
            windows_impl.send(self.ctx.ptr, buf)
        else
            unreachable;
    }

    /// Get the device name
    pub fn name(self: Device) TunError![]const u8 {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.getName(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.getName(self.ctx.ptr)
        else if (builtin.os.tag == .windows)
            windows_impl.getName(self.ctx.ptr)
        else
            unreachable;
    }

    /// Get the device MTU
    pub fn mtu(self: Device) TunError!u16 {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.getMtu(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.getMtu(self.ctx.ptr)
        else if (builtin.os.tag == .windows)
            windows_impl.getMtu(self.ctx.ptr)
        else
            unreachable;
    }

    /// Get the interface index
    pub fn ifIndex(self: Device) TunError!u32 {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.getIfIndex(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.getIfIndex(self.ctx.ptr)
        else if (builtin.os.tag == .windows)
            windows_impl.getIfIndex(self.ctx.ptr)
        else
            unreachable;
    }

    /// Get the file descriptor
    pub fn getFd(self: Device) std.posix.fd_t {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.getFd(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.getFd(self.ctx.ptr)
        else if (builtin.os.tag == .windows)
            windows_impl.getFd(self.ctx.ptr)
        else
            unreachable;
    }

    /// Set non-blocking mode
    pub fn setNonBlocking(self: Device, nonblocking: bool) TunError!void {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.setNonBlocking(self.ctx.ptr, nonblocking)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.setNonBlocking(self.ctx.ptr, nonblocking)
        else if (builtin.os.tag == .windows)
            windows_impl.setNonBlocking(self.ctx.ptr, nonblocking)
        else
            unreachable;
    }

    /// Add an IPv4 address at runtime
    pub fn addIpv4(self: Device, address: Ipv4Address, prefix: u8) TunError!void {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.addIpv4(self.ctx.ptr, address, prefix)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.addIpv4(self.ctx.ptr, address, prefix)
        else if (builtin.os.tag == .windows)
            windows_impl.addIpv4(self.ctx.ptr, address, prefix)
        else
            unreachable;
    }

    /// Add an IPv6 address at runtime
    pub fn addIpv6(self: Device, address: Ipv6Address, prefix: u8) TunError!void {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.addIpv6(self.ctx.ptr, address, prefix)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.addIpv6(self.ctx.ptr, address, prefix)
        else if (builtin.os.tag == .windows)
            windows_impl.addIpv6(self.ctx.ptr, address, prefix)
        else
            unreachable;
    }

    /// Add an IPv4 route to the system routing table
    /// On macOS: uses RTF_IFSCOPE to bind route to this interface
    pub fn addRoute(
        self: Device,
        destination: Ipv4Address,
        gateway: Ipv4Address,
        prefix_len: u8,
    ) TunError!void {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.addRoute(self.ctx.ptr, destination, gateway, prefix_len)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.addRoute(self.ctx.ptr, destination, gateway, prefix_len)
        else if (builtin.os.tag == .windows)
            windows_impl.addRoute(self.ctx.ptr, destination, gateway, prefix_len)
        else
            unreachable;
    }

    /// Destroy the device and clean up resources
    pub fn destroy(self: Device) void {
        return if (is_android or builtin.os.tag == .linux)
            linux_impl.destroy(self.ctx.ptr)
        else if (is_ios or builtin.os.tag == .macos)
            darwin_impl.destroy(self.ctx.ptr)
        else if (builtin.os.tag == .windows)
            windows_impl.destroy(self.ctx.ptr)
        else
            {};
    }
};

// ============================================================================
// TunDevice Interface (new, based on sing-tun architecture)
// ============================================================================

/// TUN device interface for platform-independent TUN operations.
///
/// Provides a clean interface for reading and writing IP packets to/from
/// TUN devices. The interface handles platform-specific details like:
/// - Darwin/macOS/iOS: 4-byte AF_INET header handling
/// - Linux/Android: Raw IP packets
/// - Windows: Wintun ring buffer I/O
pub const TunDevice = struct {
    /// Opaque pointer to platform-specific state
    ctx: *anyopaque,

    /// Function pointer for read operation
    readFn: *const fn (ctx: *anyopaque, buf: []u8) TunError!usize,
    /// Function pointer for write operation
    writeFn: *const fn (ctx: *anyopaque, buf: []const u8) TunError!usize,
    /// Function pointer for name retrieval
    nameFn: *const fn (ctx: *anyopaque) TunError![]const u8,
    /// Function pointer for MTU retrieval
    mtuFn: *const fn (ctx: *anyopaque) TunError!u16,
    /// Function pointer for interface index retrieval
    ifIndexFn: *const fn (ctx: *anyopaque) TunError!u32,
    /// Function pointer for file descriptor retrieval
    fdFn: *const fn (ctx: *anyopaque) std.posix.fd_t,
    /// Function pointer for non-blocking mode setting
    setNonBlockingFn: *const fn (ctx: *anyopaque, enabled: bool) TunError!void,
    /// Function pointer for closing/destroying
    closeFn: *const fn (ctx: *anyopaque) void,
    /// Function pointer for route addition
    addRouteFn: *const fn (ctx: *anyopaque, route: *const RouteEntry) TunError!void,
    /// Function pointer for route deletion
    deleteRouteFn: *const fn (ctx: *anyopaque, route: *const RouteEntry) TunError!void,

    /// Read a packet from the TUN device
    ///
    /// Returns the number of bytes read into buf.
    /// On Darwin/macOS, the 4-byte AF_INET header is stripped.
    /// On Linux/Windows, raw IP packets are returned.
    ///
    /// Returns 0 if no data is available (non-blocking mode).
    pub fn read(self: *const TunDevice, buf: []u8) TunError!usize {
        return self.readFn(self.ctx, buf);
    }

    /// Write a packet to the TUN device
    ///
    /// Takes a raw IP packet (without device-specific headers).
    /// On Darwin/macOS, the 4-byte AF_INET header is added automatically.
    /// On Linux/Windows, the packet is written as-is.
    ///
    /// Returns the number of bytes written.
    pub fn write(self: *const TunDevice, buf: []const u8) TunError!usize {
        return self.writeFn(self.ctx, buf);
    }

    /// Get the device name (e.g., "utun4", "tun0")
    pub fn name(self: *const TunDevice) TunError![]const u8 {
        return self.nameFn(self.ctx);
    }

    /// Get the device MTU
    pub fn mtu(self: *const TunDevice) TunError!u16 {
        return self.mtuFn(self.ctx);
    }

    /// Get the interface index for routing
    pub fn ifIndex(self: *const TunDevice) TunError!u32 {
        return self.ifIndexFn(self.ctx);
    }

    /// Get the file descriptor for event loop integration
    ///
    /// This fd can be used with libxev or similar event loops.
    pub fn fd(self: *const TunDevice) std.posix.fd_t {
        return self.fdFn(self.ctx);
    }

    /// Set non-blocking I/O mode
    pub fn setNonBlocking(self: *const TunDevice, enabled: bool) TunError!void {
        return self.setNonBlockingFn(self.ctx, enabled);
    }

    /// Close the TUN device and release resources
    pub fn close(self: *const TunDevice) void {
        return self.closeFn(self.ctx);
    }

    /// Add a route to the system routing table
    pub fn addRoute(self: *const TunDevice, route: *const RouteEntry) TunError!void {
        return self.addRouteFn(self.ctx, route);
    }

    /// Delete a route from the system routing table
    pub fn deleteRoute(self: *const TunDevice, route: *const RouteEntry) TunError!void {
        return self.deleteRouteFn(self.ctx, route);
    }
};
