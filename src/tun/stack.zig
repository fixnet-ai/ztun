//! stack.zig - Protocol stack interface for TUN devices
//!
//! Provides the TunStack interface for handling protocol processing
//! on packets received from TUN devices.

const std = @import("std");
const TunDevice = @import("device.zig").TunDevice;
const TunError = @import("device.zig").TunError;
const PacketHandler = @import("handler.zig").PacketHandler;
const Ipv4Address = @import("options.zig").Ipv4Address;
const Ipv6Address = @import("options.zig").Ipv6Address;

/// Protocol stack interface for processing packets from TUN devices.
///
/// The protocol stack is responsible for:
/// - Reading packets from the TUN device
/// - Parsing and validating IP headers
/// - Routing packets to the appropriate handler (TCP, UDP, ICMP)
/// - Writing responses back to the TUN device
///
/// Implementations:
/// - SystemStack: Uses system network stack with NAT (default)
/// - FullStack: Implements complete TCP/IP stack (future)
pub const TunStack = struct {
    /// Opaque pointer to platform-specific state
    ctx: *anyopaque,

    /// Function pointer for starting the stack
    startFn: *const fn (ctx: *anyopaque, handler: *PacketHandler) TunError!void,
    /// Function pointer for stopping the stack
    stopFn: *const fn (ctx: *anyopaque) void,
    /// Function pointer for getting the file descriptor
    fdFn: *const fn (ctx: *anyopaque) std.posix.fd_t,
    /// Function pointer for processing a packet
    processFn: *const fn (ctx: *anyopaque, packet: []const u8) TunError!void,

    /// Start the protocol stack
    ///
    /// Registers the handler for packet processing callbacks.
    pub fn start(self: *const TunStack, handler: *PacketHandler) TunError!void {
        return self.startFn(self.ctx, handler);
    }

    /// Stop the protocol stack
    ///
    /// Releases resources and stops packet processing.
    pub fn stop(self: *const TunStack) void {
        return self.stopFn(self.ctx);
    }

    /// Get the file descriptor for event loop integration
    ///
    /// Returns the file descriptor to monitor for incoming packets.
    /// Returns -1 if no file descriptor is available.
    pub fn fd(self: *const TunStack) std.posix.fd_t {
        return self.fdFn(self.ctx);
    }

    /// Process a raw packet from the TUN device
    ///
    /// Parses the IP header and dispatches to the appropriate handler.
    pub fn process(self: *const TunStack, packet: []const u8) TunError!void {
        return self.processFn(self.ctx, packet);
    }
};

/// Stack type enumeration
pub const StackType = enum {
    /// System NAT-based stack (uses system TCP/UDP)
    system,
    /// Full TCP/IP stack implementation
    full,
    /// Hybrid stack (system for UDP, full for TCP)
    hybrid,
};

/// Stack configuration
pub const StackConfig = struct {
    /// Type of stack to use
    type: StackType = .system,

    /// Stack-specific options
    options: StackOptions = .{},
};

/// Stack-specific options
pub const StackOptions = struct {
    /// Enable UDP NAT traversal
    udp_enabled: bool = true,
    /// UDP session timeout in seconds
    udp_timeout: u32 = 30,
    /// Enable ICMP echo handling
    icmp_enabled: bool = true,
    /// Enable IPv6 support
    ipv6_enabled: bool = false,
    /// MTU for outgoing packets
    mtu: u16 = 1500,
};

// pub fn createSystemStack(allocator: std.mem.Allocator, device: *TunDevice, config: StackConfig) TunError!*TunStack {
//     const SystemStack = @import("stack_system.zig");
//     return SystemStack.create(allocator, device, config);
// }
