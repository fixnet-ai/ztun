//! handler.zig - Packet handler interface for protocol callbacks
//!
//! Provides the PacketHandler interface for handling packets after they are
//! parsed from the TUN device. Implement this interface to process TCP, UDP,
//! and ICMP packets.

const std = @import("std");
const Ipv4Address = @import("options.zig").Ipv4Address;
const Ipv6Address = @import("options.zig").Ipv6Address;

/// Packet handler interface for protocol callbacks.
///
/// Implement this interface to handle packets parsed by the protocol stack.
/// The handler receives notifications for:
/// - TCP: Connection requests, data, and terminations
/// - UDP: Datagram packets
/// - ICMP: Echo requests and errors
///
/// # Example
///
/// ```zig
/// const MyHandler = struct {
///     const Self = @This();
///
///     pub fn handleTcp(
///         self: *Self,
///         src_ip: Ipv4Address,
///         dst_ip: Ipv4Address,
///         data: []const u8,
///     ) PacketResult {
///         // Process TCP packet
///         return .handled;
///     }
///
///     pub fn handleUdp(
///         self: *Self,
///         src_ip: Ipv4Address,
///         dst_ip: Ipv4Address,
///         data: []const u8,
///     ) PacketResult {
///         // Process UDP packet
///         return .handled;
///     }
///
///     pub fn handleIcmp(
///         self: *Self,
///         src_ip: Ipv4Address,
///         dst_ip: Ipv4Address,
///         data: []const u8,
///     ) PacketResult {
///         // Process ICMP packet
///         return .handled;
///     }
/// };
/// ```
pub const PacketHandler = struct {
    /// Opaque pointer to handler state
    ctx: *anyopaque,

    /// Function pointer for TCP packet handling
    handleTcpFn: *const fn (ctx: *anyopaque, src_ip: Ipv4Address, dst_ip: Ipv4Address, data: []const u8) PacketResult,
    /// Function pointer for UDP packet handling
    handleUdpFn: *const fn (ctx: *anyopaque, src_ip: Ipv4Address, dst_ip: Ipv4Address, data: []const u8) PacketResult,
    /// Function pointer for ICMP packet handling
    handleIcmpFn: *const fn (ctx: *anyopaque, src_ip: Ipv4Address, dst_ip: Ipv4Address, data: []const u8) PacketResult,
    /// Function pointer for IPv6 TCP packet handling
    handleTcp6Fn: *const fn (ctx: *anyopaque, src_ip: Ipv6Address, dst_ip: Ipv6Address, data: []const u8) PacketResult,
    /// Function pointer for IPv6 UDP packet handling
    handleUdp6Fn: *const fn (ctx: *anyopaque, src_ip: Ipv6Address, dst_ip: Ipv6Address, data: []const u8) PacketResult,
    /// Function pointer for IPv6 ICMP packet handling
    handleIcmp6Fn: *const fn (ctx: *anyopaque, src_ip: Ipv6Address, dst_ip: Ipv6Address, data: []const u8) PacketResult,

    /// Handle an incoming TCP packet
    ///
    /// Called when a TCP packet is received from the TUN device.
    ///
    /// - src_ip: Source IPv4 address
    /// - dst_ip: Destination IPv4 address
    /// - data: TCP payload (excluding IP header)
    pub fn handleTcp(
        self: *const PacketHandler,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        data: []const u8,
    ) PacketResult {
        return self.handleTcpFn(self.ctx, src_ip, dst_ip, data);
    }

    /// Handle an incoming UDP packet
    ///
    /// Called when a UDP packet is received from the TUN device.
    ///
    /// - src_ip: Source IPv4 address
    /// - dst_ip: Destination IPv4 address
    /// - data: UDP payload (excluding IP header)
    pub fn handleUdp(
        self: *const PacketHandler,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        data: []const u8,
    ) PacketResult {
        return self.handleUdpFn(self.ctx, src_ip, dst_ip, data);
    }

    /// Handle an incoming ICMP packet
    ///
    /// Called when an ICMP packet is received from the TUN device.
    ///
    /// - src_ip: Source IPv4 address
    /// - dst_ip: Destination IPv4 address
    /// - data: ICMP payload (excluding IP header)
    pub fn handleIcmp(
        self: *const PacketHandler,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        data: []const u8,
    ) PacketResult {
        return self.handleIcmpFn(self.ctx, src_ip, dst_ip, data);
    }

    /// Handle an incoming IPv6 TCP packet
    pub fn handleTcp6(
        self: *const PacketHandler,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        data: []const u8,
    ) PacketResult {
        return self.handleTcp6Fn(self.ctx, src_ip, dst_ip, data);
    }

    /// Handle an incoming IPv6 UDP packet
    pub fn handleUdp6(
        self: *const PacketHandler,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        data: []const u8,
    ) PacketResult {
        return self.handleUdp6Fn(self.ctx, src_ip, dst_ip, data);
    }

    /// Handle an incoming IPv6 ICMPv6 packet
    pub fn handleIcmp6(
        self: *const PacketHandler,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        data: []const u8,
    ) PacketResult {
        return self.handleIcmp6Fn(self.ctx, src_ip, dst_ip, data);
    }
};

/// Result of packet handling
pub const PacketResult = enum {
    /// Packet was handled successfully
    handled,
    /// Packet should be dropped
    drop,
    /// Packet should be passed to the network stack
    pass,
    /// Error occurred while handling
    failed,
};

/// Create a packet handler from an implementation struct
///
/// The implementation struct must have methods:
/// - handleTcp(src_ip, dst_ip, data) -> PacketResult
/// - handleUdp(src_ip, dst_ip, data) -> PacketResult
/// - handleIcmp(src_ip, dst_ip, data) -> PacketResult
/// - handleTcp6(src_ip, dst_ip, data) -> PacketResult (optional)
/// - handleUdp6(src_ip, dst_ip, data) -> PacketResult (optional)
/// - handleIcmp6(src_ip, dst_ip, data) -> PacketResult (optional)
pub fn createHandler(
    impl: anytype,
) PacketHandler {
    const ImplType = @TypeOf(impl);
    const ImplPtr = *ImplType;

    return PacketHandler{
        .ctx = impl,
        .handleTcpFn = struct {
            fn callback(ctx: *anyopaque, src_ip: Ipv4Address, dst_ip: Ipv4Address, data: []const u8) PacketResult {
                const self = @as(ImplPtr, @ptrCast(@alignCast(ctx)));
                return self.handleTcp(src_ip, dst_ip, data);
            }
        }.callback,
        .handleUdpFn = struct {
            fn callback(ctx: *anyopaque, src_ip: Ipv4Address, dst_ip: Ipv4Address, data: []const u8) PacketResult {
                const self = @as(ImplPtr, @ptrCast(@alignCast(ctx)));
                return self.handleUdp(src_ip, dst_ip, data);
            }
        }.callback,
        .handleIcmpFn = struct {
            fn callback(ctx: *anyopaque, src_ip: Ipv4Address, dst_ip: Ipv4Address, data: []const u8) PacketResult {
                const self = @as(ImplPtr, @ptrCast(@alignCast(ctx)));
                return self.handleIcmp(src_ip, dst_ip, data);
            }
        }.callback,
        .handleTcp6Fn = struct {
            fn callback(ctx: *anyopaque, src_ip: Ipv6Address, dst_ip: Ipv6Address, data: []const u8) PacketResult {
                const self = @as(ImplPtr, @ptrCast(@alignCast(ctx)));
                if (@hasDecl(ImplType, "handleTcp6")) {
                    return self.handleTcp6(src_ip, dst_ip, data);
                }
                return .drop;
            }
        }.callback,
        .handleUdp6Fn = struct {
            fn callback(ctx: *anyopaque, src_ip: Ipv6Address, dst_ip: Ipv6Address, data: []const u8) PacketResult {
                const self = @as(ImplPtr, @ptrCast(@alignCast(ctx)));
                if (@hasDecl(ImplType, "handleUdp6")) {
                    return self.handleUdp6(src_ip, dst_ip, data);
                }
                return .drop;
            }
        }.callback,
        .handleIcmp6Fn = struct {
            fn callback(ctx: *anyopaque, src_ip: Ipv6Address, dst_ip: Ipv6Address, data: []const u8) PacketResult {
                const self = @as(ImplPtr, @ptrCast(@alignCast(ctx)));
                if (@hasDecl(ImplType, "handleIcmp6")) {
                    return self.handleIcmp6(src_ip, dst_ip, data);
                }
                return .drop;
            }
        }.callback,
    };
}
