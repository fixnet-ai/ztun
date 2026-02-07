//! stack_core.zig - System protocol stack implementation for TUN devices
//!
//! Implements the TunStack interface using the system's native network stack
//! for packet processing. This is the default/full stack implementation.
//!
//! Key features:
//! - Uses StaticIpstack for TCP/UDP/ICMP protocol handling
//! - Zero heap allocations (static connection table)
//! - Event-driven callbacks via PacketHandler interface

const std = @import("std");
const builtin = @import("builtin");

// Use tun module exports to avoid module conflicts
const tun = @import("tun");

// TUN stack interface
const TunStack = tun.TunStack;
const TunError = tun.TunError;
const StackConfig = tun.StackConfig;
const StackOptions = tun.StackOptions;

// Packet handling interface
const PacketHandler = tun.PacketHandler;

// IP stack implementation
const ipstack = @import("ipstack");
const StaticIpstack = ipstack.StaticIpstack;
const ipv4 = ipstack.ipv4;
const ipv6 = ipstack.ipv6;
const udp = ipstack.udp;

// Address types
const Ipv4Address = tun.Ipv4Address;
const Ipv6Address = tun.Ipv6Address;

/// Maximum number of concurrent connections
const MAX_CONNECTIONS = 1024;

/// SystemStack state - holds all protocol stack state
pub const SystemStack = struct {
    /// Static IP stack instance
    ipstack: StaticIpstack,

    /// Packet handler for protocol events
    handler: PacketHandler,

    /// Configuration
    config: StackConfig,

    /// Current timestamp (updated by application)
    current_time: u32,

    /// Local IPv4 address (network byte order)
    local_ip: u32,

    /// Pseudo source IP for replies (network byte order)
    pseudo_src_ip: u32,

    /// IPv6 enabled flag
    ipv6_enabled: bool,

    /// IPv6 local address (16 bytes)
    local_ip6: [16]u8,

    /// Buffer for packet processing
    packet_buf: [65536]u8,

    /// Scratch buffer for packet building
    scratch_buf: [65536]u8,

    /// Statistics
    stats: SystemStackStats,
};

/// System stack statistics
pub const SystemStackStats = struct {
    /// Total packets processed
    packets_rx: u64 = 0,
    /// Total packets sent
    packets_tx: u64 = 0,
    /// Packets dropped due to errors
    packets_dropped: u64 = 0,
    /// TCP connections established
    tcp_connections: u32 = 0,
    /// Active TCP connections
    tcp_active: u32 = 0,
    /// UDP packets processed
    udp_packets: u32 = 0,
    /// ICMP packets processed
    icmp_packets: u32 = 0,
};

/// Convert Ipv4Address to u32 (network byte order)
fn addrToU32(addr: Ipv4Address) u32 {
    return @as(u32, addr[0]) << 24 |
        @as(u32, addr[1]) << 16 |
        @as(u32, addr[2]) << 8 |
        @as(u32, addr[3]);
}

/// Convert u32 to Ipv4Address (network byte order)
fn u32ToAddr(ip_be: u32) Ipv4Address {
    return .{
        @as(u8, @truncate(ip_be >> 24)),
        @as(u8, @truncate(ip_be >> 16)),
        @as(u8, @truncate(ip_be >> 8)),
        @as(u8, @truncate(ip_be)),
    };
}

/// Create a new system protocol stack
///
/// Parameters:
///   - allocator: Memory allocator (not used, static allocation)
///   - device: TUN device reference (not used, stack is protocol-only)
///   - config: Stack configuration
///   - handler: Packet handler for protocol events
///   - local_ip: Local IPv4 address in network byte order
///   - pseudo_src_ip: Pseudo source IP for replies
///
/// Returns: Configured SystemStack ready for use
pub fn createSystemStack(
    _: std.mem.Allocator,
    _: *anyopaque,
    config: StackConfig,
    handler: PacketHandler,
    local_ip: Ipv4Address,
    pseudo_src_ip: Ipv4Address,
) !SystemStack {
    var stack: SystemStack = undefined;

    // Convert Ipv4Address to u32
    stack.local_ip = addrToU32(local_ip);
    stack.pseudo_src_ip = addrToU32(pseudo_src_ip);

    // Store handler
    stack.handler = handler;

    // Store config
    stack.config = config;

    // Initialize IP stack with empty callbacks
    const ipstack_config = ipstack.Config{
        .local_ip = stack.local_ip,
        .pseudo_src_ip = stack.pseudo_src_ip,
        .callbacks = .{},
        .idle_timeout = config.options.udp_timeout,
        .max_connections = MAX_CONNECTIONS,
    };
    ipstack.init(&stack.ipstack, ipstack_config);

    // Initialize IPv6 if enabled
    stack.ipv6_enabled = config.options.ipv6_enabled;
    if (stack.ipv6_enabled) {
        @memset(stack.local_ip6[0..], 0);
        const ipv6_config = ipstack.Ipv6Config{
            .local_ip = stack.local_ip6,
            .enabled = true,
        };
        ipstack.setIpv6Config(&stack.ipstack, ipv6_config);
    }

    // Initialize state
    stack.current_time = 0;
    stack.stats = .{};

    return stack;
}

/// Initialize a TunStack interface for the system protocol stack
///
/// This function creates a TunStack that wraps a SystemStack and provides
/// the interface expected by the TUN device for packet processing.
///
/// Parameters:
///   - allocator: Memory allocator
///   - device: TUN device reference
///   - config: Stack configuration
///   - handler: Packet handler for protocol events
///   - local_ip: Local IPv4 address
///   - pseudo_src_ip: Pseudo source IP for replies
///
/// Returns: TunStack interface ready for use with TUN device
pub fn initSystemStack(
    allocator: std.mem.Allocator,
    device: *anyopaque,
    config: StackConfig,
    handler: PacketHandler,
    local_ip: Ipv4Address,
    pseudo_src_ip: Ipv4Address,
) !TunStack {
    const system_stack = try allocator.create(SystemStack);
    system_stack.* = try createSystemStack(
        allocator,
        device,
        config,
        handler,
        local_ip,
        pseudo_src_ip,
    );

    return TunStack{
        .ctx = system_stack,
        .startFn = startFn,
        .stopFn = stopFn,
        .fdFn = fdFn,
        .processFn = processFn,
    };
}

/// Start the protocol stack
fn startFn(ctx: *anyopaque, _: *PacketHandler) TunError!void {
    const stack = @as(*SystemStack, @ptrCast(@alignCast(ctx)));
    // IP stack is always running - just reset state
    ipstack.reset(&stack.ipstack);
}

/// Stop the protocol stack
fn stopFn(ctx: *anyopaque) void {
    const stack = @as(*SystemStack, @ptrCast(@alignCast(ctx)));
    _ = stack;
    // IP stack has no resources to release (static allocation)
}

/// Get file descriptor (not used in pure protocol stack)
/// Returns -1 since we don't have a native file descriptor
fn fdFn(ctx: *anyopaque) std.posix.fd_t {
    _ = ctx;
    return -1;
}

/// Process an incoming packet from the TUN device
///
/// This function parses the IP packet and dispatches it to the appropriate
/// protocol handler based on the IP protocol number.
///
/// Parameters:
///   - ctx: SystemStack context
///   - packet: Raw IP packet from TUN device
///
/// Returns: Error on failure
pub fn processFn(ctx: *anyopaque, packet: []const u8) TunError!void {
    const stack = @as(*SystemStack, @ptrCast(@alignCast(ctx)));

    // Validate minimum packet size
    if (packet.len < ipv4.HDR_MIN_SIZE) {
        stack.stats.packets_dropped += 1;
        return error.InvalidPacket;
    }

    // Check IP version
    const version = packet[0] >> 4;
    if (version == 4) {
        // Process IPv4 packet
        ipstack.processIpv4Packet(
            &stack.ipstack,
            packet.ptr,
            packet.len,
        ) catch {
            stack.stats.packets_dropped += 1;
            return error.InvalidPacket;
        };
        stack.stats.packets_rx += 1;
    } else if (version == 6) {
        // Process IPv6 packet (forward to handler for now)
        if (stack.ipv6_enabled) {
            // IPv6 processing would go here
            stack.stats.packets_rx += 1;
        } else {
            // IPv6 not enabled, drop packet
            stack.stats.packets_dropped += 1;
            return error.NotSupported;
        }
    } else {
        stack.stats.packets_dropped += 1;
        return error.InvalidPacket;
    }
}

/// Update the timestamp (call periodically for timeout management)
///
/// The IP stack uses timestamps for connection timeout management.
/// Applications should call this function regularly with the current time.
///
/// Parameters:
///   - ctx: SystemStack context
///   - timestamp: Current timestamp in seconds
pub fn updateTimestamp(ctx: *anyopaque, timestamp: u32) void {
    const stack = @as(*SystemStack, @ptrCast(@alignCast(ctx)));
    stack.current_time = timestamp;
    ipstack.updateTimestamp(&stack.ipstack, timestamp);
}

/// Clean up timed out connections
///
/// This function should be called periodically to remove stale connections.
/// It uses the current_time set via updateTimestamp().
///
/// Parameters:
///   - ctx: SystemStack context
pub fn cleanupTimeouts(ctx: *anyopaque) void {
    const stack = @as(*SystemStack, @ptrCast(@alignCast(ctx)));
    ipstack.cleanupTimeouts(&stack.ipstack);
}

/// Get statistics from the stack
///
/// Parameters:
///   - ctx: SystemStack context
///
/// Returns: Current statistics
pub fn getStats(ctx: *anyopaque) SystemStackStats {
    const stack = @as(*SystemStack, @ptrCast(@alignCast(ctx)));
    return stack.stats;
}

/// Send a TCP packet through the stack
///
/// Parameters:
///   - ctx: SystemStack context
///   - src_ip: Source IP in network byte order
///   - src_port: Source port
///   - dst_ip: Destination IP in network byte order
///   - dst_port: Destination port
///   - flags: TCP flags
///   - data: Payload data
///   - buf: Buffer for packet building
///
/// Returns: Error on failure
pub fn sendTcp(
    ctx: *anyopaque,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    flags: u8,
    data: []const u8,
    buf: []u8,
) TunError!usize {
    const stack = @as(*SystemStack, @ptrCast(@alignCast(ctx)));
    _ = stack;

    const ip_total_len = ipv4.HDR_MIN_SIZE + tcp.HDR_MIN_SIZE + data.len;
    if (buf.len < ip_total_len) {
        return error.BufferTooSmall;
    }

    // Build IP header
    const ip_offset = ipv4.buildHeader(
        buf.ptr,
        src_ip,
        dst_ip,
        ipv4.PROTO_TCP,
        ip_total_len,
    );

    // Build TCP header
    const tcp_offset = ip_offset + ipv4.HDR_MIN_SIZE;
    _ = ipv4.tcp.buildHeader(
        buf.ptr + tcp_offset,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        0, // seq_num
        0, // ack_num
        flags,
        65535, // window
        data,
    );

    return ip_total_len;
}

/// Send a UDP packet through the stack
///
/// Parameters:
///   - ctx: SystemStack context
///   - src_ip: Source IP in network byte order
///   - src_port: Source port
///   - dst_ip: Destination IP in network byte order
///   - dst_port: Destination port
///   - data: Payload data
///   - buf: Buffer for packet building
///
/// Returns: Error on failure
pub fn sendUdp(
    ctx: *anyopaque,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    data: []const u8,
    buf: []u8,
) TunError!usize {
    const stack = @as(*SystemStack, @ptrCast(@alignCast(ctx)));
    _ = stack;

    const udp_total = udp.HDR_SIZE + data.len;
    const ip_total_len = ipv4.HDR_SIZE + udp_total;
    if (buf.len < ip_total_len) {
        return error.BufferTooSmall;
    }

    // Build IP header
    const ip_offset = ipv4.buildHeader(
        buf.ptr,
        src_ip,
        dst_ip,
        ipv4.PROTO_UDP,
        udp_total,
    );

    // Build UDP header
    const udp_offset = ip_offset + ipv4.HDR_SIZE;
    _ = udp.buildHeader(
        buf.ptr + udp_offset,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        data,
    );

    return ip_total_len;
}

// Re-export tcp for use in sendTcp
const tcp = ipstack.tcp;

test "SystemStack creation" {
    const handler = PacketHandler{
        .ctx = undefined,
        .handleTcpFn = null,
        .handleUdpFn = null,
        .handleIcmpFn = null,
        .handleTcp6Fn = null,
        .handleUdp6Fn = null,
        .handleIcmp6Fn = null,
    };

    const local_ip = Ipv4Address{ 10, 0, 0, 1 };
    const pseudo_ip = Ipv4Address{ 10, 0, 0, 2 };

    var stack = try createSystemStack(
        std.testing.allocator,
        undefined,
        .{ .options = .{} },
        handler,
        local_ip,
        pseudo_ip,
    );
    defer _ = &stack;

    try std.testing.expectEqual(@as(u32, 0x0A000001), stack.local_ip);
    try std.testing.expectEqual(@as(u32, 0x0A000002), stack.pseudo_src_ip);
}

test "SystemStack packet processing" {
    const handler = PacketHandler{
        .ctx = undefined,
        .handleTcpFn = null,
        .handleUdpFn = null,
        .handleIcmpFn = null,
        .handleTcp6Fn = null,
        .handleUdp6Fn = null,
        .handleIcmp6Fn = null,
    };

    const local_ip = Ipv4Address{ 10, 0, 0, 1 };
    const pseudo_ip = Ipv4Address{ 10, 0, 0, 2 };

    var stack = try createSystemStack(
        std.testing.allocator,
        undefined,
        .{ .options = .{} },
        handler,
        local_ip,
        pseudo_ip,
    );
    defer _ = &stack;

    // Build a minimal UDP packet
    var packet: [28]u8 = undefined;
    // IP header
    packet[0] = 0x45; // Version + IHL
    packet[1] = 0x00; // TOS
    packet[2] = 0x00; // Total length hi
    packet[3] = 28; // Total length lo
    packet[4] = 0x00; // ID
    packet[5] = 0x00; // ID
    packet[6] = 0x00; // Flags + Fragment
    packet[7] = 0x00; // Fragment
    packet[8] = 0x40; // TTL
    packet[9] = 0x11; // Protocol = UDP
    packet[10] = 0x00; // Checksum hi
    packet[11] = 0x00; // Checksum lo
    packet[12] = 10; // Source IP
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 2;
    packet[16] = 10; // Dest IP
    packet[17] = 0;
    packet[18] = 0;
    packet[19] = 1;
    // UDP header
    packet[20] = 0x12; // Source port 1234
    packet[21] = 0x34;
    packet[22] = 0x00; // Dest port 53
    packet[23] = 0x35;
    packet[24] = 0x00; // UDP length hi
    packet[25] = 8; // UDP length lo
    packet[26] = 0x00; // Checksum hi
    packet[27] = 0x00; // Checksum lo

    // Process packet
    try processFn(&stack, &packet);
}
