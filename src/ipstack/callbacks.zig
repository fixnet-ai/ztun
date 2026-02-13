//! callbacks.zig - Callback Interface Definitions
//!
//! Defines callback function types for IP stack events.
//! Applications register these callbacks to handle protocol events.

const std = @import("std");
const connection = @import("ipstack_connection");

// Forward declarations
const TcpConnection = connection.Connection;

/// TCP Accept Callback
/// Called when a SYN packet is received and a new connection is being established.
/// Applications can implement access control here.
/// src_ip: Source IP (network byte order)
/// src_port: Source port
/// dst_ip: Destination IP (network byte order)
/// dst_port: Destination port
/// Returns: true to accept connection, false to reject (send RST)
pub const OnTcpAccept = *const fn (
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
) bool;

/// TCP Data Callback
/// Called when application data is received on an established connection.
/// conn: TCP connection
/// data: Application data (payload, without TCP header)
pub const OnTcpData = *const fn (
    conn: *TcpConnection,
    data: []const u8,
) void;

/// TCP Reset Callback
/// Called when a RST packet is received or connection is reset.
/// Applications should clean up any resources associated with this connection.
/// conn: TCP connection that was reset
pub const OnTcpReset = *const fn (
    conn: *TcpConnection,
) void;

/// TCP Connection Closed Callback
/// Called when connection is fully closed (either direction).
/// Useful for cleanup and statistics.
/// conn: TCP connection that was closed
pub const OnTcpClose = *const fn (
    conn: *TcpConnection,
) void;

/// TCP Accept Complete Callback
/// Called after 3-way handshake completes and connection is established.
/// Useful for initiating application-level protocols.
/// conn: Established TCP connection
pub const OnTcpEstablished = *const fn (
    conn: *TcpConnection,
) void;

/// UDP Data Callback
/// Called when a UDP packet is received.
/// Applications should forward this data to the appropriate destination.
/// src_ip: Source IP (network byte order)
/// src_port: Source port
/// dst_ip: Destination IP (network byte order)
/// dst_port: Destination port
/// data: UDP payload
pub const OnUdp = *const fn (
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    data: []const u8,
) void;

/// ICMP Packet Callback
/// Called when an ICMP packet is received (non-echo).
/// Used for error handling and network diagnostics.
/// src_ip: Source IP (network byte order)
/// dst_ip: Destination IP (network byte order)
/// msg_type: ICMP type
/// code: ICMP code
/// data: ICMP payload
pub const OnIcmp = *const fn (
    src_ip: u32,
    dst_ip: u32,
    msg_type: u8,
    code: u8,
    data: []const u8,
) void;

/// ICMP Echo Request Callback
/// Called when an ICMP Echo Request (ping) is received.
/// Applications can implement ping handling.
/// src_ip: Source IP (network byte order)
/// dst_ip: Destination IP (network byte order)
/// identifier: ICMP identifier
/// sequence: ICMP sequence number
/// payload: Echo payload
/// Returns: true to respond, false to ignore
pub const OnIcmpEcho = *const fn (
    src_ip: u32,
    dst_ip: u32,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
) bool;

/// IPv4 Packet Callback (Raw)
/// Called for any IPv4 packet that doesn't match TCP/UDP/ICMP.
/// Useful for implementing custom protocols.
/// src_ip: Source IP (network byte order)
/// dst_ip: Destination IP (network byte order)
/// protocol: IP protocol number
/// data: Packet payload
pub const OnIpv4Packet = *const fn (
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    data: []const u8,
) void;

/// IPv6 Packet Callback (Raw)
/// Called for any IPv6 packet that doesn't match TCP/UDP/ICMPv6.
/// src_ip: Source IP (16 bytes, network byte order)
/// dst_ip: Destination IP (16 bytes)
/// next_header: Next header value
/// data: Packet payload
pub const OnIpv6Packet = *const fn (
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
    next_header: u8,
    data: []const u8,
) void;

/// IPv6 UDP Data Callback
/// Called when a UDP packet is received over IPv6.
/// src_ip: Source IPv6 address
/// src_port: Source port
/// dst_ip: Destination IPv6 address
/// dst_port: Destination port
/// data: UDP payload
pub const OnIpv6Udp = *const fn (
    src_ip: *const [16]u8,
    src_port: u16,
    dst_ip: *const [16]u8,
    dst_port: u16,
    data: []const u8,
) void;

/// ICMPv6 Packet Callback
/// Called when an ICMPv6 packet is received (non-echo).
/// Used for error handling and network diagnostics.
/// src_ip: Source IPv6 address
/// dst_ip: Destination IPv6 address
/// msg_type: ICMPv6 type
/// code: ICMPv6 code
/// data: ICMPv6 payload
pub const OnIcmpv6 = *const fn (
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
    msg_type: u8,
    code: u8,
    data: []const u8,
) void;

/// ICMPv6 Echo Request Callback
/// Called when an ICMPv6 Echo Request (ping) is received.
/// src_ip: Source IPv6 address
/// dst_ip: Destination IPv6 address
/// identifier: ICMPv6 identifier
/// sequence: ICMPv6 sequence number
/// payload: Echo payload
pub const OnIcmpv6Echo = *const fn (
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
) void;

/// Error Callback
/// Called when an error occurs in the IP stack.
/// err: Error type
/// message: Error message
pub const OnError = *const fn (
    err: Error,
    message: []const u8,
) void;

/// Error types
pub const Error = enum {
    InvalidPacket,
    ChecksumError,
    ConnectionTableFull,
    InvalidState,
    BufferOverflow,
    Timeout,
    Unknown,
};

/// Callback collection for IP stack
/// All callbacks are optional (null means no handler)
pub const Callbacks = struct {
    // TCP callbacks
    onTcpAccept: ?OnTcpAccept = null,
    onTcpData: ?OnTcpData = null,
    onTcpReset: ?OnTcpReset = null,
    onTcpClose: ?OnTcpClose = null,
    onTcpEstablished: ?OnTcpEstablished = null,

    // UDP callback
    onUdp: ?OnUdp = null,
    onIpv6Udp: ?OnIpv6Udp = null,

    // ICMP callbacks
    onIcmp: ?OnIcmp = null,
    onIcmpEcho: ?OnIcmpEcho = null,
    onIcmpv6: ?OnIcmpv6 = null,
    onIcmpv6Echo: ?OnIcmpv6Echo = null,

    // Raw packet callbacks
    onIpv4Packet: ?OnIpv4Packet = null,
    onIpv6Packet: ?OnIpv6Packet = null,

    // Error callback
    onError: ?OnError = null,
};

/// Helper to invoke optional callback safely
pub fn invokeTcpAccept(
    callbacks: *const Callbacks,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
) bool {
    if (callbacks.onTcpAccept) |cb| {
        return cb(src_ip, src_port, dst_ip, dst_port);
    }
    // Default: accept all connections
    return true;
}

pub fn invokeTcpData(
    callbacks: *const Callbacks,
    conn: *TcpConnection,
    data: []const u8,
) void {
    if (callbacks.onTcpData) |cb| {
        cb(conn, data);
    }
}

pub fn invokeTcpReset(
    callbacks: *const Callbacks,
    conn: *TcpConnection,
) void {
    if (callbacks.onTcpReset) |cb| {
        cb(conn);
    }
}

pub fn invokeTcpClose(
    callbacks: *const Callbacks,
    conn: *TcpConnection,
) void {
    if (callbacks.onTcpClose) |cb| {
        cb(conn);
    }
}

pub fn invokeTcpEstablished(
    callbacks: *const Callbacks,
    conn: *TcpConnection,
) void {
    if (callbacks.onTcpEstablished) |cb| {
        cb(conn);
    }
}

pub fn invokeUdp(
    callbacks: *const Callbacks,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    data: []const u8,
) void {
    if (callbacks.onUdp) |cb| {
        cb(src_ip, src_port, dst_ip, dst_port, data);
    }
}

pub fn invokeIcmp(
    callbacks: *const Callbacks,
    src_ip: u32,
    dst_ip: u32,
    msg_type: u8,
    code: u8,
    data: []const u8,
) void {
    if (callbacks.onIcmp) |cb| {
        cb(src_ip, dst_ip, msg_type, code, data);
    }
}

pub fn invokeIcmpEcho(
    callbacks: *const Callbacks,
    src_ip: u32,
    dst_ip: u32,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
) bool {
    if (callbacks.onIcmpEcho) |cb| {
        return cb(src_ip, dst_ip, identifier, sequence, payload);
    }
    // Default: respond to echo requests
    return true;
}

pub fn invokeError(
    callbacks: *const Callbacks,
    err: Error,
    message: []const u8,
) void {
    if (callbacks.onError) |cb| {
        cb(err, message);
    }
}

pub fn invokeIpv6Udp(
    callbacks: *const Callbacks,
    src_ip: *const [16]u8,
    src_port: u16,
    dst_ip: *const [16]u8,
    dst_port: u16,
    data: []const u8,
) void {
    if (callbacks.onIpv6Udp) |cb| {
        cb(src_ip, src_port, dst_ip, dst_port, data);
    }
}

pub fn invokeIcmpv6(
    callbacks: *const Callbacks,
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
    msg_type: u8,
    code: u8,
    data: []const u8,
) void {
    if (callbacks.onIcmpv6) |cb| {
        cb(src_ip, dst_ip, msg_type, code, data);
    }
}

pub fn invokeIcmpv6Echo(
    callbacks: *const Callbacks,
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
) void {
    if (callbacks.onIcmpv6Echo) |cb| {
        cb(src_ip, dst_ip, identifier, sequence, payload);
    }
}

// Unit tests
test "callbacks default accept" {
    const callbacks: Callbacks = .{};
    try std.testing.expect(invokeTcpAccept(&callbacks, 0, 0, 0, 0));
}

test "callbacks default echo" {
    const callbacks: Callbacks = .{};
    try std.testing.expect(invokeIcmpEcho(&callbacks, 0, 0, 0, 0, &.{}));
}

test "callbacks invoke" {
    var data_received = false;

    const callbacks: Callbacks = .{
        .onTcpAccept = struct {
            fn cb(_: u32, _: u16, _: u32, _: u16) bool {
                return true;
            }
        }.cb,
        .onTcpData = struct {
            fn cb(_: *TcpConnection, _: []const u8, flag: *bool) void {
                flag.* = true;
            }
        }.cb,
    };

    try std.testing.expect(invokeTcpAccept(&callbacks, 0, 0, 0, 0));

    var conn: connection.Connection = undefined;
    connection.initListen(&conn, 0, 0, 0, 0);
    invokeTcpData(&callbacks, &conn, "test", &data_received);
    try std.testing.expect(data_received);
}
