//! socks5.zig - SOCKS5 proxy backend
//!
//! Implements the SOCKS5 proxy protocol for TCP forwarding.

const std = @import("std");

/// SOCKS5 proxy type (re-exported from route.zig)
const ProxyType = @import("../route.zig").ProxyType;

/// SOCKS5 connection state
const Socks5State = enum(u8) {
    /// Initial state, send greeting
    Greeting = 0,
    /// Waiting for greeting acknowledgment
    GreetingAck = 1,
    /// Send connect request
    Connect = 2,
    /// Waiting for connect acknowledgment
    ConnectAck = 3,
    /// Ready to forward data
    Ready = 4,
    /// Error state
    Error = 5,
};

/// SOCKS5 authentication methods
const AuthMethod = enum(u8) {
    /// No authentication required
    None = 0,
    /// Username/password authentication
    Username = 2,
    /// No acceptable methods
    NoneAcceptable = 0xFF,
};

/// SOCKS5 reply codes
const ReplyCode = enum(u8) {
    /// Request succeeded
    Succeeded = 0,
    /// General SOCKS server failure
    GeneralFailure = 1,
    /// Connection not allowed by ruleset
    NotAllowed = 2,
    /// Network unreachable
    NetworkUnreachable = 3,
    /// Host unreachable
    HostUnreachable = 4,
    /// Connection refused
    ConnectionRefused = 5,
    /// TTL expired
    TtlExpired = 6,
    /// Command not supported
    CommandNotSupported = 7,
    /// Address type not supported
    AddressNotSupported = 8,
};

/// SOCKS5 connection handle
pub const Socks5Conn = opaque {};

/// Create a new SOCKS5 connection
pub fn socks5Connect(
    addr: [*:0]const u8,
    port: u16,
) !*Socks5Conn {
    _ = addr;
    _ = port;
    @panic("Not implemented yet");
}

/// Send data through SOCKS5 connection
pub fn socks5Send(conn: *Socks5Conn, data: []const u8) !usize {
    _ = conn;
    _ = data;
    @panic("Not implemented yet");
}

/// Receive data from SOCKS5 connection
pub fn socks5Recv(conn: *Socks5Conn, buf: []u8) !usize {
    _ = conn;
    _ = buf;
    @panic("Not implemented yet");
}

/// Close SOCKS5 connection
pub fn socks5Close(conn: *Socks5Conn) void {
    _ = conn;
}

/// Check if SOCKS5 connection is ready
pub fn socks5IsReady(conn: *Socks5Conn) bool {
    _ = conn;
    return false;
}

/// Get SOCKS5 connection state
pub fn socks5State(conn: *Socks5Conn) Socks5State {
    _ = conn;
    return .Error;
}

/// Build SOCKS5 greeting message
pub fn buildGreeting(buf: []u8) usize {
    if (buf.len < 3) return 0;

    buf[0] = 0x05;  // SOCKS5 version
    buf[1] = 1;      // Number of auth methods
    buf[2] = 0x00;   // No authentication

    return 3;
}

/// Parse SOCKS5 greeting acknowledgment
pub fn parseGreetingAck(data: []const u8) !void {
    if (data.len < 2) return error.InvalidData;
    if (data[0] != 0x05) return error.InvalidVersion;
    if (data[1] == 0xFF) return error.AuthRequired;
}

/// Build SOCKS5 connect request
pub fn buildConnectRequest(
    buf: []u8,
    dst_ip: u32,
    dst_port: u16,
) usize {
    if (buf.len < 10) return 0;

    buf[0] = 0x05;  // SOCKS5 version
    buf[1] = 0x01;  // CONNECT command
    buf[2] = 0x00;  // Reserved

    // IPv4 address type
    buf[3] = 0x01;

    // Destination IP (network byte order)
    @memcpy(buf[4..8], std.mem.asBytes(&dst_ip));

    // Destination port (network byte order)
    const port_be = std.mem.nativeToBig(u16, dst_port);
    @memcpy(buf[8..10], std.mem.asBytes(&port_be));

    return 10;
}

/// Parse SOCKS5 connect reply
pub fn parseConnectReply(data: []const u8) !void {
    if (data.len < 10) return error.InvalidData;
    if (data[0] != 0x05) return error.InvalidVersion;
    if (data[1] != 0x00) return error.ConnectionFailed;
}

/// Convert IP address to SOCKS5 address format
pub fn ipToSocks5Addr(ip: u32, buf: []u8) usize {
    if (buf.len < 5) return 0;

    buf[0] = 0x01;  // IPv4 address type
    @memcpy(buf[1..5], std.mem.asBytes(&ip));

    return 5;
}
