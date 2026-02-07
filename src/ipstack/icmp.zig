//! icmp.zig - ICMP Protocol Utilities
//!
//! Provides ICMPv4 header structures and packet utilities.
//! ICMP is used for network diagnostics and error reporting.

const std = @import("std");
const builtin = @import("builtin");
const checksum = @import("ipstack_checksum");

// ICMPv4 constants
pub const HDR_SIZE = 8;

// ICMPv4 Type values
pub const TYPE_ECHO_REPLY = 0;
pub const TYPE_DEST_UNREACH = 3;
pub const TYPE_SOURCE_QUENCH = 4;
pub const TYPE_REDIRECT = 5;
pub const TYPE_ECHO_REQUEST = 8;
pub const TYPE_ROUTER_ADVERT = 9;
pub const TYPE_ROUTER_SOLICIT = 10;
pub const TYPE_TIME_EXCEEDED = 11;
pub const TYPE_PARAM_PROBLEM = 12;
pub const TYPE_TIMESTAMP_REQUEST = 13;
pub const TYPE_TIMESTAMP_REPLY = 14;
pub const TYPE_INFO_REQUEST = 15;
pub const TYPE_INFO_REPLY = 16;
pub const TYPE_ADDRESS_MASK_REQUEST = 17;
pub const TYPE_ADDRESS_MASK_REPLY = 18;

// ICMPv4 Code values (for TYPE_DEST_UNREACH)
pub const CODE_NET_UNREACH = 0;
pub const CODE_HOST_UNREACH = 1;
pub const CODE_PROTO_UNREACH = 2;
pub const CODE_PORT_UNREACH = 3;
pub const CODE_FRAG_NEEDED = 4;
pub const CODE_ROUTE_FAILED = 5;

// ICMPv4 Code values (for TYPE_TIME_EXCEEDED)
pub const CODE_TTL_EXPIRED = 0;
pub const CODE_FRAG_EXPIRED = 1;

// ICMPv4 Code values (for TYPE_REDIRECT)
pub const CODE_REDIRECT_NET = 0;
pub const CODE_REDIRECT_HOST = 1;
pub const CODE_REDIRECT_TOS_NET = 2;
pub const CODE_REDIRECT_TOS_HOST = 3;

/// ICMPv4 Header (8 bytes minimum)
pub const IcmpHeader = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    rest: u32,  // Type-specific data (varies by type)
};

/// ICMPv4 Echo Request/Reply (8 bytes)
pub const IcmpEcho = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
};

/// ICMPv4 Destination Unreachable (with original packet)
pub const IcmpDestUnreach = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    unused: u32,
    // Followed by original IP header + 8 bytes of original data
};

/// ICMP Time Exceeded
pub const IcmpTimeExceeded = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    unused: u32,
    // Followed by original IP header + 8 bytes of original data
};

/// ICMP Packet information
pub const PacketInfo = struct {
    type: u8,
    code: u8,
    checksum_valid: bool,
    identifier: u16,
    sequence: u16,
    payload_len: usize,
};

/// Parse ICMP header
/// data: Pointer to ICMP header
/// len: Total ICMP packet length
/// Returns: PacketInfo on success, null if invalid
pub fn parseHeader(data: [*]const u8, len: usize) ?PacketInfo {
    if (len < HDR_SIZE) return null;

    const header = @as(*const IcmpHeader, @ptrCast(@alignCast(data)));

    // Verify checksum
    const cs = checksum.checksum(data, len);
    const valid = (cs == 0);

    // Parse based on type
    var ident: u16 = 0;
    var seq: u16 = 0;

    if (header.type == TYPE_ECHO_REQUEST or header.type == TYPE_ECHO_REPLY) {
        if (len >= HDR_SIZE) {
            const echo = @as(*const IcmpEcho, @ptrCast(@alignCast(data)));
            ident = echo.identifier;
            seq = echo.sequence;
        }
    }

    return PacketInfo{
        .type = header.type,
        .code = header.code,
        .checksum_valid = valid,
        .identifier = ident,
        .sequence = seq,
        .payload_len = if (len > HDR_SIZE) len - HDR_SIZE else 0,
    };
}

/// Build ICMP header (generic)
/// buf: Output buffer
/// type: ICMP type
/// code: ICMP code
/// rest: Rest of header value
/// Returns: Number of bytes written (8)
pub fn buildHeader(
    buf: [*]u8,
    type_: u8,
    code: u8,
    rest: u32,
) usize {
    const header = @as(*IcmpHeader, @ptrCast(buf));
    header.type = type_;
    header.code = code;
    header.checksum = 0;
    header.rest = rest;
    return HDR_SIZE;
}

/// Build ICMP Echo Request
/// buf: Output buffer
/// identifier: ICMP identifier
/// sequence: ICMP sequence number
/// payload: Optional payload data
/// Returns: Total packet length
pub fn buildEchoRequest(
    buf: [*]u8,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
) usize {
    const header = @as(*IcmpEcho, @ptrCast(@alignCast(buf)));
    header.type = TYPE_ECHO_REQUEST;
    header.code = 0;
    header.checksum = 0;
    header.identifier = identifier;
    header.sequence = sequence;

    // Copy payload if present
    if (payload.len > 0) {
        @memcpy(buf[8..][0..payload.len], payload);
    }

    // Calculate checksum
    const total_len = HDR_SIZE + payload.len;
    const cs = checksum.checksum(buf, total_len);
    header.checksum = cs;

    return total_len;
}

/// Build ICMP Echo Reply
/// buf: Output buffer
/// identifier: ICMP identifier
/// sequence: ICMP sequence number
/// payload: Payload from original request
/// Returns: Total packet length
pub fn buildEchoReply(
    buf: [*]u8,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
) usize {
    const header = @as(*IcmpEcho, @ptrCast(@alignCast(buf)));
    header.type = TYPE_ECHO_REPLY;
    header.code = 0;
    header.checksum = 0;
    header.identifier = identifier;
    header.sequence = sequence;

    // Copy payload
    if (payload.len > 0) {
        @memcpy(buf[8..][0..payload.len], payload);
    }

    // Calculate checksum
    const total_len = HDR_SIZE + payload.len;
    const cs = checksum.checksum(buf, total_len);
    header.checksum = cs;

    return total_len;
}

/// Build ICMP Destination Unreachable
/// buf: Output buffer
/// code: Unreachable code
/// orig_pkt: Original packet that caused the error (IP header + 8 bytes of data)
/// Returns: Total packet length
pub fn buildDestUnreach(
    buf: [*]u8,
    code: u8,
    orig_pkt: []const u8,
) usize {
    const header = @as(*IcmpDestUnreach, @ptrCast(buf));
    header.type = TYPE_DEST_UNREACH;
    header.code = code;
    header.checksum = 0;
    header.unused = 0;

    // Copy original packet (limited to avoid overflow)
    const copy_len = @min(orig_pkt.len, 512);
    if (copy_len > 0) {
        @memcpy(buf[8..][0..copy_len], orig_pkt);
    }

    // Calculate checksum
    const total_len = HDR_SIZE + copy_len;
    const cs = checksum.checksum(buf, total_len);
    header.checksum = cs;

    return total_len;
}

/// Build ICMP Time Exceeded
/// buf: Output buffer
/// code: Time exceeded code (TTL or Fragment)
/// orig_pkt: Original packet
/// Returns: Total packet length
pub fn buildTimeExceeded(
    buf: [*]u8,
    code: u8,
    orig_pkt: []const u8,
) usize {
    const header = @as(*IcmpTimeExceeded, @ptrCast(buf));
    header.type = TYPE_TIME_EXCEEDED;
    header.code = code;
    header.checksum = 0;
    header.unused = 0;

    // Copy original packet
    const copy_len = @min(orig_pkt.len, 512);
    if (copy_len > 0) {
        @memcpy(buf[8..][0..copy_len], orig_pkt);
    }

    const total_len = HDR_SIZE + copy_len;
    const cs = checksum.checksum(buf, total_len);
    header.checksum = cs;

    return total_len;
}

/// Check if ICMP type is an error message
pub fn isError(type_: u8) bool {
    return switch (type_) {
        TYPE_DEST_UNREACH,
        TYPE_SOURCE_QUENCH,
        TYPE_REDIRECT,
        TYPE_TIME_EXCEEDED,
        TYPE_PARAM_PROBLEM,
        => true,
        else => false,
    };
}

/// Check if ICMP type is a query message
pub fn isQuery(type_: u8) bool {
    return switch (type_) {
        TYPE_ECHO_REQUEST,
        TYPE_ECHO_REPLY,
        TYPE_TIMESTAMP_REQUEST,
        TYPE_TIMESTAMP_REPLY,
        TYPE_INFO_REQUEST,
        TYPE_INFO_REPLY,
        TYPE_ADDRESS_MASK_REQUEST,
        TYPE_ADDRESS_MASK_REPLY,
        => true,
        else => false,
    };
}

/// Check if ICMP packet needs a response (ping request)
pub fn needsResponse(type_: u8) bool {
    return type_ == TYPE_ECHO_REQUEST;
}

// Unit tests
test "ICMP header size" {
    try std.testing.expectEqual(@as(usize, 8), HDR_SIZE);
}

test "ICMP echo request" {
    var buf: [1500]u8 = undefined;

    const len = buildEchoRequest(buf[0..].ptr, 1234, 1, "test");
    try std.testing.expectEqual(@as(usize, 12), len);

    // Parse back
    const info = parseHeader(buf[0..].ptr, len);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(@as(u8, TYPE_ECHO_REQUEST), info.?.type);
    try std.testing.expectEqual(@as(u16, 1234), info.?.identifier);
    try std.testing.expectEqual(@as(u16, 1), info.?.sequence);
    try std.testing.expect(info.?.checksum_valid);
}

test "ICMP echo reply" {
    var buf: [1500]u8 = undefined;

    const len = buildEchoReply(buf[0..].ptr, 1234, 1, "test");
    try std.testing.expectEqual(@as(usize, 12), len);

    const info = parseHeader(buf[0..].ptr, len);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(@as(u8, TYPE_ECHO_REPLY), info.?.type);
    try std.testing.expect(info.?.checksum_valid);
}

test "ICMP type classification" {
    try std.testing.expect(isError(TYPE_DEST_UNREACH));
    try std.testing.expect(!isError(TYPE_ECHO_REQUEST));

    try std.testing.expect(isQuery(TYPE_ECHO_REQUEST));
    try std.testing.expect(!isQuery(TYPE_DEST_UNREACH));

    try std.testing.expect(needsResponse(TYPE_ECHO_REQUEST));
    try std.testing.expect(!needsResponse(TYPE_ECHO_REPLY));
    try std.testing.expect(!needsResponse(TYPE_DEST_UNREACH));
}

test "ICMP checksum" {
    var buf: [8]u8 = undefined;

    // Build echo request without checksum
    const echo = @as(*IcmpEcho, @ptrCast(buf[0..].ptr));
    echo.type = TYPE_ECHO_REQUEST;
    echo.code = 0;
    echo.checksum = 0;
    echo.identifier = 1234;
    echo.sequence = 1;

    const cs = checksum.checksum(buf[0..].ptr, 8);
    try std.testing.expect(cs != 0);
}

comptime {
    // Ensure header is correct size
    if (builtin.is_test) {
        std.debug.assert(@sizeOf(IcmpHeader) == 8);
        std.debug.assert(@sizeOf(IcmpEcho) == 8);
    }
}
