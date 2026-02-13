//! icmpv6.zig - ICMPv6 Protocol Utilities
//!
//! Provides ICMPv6 header structures and packet utilities.
//! ICMPv6 is used for network diagnostics (ping), error reporting,
//! and neighbor discovery in IPv6.

const std = @import("std");
const builtin = @import("builtin");
const ipv6 = @import("ipv6");

// ICMPv6 constants
pub const HDR_SIZE = 8;

// ICMPv6 Type values
pub const TYPE_DEST_UNREACH = 1;
pub const TYPE_PACKET_TOO_BIG = 2;
pub const TYPE_TIME_EXCEEDED = 3;
pub const TYPE_PARAM_PROBLEM = 4;
pub const TYPE_ECHO_REQUEST = 128;
pub const TYPE_ECHO_REPLY = 129;
pub const TYPE_ROUTER_SOLICIT = 133;
pub const TYPE_ROUTER_ADVERT = 134;
pub const TYPE_NEIGHBOR_SOLICIT = 135;
pub const TYPE_NEIGHBOR_ADVERT = 136;
pub const TYPE_REDIRECT = 137;

// ICMPv6 Code values (for TYPE_DEST_UNREACH)
pub const CODE_NO_ROUTE = 0;
pub const CODE_PROHIBITED = 1;
pub const CODE_UNREACHABLE = 2;
pub const CODE_ADDRESS_UNREACH = 3;
pub const CODE_PORT_UNREACH = 4;

// ICMPv6 Code values (for TYPE_TIME_EXCEEDED)
pub const CODE_HOP_LIMIT = 0;
pub const CODE_FRAG_REASSEMBLY = 1;

// ICMPv6 Code values (for TYPE_PARAM_PROBLEM)
pub const CODE_HEADER_FIELD = 0;
pub const CODE_NEXT_HEADER_FIELD = 1;
pub const CODE_OPTION_FIELD = 2;

/// ICMPv6 Header (8 bytes minimum)
pub const Icmpv6Header = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    rest: u32, // Type-specific data
};

/// ICMPv6 Echo Request/Reply
pub const Icmpv6Echo = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
};

/// ICMPv6 Packet Too Big
pub const Icmpv6PacketTooBig = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    mtu: u32,
};

/// ICMPv6 Time Exceeded
pub const Icmpv6TimeExceeded = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    unused: u32,
};

/// ICMPv6 Parameter Problem
pub const Icmpv6ParamProblem = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    pointer: u32,
};

/// ICMPv6 Destination Unreachable
pub const Icmpv6DestUnreach = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    unused: u32,
};

/// ICMPv6 Packet information
pub const PacketInfo = struct {
    type: u8,
    code: u8,
    checksum_valid: bool,
    identifier: u16,
    sequence: u16,
    payload_len: usize,
    mtu: u32, // For TYPE_PACKET_TOO_BIG
    pointer: u32, // For TYPE_PARAM_PROBLEM
};

/// Parse ICMPv6 header
/// data: Pointer to ICMPv6 header
/// len: Total ICMPv6 packet length
/// src_ip: Source IPv6 address (for checksum verification)
/// dst_ip: Destination IPv6 address (for checksum verification)
/// Returns: PacketInfo on success, null if invalid
pub fn parseHeader(
    data: [*]const u8,
    len: usize,
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
) ?PacketInfo {
    if (len < HDR_SIZE) return null;

    const header = @as(*const Icmpv6Header, @ptrCast(@alignCast(data)));

    // Verify checksum using pseudo-header
    const cs = checksum(data, len, src_ip, dst_ip);
    const valid = (cs == 0);

    // Parse based on type
    var ident: u16 = 0;
    var seq: u16 = 0;
    var mtu: u32 = 0;
    var pointer: u32 = 0;

    if (header.type == TYPE_ECHO_REQUEST or header.type == TYPE_ECHO_REPLY) {
        if (len >= HDR_SIZE) {
            const echo = @as(*const Icmpv6Echo, @ptrCast(@alignCast(data)));
            ident = echo.identifier;
            seq = echo.sequence;
        }
    } else if (header.type == TYPE_PACKET_TOO_BIG) {
        if (len >= HDR_SIZE) {
            const ptb = @as(*const Icmpv6PacketTooBig, @ptrCast(@alignCast(data)));
            mtu = ptb.mtu;
        }
    } else if (header.type == TYPE_PARAM_PROBLEM) {
        if (len >= HDR_SIZE) {
            const pp = @as(*const Icmpv6ParamProblem, @ptrCast(@alignCast(data)));
            pointer = pp.pointer;
        }
    }

    return PacketInfo{
        .type = header.type,
        .code = header.code,
        .checksum_valid = valid,
        .identifier = ident,
        .sequence = seq,
        .payload_len = if (len > HDR_SIZE) len - HDR_SIZE else 0,
        .mtu = mtu,
        .pointer = pointer,
    };
}

/// Calculate ICMPv6 checksum
/// data: ICMPv6 packet data
/// len: Length of ICMPv6 packet
/// src_ip: Source IPv6 address
/// dst_ip: Destination IPv6 address
pub fn checksum(
    data: [*]const u8,
    len: usize,
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
) u16 {
    var sum: u32 = 0;

    // Pseudo-header: src_ip (16) + dst_ip (16) + length (4) + zero (3) + next_header (1)
    const src_hi = @as(*const u64, @ptrCast(&src_ip[0])).*;
    const src_lo = @as(*const u64, @ptrCast(&src_ip[8])).*;
    const dst_hi = @as(*const u64, @ptrCast(&dst_ip[0])).*;
    const dst_lo = @as(*const u64, @ptrCast(&dst_ip[8])).*;

    sum += @as(u32, @truncate(src_hi >> 32));
    sum += @as(u32, @truncate(src_hi));
    sum += @as(u32, @truncate(src_lo >> 32));
    sum += @as(u32, @truncate(src_lo));
    sum += @as(u32, @truncate(dst_hi >> 32));
    sum += @as(u32, @truncate(dst_hi));
    sum += @as(u32, @truncate(dst_lo >> 32));
    sum += @as(u32, @truncate(dst_lo));

    sum += @as(u32, len); // Length as 32-bit
    sum += ipv6.NH_ICMPV6; // Next header for ICMPv6

    // Sum ICMPv6 data (with checksum field zeroed)
    var i: usize = 0;
    while (i + 1 < len) : (i += 2) {
        if (i == 2) continue; // Skip checksum field
        const w = @as(*const u16, @ptrCast(@alignCast(data[i..].ptr))).*;
        sum += w;
    }
    if (i < len) {
        sum += @as(u32, data[i]);
    }

    // Fold
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @as(u16, ~sum);
}

/// Build ICMPv6 header (generic)
/// buf: Output buffer
/// type: ICMPv6 type
/// code: ICMPv6 code
/// rest: Rest of header value
/// Returns: Number of bytes written (8)
pub fn buildHeader(
    buf: [*]u8,
    type_: u8,
    code: u8,
    rest: u32,
) usize {
    const header = @as(*Icmpv6Header, @ptrCast(buf));
    header.type = type_;
    header.code = code;
    header.checksum = 0;
    header.rest = rest;
    return HDR_SIZE;
}

/// Build ICMPv6 Echo Request
/// buf: Output buffer
/// identifier: ICMPv6 identifier
/// sequence: ICMPv6 sequence number
/// payload: Optional payload data
/// src_ip: Source IPv6 address
/// dst_ip: Destination IPv6 address
/// Returns: Total packet length
pub fn buildEchoRequest(
    buf: [*]u8,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
) usize {
    const header = @as(*Icmpv6Echo, @ptrCast(@alignCast(buf)));
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
    header.checksum = checksum(buf[0..total_len].ptr, total_len, src_ip, dst_ip);

    return total_len;
}

/// Build ICMPv6 Echo Reply
/// buf: Output buffer
/// identifier: ICMPv6 identifier
/// sequence: ICMPv6 sequence number
/// payload: Payload from original request
/// src_ip: Source IPv6 address (TUN address)
/// dst_ip: Destination IPv6 address (original sender)
/// Returns: Total packet length
pub fn buildEchoReply(
    buf: [*]u8,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
) usize {
    const header = @as(*Icmpv6Echo, @ptrCast(@alignCast(buf)));
    header.type = TYPE_ECHO_REPLY;
    header.code = 0;
    header.checksum = 0;
    header.identifier = identifier;
    header.sequence = sequence;

    // Copy payload
    if (payload.len > 0) {
        @memcpy(buf[8..][0..payload.len], payload);
    }

    // Calculate checksum (swap src/dst for reply)
    const total_len = HDR_SIZE + payload.len;
    header.checksum = checksum(buf[0..total_len].ptr, total_len, src_ip, dst_ip);

    return total_len;
}

/// Build ICMPv6 Destination Unreachable
/// buf: Output buffer
/// code: Unreachable code
/// orig_pkt: Original IPv6 packet that caused the error
/// src_ip: Source IPv6 address
/// dst_ip: Destination IPv6 address
/// Returns: Total packet length
pub fn buildDestUnreach(
    buf: [*]u8,
    code: u8,
    orig_pkt: []const u8,
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
) usize {
    const header = @as(*Icmpv6DestUnreach, @ptrCast(buf));
    header.type = TYPE_DEST_UNREACH;
    header.code = code;
    header.checksum = 0;
    header.unused = 0;

    // Copy original packet (limited)
    const copy_len = @min(orig_pkt.len, 512);
    if (copy_len > 0) {
        @memcpy(buf[8..][0..copy_len], orig_pkt);
    }

    const total_len = HDR_SIZE + copy_len;
    header.checksum = checksum(buf[0..total_len].ptr, total_len, src_ip, dst_ip);

    return total_len;
}

/// Build ICMPv6 Time Exceeded
/// buf: Output buffer
/// code: Time exceeded code
/// orig_pkt: Original IPv6 packet
/// src_ip: Source IPv6 address
/// dst_ip: Destination IPv6 address
/// Returns: Total packet length
pub fn buildTimeExceeded(
    buf: [*]u8,
    code: u8,
    orig_pkt: []const u8,
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
) usize {
    const header = @as(*Icmpv6TimeExceeded, @ptrCast(buf));
    header.type = TYPE_TIME_EXCEEDED;
    header.code = code;
    header.checksum = 0;
    header.unused = 0;

    const copy_len = @min(orig_pkt.len, 512);
    if (copy_len > 0) {
        @memcpy(buf[8..][0..copy_len], orig_pkt);
    }

    const total_len = HDR_SIZE + copy_len;
    header.checksum = checksum(buf[0..total_len].ptr, total_len, src_ip, dst_ip);

    return total_len;
}

/// Check if ICMPv6 type is an error message
pub fn isError(type_: u8) bool {
    return switch (type_) {
        TYPE_DEST_UNREACH,
        TYPE_PACKET_TOO_BIG,
        TYPE_TIME_EXCEEDED,
        TYPE_PARAM_PROBLEM,
        => true,
        else => false,
    };
}

/// Check if ICMPv6 type is a query message
pub fn isQuery(type_: u8) bool {
    return switch (type_) {
        TYPE_ECHO_REQUEST,
        TYPE_ECHO_REPLY,
        TYPE_ROUTER_SOLICIT,
        TYPE_ROUTER_ADVERT,
        TYPE_NEIGHBOR_SOLICIT,
        TYPE_NEIGHBOR_ADVERT,
        TYPE_REDIRECT,
        => true,
        else => false,
    };
}

/// Check if ICMPv6 packet needs a response (ping request)
pub fn needsResponse(type_: u8) bool {
    return type_ == TYPE_ECHO_REQUEST;
}

/// Check if ICMPv6 packet should be forwarded to proxy
/// (Only echo requests are handled locally, others are silently dropped)
pub fn shouldForward(type_: u8) bool {
    return !isQuery(type_);
}

// Unit tests
test "ICMPv6 header size" {
    try std.testing.expectEqual(@as(usize, 8), HDR_SIZE);
}

test "ICMPv6 echo request build" {
    var buf: [1500]u8 = undefined;
    var src: [16]u8 = undefined;
    var dst: [16]u8 = undefined;
    @memset(src[0..], 0);
    @memset(dst[0..], 0);
    src[15] = 1;
    dst[15] = 2;

    const len = buildEchoRequest(buf[0..].ptr, 1234, 1, "test", &src, &dst);
    try std.testing.expectEqual(@as(usize, 12), len);

    const header = @as(*const Icmpv6Echo, @ptrCast(@alignCast(buf[0..].ptr)));
    try std.testing.expectEqual(@as(u8, TYPE_ECHO_REQUEST), header.type);
    try std.testing.expectEqual(@as(u16, 1234), header.identifier);
}

test "ICMPv6 type classification" {
    try std.testing.expect(isError(TYPE_DEST_UNREACH));
    try std.testing.expect(!isError(TYPE_ECHO_REQUEST));

    try std.testing.expect(isQuery(TYPE_ECHO_REQUEST));
    try std.testing.expect(!isQuery(TYPE_DEST_UNREACH));

    try std.testing.expect(needsResponse(TYPE_ECHO_REQUEST));
    try std.testing.expect(!needsResponse(TYPE_ECHO_REPLY));
}

comptime {
    // Ensure header is correct size
    if (builtin.is_test) {
        std.debug.assert(@sizeOf(Icmpv6Header) == 8);
        std.debug.assert(@sizeOf(Icmpv6Echo) == 8);
    }
}
