//! checksum.zig - Internet Checksum Utilities
//!
//! Implements RFC 1071 Internet checksum algorithm.
//! Used for IP, ICMP, TCP, and UDP checksums.

const std = @import("std");

// Minimum alignment for checksum computation
const CHECKSUM_ALIGN = 2;

/// Calculate Internet checksum (RFC 1071)
/// data: Input data (must be 2-byte aligned)
/// len: Length in bytes (must be even)
/// Returns: 16-bit checksum in host byte order
pub fn checksum(data: [*]const u8, len: usize) u16 {
    // Ensure even length
    const n = len & ~@as(usize, 1);

    var sum: u32 = 0;
    var i: usize = 0;

    // Sum 16-bit words
    while (i < n) : (i += 2) {
        sum += @as(u16, data[i]) | (@as(u16, data[i + 1]) << 8);
    }

    // Handle odd-length case
    if (n != len) {
        sum += @as(u16, data[n]);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @as(u16, @truncate(~sum));
}

/// Calculate checksum with pseudo-header (TCP/UDP/ICMPv6)
/// src_addr: Source address (4 bytes for IPv4, 16 bytes for IPv6)
/// dst_addr: Destination address
/// addr_len: Address length (4 for IPv4, 16 for IPv6)
/// protocol: Protocol number (6 for TCP, 17 for UDP, 58 for ICMPv6)
/// data: Protocol data (TCP/UDP header + payload)
/// data_len: Length of protocol data
/// Returns: 16-bit checksum in host byte order
pub fn checksumPseudo(
    src_addr: [*]const u8,
    dst_addr: [*]const u8,
    addr_len: usize,
    protocol: u8,
    data: [*]const u8,
    data_len: usize,
) u16 {
    var sum: u32 = 0;

    // Sum source address
    var i: usize = 0;
    while (i < addr_len) : (i += 2) {
        sum += @as(u16, src_addr[i]) | (@as(u16, src_addr[i + 1]) << 8);
    }

    // Sum destination address
    i = 0;
    while (i < addr_len) : (i += 2) {
        sum += @as(u16, dst_addr[i]) | (@as(u16, dst_addr[i + 1]) << 8);
    }

    // Sum protocol and length (24 bits total, expand to 32)
    sum += protocol;
    sum += @as(u16, data_len) | (@as(u16, data_len >> 8) << 8);

    // Sum protocol data
    i = 0;
    const n = data_len & ~@as(usize, 1);
    while (i < n) : (i += 2) {
        sum += @as(u16, data[i]) | (@as(u16, data[i + 1]) << 8);
    }

    // Handle odd-length case
    if (n != data_len) {
        sum += @as(u16, data[n]);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @as(u16, @truncate(~sum));
}

/// Calculate IPv4 pseudo-header checksum for TCP/UDP
/// src_ip: Source IP (network byte order, u32)
/// dst_ip: Destination IP (network byte order, u32)
/// protocol: Protocol number (6=TCP, 17=UDP)
/// len: TCP/UDP header + payload length
/// Returns: Pseudo-header partial sum (add to TCP/UDP checksum field)
pub fn checksumPseudoIPv4(src_ip: u32, dst_ip: u32, protocol: u8, len: u16) u32 {
    var sum: u32 = 0;

    // Source IP
    sum += src_ip;

    // Destination IP
    sum += dst_ip;

    // Protocol + Length (24 bits)
    sum += protocol;
    sum += len;

    // Fold
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum;
}

/// Verify a checksum is correct
/// data: Data to verify
/// len: Length of data
/// expected: Expected checksum
/// Returns: true if checksum is valid
pub fn verify(data: [*]const u8, len: usize, expected: u16) bool {
    return checksum(data, len) == expected;
}

/// Add a checksum to a buffer (for in-place computation)
/// buf: Buffer containing data
/// offset: Offset of checksum field in buffer
/// len: Total length of data (including checksum)
pub fn addChecksum(buf: [*]u8, offset: usize, len: usize) void {
    // Zero the checksum field first
    buf[offset] = 0;
    buf[offset + 1] = 0;

    // Compute checksum
    const sum = checksum(buf, len);

    // Store final checksum
    buf[offset] = @as(u8, @truncate(sum));
    buf[offset + 1] = @as(u8, @truncate(sum >> 8));
}

/// Fold 32-bit sum to 16 bits (internal helper)
fn fold(sum: u32) u16 {
    var s = sum;
    while (s >> 16 != 0) {
        s = (s & 0xFFFF) + (s >> 16);
    }
    return @as(u16, @bitCast(s));
}

// Unit tests
test "checksum basic" {
    // Test case from RFC 1071
    const data = [_]u8{ 0x00, 0x01, 0xF2, 0x03, 0xF4, 0x05, 0xF6, 0x07 };
    const expected: u16 = 0x218C;

    const result = checksum(data[0..].ptr, data.len);
    try std.testing.expectEqual(expected, result);
}

test "checksum odd length" {
    // Test with odd-length data
    const data = [_]u8{ 0x00, 0x01, 0x02 };
    const result = checksum(data[0..].ptr, data.len);
    try std.testing.expect(result != 0);
}

test "checksum zero" {
    // All zeros checksum should be 0xFFFF
    const data = [_]u8{ 0x00, 0x00 };
    const result = checksum(data[0..].ptr, data.len);
    try std.testing.expectEqual(@as(u16, 0xFFFF), result);
}

test "checksum ones" {
    // All ones should yield zero
    const data = [_]u8{ 0xFF, 0xFF };
    const result = checksum(data[0..].ptr, data.len);
    try std.testing.expectEqual(@as(u16, 0x0000), result);
}

test "checksum pseudo ipv4" {
    const src_ip: u32 = 0xC0A80101; // 192.168.1.1
    const dst_ip: u32 = 0xC0A80102; // 192.168.1.2
    const proto: u8 = 6; // TCP
    const len: u16 = 20; // TCP header

    const sum = checksumPseudoIPv4(src_ip, dst_ip, proto, len);
    try std.testing.expect(sum > 0);
}

test "verify correct checksum" {
    const data = [_]u8{ 0x00, 0x01, 0xF2, 0x03 };
    const cs = checksum(data[0..].ptr, data.len);
    try std.testing.expect(verify(data[0..].ptr, data.len, cs));
}
