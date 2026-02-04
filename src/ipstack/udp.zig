//! udp.zig - UDP Protocol Utilities
//!
//! Provides UDP header structures and packet building utilities.
//! UDP is stateless - no connection tracking required.

const std = @import("std");
const builtin = @import("builtin");
const checksum = @import("checksum");

// UDP header size
pub const HDR_SIZE = 8;

/// UDP Header (8 bytes)
pub const UdpHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

/// UDP packet information
pub const PacketInfo = struct {
    src_port: u16,
    dst_port: u16,
    length: usize,
    payload_len: usize,
};

/// Parse UDP header
/// data: Pointer to UDP header
/// total_len: Total UDP packet length
/// Returns: PacketInfo on success, null if invalid
pub fn parseHeader(data: [*]const u8, total_len: usize) ?PacketInfo {
    if (total_len < HDR_SIZE) return null;

    const header = @as(*const UdpHeader, @ptrCast(data));
    // Read length in network byte order (big-endian)
    const length = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(&header.length)), .big);

    if (length < HDR_SIZE or @as(usize, length) > total_len) return null;

    // Read ports in network byte order
    const src_port = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(&header.src_port)), .big);
    const dst_port = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(&header.dst_port)), .big);

    return PacketInfo{
        .src_port = src_port,
        .dst_port = dst_port,
        .length = @as(usize, length),
        .payload_len = @as(usize, length) - HDR_SIZE,
    };
}

/// Build UDP header
/// buf: Output buffer (must be at least HDR_SIZE bytes)
/// src_port: Source port (network byte order)
/// dst_port: Destination port (network byte order)
/// payload_len: UDP payload length
/// Returns: Number of bytes written (8)
pub fn buildHeader(
    buf: [*]u8,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
) usize {
    const header = @as(*UdpHeader, @ptrCast(buf));

    // Write ports in network byte order
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&header.src_port)), src_port, .big);
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&header.dst_port)), dst_port, .big);

    // Write length in network byte order
    const total_len = HDR_SIZE + payload_len;
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&header.length)), @as(u16, total_len), .big);

    header.checksum = 0;

    return HDR_SIZE;
}

/// Build UDP header with checksum (IPv4)
/// buf: Output buffer
/// src_ip: Source IP (network byte order)
/// dst_ip: Destination IP
/// src_port: Source port
/// dst_port: Destination port
/// payload: UDP payload
/// Returns: Header size (8)
pub fn buildHeaderWithChecksum(
    buf: [*]u8,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
) usize {
    const header_len = buildHeader(buf, src_port, dst_port, payload.len);

    // Compute pseudo-header sum
    const pseudo_sum = checksum.checksumPseudoIPv4(src_ip, dst_ip, 17, @as(u16, header_len) + @as(u16, payload.len));

    // Compute full checksum
    const header_u16 = @as([*]const u16, @ptrCast(buf));
    var sum: u32 = pseudo_sum;
    sum += header_u16[0]; // src_port + dst_port
    sum += header_u16[1]; // length
    sum += header_u16[2]; // checksum (0) + padding

    // Add payload
    var i: usize = 0;
    while (i + 1 < payload.len) : (i += 2) {
        sum += @as(u16, payload[i]) | (@as(u16, payload[i + 1]) << 8);
    }

    if (i < payload.len) {
        sum += @as(u16, payload[i]);
    }

    // Fold
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const cs = @as(u16, @bitCast(sum));
    // Write checksum in network byte order
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&buf[6])), ~cs, .big);

    return header_len;
}

/// Build UDP header with checksum (IPv6)
/// buf: Output buffer
/// src_addr: Source IPv6 address (16 bytes)
/// dst_addr: Destination IPv6 address
/// src_port: Source port
/// dst_port: Destination port
/// payload: UDP payload
/// Returns: Header size (8)
pub fn buildHeaderWithChecksumIPv6(
    buf: [*]u8,
    src_addr: *const [16]u8,
    dst_addr: *const [16]u8,
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
) usize {
    const header_len = buildHeader(buf, src_port, dst_port, payload.len);

    // Compute pseudo-header sum for IPv6
    var sum: u32 = checksum.checksumPseudoHeader(
        src_addr,
        dst_addr,
        17, // Next Header = UDP
        @as(u32, header_len) + @as(u32, payload.len),
    );

    // Add UDP header fields (length and checksum)
    const header_u16 = @as([*]const u16, @ptrCast(buf));
    sum += header_u16[0]; // src_port + dst_port
    sum += header_u16[1]; // length
    sum += header_u16[2]; // checksum (0) + padding

    // Add payload
    var i: usize = 0;
    while (i + 1 < payload.len) : (i += 2) {
        sum += @as(u16, payload[i]) | (@as(u16, payload[i + 1]) << 8);
    }

    if (i < payload.len) {
        sum += @as(u16, payload[i]);
    }

    // Fold
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const cs = @as(u16, @bitCast(sum));
    // Write checksum in network byte order
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&buf[6])), ~cs, .big);

    return header_len;
}

/// Verify UDP checksum
/// data: UDP packet data (header + payload)
/// len: Total length
/// src_ip: Source IP (for pseudo-header)
/// dst_ip: Destination IP
/// Returns: true if checksum is valid
pub fn verifyChecksum(
    data: [*]const u8,
    len: usize,
    src_ip: u32,
    dst_ip: u32,
) bool {
    if (len < HDR_SIZE) return false;

    // Read checksum in network byte order
    const saved_checksum = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(&data[6])), .big);

    // Zero checksum field (must write in network byte order)
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&data[6])), 0, .big);

    // Compute checksum
    const pseudo_sum = checksum.checksumPseudoIPv4(src_ip, dst_ip, 17, @as(u16, len));

    const header_u16 = @as([*]const u16, @ptrCast(data));
    var sum: u32 = pseudo_sum;
    var i: usize = 0;
    while (i < len / 2) : (i += 1) {
        sum += header_u16[i];
    }

    if (len % 2 == 1) {
        sum += @as(u16, data[len - 1]);
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const computed = ~@as(u16, @bitCast(sum));

    // Restore checksum (in network byte order)
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&data[6])), saved_checksum, .big);

    return computed == saved_checksum;
}

/// UDP port utilities
pub const PORT_ANY = 0;
pub const PORT_ECHO = 7;
pub const PORT_DISCARD = 9;
pub const PORT_DAYTIME = 13;
pub const PORT_QOTD = 17;
pub const PORT_CHARGEN = 19;
pub const PORT_FTP = 21;
pub const PORT_TELNET = 23;
pub const PORT_SMTP = 25;
pub const PORT_TIME = 37;
pub const PORT_DNS = 53;
pub const PORT_BOOTPS = 67;
pub const PORT_BOOTPC = 68;
pub const PORT_TFTP = 69;
pub const PORT_HTTP = 80;
pub const PORT_POP3 = 110;
pub const PORT_NTP = 123;
pub const PORT_IMAP = 143;
pub const PORT_SNMP = 161;
pub const PORT_SNMP_TRAP = 162;
pub const PORT_LDAP = 389;
pub const PORT_HTTPS = 443;

// Unit tests
test "UDP header size" {
    try std.testing.expectEqual(@as(usize, 8), HDR_SIZE);
}

test "UDP build and parse" {
    var buf: [1500]u8 = undefined;

    // Build
    const len = buildHeader(buf[0..].ptr, 12345, 80, 100);
    try std.testing.expectEqual(@as(usize, 8), len);

    // Parse
    const info = parseHeader(buf[0..].ptr, 108);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(@as(u16, 12345), info.?.src_port);
    try std.testing.expectEqual(@as(u16, 80), info.?.dst_port);
    try std.testing.expectEqual(@as(usize, 108), info.?.length);
    try std.testing.expectEqual(@as(usize, 100), info.?.payload_len);
}

test "UDP parse invalid" {
    var buf: [1500]u8 = undefined;

    // Too short
    try std.testing.expect(parseHeader(buf[0..].ptr, 4) == null);

    // Invalid length - write in network byte order
    _ = buildHeader(buf[0..].ptr, 12345, 80, 100);
    // Write invalid length (4) in network byte order
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&buf[4])), 4, .big);
    try std.testing.expect(parseHeader(buf[0..].ptr, 108) == null);
}

comptime {
    // Ensure header is correct size
    if (builtin.is_test) {
        std.debug.assert(@sizeOf(UdpHeader) == 8);
    }
}
