//! ipv4.zig - IPv4 Packet Parsing and Building
//!
//! Provides IPv4 header structures and utilities for packet processing.
//! Supports header parsing, building, and checksum verification.

const std = @import("std");
const builtin = @import("builtin");

// IP protocol numbers
pub const PROTO_ICMP = 1;
pub const PROTO_TCP = 6;
pub const PROTO_UDP = 17;
pub const PROTO_ICMPV6 = 58;

// IP header size constants
pub const HDR_MIN_SIZE = 20;
pub const HDR_MAX_SIZE = 60;
pub const MAX_PACKET_SIZE = 65535;

// IPv4 Address utilities
pub const Ipv4Address = [4]u8;

/// IPv4 Header (20 bytes minimum)
/// Packed structure for direct memory access
pub const Ipv4Header = extern struct {
    // First row: version + IHL + TOS + total length
    ver_ihl: u8,
    tos: u8,
    total_len: u16,

    // Second row: identification + flags + fragment offset
    identification: u16,
    flags_frag: u16,

    // Third row: TTL + protocol + checksum
    ttl: u8,
    protocol: u8,
    checksum: u16,

    // Source and destination addresses
    src_addr: u32,
    dst_addr: u32,

    // Options follow (if IHL > 5)
};

/// IPv4 Header with options (maximum 60 bytes)
pub const Ipv4HeaderFull = extern struct {
    ver_ihl: u8,
    tos: u8,
    total_len: u16,
    identification: u16,
    flags_frag: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
    options: [40]u8,  // Maximum options: 60 - 20 = 40 bytes
};

/// Get IP version from header (bits 4-7 of first byte)
pub fn getVersion(header: *const Ipv4Header) u4 {
    return @as(u4, header.ver_ihl >> 4);
}

/// Get IHL (Internet Header Length) from header (bits 0-3 of first byte)
pub fn getIHL(header: *const Ipv4Header) u4 {
    return @as(u4, header.ver_ihl & 0x0F);
}

/// Set version and IHL
pub fn setVersionIHL(header: *Ipv4Header, version: u4, ihl: u4) void {
    header.ver_ihl = (version << 4) | ihl;
}

/// Get total header size in bytes
pub fn headerSize(header: *const Ipv4Header) usize {
    return @as(usize, getIHL(header)) * 4;
}

/// Get flags from flags_frag field (bits 13-15)
pub fn getFlags(header: *const Ipv4Header) u3 {
    return @as(u3, (header.flags_frag >> 13) & 0x07);
}

/// Get fragment offset from flags_frag field (bits 0-12)
pub fn getFragmentOffset(header: *const Ipv4Header) u13 {
    return @as(u13, header.flags_frag & 0x1FFF);
}

/// Set flags and fragment offset
pub fn setFlagsFrag(header: *Ipv4Header, flags: u3, offset: u13) void {
    header.flags_frag = (@as(u16, flags) << 13) | offset;
}

/// Fragment flags
pub const FRAG_DONT = 0x4000;  // Don't fragment
pub const FRAG_MORE = 0x2000;  // More fragments
pub const FRAG_OFFSET_MASK = 0x1FFF;

/// IPv4 packet information extracted from header
pub const PacketInfo = struct {
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    total_len: usize,
    header_len: usize,
    payload_len: usize,
    is_fragment: bool,
    is_first_fragment: bool,
};

/// Parse IPv4 header and extract packet information
/// Returns: PacketInfo on success, null if invalid header
pub fn parseHeader(data: [*]const u8, len: usize) ?PacketInfo {
    if (len < HDR_MIN_SIZE) return null;

    const header = @as(*const Ipv4Header, @ptrCast(data));

    // Validate version
    if (getVersion(header) != 4) return null;

    const ihl = getIHL(header);
    if (ihl < 5) return null;  // Minimum IHL is 5 (20 bytes)

    const hdr_size = @as(usize, ihl) * 4;
    if (len < hdr_size) return null;
    if (hdr_size > HDR_MAX_SIZE) return null;

    // Validate total length (network byte order -> big-endian)
    const total_len = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(&header.total_len)), .big);
    if (total_len < hdr_size or @as(usize, total_len) > len) return null;

    // Check if this is a fragment
    const flags = getFlags(header);
    const offset = getFragmentOffset(header);
    const is_fragment = offset != 0 or (flags & FRAG_MORE) != 0;
    const is_first_fragment = (offset == 0);

    // Read IP addresses from raw packet data (network byte order)
    const src_ip = std.mem.readInt(u32, data[12..16], .big);
    const dst_ip = std.mem.readInt(u32, data[16..20], .big);

    return PacketInfo{
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .protocol = header.protocol,
        .total_len = @as(usize, total_len),
        .header_len = hdr_size,
        .payload_len = @as(usize, total_len) - hdr_size,
        .is_fragment = is_fragment,
        .is_first_fragment = is_first_fragment,
    };
}

/// Build IPv4 header (without options)
/// buf: Output buffer (must be at least HDR_MIN_SIZE bytes)
/// src_ip: Source IP (network byte order)
/// dst_ip: Destination IP (network byte order)
/// protocol: IP protocol number
/// payload_len: Length of payload (TCP/UDP header + data)
/// Returns: Number of bytes written (20 for standard header)
pub fn buildHeader(
    buf: [*]u8,
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    payload_len: usize,
) usize {
    const header = @as(*Ipv4Header, @ptrCast(buf));

    // Version (4) and IHL (5 = 20 bytes)
    header.ver_ihl = (4 << 4) | 5;

    // Type of Service (default 0)
    header.tos = 0;

    // Total length = header + payload (write in network byte order)
    const total_len = HDR_MIN_SIZE + payload_len;
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&header.total_len)), @as(u16, @intCast(total_len)), .big);

    // Identification (for fragmentation)
    header.identification = 0;

    // Flags and fragment offset (no fragmentation)
    header.flags_frag = FRAG_DONT;

    // Time to Live
    header.ttl = 64;

    // Protocol
    header.protocol = protocol;

    // Checksum (will be filled by caller)
    header.checksum = 0;

    // Source and destination addresses
    header.src_addr = src_ip;
    header.dst_addr = dst_ip;

    return HDR_MIN_SIZE;
}

/// Calculate and set header checksum
pub fn setChecksum(buf: [*]u8, ihl: u4) void {
    const header = @as(*Ipv4Header, @ptrCast(buf));
    header.checksum = 0;

    const hdr_size = @as(usize, ihl) * 4;
    const cs = checksum(buf, hdr_size);
    // Write checksum in network byte order
    std.mem.writeInt(u16, @as(*[2]u8, @ptrCast(&header.checksum)), cs, .big);
}

/// Build IPv4 header with checksum
pub fn buildHeaderWithChecksum(
    buf: [*]u8,
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    payload_len: usize,
) usize {
    const len = buildHeader(buf, src_ip, dst_ip, protocol, payload_len);
    setChecksum(buf, 5);
    return len;
}

/// Convert u32 IP to bytes (network byte order)
pub fn ipToBytes(ip: u32, out: *[4]u8) void {
    out[0] = @as(u8, @truncate(ip >> 24));
    out[1] = @as(u8, @truncate(ip >> 16));
    out[2] = @as(u8, @truncate(ip >> 8));
    out[3] = @as(u8, @truncate(ip));
}

/// Convert bytes to u32 IP (network byte order)
pub fn bytesToIp(bytes: *[4]u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
           (@as(u32, bytes[1]) << 16) |
           (@as(u32, bytes[2]) << 8) |
           @as(u32, bytes[3]);
}

/// Parse IP address from string
/// str: IP address string (e.g., "192.168.1.1")
/// out: Output buffer for parsed IP (network byte order)
/// Returns: true on success, false on failure
pub fn parseIpString(str: []const u8, out: *u32) bool {
    var parts: [4]u32 = undefined;
    var count: usize = 0;

    var start: usize = 0;
    var i: usize = 0;
    while (i <= str.len) : (i += 1) {
        if (i == str.len or str[i] == '.') {
            if (count >= 4) return false;
            const part = std.fmt.parseInt(u32, str[start..i], 10) catch return false;
            if (part > 255) return false;
            parts[count] = part;
            count += 1;
            start = i + 1;
        }
    }

    if (count != 4) return false;

    out.* = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    return true;
}

/// Format IP address to string
/// ip: IP address in network byte order
/// buf: Output buffer (must be at least 16 bytes)
/// Returns: Slice of formatted string
pub fn formatIp(ip: u32, buf: *[16]u8) []u8 {
    const bytes = @as(*const [4]u8, @ptrCast(&ip));
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        bytes[0], bytes[1], bytes[2], bytes[3],
    }) catch unreachable;
}

/// IPv4 Options (for reference)
pub const OPT_END = 0;
pub const OPT_NOOP = 1;
pub const OPT_SECURITY = 130;
pub const OPT_LSRR = 131;  // Loose Source Route
pub const OPT_SSRR = 137;   // Strict Source Route
pub const OPT_RECORD = 7;
pub const OPT_TIMESTAMP = 68;

// Inline checksum implementation for hot path
inline fn checksum(data: [*]const u8, len: usize) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    const n = len & ~@as(usize, 1);

    while (i < n) : (i += 2) {
        sum += @as(u16, data[i]) | (@as(u16, data[i + 1]) << 8);
    }

    if (n != len) {
        sum += @as(u16, data[n]);
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @bitCast(sum));
}

// Unit tests
test "IPv4 header size" {
    try std.testing.expectEqual(@as(usize, 20), HDR_MIN_SIZE);
    try std.testing.expectEqual(@as(usize, 60), HDR_MAX_SIZE);
}

test "IPv4 get/set version IHL" {
    var header: Ipv4Header = undefined;
    setVersionIHL(&header, 4, 5);
    try std.testing.expectEqual(@as(u4, 4), getVersion(&header));
    try std.testing.expectEqual(@as(u4, 5), getIHL(&header));
    try std.testing.expectEqual(@as(u8, 0x45), header.ver_ihl);
}

test "IPv4 get/set flags frag" {
    var header: Ipv4Header = undefined;
    setFlagsFrag(&header, 0b010, 100);  // More fragments flag, offset 100
    try std.testing.expectEqual(@as(u3, 0b010), getFlags(&header));
    try std.testing.expectEqual(@as(u13, 100), getFragmentOffset(&header));
}

test "IPv4 header parse" {
    var buf: [1500]u8 = undefined;

    // Build a simple TCP packet
    const ip_offset = buildHeader(buf[0..].ptr, 0xC0A80101, 0xC0A80102, 6, 20);
    try std.testing.expectEqual(@as(usize, 20), ip_offset);

    // Parse it back
    const info = parseHeader(buf[0..].ptr, 1500);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), info.?.src_ip);
    try std.testing.expectEqual(@as(u32, 0xC0A80102), info.?.dst_ip);
    try std.testing.expectEqual(@as(u8, 6), info.?.protocol);
    try std.testing.expect(!info.?.is_fragment);
}

test "IPv4 ip conversion" {
    const ip: u32 = 0xC0A80101; // 192.168.1.1
    var bytes: [4]u8 = undefined;
    ipToBytes(ip, &bytes);
    try std.testing.expectEqual(@as(u8, 192), bytes[0]);
    try std.testing.expectEqual(@as(u8, 168), bytes[1]);
    try std.testing.expectEqual(@as(u8, 1), bytes[2]);
    try std.testing.expectEqual(@as(u8, 1), bytes[3]);

    const ip2 = bytesToIp(&bytes);
    try std.testing.expectEqual(ip, ip2);
}

test "IPv4 parse string" {
    var ip: u32 = undefined;
    try std.testing.expect(parseIpString("192.168.1.1", &ip));
    try std.testing.expectEqual(@as(u32, 0xC0A80101), ip);

    try std.testing.expect(!parseIpString("256.1.1.1", &ip));
    try std.testing.expect(!parseIpString("192.168.1", &ip));
}

test "IPv4 format" {
    const ip: u32 = 0xC0A80101;
    var buf: [16]u8 = undefined;
    const str = formatIp(ip, &buf);
    try std.testing.expectEqualStrings("192.168.1.1", str);
}

comptime {
    // Ensure Ipv4Header is the correct size
    if (builtin.is_test) {
        std.debug.assert(@sizeOf(Ipv4Header) == 20);
    }
}
