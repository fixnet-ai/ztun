//! ipv6.zig - IPv6 Packet Parsing and Building
//!
//! Provides IPv6 header structures and utilities for packet processing.
//! Supports basic IPv6 header, extension headers, and checksum.

const std = @import("std");
const builtin = @import("builtin");
const checksum = @import("checksum");

// IPv6 constants
pub const HDR_SIZE = 40;           // Basic header size
pub const PAYLOAD_MAX = 65535;     // Maximum payload size
pub const MTU_MIN = 1280;          // Minimum MTU

// IPv6 Next Header values
pub const NH_NO_NEXT = 59;
pub const NH_HOP_OPTS = 0;
pub const NH_ROUTING = 43;
pub const NH_FRAGMENT = 44;
pub const NH_DEST_OPTS = 60;
pub const NH_ICMPV6 = 58;
pub const NH_TCP = 6;
pub const NH_UDP = 17;

// IPv6 Extension Header lengths (in 8-byte units, excluding first 8 bytes)
pub const EXT_HOP_SIZE = 8;
pub const EXT_ROUTING_SIZE = 8;
pub const EXT_FRAG_SIZE = 1;  // 8 bytes total
pub const EXT_DEST_SIZE = 8;

/// IPv6 Address (16 bytes)
pub const Ipv6Address = [16]u8;

/// IPv6 Basic Header (40 bytes)
pub const Ipv6Header = extern struct {
    // Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
    ver_tc_flow: u32,

    // Payload Length (16 bits) + Next Header (8 bits) + Hop Limit (8 bits)
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,

    // Source Address (128 bits)
    src_addr: [16]u8,

    // Destination Address (128 bits)
    dst_addr: [16]u8,
};

/// IPv6 Fragment Header (8 bytes)
pub const Ipv6FragmentHeader = extern struct {
    next_header: u8,
    reserved: u8,
    frag_offset: u8,  // Bits 0-12 = offset, bit 13 = M flag
    identification: u32,
};

/// IPv6 Hop-by-Hop Options Header
pub const Ipv6HopOptsHeader = extern struct {
    next_header: u8,
    hdr_ext_len: u8,  // In 8-byte units, excluding first 8 bytes
    options: [0]u8,   // Variable length, padded to 8-byte boundary
};

/// IPv6 Routing Header
pub const Ipv6RoutingHeader = extern struct {
    next_header: u8,
    hdr_ext_len: u8,  // In 8-byte units, excluding first 8 bytes
    routing_type: u8,
    segments_left: u8,
    reserved: u32,
    addresses: [0]u8,  // Variable length
};

/// IPv6 Destination Options Header
pub const Ipv6DestOptsHeader = extern struct {
    next_header: u8,
    hdr_ext_len: u8,
    options: [0]u8,
};

/// IPv6 packet information
pub const PacketInfo = struct {
    src_addr: [16]u8,
    dst_addr: [16]u8,
    next_header: u8,
    payload_len: usize,
    total_len: usize,
    is_fragment: bool,
    fragment_offset: u13,
    is_first_fragment: bool,
};

/// Get IPv6 version from ver_tc_flow (bits 28-31)
pub fn getVersion(header: *const Ipv6Header) u4 {
    return @as(u4, @truncate(header.ver_tc_flow >> 28));
}

/// Get Traffic Class from ver_tc_flow (bits 20-27)
pub fn getTrafficClass(header: *const Ipv6Header) u8 {
    return @as(u8, @truncate(header.ver_tc_flow >> 20));
}

/// Set Traffic Class
pub fn setTrafficClass(header: *Ipv6Header, tc: u8) void {
    header.ver_tc_flow = (header.ver_tc_flow & 0xF00FFFFF) | (@as(u32, tc) << 20);
}

/// Get Flow Label from ver_tc_flow (bits 0-19)
pub fn getFlowLabel(header: *const Ipv6Header) u20 {
    return @as(u20, @truncate(header.ver_tc_flow));
}

/// Set Flow Label
pub fn setFlowLabel(header: *Ipv6Header, label: u20) void {
    header.ver_tc_flow = (header.ver_tc_flow & 0xFFF00000) | label;
}

/// Fragment offset from Fragment Header
pub fn getFragmentOffset(header: *const Ipv6FragmentHeader) u13 {
    return @as(u13, @truncate(header.frag_offset >> 3));
}

/// More Fragments flag
pub fn getMFlag(header: *const Ipv6FragmentHeader) bool {
    return (header.frag_offset & 1) != 0;
}

/// Set fragment offset and M flag
pub fn setFragmentInfo(header: *Ipv6FragmentHeader, offset: u13, more: bool) void {
    header.frag_offset = (@as(u8, offset) << 3) | if (more) @as(u8, 1) else @as(u8, 0);
}

/// Parse IPv6 basic header
/// Returns: PacketInfo on success, null if invalid
pub fn parseHeader(data: [*]const u8, len: usize) ?PacketInfo {
    if (len < HDR_SIZE) return null;

    const header = @as(*const Ipv6Header, @ptrCast(data));

    // Validate version (must be 6)
    if (getVersion(header) != 6) return null;

    // Payload length includes extension headers + upper layer
    const payload_len = @as(usize, header.payload_len);
    const total_len = HDR_SIZE + payload_len;
    if (total_len > PAYLOAD_MAX or total_len > len) return null;

    return PacketInfo{
        .src_addr = header.src_addr,
        .dst_addr = header.dst_addr,
        .next_header = header.next_header,
        .payload_len = payload_len,
        .total_len = total_len,
        .is_fragment = false,
        .fragment_offset = 0,
        .is_first_fragment = true,
    };
}

/// Build IPv6 basic header
/// buf: Output buffer (must be at least HDR_SIZE bytes)
/// src_ip: Source address (16 bytes)
/// dst_ip: Destination address (16 bytes)
/// next_header: Next Header value (e.g., NH_TCP, NH_UDP, NH_ICMPV6)
/// payload_len: Length of payload (extension headers + data)
pub fn buildHeader(
    buf: [*]u8,
    src_ip: *const [16]u8,
    dst_ip: *const [16]u8,
    next_header: u8,
    payload_len: usize,
) void {
    const header = @as(*Ipv6Header, @ptrCast(buf));

    // Version 6, Traffic Class 0, Flow Label 0
    header.ver_tc_flow = 0x60000000;

    // Payload length + Next Header + Hop Limit
    header.payload_len = @as(u16, payload_len);
    header.next_header = next_header;
    header.hop_limit = 64;

    // Addresses
    @memcpy(header.src_addr[0..], src_ip);
    @memcpy(header.dst_addr[0..], dst_ip);
}

/// Build IPv6 Fragment Header
pub fn buildFragmentHeader(
    buf: [*]u8,
    next_header: u8,
    offset: u13,
    more: bool,
    identification: u32,
) void {
    const header = @as(*Ipv6FragmentHeader, @ptrCast(buf));
    header.next_header = next_header;
    header.reserved = 0;
    setFragmentInfo(header, offset, more);
    header.identification = identification;
}

/// Skip extension headers and get upper layer info
/// data: Packet data starting at IPv6 header
/// len: Packet length
/// out_next_header: Output for the final next header
/// out_ext_len: Output for total extension header length
/// Returns: Pointer to upper layer header, null if invalid
pub fn skipExtensionHeaders(
    data: [*]const u8,
    len: usize,
    out_next_header: *u8,
    out_ext_len: *usize,
) ?[*]const u8 {
    if (len < HDR_SIZE) return null;

    const header = @as(*const Ipv6Header, @ptrCast(data));
    var ptr = data + HDR_SIZE;
    var remaining = len - HDR_SIZE;
    var next_header = header.next_header;
    var ext_len: usize = 0;

    while (true) {
        if (next_header == NH_NO_NEXT) {
            // No more headers
            out_next_header.* = NH_NO_NEXT;
            out_ext_len.* = ext_len;
            return null;
        }

        if (next_header == NH_HOP_OPTS or next_header == NH_DEST_OPTS) {
            if (remaining < 8) return null;
            const ext = @as(*const Ipv6HopOptsHeader, @ptrCast(ptr));
            next_header = ext.next_header;
            ext_len += 8;
            ptr += 8;
            remaining -= 8;
        } else if (next_header == NH_ROUTING) {
            if (remaining < 8) return null;
            const ext = @as(*const Ipv6RoutingHeader, @ptrCast(ptr));
            const ext_len_units = ext.hdr_ext_len;
            const ext_total = 8 + @as(usize, ext_len_units) * 8;
            if (remaining < ext_total) return null;
            next_header = ext.next_header;
            ext_len += ext_total;
            ptr += ext_total;
            remaining -= ext_total;
        } else if (next_header == NH_FRAGMENT) {
            if (remaining < 8) return null;
            const ext = @as(*const Ipv6FragmentHeader, @ptrCast(ptr));
            next_header = ext.next_header;
            ext_len += 8;
            ptr += 8;
            remaining -= 8;
        } else {
            // Upper layer protocol
            out_next_header.* = next_header;
            out_ext_len.* = ext_len;
            return ptr;
        }
    }
}

/// Parse IPv6 address from string
/// str: IPv6 address string (e.g., "2001:db8::1")
/// out: Output buffer for parsed address
/// Returns: true on success, false on failure
pub fn parseIpString(str: []const u8, out: *Ipv6Address) bool {
    var parts: [8]u16 = undefined;
    var parts_count: usize = 0;
    var double_colon_idx: ?usize = null;
    var i: usize = 0;
    var val: usize = 0;

    while (i < str.len) {
        if (str[i] == ':') {
            if (parts_count >= 8) return false;
            if (val > 0xFFFF) return false;
            parts[parts_count] = @as(u16, val);
            parts_count += 1;
            val = 0;

            if (i + 1 < str.len and str[i + 1] == ':') {
                if (double_colon_idx != null) return false;  // Multiple ::
                double_colon_idx = parts_count;
                i += 2;
            } else {
                i += 1;
            }
        } else if (str[i] == '.') {
            // IPv4-mapped IPv6
            break;
        } else if (std.ascii.isHexDigit(str[i])) {
            val = val * 16 + std.fmt.parseInt(usize, str[i..i+1], 16) catch return false;
            if (val > 0xFFFF) return false;
            i += 1;
        } else {
            return false;
        }
    }

    // Handle remaining part after last colon
    if (i > 0 and str[i - 1] != ':') {
        if (parts_count >= 8) return false;
        if (val > 0xFFFF) return false;
        parts[parts_count] = @as(u16, val);
        parts_count += 1;
    }

    // Expand ::
    var result: Ipv6Address = undefined;
    @memset(result[0..], 0);

    if (double_colon_idx) |idx| {
        // Copy parts before ::
        var j: usize = 0;
        while (j < idx) : (j += 1) {
            result[j * 2] = @as(u8, @truncate(parts[j] >> 8));
            result[j * 2 + 1] = @as(u8, @truncate(parts[j]));
        }

        // Fill zeros
        const before = idx;
        const zeros = 8 - parts_count;
        var k: usize = 0;
        while (k < zeros) : (k += 1) {
            result[(before + k) * 2] = 0;
            result[(before + k) * 2 + 1] = 0;
        }

        // Copy parts after ::
        j = idx;
        var dst = (before + zeros) * 2;
        while (j < parts_count) : (j += 1) {
            result[dst] = @as(u8, @truncate(parts[j] >> 8));
            result[dst + 1] = @as(u8, @truncate(parts[j]));
            dst += 2;
        }
    } else {
        // No ::, must have exactly 8 parts
        if (parts_count != 8) return false;
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            result[j * 2] = @as(u8, @truncate(parts[j] >> 8));
            result[j * 2 + 1] = @as(u8, @truncate(parts[j]));
        }
    }

    out.* = result;
    return true;
}

/// Format IPv6 address to string
/// ip: IPv6 address
/// buf: Output buffer (at least 46 bytes for max format)
/// Returns: Formatted string
pub fn formatIp(ip: *const Ipv6Address, buf: *[46]u8) []u8 {
    // Find longest run of zeros for :: notation
    var max_start: usize = 0;
    var max_len: usize = 0;
    var start: usize = 0;
    var len: usize = 0;

    var i: usize = 0;
    while (i < 16) : (i += 2) {
        if (ip[i] == 0 and ip[i + 1] == 0) {
            if (len == 0) start = i;
            len += 2;
        } else {
            if (len > max_len) {
                max_start = start;
                max_len = len;
            }
            len = 0;
        }
    }

    // Check last run
    if (len > max_len) {
        max_start = start;
        max_len = len;
    }

    // Minimum compression: at least 2 consecutive zeros
    if (max_len >= 4) {
        // Use :: compression
        var pos: usize = 0;

        // Before compression
        if (max_start > 0) {
            const count = max_start / 2;
            var j: usize = 0;
            while (j < count) : (j += 1) {
                const part = (@as(u16, ip[j * 2]) << 8) | ip[j * 2 + 1];
                const slice = std.fmt.bufPrint(buf[pos..], "{x}", .{part}) catch unreachable;
                pos += slice.len;
                if (j + 1 < count) {
                    buf[pos] = ':';
                    pos += 1;
                }
            }
        }

        // ::
        buf[pos] = ':';
        pos += 1;
        buf[pos] = ':';
        pos += 1;

        // After compression
        const after_start = (max_start + max_len) / 2;
        const count = 8 - after_start;
        var j: usize = 0;
        while (j < count) : (j += 1) {
            const part = (@as(u16, ip[(after_start + j) * 2]) << 8) | ip[(after_start + j) * 2 + 1];
            const slice = std.fmt.bufPrint(buf[pos..], "{x}", .{part}) catch unreachable;
            pos += slice.len;
            if (j + 1 < count) {
                buf[pos] = ':';
                pos += 1;
            }
        }

        return buf[0..pos];
    } else {
        // No compression needed
        var pos: usize = 0;
        var first: bool = true;
        var idx6: usize = 0;
        while (idx6 < 16) : (idx6 += 2) {
            const part = (@as(u16, ip[idx6]) << 8) | ip[idx6 + 1];
            if (!first) {
                buf[pos] = ':';
                pos += 1;
            }
            const slice = std.fmt.bufPrint(buf[pos..], "{x}", .{part}) catch unreachable;
            pos += slice.len;
            first = false;
        }
        return buf[0..pos];
    }
}

/// IPv6 checksum pseudo-header for upper layer protocols
pub fn checksumPseudoHeader(
    src_addr: *const Ipv6Address,
    dst_addr: *const Ipv6Address,
    next_header: u8,
    len: u32,
) u32 {
    var sum: u32 = 0;

    // Sum source address (two u64s)
    const src_hi = @as(*const u64, @ptrCast(&src_addr[0])).*;
    const src_lo = @as(*const u64, @ptrCast(&src_addr[8])).*;
    sum += @as(u32, @truncate(src_hi >> 32));
    sum += @as(u32, @truncate(src_hi));
    sum += @as(u32, @truncate(src_lo >> 32));
    sum += @as(u32, @truncate(src_lo));

    // Sum destination address
    const dst_hi = @as(*const u64, @ptrCast(&dst_addr[0])).*;
    const dst_lo = @as(*const u64, @ptrCast(&dst_addr[8])).*;
    sum += @as(u32, @truncate(dst_hi >> 32));
    sum += @as(u32, @truncate(dst_hi));
    sum += @as(u32, @truncate(dst_lo >> 32));
    sum += @as(u32, @truncate(dst_lo));

    // Sum next_header and length (expanded to 32 bits)
    sum += next_header;
    sum += len;

    // Fold
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum;
}

// Unit tests
test "IPv6 header size" {
    try std.testing.expectEqual(@as(usize, 40), HDR_SIZE);
}

test "IPv6 get/set version" {
    var header: Ipv6Header = undefined;
    header.ver_tc_flow = 0x60000000;
    try std.testing.expectEqual(@as(u4, 6), getVersion(&header));
}

test "IPv6 header build and parse" {
    var buf: [1500]u8 = undefined;
    var src: Ipv6Address = undefined;
    var dst: Ipv6Address = undefined;

    // Set addresses
    @memset(src[0..], 0);
    @memset(dst[0..], 0);
    src[15] = 1;
    dst[15] = 2;

    // Build header
    buildHeader(buf[0..].ptr, &src, &dst, 6, 100);
    try std.testing.expectEqual(@as(u16, 100), @as(*const Ipv6Header, @ptrCast(buf[0..].ptr)).payload_len);
    try std.testing.expectEqual(@as(u8, 6), @as(*const Ipv6Header, @ptrCast(buf[0..].ptr)).next_header);
}

test "IPv6 parse string" {
    var ip: Ipv6Address = undefined;
    try std.testing.expect(parseIpString("2001:db8::1", &ip));
    try std.testing.expectEqual(@as(u8, 0x20), ip[0]);
    try std.testing.expectEqual(@as(u8, 0x01), ip[1]);
    try std.testing.expectEqual(@as(u8, 0x0D), ip[2]);
    try std.testing.expectEqual(@as(u8, 0xB8), ip[3]);

    try std.testing.expect(parseIpString("::1", &ip));
    try std.testing.expectEqual(@as(u8, 1), ip[15]);

    try std.testing.expect(!parseIpString("invalid", &ip));
}

test "IPv6 format" {
    var ip: Ipv6Address = undefined;
    var buf: [46]u8 = undefined;

    // Set ::1
    @memset(ip[0..], 0);
    ip[15] = 1;

    const str = formatIp(&ip, &buf);
    try std.testing.expectEqualStrings("::1", str);
}

comptime {
    // Ensure header is correct size
    if (builtin.is_test) {
        std.debug.assert(@sizeOf(Ipv6Header) == 40);
        std.debug.assert(@sizeOf(Ipv6FragmentHeader) == 8);
    }
}
