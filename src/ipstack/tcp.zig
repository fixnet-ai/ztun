//! tcp.zig - TCP Protocol Utilities
//!
//! Provides TCP header structures, flags, sequence validation,
//! and packet building utilities for TCP/IP stack.

const std = @import("std");
const builtin = @import("builtin");
const checksum = @import("checksum");

// TCP header size constants
pub const HDR_MIN_SIZE = 20;
pub const HDR_MAX_SIZE = 60;
pub const MAX_OPTIONS_SIZE = 40;

// TCP flags
pub const FLAG_FIN = 0x01;
pub const FLAG_SYN = 0x02;
pub const FLAG_RST = 0x04;
pub const FLAG_PSH = 0x08;
pub const FLAG_ACK = 0x10;
pub const FLAG_URG = 0x20;
pub const FLAG_ECE = 0x40;
pub const FLAG_CWR = 0x80;

// TCP states (mirrors connection.zig for reference)
pub const STATE_CLOSED = 0;
pub const STATE_LISTEN = 1;
pub const STATE_SYN_SENT = 2;
pub const STATE_SYN_RECEIVED = 3;
pub const STATE_ESTABLISHED = 4;
pub const STATE_FIN_WAIT_1 = 5;
pub const STATE_FIN_WAIT_2 = 6;
pub const STATE_CLOSE_WAIT = 7;
pub const STATE_CLOSING = 8;
pub const STATE_LAST_ACK = 9;
pub const STATE_TIME_WAIT = 10;

// TCP Option Kinds
pub const OPT_END = 0;
pub const OPT_NOP = 1;
pub const OPT_MSS = 2;
pub const OPT_WSCALE = 3;
pub const OPT_SACK_PERM = 4;
pub const OPT_SACK = 5;
pub const OPT_TIMESTAMP = 8;

// MSS default
pub const DEFAULT_MSS = 1460;

/// TCP Header (20 bytes minimum)
pub const TcpHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags_len: u16,  // Lower 4 bits = data offset, upper bits = flags
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
};

/// TCP Header with options (60 bytes max)
pub const TcpHeaderFull = extern struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags_len: u16,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
    options: [40]u8,
};

/// Get data offset (header length) from flags_len
pub fn getDataOffset(header: *const TcpHeader) u4 {
    return @as(u4, header.flags_len >> 12);
}

/// Set data offset
pub fn setDataOffset(header: *TcpHeader, offset: u4) void {
    header.flags_len = (header.flags_len & 0x0FFF) | (@as(u16, offset) << 12);
}

/// Get TCP flags from flags_len
pub fn getFlags(header: *const TcpHeader) u8 {
    return @as(u8, header.flags_len & 0x3F);
}

/// Set TCP flags
pub fn setFlags(header: *TcpHeader, flags: u8) void {
    header.flags_len = (header.flags_len & 0xFFC0) | (@as(u16, flags) & 0x3F);
}

/// Check if SYN flag is set
pub fn isSyn(header: *const TcpHeader) bool {
    return (header.flags_len & FLAG_SYN) != 0;
}

/// Check if ACK flag is set
pub fn isAck(header: *const TcpHeader) bool {
    return (header.flags_len & FLAG_ACK) != 0;
}

/// Check if FIN flag is set
pub fn isFin(header: *const TcpHeader) bool {
    return (header.flags_len & FLAG_FIN) != 0;
}

/// Check if RST flag is set
pub fn isRst(header: *const TcpHeader) bool {
    return (header.flags_len & FLAG_RST) != 0;
}

/// Check if PSH flag is set
pub fn isPsh(header: *const TcpHeader) bool {
    return (header.flags_len & FLAG_PSH) != 0;
}

/// TCP header size in bytes
pub fn headerSize(header: *const TcpHeader) usize {
    return @as(usize, getDataOffset(header)) * 4;
}

/// TCP packet information
pub const PacketInfo = struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    header_len: usize,
    payload_len: usize,
    is_syn: bool,
    is_ack: bool,
    is_fin: bool,
    is_rst: bool,
};

/// Parse TCP header
/// data: Pointer to TCP header
/// len: Total TCP packet length (header + payload)
/// Returns: PacketInfo on success, null if invalid
pub fn parseHeader(data: [*]const u8, len: usize) ?PacketInfo {
    if (len < HDR_MIN_SIZE) return null;

    const header = @as(*const TcpHeader, @ptrCast(data));
    const hdr_len = headerSize(header);
    if (len < hdr_len) return null;

    return PacketInfo{
        .src_port = header.src_port,
        .dst_port = header.dst_port,
        .seq_num = header.seq_num,
        .ack_num = header.ack_num,
        .flags = getFlags(header),
        .header_len = hdr_len,
        .payload_len = len - hdr_len,
        .is_syn = isSyn(header),
        .is_ack = isAck(header),
        .is_fin = isFin(header),
        .is_rst = isRst(header),
    };
}

/// Build TCP header
/// buf: Output buffer
/// src_port: Source port (network byte order)
/// dst_port: Destination port (network byte order)
/// seq_num: Sequence number
/// ack_num: Acknowledgment number
/// flags: TCP flags
/// window: Window size
/// Returns: Number of bytes written (20 for standard header)
pub fn buildHeader(
    buf: [*]u8,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
) usize {
    const header = @as(*TcpHeader, @ptrCast(buf));

    header.src_port = src_port;
    header.dst_port = dst_port;
    header.seq_num = seq_num;
    header.ack_num = ack_num;

    // Data offset (5 = 20 bytes) and flags
    header.flags_len = (@as(u16, 5) << 12) | flags;

    header.window = window;
    header.checksum = 0;
    header.urgent_ptr = 0;

    return HDR_MIN_SIZE;
}

/// Build TCP header with checksum
/// buf: Output buffer
/// src_ip: Source IP (network byte order, u32)
/// dst_ip: Destination IP
/// src_port: Source port
/// dst_port: Destination port
/// seq_num: Sequence number
/// ack_num: Acknowledgment number
/// flags: TCP flags
/// window: Window size
/// payload: TCP payload data
/// Returns: Header length
pub fn buildHeaderWithChecksum(
    buf: [*]u8,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: []const u8,
) usize {
    const header_len = buildHeader(buf, src_port, dst_port, seq_num, ack_num, flags, window);

    // Compute pseudo-header sum
    const pseudo_sum = checksum.checksumPseudoIPv4(src_ip, dst_ip, 6, @as(u16, header_len) + @as(u16, payload.len));

    // Compute full checksum
    const header_u16 = @as([*]const u16, @ptrCast(buf));
    var sum: u32 = pseudo_sum;

    var i: usize = 0;
    while (i < header_len / 2) : (i += 1) {
        sum += header_u16[i];
    }

    // Add payload
    var j: usize = 0;
    while (j < payload.len / 2) : (j += 1) {
        const val = @as(u16, payload[j * 2]) | (@as(u16, payload[j * 2 + 1]) << 8);
        sum += val;
    }

    if (payload.len % 2 == 1) {
        sum += @as(u16, payload[payload.len - 1]);
    }

    // Fold and complement
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    const cs = @as(u16, @bitCast(sum));
    @as(*TcpHeader, @ptrCast(buf)).checksum = ~cs;

    return header_len;
}

/// Validate TCP flags
/// flags: TCP flags to check
/// Returns: true if flags are valid (no illegal combinations)
pub fn validateFlags(flags: u8) bool {
    // FIN, SYN, RST are mutually exclusive for new connections
    const control_bits = flags & (FLAG_FIN | FLAG_SYN | FLAG_RST);
    if (control_bits != 0 and control_bits != FLAG_FIN and
        control_bits != FLAG_SYN and control_bits != FLAG_RST) {
        return false;
    }
    return true;
}

/// Check if sequence number is within receive window
/// seq: Sequence number to check
/// rcv_nxt: Expected next sequence number (window start)
/// window: Window size
/// Returns: true if in window
pub fn seqInWindow(seq: u32, rcv_nxt: u32, window: u32) bool {
    const seq32 = @as(u32, seq);
    const nxt32 = @as(u32, rcv_nxt);
    const win32 = @as(u32, window);

    if (win32 == 0) return false;

    // Handle wraparound
    const diff = if (seq32 >= nxt32) seq32 - nxt32 else seq32 + (0xFFFFFFFF - nxt32) + 1;

    return diff < win32;
}

/// Parse TCP options
/// tcp_data: Pointer to start of TCP header (options start after header)
/// tcp_len: Total TCP packet length
/// max_opts: Maximum number of options to parse
/// Returns: Number of options parsed
pub const TcpOption = struct {
    kind: u8,
    len: u8,
    data: []const u8,
};

pub fn parseOptions(
    tcp_data: [*]const u8,
    tcp_len: usize,
    opts: []TcpOption,
) usize {
    const header = @as(*const TcpHeader, @ptrCast(tcp_data));
    const hdr_len = headerSize(header);

    if (hdr_len <= HDR_MIN_SIZE) return 0;

    var offset = HDR_MIN_SIZE;
    var count: usize = 0;
    const end = tcp_len;

    while (offset < end and count < opts.len) {
        const kind = tcp_data[offset];

        if (kind == OPT_END) {
            break;
        } else if (kind == OPT_NOP) {
            offset += 1;
        } else {
            if (offset + 2 > end) break;
            const len = tcp_data[offset + 1];
            if (offset + len > end) break;

            opts[count] = .{
                .kind = kind,
                .len = len,
                .data = tcp_data[offset + 2 .. offset + len],
            };
            count += 1;
            offset += len;
        }
    }

    return count;
}

/// Build MSS option
/// buf: Output buffer
/// mss: MSS value
/// Returns: Number of bytes written (4)
pub fn buildMssOption(buf: [*]u8, mss: u16) usize {
    buf[0] = OPT_MSS;
    buf[1] = 4;
    buf[2] = @as(u8, @truncate(mss >> 8));
    buf[3] = @as(u8, @truncate(mss));
    return 4;
}

/// Build NOP option
pub fn buildNopOption(buf: [*]u8) usize {
    buf[0] = OPT_NOP;
    return 1;
}

/// Build End of Options List
pub fn buildEndOption(buf: [*]u8) usize {
    buf[0] = OPT_END;
    return 1;
}

/// TCP pseudo-header checksum helper for IPv6
pub fn checksumPseudoHeaderIPv6(
    src_addr: *const [16]u8,
    dst_addr: *const [16]u8,
    _: u32,
    _: u32,
    _: u8,
    payload_len: u32,
) u32 {
    var sum: u32 = 0;

    // Sum source address
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u16, src_addr[i]) | (@as(u16, src_addr[i + 1]) << 8);
    }

    // Sum destination address
    i = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u16, dst_addr[i]) | (@as(u16, dst_addr[i + 1]) << 8);
    }

    // Zero padding + Next Header (6 = TCP)
    sum += 6;

    // TCP length
    sum += payload_len;

    // TCP header fields (simplified, real impl needs careful folding)
    sum += 0; // placeholder
    sum += 0; // placeholder

    // Fold
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum;
}

// Unit tests
test "TCP header size" {
    try std.testing.expectEqual(@as(usize, 20), HDR_MIN_SIZE);
    try std.testing.expectEqual(@as(usize, 60), HDR_MAX_SIZE);
}

test "TCP get/set flags" {
    var header: TcpHeader = undefined;
    header.flags_len = 0;

    setFlags(&header, FLAG_SYN | FLAG_ACK);
    try std.testing.expectEqual(@as(u8, FLAG_SYN | FLAG_ACK), getFlags(&header));
}

test "TCP get/set data offset" {
    var header: TcpHeader = undefined;
    header.flags_len = 0;

    setDataOffset(&header, 6);
    try std.testing.expectEqual(@as(u4, 6), getDataOffset(&header));
    try std.testing.expectEqual(@as(u16, 0x6018), header.flags_len);  // 0x6000 + 0x18
}

test "TCP flag checks" {
    var header: TcpHeader = undefined;
    header.flags_len = FLAG_SYN;

    try std.testing.expect(isSyn(&header));
    try std.testing.expect(!isAck(&header));
    try std.testing.expect(!isFin(&header));
}

test "TCP validate flags" {
    try std.testing.expect(validateFlags(FLAG_SYN));
    try std.testing.expect(validateFlags(FLAG_ACK));
    try std.testing.expect(!validateFlags(FLAG_SYN | FLAG_FIN));  // Invalid
}

test "TCP seq in window" {
    // Normal case
    try std.testing.expect(seqInWindow(100, 50, 100));
    try std.testing.expect(!seqInWindow(200, 50, 100));

    // Wraparound case
    try std.testing.expect(seqInWindow(10, 0xFFFFFFFF - 5, 100));
    try std.testing.expect(!seqInWindow(0xFFFFFFFF - 10, 0xFFFFFFFF - 5, 100));
}

test "TCP build header" {
    var buf: [60]u8 = undefined;
    const len = buildHeader(buf[0..].ptr, 12345, 80, 1000, 0, FLAG_SYN, 65535);

    try std.testing.expectEqual(@as(usize, 20), len);

    const header = @as(*const TcpHeader, @ptrCast(buf[0..].ptr));
    try std.testing.expectEqual(@as(u16, 12345), header.src_port);
    try std.testing.expectEqual(@as(u16, 80), header.dst_port);
    try std.testing.expectEqual(@as(u32, 1000), header.seq_num);
}

test "TCP parse options" {
    var buf: [60]u8 = undefined;
    var opts: [4]TcpOption = undefined;

    // Build header with MSS option
    _ = buildHeader(buf[0..].ptr, 12345, 80, 1000, 0, FLAG_SYN, 65535);
    _ = buildMssOption(buf[20..].ptr, 1460);
    _ = buildEndOption(buf[24..].ptr);

    const count = parseOptions(buf[0..].ptr, 28, opts[0..]);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u8, OPT_MSS), opts[0].kind);
}

comptime {
    // Ensure header is correct size
    if (builtin.is_test) {
        std.debug.assert(@sizeOf(TcpHeader) == 20);
    }
}
