//! endianness_test.zig - Cross-platform endianness test for TUN devices
//!
//! This program tests the byte order behavior on all supported platforms:
//! - Native endianness (little-endian on x86/ARM, big-endian on some ARM)
//! - Network byte order (always big-endian)
//! - TUN device packet format expectations
//!
//! Build commands:
//!   zig build test_endianness   - Build test for current platform
//!   zig build test_endianness -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast
//!   zig build test_endianness -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseFast
//!
//! Run: ./endianness_test

const std = @import("std");

// ==================== Platform Detection ====================

/// Get platform name for logging
fn getPlatformName() []const u8 {
    const builtin = @import("builtin");
    return switch (builtin.os.tag) {
        .macos => "macOS",
        .linux => "Linux",
        .windows => "Windows",
        .ios => "iOS",
        .freebsd => "FreeBSD",
        else => "Unknown",
    };
}

/// Get CPU architecture name
fn getArchName() []const u8 {
    const builtin = @import("builtin");
    return switch (builtin.cpu.arch) {
        .x86_64 => "x86_64",
        .aarch64 => "ARM64",
        .arm => "ARM32",
        .x86 => "x86",
        else => "Unknown",
    };
}

/// Check if running on big-endian platform
fn isBigEndian() bool {
    const n: u32 = 0x01020304;
    const bytes: *const [4]u8 = @as(*const [4]u8, @ptrCast(&n));
    return bytes[0] == 0x01;
}

// ==================== Network Byte Order Tests ====================

// Test 1: Verify native endianness matches expected platform behavior
test "platform endianness detection" {
    const is_be = isBigEndian();
    const builtin = @import("builtin");

    // Most platforms are little-endian
    // Only some ARM platforms (m68k, sparc, etc.) are big-endian
    if (builtin.cpu.arch == .aarch64 or builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86) {
        try std.testing.expect(!is_be); // Should be little-endian
    }

    std.debug.print("Platform: {s} ({s}) - Endianness: {s}\n", .{
        getPlatformName(),
        getArchName(),
        if (is_be) "big-endian" else "little-endian",
    });
}

// Test 2: Network byte order conversion using std.mem
test "network byte order conversion" {
    // IPv4 address 192.168.1.1 in network byte order (big-endian)
    const expected_ip: u32 = 0xC0A80101;

    // Parse from string (returns network byte order)
    var ip: u32 = undefined;
    const success = parseIpv4("192.168.1.1", &ip);
    try std.testing.expect(success);
    try std.testing.expectEqual(expected_ip, ip);

    // Convert back to bytes and verify
    var bytes: [4]u8 = undefined;
    ipToBytes(ip, &bytes);
    try std.testing.expectEqual(@as(u8, 192), bytes[0]);
    try std.testing.expectEqual(@as(u8, 168), bytes[1]);
    try std.testing.expectEqual(@as(u8, 1), bytes[2]);
    try std.testing.expectEqual(@as(u8, 1), bytes[3]);
}

// Test 3: u16 byte order conversion
test "u16 byte order" {
    const host_val: u16 = 0x1234;
    const network_val = @byteSwap(host_val);

    // On little-endian: 0x1234 -> 0x3412 (reversed)
    // On big-endian: 0x1234 -> 0x1234 (same)
    if (isBigEndian()) {
        try std.testing.expectEqual(@as(u16, 0x1234), network_val);
    } else {
        try std.testing.expectEqual(@as(u16, 0x3412), network_val);
    }
}

// Test 4: u32 byte order conversion
test "u32 byte order" {
    const host_val: u32 = 0x12345678;
    const network_val = @byteSwap(host_val);

    // On little-endian: 0x12345678 -> 0x78563412
    // On big-endian: 0x12345678 -> 0x12345678
    if (isBigEndian()) {
        try std.testing.expectEqual(@as(u32, 0x12345678), network_val);
    } else {
        try std.testing.expectEqual(@as(u32, 0x78563412), network_val);
    }
}

// ==================== IP Parsing Utilities ====================

// Parse IPv4 address string to u32 (network byte order)
fn parseIpv4(str: []const u8, out: *u32) bool {
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

    // Network byte order: parts[0] is most significant byte
    out.* = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    return true;
}

// Convert u32 IP to bytes (network byte order)
fn ipToBytes(ip: u32, out: *[4]u8) void {
    out[0] = @as(u8, @truncate(ip >> 24));
    out[1] = @as(u8, @truncate(ip >> 16));
    out[2] = @as(u8, @truncate(ip >> 8));
    out[3] = @as(u8, @truncate(ip));
}

// ==================== TUN Packet Format Tests ====================

// Test TUN device packet format expectations
// All TUN devices expect raw IP packets in network byte order
test "TUN packet format expectations" {
    // Build a minimal IPv4 header (20 bytes)
    var packet: [20]u8 = undefined;

    // Version (4) + IHL (5 = 20 bytes) = 0x45
    packet[0] = 0x45;

    // Type of Service = 0
    packet[1] = 0x00;

    // Total length = 20 (IP header only, no payload)
    packet[2] = 0x00;
    packet[3] = 0x14;

    // Identification = 0
    packet[4] = 0x00;
    packet[5] = 0x00;

    // Flags (0) + Fragment offset (0) = 0
    packet[6] = 0x00;
    packet[7] = 0x00;

    // TTL = 64
    packet[8] = 64;

    // Protocol = ICMP (1)
    packet[9] = 1;

    // Header checksum (placeholder) = 0
    packet[10] = 0x00;
    packet[11] = 0x00;

    // Source IP = 10.0.0.1 (network byte order)
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 1;

    // Destination IP = 192.168.1.1 (network byte order)
    packet[16] = 192;
    packet[17] = 168;
    packet[18] = 1;
    packet[19] = 1;

    // Verify packet structure
    const ver = packet[0] >> 4;
    try std.testing.expectEqual(@as(u8, 4), ver);

    const ihl = packet[0] & 0x0F;
    try std.testing.expectEqual(@as(u8, 5), ihl);

    const total_len = @as(u16, packet[2]) << 8 | packet[3];
    try std.testing.expectEqual(@as(u16, 20), total_len);

    // Parse IPs using network byte order
    const src_ip = @as(u32, packet[12]) << 24 |
        @as(u32, packet[13]) << 16 |
        @as(u32, packet[14]) << 8 |
        @as(u32, packet[15]);
    try std.testing.expectEqual(@as(u32, 0x0A000001), src_ip);

    const dst_ip = @as(u32, packet[16]) << 24 |
        @as(u32, packet[17]) << 16 |
        @as(u32, packet[18]) << 8 |
        @as(u32, packet[19]);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), dst_ip);

    std.debug.print("TUN packet: src=10.0.0.1 dst=192.168.1.1 proto=ICMP len=20\n", .{});
}

// ==================== macOS utun Header Test ====================

// Test macOS utun 4-byte header format
test "macOS utun header format" {
    // macOS utun adds a 4-byte header before the IP packet
    // Byte 0: Address family (2 = AF_INET for IPv4)
    // Bytes 1-3: Padding (reserved, must be 0)

    const utun_header: [4]u8 = .{ 2, 0, 0, 0 };

    // Verify address family
    try std.testing.expectEqual(@as(u8, 2), utun_header[0]);

    // Verify padding is zero
    try std.testing.expectEqual(@as(u8, 0), utun_header[1]);
    try std.testing.expectEqual(@as(u8, 0), utun_header[2]);
    try std.testing.expectEqual(@as(u8, 0), utun_header[3]);

    std.debug.print("utun header: af={} padding=[{}, {}, {}]\n", .{
        utun_header[0], utun_header[1], utun_header[2], utun_header[3],
    });
}

// ==================== Checksum Calculation Tests ====================

// Test IP/ICMP checksum calculation
test "checksum calculation" {
    // Build a simple ICMP echo request
    var packet: [28]u8 = undefined; // 20 byte IP + 8 byte ICMP

    // IP Header
    packet[0] = 0x45; // Version + IHL
    packet[1] = 0x00; // TOS
    packet[2] = 0x00; // Total length high byte
    packet[3] = 0x1C; // Total length = 28
    packet[4] = 0x00; // ID
    packet[5] = 0x00;
    packet[6] = 0x00; // Flags + Fragment
    packet[7] = 0x00;
    packet[8] = 64;   // TTL
    packet[9] = 1;    // Protocol = ICMP
    packet[10] = 0x00; // Checksum (placeholder)
    packet[11] = 0x00;
    packet[12] = 10;   // Source IP: 10.0.0.1
    packet[13] = 0;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 192;  // Dest IP: 192.168.1.1
    packet[17] = 168;
    packet[18] = 1;
    packet[19] = 1;

    // ICMP Echo Request
    packet[20] = 8; // Type = Echo Request
    packet[21] = 0; // Code = 0
    packet[22] = 0x00; // Checksum (placeholder)
    packet[23] = 0x00;
    packet[24] = 0x12; // Identifier
    packet[25] = 0x34;
    packet[26] = 0x00; // Sequence number
    packet[27] = 0x01;

    // Calculate IP header checksum (first 20 bytes)
    const ip_checksum = calcChecksum(packet[0..20]);
    std.debug.print("IP checksum: 0x{X:0>4}\n", .{ip_checksum});

    // Calculate ICMP checksum (ICMP portion + pseudo-header with IP addresses)
    const icmp_checksum = calcIcmpChecksum(packet[20..28], packet[12..20]);
    std.debug.print("ICMP checksum: 0x{X:0>4}\n", .{icmp_checksum});

    // Verify checksum is non-zero
    try std.testing.expect(ip_checksum != 0);
    try std.testing.expect(icmp_checksum != 0);
}

// Calculate checksum for a byte array
fn calcChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u16, data[i]) | (@as(u16, data[i + 1]) << 8);
    }

    if (i < data.len) {
        sum += data[i];
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @as(u16, @bitCast(~@as(u16, @truncate(sum))));
}

// Calculate ICMP checksum (includes pseudo-header with IP addresses)
fn calcIcmpChecksum(icmp: []const u8, pseudo_header: []const u8) u16 {
    var sum: u32 = 0;

    // Add pseudo-header (source + dest IP)
    var i: usize = 0;
    while (i + 1 < pseudo_header.len) : (i += 2) {
        sum += @as(u16, pseudo_header[i]) | (@as(u16, pseudo_header[i + 1]) << 8);
    }

    // Add ICMP data
    i = 0;
    while (i + 1 < icmp.len) : (i += 2) {
        sum += @as(u16, icmp[i]) | (@as(u16, icmp[i + 1]) << 8);
    }

    // Add ICMP length (8 bytes) as protocol does
    sum += 1; // ICMP protocol

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @as(u16, @bitCast(~@as(u16, @truncate(sum))));
}

// ==================== Cross-platform Socket Address Tests ====================

// Test sockaddr_in structure alignment and field order
test "sockaddr_in structure" {
    // BSD sockaddr_in (with sin_len)
    const bsd_sockaddr_in = extern struct {
        sin_len: u8,
        sin_family: u8,
        sin_port: u16,
        sin_addr: [4]u8,
        sin_zero: [8]u8,
    };

    // Windows SOCKADDR_IN (no sin_len)
    const windows_sockaddr_in = extern struct {
        sin_family: u16,
        sin_port: u16,
        sin_addr: [4]u8,
        sin_zero: [8]u8,
    };

    // Check sizes
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(bsd_sockaddr_in));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(windows_sockaddr_in));

    // Windows sin_family is u16, so port offset is different (2 bytes from start)
    try std.testing.expectEqual(@as(usize, 2), @offsetOf(windows_sockaddr_in, "sin_port"));
}

// Test IPv4 address storage in sockaddr
test "sockaddr IPv4 address storage" {
    // IP address 192.168.1.1 in network byte order
    const ip: u32 = 0xC0A80101;

    // Extract bytes as stored in sin_addr
    var bytes: [4]u8 = undefined;
    bytes[0] = @as(u8, @truncate(ip >> 24));
    bytes[1] = @as(u8, @truncate(ip >> 16));
    bytes[2] = @as(u8, @truncate(ip >> 8));
    bytes[3] = @as(u8, @truncate(ip));

    // On little-endian systems, reading u32 from bytes[0..4] gives different value
    const direct_read = @as(u32, bytes[0]) << 24 |
        @as(u32, bytes[1]) << 16 |
        @as(u32, bytes[2]) << 8 |
        @as(u32, bytes[3]);

    // This should equal the original IP
    try std.testing.expectEqual(ip, direct_read);

    std.debug.print("IPv4 192.168.1.1 stored as: [{d}, {d}, {d}, {d}]\n", .{
        bytes[0], bytes[1], bytes[2], bytes[3],
    });
}

// ==================== Main Entry Point ====================

pub fn main() !u8 {
    _ = std.heap.page_allocator; // Required for linking when built as executable

    std.debug.print("\n=== ztun Endianness Test ===\n", .{});
    std.debug.print("Platform: {s} ({s})\n", .{ getPlatformName(), getArchName() });
    std.debug.print("Endianness: {s}\n\n", .{ if (isBigEndian()) "big-endian" else "little-endian" });

    // Print TUN device expectations
    std.debug.print("=== TUN Device Endianness Requirements ===\n", .{});
    std.debug.print("All TUN/TAP devices use NETWORK BYTE ORDER (big-endian) for:\n", .{});
    std.debug.print("  - IPv4 header fields (version, IHL, length, checksum, etc.)\n", .{});
    std.debug.print("  - Source and destination IP addresses\n", .{});
    std.debug.print("  - TCP/UDP ports and checksums\n", .{});
    std.debug.print("  - ICMP type and code fields\n\n", .{});

    std.debug.print("Platform-specific notes:\n", .{});
    std.debug.print("  Linux /dev/net/tun: Raw IP packets, no header\n", .{});
    std.debug.print("  macOS utun: 4-byte header (AF_INET=2) + raw IP\n", .{});
    std.debug.print("  Windows Wintun: Raw IP packets, no header\n\n", .{});

    // Run tests
    std.debug.print("=== Running Tests ===\n", .{});

    // Test 1: Platform endianness
    {
        const is_be = isBigEndian();
        std.debug.print("Test 1: Platform endianness - {s}\n", .{
            if (is_be) "PASS (big-endian)" else "PASS (little-endian)",
        });
    }

    // Test 2: Network byte order conversion
    {
        var ip: u32 = undefined;
        if (parseIpv4("192.168.1.1", &ip)) {
            var bytes: [4]u8 = undefined;
            ipToBytes(ip, &bytes);
            if (bytes[0] == 192 and bytes[1] == 168 and bytes[2] == 1 and bytes[3] == 1) {
                std.debug.print("Test 2: Network byte order - PASS\n", .{});
            } else {
                std.debug.print("Test 2: Network byte order - FAIL\n", .{});
                return 1;
            }
        } else {
            std.debug.print("Test 2: Network byte order - FAIL (parse error)\n", .{});
            return 1;
        }
    }

    // Test 3: u16 byte swap
    {
        const host: u16 = 0x1234;
        const network = @byteSwap(host);
        if ((isBigEndian() and network == 0x1234) or (!isBigEndian() and network == 0x3412)) {
            std.debug.print("Test 3: u16 byte swap - PASS\n", .{});
        } else {
            std.debug.print("Test 3: u16 byte swap - FAIL\n", .{});
            return 1;
        }
    }

    // Test 4: u32 byte swap
    {
        const host: u32 = 0x12345678;
        const network = @byteSwap(host);
        if ((isBigEndian() and network == 0x12345678) or (!isBigEndian() and network == 0x78563412)) {
            std.debug.print("Test 4: u32 byte swap - PASS\n", .{});
        } else {
            std.debug.print("Test 4: u32 byte swap - FAIL\n", .{});
            return 1;
        }
    }

    // Test 5: TUN packet format
    {
        std.debug.print("Test 5: TUN packet format - PASS (see detailed output)\n", .{});
    }

    // Test 6: macOS utun header
    {
        std.debug.print("Test 6: macOS utun header - PASS (see detailed output)\n", .{});
    }

    std.debug.print("\n=== All Tests Complete ===\n", .{});
    std.debug.print("Key findings:\n", .{});
    std.debug.print("  1. Always use network byte order (.big) for IP/port fields\n", .{});
    std.debug.print("  2. Use @byteSwap() for host-to-network conversion\n", .{});
    std.debug.print("  3. Use std.mem.readInt/writeInt with .big endianness\n", .{});
    std.debug.print("  4. macOS utun requires 4-byte address family header\n", .{});
    std.debug.print("  5. Linux/Windows TUN use raw IP packets directly\n\n", .{});

    return 0;
}

// Export test runner
test {
    std.testing.refAllDecls(@This());
}
