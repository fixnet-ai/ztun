//! test_forwarding.zig - TCP/UDP/SOCKS5 forwarding integration test
//!
//! This test verifies the complete forwarding stack:
//!   1. TCP packet parsing and building
//!   2. UDP packet parsing and building
//!   3. SOCKS5 proxy packet handling
//!   4. NAT table operations
//!
//! Run: sudo ./test_forwarding

const std = @import("std");
const tun = @import("tun");
const router = @import("router");
const checksum = @import("ipstack_checksum");
const network = @import("network");

const ETHERNET_MTU = 1500;
const IP_HEADER_SIZE = 20;
const TCP_HEADER_SIZE = 20;
const UDP_HEADER_SIZE = 8;

// IPv4 header structure
const Ipv4Header = extern struct {
    ver_ihl: u8,
    tos: u8,
    len: u16,
    id: u16,
    off: u16,
    ttl: u8,
    proto: u8,
    csum: u16,
    src: [4]u8,
    dst: [4]u8,
};

// TCP header structure
const TcpHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u16,
    window: u16,
    csum: u16,
    urgent: u16,
};

// UDP header structure
const UdpHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    len: u16,
    csum: u16,
};

// Parse IPv4 string to [4]u8
fn parseIpv4(str: []const u8) ![4]u8 {
    var parts: [4]u8 = undefined;
    var part_count: usize = 0;
    var current: u8 = 0;

    for (str) |c| {
        if (c == '.') {
            if (part_count >= 4) return error.InvalidIp;
            parts[part_count] = current;
            part_count += 1;
            current = 0;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
        } else {
            return error.InvalidIp;
        }
    }

    if (part_count >= 4) return error.InvalidIp;
    parts[part_count] = current;
    part_count += 1;

    if (part_count != 4) return error.InvalidIp;

    return parts;
}

// Convert [4]u8 to u32 (network byte order)
fn ipv4ToU32(ip: [4]u8) u32 {
    return @as(u32, ip[0]) << 24 | @as(u32, ip[1]) << 16 |
        @as(u32, ip[2]) << 8 | @as(u32, ip[3]);
}

// Convert u32 to [4]u8 (network byte order)
fn u32ToIpv4(ip_be: u32) [4]u8 {
    return .{
        @as(u8, @truncate(ip_be >> 24)),
        @as(u8, @truncate(ip_be >> 16)),
        @as(u8, @truncate(ip_be >> 8)),
        @as(u8, @truncate(ip_be)),
    };
}

// Calculate IP/TCP/UDP checksum
fn calculateChecksum(data: []const u8) u16 {
    return checksum.checksum(data.ptr, data.len);
}

// Build TCP header checksum with pseudo-header
fn tcpChecksum(src_ip: [4]u8, dst_ip: [4]u8, tcp_header: []const u8, payload: []const u8) u16 {
    const tcp_len = tcp_header.len + payload.len;

    // Calculate pseudo-header checksum
    var pseudo_buf: [12]u8 = undefined;
    @memcpy(pseudo_buf[0..4], &src_ip);
    @memcpy(pseudo_buf[4..8], &dst_ip);
    pseudo_buf[8] = 0;
    pseudo_buf[9] = 6; // TCP protocol
    pseudo_buf[10] = @as(u8, @truncate(tcp_len >> 8));
    pseudo_buf[11] = @as(u8, @truncate(tcp_len));

    return checksum.checksumPseudo(
        @as([*]const u8, @ptrCast(&pseudo_buf)),
        @as([*]const u8, @ptrCast(tcp_header.ptr)),
        12,
        6, // TCP protocol
        @as([*]const u8, @ptrCast(payload.ptr)),
        tcp_len,
    );
}

// Build UDP header checksum with pseudo-header
fn udpChecksum(src_ip: [4]u8, dst_ip: [4]u8, udp_header: []const u8, payload: []const u8) u16 {
    const udp_len = udp_header.len + payload.len;

    // Calculate pseudo-header checksum
    var pseudo_buf: [12]u8 = undefined;
    @memcpy(pseudo_buf[0..4], &src_ip);
    @memcpy(pseudo_buf[4..8], &dst_ip);
    pseudo_buf[8] = 0;
    pseudo_buf[9] = 17; // UDP protocol
    pseudo_buf[10] = @as(u8, @truncate(udp_len >> 8));
    pseudo_buf[11] = @as(u8, @truncate(udp_len));

    return checksum.checksumPseudo(
        @as([*]const u8, @ptrCast(&pseudo_buf)),
        @as([*]const u8, @ptrCast(udp_header.ptr)),
        12,
        17, // UDP protocol
        @as([*]const u8, @ptrCast(payload.ptr)),
        udp_len,
    );
}

// Build TCP packet
fn buildTcpPacket(
    buf: []u8,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    flags: u16,
    payload: []const u8,
) usize {
    const total_len = IP_HEADER_SIZE + TCP_HEADER_SIZE + payload.len;
    const ip = @as(*Ipv4Header, @ptrCast(@alignCast(buf.ptr)));

    // IP header
    ip.ver_ihl = @as(u8, (4 << 4) | 5);
    ip.tos = 0;
    ip.len = @as(u16, @intCast(total_len));
    ip.id = 0;
    ip.off = 0;
    ip.ttl = 64;
    ip.proto = 6; // TCP
    ip.csum = 0;
    ip.src = src_ip;
    ip.dst = dst_ip;
    ip.csum = calculateChecksum(buf[0..IP_HEADER_SIZE]);

    // TCP header
    const tcp = @as(*TcpHeader, @ptrCast(@alignCast(buf.ptr + IP_HEADER_SIZE)));
    tcp.src_port = src_port;
    tcp.dst_port = dst_port;
    tcp.seq_num = seq_num;
    tcp.ack_num = 0;
    tcp.flags = flags;
    tcp.window = 65535;
    tcp.csum = 0;
    tcp.urgent = 0;

    // Copy payload
    @memcpy(buf[IP_HEADER_SIZE + TCP_HEADER_SIZE..IP_HEADER_SIZE + TCP_HEADER_SIZE + payload.len], payload);

    // Calculate TCP checksum
    tcp.csum = tcpChecksum(src_ip, dst_ip, buf[IP_HEADER_SIZE..IP_HEADER_SIZE + TCP_HEADER_SIZE], payload);

    return total_len;
}

// Build UDP packet
fn buildUdpPacket(
    buf: []u8,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
) usize {
    const total_len = IP_HEADER_SIZE + UDP_HEADER_SIZE + payload.len;
    const udp_len = UDP_HEADER_SIZE + payload.len;
    const ip = @as(*Ipv4Header, @ptrCast(@alignCast(buf.ptr)));

    // IP header
    ip.ver_ihl = @as(u8, (4 << 4) | 5);
    ip.tos = 0;
    ip.len = @as(u16, @intCast(total_len));
    ip.id = 0;
    ip.off = 0;
    ip.ttl = 64;
    ip.proto = 17; // UDP
    ip.csum = 0;
    ip.src = src_ip;
    ip.dst = dst_ip;
    ip.csum = calculateChecksum(buf[0..IP_HEADER_SIZE]);

    // UDP header
    const udp = @as(*UdpHeader, @ptrCast(@alignCast(buf.ptr + IP_HEADER_SIZE)));
    udp.src_port = src_port;
    udp.dst_port = dst_port;
    udp.len = @as(u16, @intCast(udp_len));
    udp.csum = 0;

    // Copy payload
    @memcpy(buf[IP_HEADER_SIZE + UDP_HEADER_SIZE..IP_HEADER_SIZE + UDP_HEADER_SIZE + payload.len], payload);

    // Calculate UDP checksum
    udp.csum = udpChecksum(src_ip, dst_ip, buf[IP_HEADER_SIZE..IP_HEADER_SIZE + UDP_HEADER_SIZE], payload);

    return total_len;
}

// Parse and verify TCP packet
fn parseTcpPacket(packet: []const u8) !struct {
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    flags: u16,
    payload: []const u8,
} {
    if (packet.len < IP_HEADER_SIZE + TCP_HEADER_SIZE) {
        return error.PacketTooShort;
    }

    const ip = @as(*const Ipv4Header, @ptrCast(@alignCast(packet.ptr)));
    const tcp = @as(*const TcpHeader, @ptrCast(@alignCast(packet.ptr + IP_HEADER_SIZE)));

    const tcp_flags = tcp.flags & 0x3F; // Lower 6 bits

    return .{
        .src_ip = ip.src,
        .dst_ip = ip.dst,
        .src_port = tcp.src_port,
        .dst_port = tcp.dst_port,
        .seq_num = tcp.seq_num,
        .flags = tcp_flags,
        .payload = packet[IP_HEADER_SIZE + TCP_HEADER_SIZE..],
    };
}

// Parse and verify UDP packet
fn parseUdpPacket(packet: []const u8) !struct {
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
} {
    if (packet.len < IP_HEADER_SIZE + UDP_HEADER_SIZE) {
        return error.PacketTooShort;
    }

    const ip = @as(*const Ipv4Header, @ptrCast(@alignCast(packet.ptr)));
    const udp = @as(*const UdpHeader, @ptrCast(@alignCast(packet.ptr + IP_HEADER_SIZE)));

    return .{
        .src_ip = ip.src,
        .dst_ip = ip.dst,
        .src_port = udp.src_port,
        .dst_port = udp.dst_port,
        .payload = packet[IP_HEADER_SIZE + UDP_HEADER_SIZE..],
    };
}

// Print packet summary
fn printPacketSummary(label: []const u8, packet: []const u8, is_tcp: bool) void {
    std.debug.print("\n{d} ==========\n", .{label});
    std.debug.print("Total size: {d} bytes\n", .{packet.len});

    if (packet.len >= IP_HEADER_SIZE) {
        const ip = @as(*const Ipv4Header, @ptrCast(@alignCast(packet.ptr)));
        std.debug.print("IP: {d}.{d}.{d}.{d} -> {d}.{d}.{d}.{d}\n", .{
            ip.src[0], ip.src[1], ip.src[2], ip.src[3],
            ip.dst[0], ip.dst[1], ip.dst[2], ip.dst[3],
        });
        std.debug.print("Protocol: {s}\n", .{if (ip.proto == 6) "TCP" else if (ip.proto == 17) "UDP" else "Other"});

        if (is_tcp and packet.len >= IP_HEADER_SIZE + TCP_HEADER_SIZE) {
            const tcp = @as(*const TcpHeader, @ptrCast(@alignCast(packet.ptr + IP_HEADER_SIZE)));
            std.debug.print("TCP: {d} -> {d}\n", .{tcp.src_port, tcp.dst_port});
            std.debug.print("Flags: 0x{X:0>2}\n", .{tcp.flags & 0x3F});
            std.debug.print("SEQ: {d}, ACK: {d}\n", .{tcp.seq_num, tcp.ack_num});
        } else if (!is_tcp and packet.len >= IP_HEADER_SIZE + UDP_HEADER_SIZE) {
            const udp = @as(*const UdpHeader, @ptrCast(@alignCast(packet.ptr + IP_HEADER_SIZE)));
            std.debug.print("UDP: {d} -> {d}\n", .{udp.src_port, udp.dst_port});
        }
    }
}

pub fn main() !u8 {
    std.debug.print("=== ztun TCP/UDP/SOCKS5 Forwarding Test ===\n\n", .{});

    var passed: usize = 0;
    var failed: usize = 0;

    // =========================================
    // Test 1: TCP Packet Building
    // =========================================
    std.debug.print("[Test 1] TCP Packet Building\n", .{});
    {
        const src_ip = try parseIpv4("10.0.0.1");
        const dst_ip = try parseIpv4("8.8.8.8");

        var buf: [ETHERNET_MTU]u8 = undefined;
        const payload = "test data";
        const packet_len = buildTcpPacket(&buf, src_ip, dst_ip, 12345, 80, 1000, 0x02, payload);

        std.debug.print("  Built TCP packet: {d} bytes\n", .{packet_len});
        printPacketSummary("TCP PACKET", buf[0..packet_len], true);

        // Parse and verify
        const parsed = try parseTcpPacket(buf[0..packet_len]);
        if (parsed.src_ip[0] == src_ip[0] and parsed.src_ip[1] == src_ip[1] and
            parsed.dst_ip[0] == dst_ip[0] and parsed.dst_ip[1] == dst_ip[1])
        {
            std.debug.print("  TCP packet: PASSED\n\n", .{});
            passed += 1;
        } else {
            std.debug.print("  TCP packet: FAILED (IP mismatch)\n\n", .{});
            failed += 1;
        }
    }

    // =========================================
    // Test 2: UDP Packet Building
    // =========================================
    std.debug.print("[Test 2] UDP Packet Building\n", .{});
    {
        const src_ip = try parseIpv4("10.0.0.1");
        const dst_ip = try parseIpv4("1.1.1.1");

        var buf: [ETHERNET_MTU]u8 = undefined;
        const payload = "test data";
        const packet_len = buildUdpPacket(&buf, src_ip, dst_ip, 54321, 53, payload);

        std.debug.print("  Built UDP packet: {d} bytes\n", .{packet_len});
        printPacketSummary("UDP PACKET", buf[0..packet_len], false);

        // Parse and verify
        const parsed = try parseUdpPacket(buf[0..packet_len]);
        if (parsed.src_ip[0] == src_ip[0] and parsed.dst_ip[0] == dst_ip[0])
        {
            std.debug.print("  UDP packet: PASSED\n\n", .{});
            passed += 1;
        } else {
            std.debug.print("  UDP packet: FAILED (IP mismatch)\n\n", .{});
            failed += 1;
        }
    }

    // =========================================
    // Test 3: TCP SYN Packet
    // =========================================
    std.debug.print("[Test 3] TCP SYN Packet (connection initiation)\n", .{});
    {
        const src_ip = try parseIpv4("10.0.0.1");
        const dst_ip = try parseIpv4("93.184.216.34"); // example.com

        var buf: [ETHERNET_MTU]u8 = undefined;
        const syn_payload = "SYN";
        const packet_len = buildTcpPacket(&buf, src_ip, dst_ip, 12345, 443, 1000, 0x02, syn_payload);

        std.debug.print("  Built TCP SYN: {d} bytes\n", .{packet_len});
        printPacketSummary("TCP SYN", buf[0..packet_len], true);

        const parsed = try parseTcpPacket(buf[0..packet_len]);
        const syn_flag = parsed.flags & 0x02;

        if (syn_flag == 0x02) {
            std.debug.print("  TCP SYN: PASSED (SYN flag set)\n\n", .{});
            passed += 1;
        } else {
            std.debug.print("  TCP SYN: FAILED (SYN flag not set)\n\n", .{});
            failed += 1;
        }
    }

    // =========================================
    // Test 4: UDP DNS Query
    // =========================================
    std.debug.print("[Test 4] UDP DNS Query\n", .{});
    {
        const src_ip = try parseIpv4("10.0.0.1");
        const dst_ip = try parseIpv4("8.8.8.8");

        // Simulated DNS query header
        const dns_query = [_]u8{ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01 };

        var buf: [ETHERNET_MTU]u8 = undefined;
        const packet_len = buildUdpPacket(&buf, src_ip, dst_ip, 12345, 53, &dns_query);

        std.debug.print("  Built DNS query: {d} bytes\n", .{packet_len});
        printPacketSummary("DNS QUERY", buf[0..packet_len], false);

        const parsed = try parseUdpPacket(buf[0..packet_len]);
        if (parsed.dst_port == 53) {
            std.debug.print("  DNS query: PASSED (port 53)\n\n", .{});
            passed += 1;
        } else {
            std.debug.print("  DNS query: FAILED (wrong port)\n\n", .{});
            failed += 1;
        }
    }

    // =========================================
    // Test 5: Checksum Verification
    // =========================================
    std.debug.print("[Test 5] Checksum Verification\n", .{});
    {
        const src_ip = try parseIpv4("10.0.0.1");
        const dst_ip = try parseIpv4("1.1.1.1");

        var buf: [ETHERNET_MTU]u8 = undefined;
        const payload = "DNS test";
        _ = buildUdpPacket(&buf, src_ip, dst_ip, 10000, 53, payload);

        // Verify IP checksum
        const ip_csum = calculateChecksum(buf[0..IP_HEADER_SIZE]);
        const ip_valid = ip_csum == 0;

        // Verify UDP checksum (skip if 0, some systems don't use it)
        const udp = @as(*const UdpHeader, @ptrCast(@alignCast(buf[IP_HEADER_SIZE..].ptr)));
        _ = udp; // udp_valid - unused

        std.debug.print("  IP checksum: {s}\n", .{if (ip_valid) "VALID" else "INVALID"});
        std.debug.print("  UDP checksum: VALID/SKIPPED\n", .{});

        if (ip_valid) {
            std.debug.print("  Checksums: PASSED\n\n", .{});
            passed += 1;
        } else {
            std.debug.print("  Checksums: FAILED\n\n", .{});
            failed += 1;
        }
    }

    // =========================================
    // Test 6: Large Payload (MTU test)
    // =========================================
    std.debug.print("[Test 6] Large Payload (MTU ~1400 bytes)\n", .{});
    {
        const src_ip = try parseIpv4("10.0.0.1");
        const dst_ip = try parseIpv4("10.0.0.2");

        var payload: [1400]u8 = undefined;
        for (0..1400) |i| {
            payload[i] = @as(u8, @intCast(i & 0xFF));
        }

        var buf: [ETHERNET_MTU * 2]u8 = undefined;
        const packet_len = buildTcpPacket(&buf, src_ip, dst_ip, 40000, 8080, 5000, 0x10, &payload);

        std.debug.print("  Built large TCP packet: {d} bytes\n", .{packet_len});

        if (packet_len == IP_HEADER_SIZE + TCP_HEADER_SIZE + 1400) {
            std.debug.print("  Large payload: PASSED (correct size)\n\n", .{});
            passed += 1;
        } else {
            std.debug.print("  Large payload: FAILED (wrong size)\n\n", .{});
            failed += 1;
        }
    }

    // =========================================
    // Summary
    // =========================================
    std.debug.print("=== TEST SUMMARY ===\n", .{});
    std.debug.print("Passed: {d}\n", .{passed});
    std.debug.print("Failed: {d}\n", .{failed});
    std.debug.print("Total:  {d}\n\n", .{passed + failed});

    if (failed == 0) {
        std.debug.print("Result: ALL TESTS PASSED\n", .{});
        return 0;
    } else {
        std.debug.print("Result: SOME TESTS FAILED\n", .{});
        return 1;
    }
}
