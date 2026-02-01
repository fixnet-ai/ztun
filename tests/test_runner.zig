//! test_runner.zig - Integration Tests for ztun
//!
//! Tests the full library functionality.
//!
//! Usage: sudo ./zig-out/bin/test_runner
//! This will create a TUN device at 10.0.0.1, read one ICMP packet,
//! swap src/dst, fix checksum, send it back, then exit.

const std = @import("std");
const builtin = @import("builtin");
const ztun = @import("tun");
const Device = ztun.Device;
const Ipv4Address = ztun.Ipv4Address;

// ==================== ICMP Packet Processor ====================

/// Process a single ICMP echo request packet
/// Returns true if packet was processed and should be sent back
fn processIcmpPacket(packet: []u8) bool {
    // Minimum IP header (20 bytes) + ICMP header (8 bytes)
    if (packet.len < 28) return false;

    const ip_ver_ihl = packet[0];
    const ip_ver = ip_ver_ihl >> 4;
    const ip_ihl = ip_ver_ihl & 0x0F;

    // Must be IPv4 with valid header length
    if (ip_ver != 4) return false;
    if (ip_ihl < 5) return false;

    const ip_header_len = ip_ihl * 4;
    if (packet.len < ip_header_len + 8) return false;

    // Must be ICMP (protocol = 1)
    const protocol = packet[9];
    if (protocol != 1) return false;

    // Must be ICMP Echo Request (type = 8)
    const icmp_type = packet[ip_header_len];
    if (icmp_type != 8) return false;

    std.debug.print("  Received ICMP Echo Request\n", .{});

    // Swap src and dst IP addresses
    const src_ip = packet[12..16];
    const dst_ip = packet[16..20];
    for (0..4) |i| {
        const tmp = src_ip[i];
        src_ip[i] = dst_ip[i];
        dst_ip[i] = tmp;
    }

    // Change ICMP Echo Request (8) to Echo Reply (0)
    packet[ip_header_len] = 0;

    // Recalculate IP checksum
    packet[10] = 0;
    packet[11] = 0;
    const ip_sum = checksum(packet[0..ip_header_len]);
    std.mem.writeInt(u16, packet[10..12], ip_sum, .big);

    // Recalculate ICMP checksum
    packet[ip_header_len + 2] = 0;
    packet[ip_header_len + 3] = 0;
    const icmp_sum = checksum(packet[ip_header_len..]);
    std.mem.writeInt(u16, packet[ip_header_len + 2..][0..2], icmp_sum, .big);

    std.debug.print("  Sent ICMP Echo Reply\n", .{});
    return true;
}

/// Calculate Internet Checksum
fn checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    const bytes = data.len;

    var i: usize = 0;
    while (i + 1 < bytes) : (i += 2) {
        sum += std.mem.readInt(u16, data[i..][0..2], .big);
    }

    if (bytes % 2 == 1) {
        sum += @as(u16, data[bytes - 1]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @truncate(sum));
}

// ==================== Test Scenario ====================

fn testSyncIcmpEchoReply(_: *anyopaque) bool {
    const allocator = std.heap.page_allocator;

    // Print platform info for debugging
    std.debug.print("  Platform: {s}\n", .{@tagName(builtin.os.tag)});

    const tun_addr: Ipv4Address = .{ 10, 0, 0, 1 };
    var builder = ztun.DeviceBuilder.init();
    _ = builder.setName("ztun-test");
    _ = builder.setMtu(1500);
    _ = builder.setIpv4(tun_addr, 24, null);

    const device = builder.build() catch |err| {
        std.debug.print("  Failed to create TUN device: {} (os={s})\n", .{ err, @tagName(builtin.os.tag) });
        return false;  // Test fails if we can't create device
    };
    defer device.destroy();

    const dev_name = device.name() catch "unknown";
    const dev_mtu = device.mtu() catch 0;
    std.debug.print("  Created TUN device: {s}, MTU: {d}\n", .{ dev_name, dev_mtu });
    std.debug.print("  Device IP: 10.0.0.1/24\n", .{});
    std.debug.print("  Mode: synchronous, one-shot\n", .{});
    std.debug.print("  Waiting for ICMP packet...\n", .{});

    // Allocate buffer for one packet
    const buf_size = 4096;
    const buf = allocator.alloc(u8, buf_size) catch {
        std.debug.print("  Failed to allocate packet buffer\n", .{});
        return false;
    };
    defer allocator.free(buf);

    // Synchronous read - blocking until packet arrives
    const len = device.recv(buf) catch {
        std.debug.print("  Failed to read packet\n", .{});
        return false;
    };

    if (len == 0) {
        std.debug.print("  No packet received\n", .{});
        return false;
    }

    std.debug.print("  Read packet: {d} bytes\n", .{len});

    // Process and potentially reply
    if (processIcmpPacket(buf[0..len])) {
        _ = device.send(buf[0..len]) catch {
            std.debug.print("  Failed to send packet\n", .{});
            return false;
        };
    }

    return true;
}

// ==================== Main Entry ====================

pub fn main() u8 {
    std.debug.print("\n=== ztun ICMP Echo Test ===\n\n", .{});
    std.debug.print("This test creates a TUN device at 10.0.0.1,\n", .{});
    std.debug.print("reads one ICMP packet, swaps src/dst,\n", .{});
    std.debug.print("fixes checksum, sends reply, then exits.\n\n", .{});

    const passed = testSyncIcmpEchoReply(undefined);

    std.debug.print("\n=== Result ===\n", .{});
    if (passed) {
        std.debug.print("Test passed!\n", .{});
        return 0;
    } else {
        std.debug.print("Test failed!\n", .{});
        return 1;
    }
}
