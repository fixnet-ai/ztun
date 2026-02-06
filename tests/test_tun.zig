//! test_tun.zig - Simple ping echo test
//!
//! Test steps:
//! 1. Create TUN device with IP 10.0.0.1 (bound to utun4)
//! 2. Add route: 10.0.0.0/24 -> via 10.0.0.1 utun4
//! 3. Listen for TUN read events
//! 4. Receive ICMP echo request (ping to 10.0.0.2)
//! 5. Construct ICMP echo reply (src=10.0.0.1, dst=ping source)
//! 6. Write back to TUN
//! 7. Verify ping succeeds
//!
//! Run: sudo ./test_tun
//! Then in another terminal: ping 10.0.0.2

const std = @import("std");
const tun = @import("tun");
const DeviceConfig = tun.DeviceConfig;
const NetworkAddress = tun.NetworkAddress;
const checksum = @import("ipstack_checksum");
const sysroute = @import("sysroute");

const ICMP_ECHO = 8;
const ICMP_ECHOREPLY = 0;
const ICMP_PROTOCOL = 1;

// Convert [4]u8 to null-terminated C string
fn toCStr(dest: *[16]u8, src: []const u8) void {
    @memcpy(dest[0..src.len], src);
    dest[src.len] = 0;
}

// ICMP header structure
const IcmpHeader = extern struct {
    icmp_type: u8,
    icmp_code: u8,
    icmp_csum: u16,
    icmp_id: u16,
    icmp_seq: u16,
};

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

const ETHERNET_MTU = 1500;
const IP_HEADER_SIZE = 20;
const ICMP_HEADER_SIZE = 8;

pub fn main() !void {
    // Test configuration for ping echo test
    // - TUN device IP: 10.0.0.1 (bound to utun4)
    // - Ping target: 10.0.0.2 (non-existent IP, routed to utun4)
    // This ensures ping packets go through utun4 instead of loopback
    const tun_ip_str = "10.0.0.1";
    const target_ip_str = "10.0.0.2";

    std.debug.print("=== ztun Ping Echo Test ===\n", .{});
    std.debug.print("TUN IP: {s}\n", .{tun_ip_str});
    std.debug.print("Target IP: {s}\n", .{target_ip_str});
    std.debug.print("Ping command: ping {s}\n\n", .{target_ip_str});

    // Parse IP addresses
    const tun_ip = try parseIpv4(tun_ip_str);

    // Create TUN device
    std.debug.print("[1/5] Creating TUN device...\n", .{});
    const config = DeviceConfig{
        .mtu = 1500,
        .ipv4 = NetworkAddress{
            .address = tun_ip,
            .prefix = 24,
        },
    };

    var device = try tun.Device.create(config);
    defer device.destroy();

    const dev_name = device.name() catch "unknown";
    std.debug.print("    TUN device created: {s}\n", .{dev_name});

    // Get interface index for routing
    const if_index = device.ifIndex() catch 0;
    std.debug.print("    Interface index: {d}\n", .{if_index});

    // Set non-blocking mode
    try device.setNonBlocking(true);
    std.debug.print("    Non-blocking mode enabled\n", .{});

    // Add route using sysroute.zig
    std.debug.print("[2/5] Adding route...\n", .{});
    const target_ip = try parseIpv4(target_ip_str);
    const tun_ip_bytes = try parseIpv4(tun_ip_str);

    // Get interface index from device name
    var name_buf: [16]u8 = undefined;
    toCStr(&name_buf, dev_name);
    const iface_idx = sysroute.getIfaceIndex(@as([*:0]const u8, @ptrCast(&name_buf))) catch {
        std.debug.print("    Warning: Failed to get interface index\n", .{});
        return;
    };
    std.debug.print("    Interface: {s}, index: {d}\n", .{ dev_name, iface_idx });

    // Convert [4]u8 to u32 (host order), then to network byte order using @byteSwap
    const dst_ip_be = @byteSwap(@as(u32, target_ip[0]) << 24 | @as(u32, target_ip[1]) << 16 | @as(u32, target_ip[2]) << 8 | @as(u32, target_ip[3]));
    const gw_ip_be = @byteSwap(@as(u32, tun_ip_bytes[0]) << 24 | @as(u32, tun_ip_bytes[1]) << 16 | @as(u32, tun_ip_bytes[2]) << 8 | @as(u32, tun_ip_bytes[3]));

    // Create and add route
    var route = sysroute.createIpv4Route(dst_ip_be, 32, gw_ip_be, iface_idx, 0);
    route.interface_scope = true;
    route.iface_name = @as([*:0]const u8, @ptrCast(&name_buf));
    sysroute.routeAdd(&route) catch |err| {
        std.debug.print("    Warning: Failed to add route: {}\n", .{err});
    };

    // Allocate buffers
    var packet_buf: [ETHERNET_MTU]u8 = undefined;
    var reply_buf: [ETHERNET_MTU]u8 = undefined;

    std.debug.print("[3/5] Listening for ICMP echo requests...\n", .{});

    while (true) {
        // Read packet from TUN (non-blocking)
        const bytes = device.recv(&packet_buf) catch |err| {
            if (err == tun.TunError.IoError) {
                // EAGAIN/EWOULDBLOCK - no data available, try again
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            std.debug.print("ERROR: Failed to read from TUN: {}\n", .{err});
            continue;
        };

        if (bytes == 0) {
            std.time.sleep(10 * std.time.ns_per_ms);
            continue;
        }

        std.debug.print("    Received {d} bytes from TUN\n", .{bytes});

        // Parse IP header
        if (bytes < IP_HEADER_SIZE) {
            continue;
        }

        const ip_header = @as(*const Ipv4Header, @ptrCast(@alignCast(&packet_buf)));
        const ip_header_len = (ip_header.ver_ihl & 0x0F) * 4;
        const protocol = ip_header.proto;

        // Check if ICMP
        if (protocol == 1 and bytes >= ip_header_len + ICMP_HEADER_SIZE) {
            const icmp_offset = ip_header_len;
            const icmp_header = @as(*const IcmpHeader, @ptrCast(@alignCast(&packet_buf[icmp_offset])));

            // Check if ICMP Echo Request (type=8)
            if (icmp_header.icmp_type == ICMP_ECHO) {
                std.debug.print("    ICMP Echo Request: id={d}, seq={d}\n", .{
                    icmp_header.icmp_id,
                    icmp_header.icmp_seq,
                });

                // Copy IP header
                for (0..bytes) |i| {
                    reply_buf[i] = packet_buf[i];
                }
                const reply_ip = @as(*Ipv4Header, @ptrCast(@alignCast(&reply_buf)));
                // Echo Reply: src = TUN device IP, dst = original dst (ping target)
                reply_ip.src = tun_ip;
                reply_ip.dst = ip_header.dst; // dst = ping target IP (10.0.0.2)

                // Copy ICMP header and data
                for (icmp_offset..bytes) |i| {
                    reply_buf[i] = packet_buf[i];
                }
                const reply_icmp_ptr = @as(*IcmpHeader, @ptrCast(@alignCast(&reply_buf[icmp_offset])));
                reply_icmp_ptr.icmp_type = ICMP_ECHOREPLY;
                reply_icmp_ptr.icmp_csum = 0; // Recalculate checksum

                // Recalculate IP checksum (covers IP header only)
                reply_ip.csum = 0;
                reply_ip.csum = calculateChecksum(reply_buf[0..ip_header_len]);

                // Recalculate ICMP checksum with pseudo-header (required for ICMPv4)
                // Pseudo-header: src_ip + dst_ip + 0 + protocol(1) + icmp_len
                const icmp_len = bytes - icmp_offset;
                // Convert IPs to network byte order for pseudo-header checksum
                const icmp_src_ip_be = @byteSwap(@as(u32, reply_ip.src[0]) << 24 | @as(u32, reply_ip.src[1]) << 16 | @as(u32, reply_ip.src[2]) << 8 | @as(u32, reply_ip.src[3]));
                const icmp_dst_ip_be = @byteSwap(@as(u32, reply_ip.dst[0]) << 24 | @as(u32, reply_ip.dst[1]) << 16 | @as(u32, reply_ip.dst[2]) << 8 | @as(u32, reply_ip.dst[3]));
                reply_icmp_ptr.icmp_csum = checksum.checksumPseudo(
                    @as([*]const u8, @ptrCast(&icmp_src_ip_be)),
                    @as([*]const u8, @ptrCast(&icmp_dst_ip_be)),
                    4, // IPv4 address length
                    ICMP_PROTOCOL,
                    @as([*]const u8, @ptrCast(&reply_buf[icmp_offset])),
                    icmp_len,
                );

                // ========== PACKET DUMP DEBUG ==========
                const reply_ip_ptr = @as(*const Ipv4Header, @ptrCast(@alignCast(&reply_buf)));

                // Dump AF_INET header (4 bytes) - device.send() adds this
                std.debug.print("\n========== SENDING PACKET DUMP ==========\n", .{});
                std.debug.print("AF_INET header: 0x00000002 (4 bytes will be prepended by device.send())\n", .{});

                // Dump IP header
                std.debug.print("IP Header:\n", .{});
                std.debug.print("  Version: {d}, IHL: {d} (header size: {d} bytes)\n", .{
                    reply_ip_ptr.ver_ihl >> 4,
                    reply_ip_ptr.ver_ihl & 0x0F,
                    ip_header_len,
                });
                std.debug.print("  TOS: 0x{X:0>2}, Total Length: {d} (0x{X:0>4})\n", .{
                    reply_ip_ptr.tos,
                    reply_ip_ptr.len,
                    reply_ip_ptr.len,
                });
                std.debug.print("  ID: {d}, Flags/Offset: 0x{X:0>4}\n", .{
                    reply_ip_ptr.id,
                    reply_ip_ptr.off,
                });
                std.debug.print("  TTL: {d}, Protocol: {d} (1=ICMP)\n", .{
                    reply_ip_ptr.ttl,
                    reply_ip_ptr.proto,
                });
                std.debug.print("  Header Checksum: 0x{X:0>4}\n", .{reply_ip_ptr.csum});
                std.debug.print("  Src IP: {d}.{d}.{d}.{d}\n", .{
                    reply_ip_ptr.src[0], reply_ip_ptr.src[1],
                    reply_ip_ptr.src[2], reply_ip_ptr.src[3],
                });
                std.debug.print("  Dst IP: {d}.{d}.{d}.{d}\n", .{
                    reply_ip_ptr.dst[0], reply_ip_ptr.dst[1],
                    reply_ip_ptr.dst[2], reply_ip_ptr.dst[3],
                });

                // Dump ICMP header
                std.debug.print("ICMP Header:\n", .{});
                std.debug.print("  Type: {d} (0=Echo Reply)\n", .{reply_icmp_ptr.icmp_type});
                std.debug.print("  Code: {d}\n", .{reply_icmp_ptr.icmp_code});
                std.debug.print("  Checksum: 0x{X:0>4}\n", .{reply_icmp_ptr.icmp_csum});
                std.debug.print("  ID: {d}, Seq: {d}\n", .{
                    reply_icmp_ptr.icmp_id,
                    reply_icmp_ptr.icmp_seq,
                });

                // Dump raw packet bytes (IP header + ICMP)
                std.debug.print("Raw Packet (first {d} bytes):\n", .{@min(bytes, 64)});
                const dump_len = @min(bytes, 64);
                for (0..dump_len) |i| {
                    std.debug.print("{X:0>2} ", .{reply_buf[i]});
                    if (i % 16 == 15) std.debug.print("\n", .{});
                }
                if (dump_len % 16 != 0) std.debug.print("\n", .{});
                if (bytes > 64) std.debug.print("  ... ({d} more bytes)\n", .{bytes - 64});
                std.debug.print("===========================================\n\n", .{});

                // Send reply
                const sent = device.send(reply_buf[0..bytes]) catch {
                    std.debug.print("ERROR: Failed to send reply\n", .{});
                    continue;
                };
                std.debug.print("    Sent ICMP Echo Reply: {d} bytes\n", .{sent});
            }
        }
    }
}

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

    // Last part
    if (part_count >= 4) return error.InvalidIp;
    parts[part_count] = current;
    part_count += 1;

    if (part_count != 4) return error.InvalidIp;

    return parts;
}

fn calculateChecksum(data: []const u8) u16 {
    return checksum.checksum(data.ptr, data.len);
}
