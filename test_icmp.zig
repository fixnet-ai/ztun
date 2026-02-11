// test_icmp.zig - TUN ICMP Echo Reply Test using C Helper
// Build: zig build-exe test_icmp.zig test_icmp_help.c -lc -I.
// Run: sudo ./test_icmp
//
// This version wraps test_icmp.c completely in C helper,
// Zig only calls C functions via extern declarations.

const std = @import("std");

// ============================================================================
// C Function Declarations (extern, no header)
// ============================================================================

// ============================================================================
// C Function Declarations (to be migrated)
// ============================================================================

extern "c" fn create_utun_socket(ifname: [*]u8, max_len: usize) c_int;
extern "c" fn configure_ip(ifname: [*:0]const u8, ip: [*:0]const u8) c_int;
extern "c" fn configure_peer(ifname: [*:0]const u8, peer: [*:0]const u8) c_int;
extern "c" fn interface_up(ifname: [*:0]const u8) c_int;  // Keep C version
extern "c" fn calc_sum(addr: [*]u16, len: c_int) u16;  // Keep C version (used by process_packet_c)
extern "c" fn ip2str(ip: u32) [*:0]const u8;  // Keep C version (used by process_packet_c)
extern "c" fn get_buffer() [*]u8;
extern "c" fn get_buffer_size() c_int;
extern "c" fn set_nonblocking(fd: c_int) c_int;
extern "c" fn tun_read(fd: c_int, error_code: *c_int) c_int;
extern "c" fn tun_write(fd: c_int, len: c_int, error_code: *c_int) c_int;
extern "c" fn tun_close(fd: c_int) c_int;
extern "c" fn process_packet_c(len: c_int) c_int;

// ============================================================================
// Migrated Functions
// ============================================================================

// Calculate checksum (migrated from C, also available in C layer)
pub fn calc_sum_zig(addr: [*]u16, len: usize) u16 {
    var nleft: usize = len;
    var sum: u32 = 0;
    var w: [*]u16 = addr;

    while (nleft > 1) {
        sum += w[0];
        w = w[1..];
        nleft -= 2;
    }
    if (nleft == 1) {
        const byte_ptr = @as([*]u8, @ptrCast(w));
        sum += byte_ptr[0];
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return @as(u16, @truncate(~sum));
}

// Convert IP to string (migrated from C, also available in C layer)
var ip2str_buf: [16]u8 = undefined;
pub fn ip2str_zig(ip: u32) [*:0]const u8 {
    // Network byte order: big-endian, so first byte is highest
    const b0 = (ip >> 24) & 0xFF;
    const b1 = (ip >> 16) & 0xFF;
    const b2 = (ip >> 8) & 0xFF;
    const b3 = ip & 0xFF;
    const len = std.fmt.bufPrint(&ip2str_buf, "{d}.{d}.{d}.{d}", .{ b0, b1, b2, b3 }) catch unreachable;
    ip2str_buf[len.len] = 0;
    return @as([*:0]const u8, @ptrCast(&ip2str_buf));
}

// Buffer size constant (migrated from C)
const BUF_SIZE = 4096;
fn get_buffer_size_zig() usize {
    return BUF_SIZE;
}

// Delete route (migrated from C)
extern "c" fn system(command: [*:0]const u8) c_int;
fn delete_route_zig() c_int {
    return system("route -q -n delete -inet 10.0.0.2 2>/dev/null");
}

// Verify route (migrated from C)
fn verify_route_zig() c_int {
    return system("route -n get 10.0.0.2 2>&1");
}

// Add route (migrated from C)
fn add_route_zig(tun_name: [*:0]const u8) c_int {
    var buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrintZ(&buf, "route -q -n add -inet 10.0.0.2/32 -iface {s} 2>&1", .{tun_name}) catch unreachable;
    return system(cmd);
}

// ============================================================================
// Packet Processing (migrated from C)
// ============================================================================

// Process packet in Zig layer (migrated from C)
var packet_buf: [4096]u8 = undefined;
pub fn process_packet(buf: []u8) !usize {
    const n = @as(isize, @intCast(buf.len));

    // Skip macOS utun 4-byte header if present
    var offset: usize = 0;
    if (n >= 4 and buf[0] == 0 and buf[1] == 0) {
        offset = 4;
        std.debug.print("Skipped 4-byte utun header\n", .{});
    }

    if (n - @as(isize, @intCast(offset)) < 20) {
        std.debug.print("Packet too small\n\n", .{});
        return 0;
    }

    // Parse IP header directly (no struct casting for alignment)
    const vhl = buf[offset];
    const ip_hlen = (@as(usize, vhl) & 0x0F) * 4;
    const ip_len = std.mem.readInt(u16, buf[offset + 2..][0..2], .big);
    const proto = buf[offset + 9];
    const src_ip = std.mem.readInt(u32, buf[offset + 12..][0..4], .big);
    const dst_ip = std.mem.readInt(u32, buf[offset + 16..][0..4], .big);

    std.debug.print("IP: {s} -> {s}\n", .{ ip2str_zig(src_ip), ip2str_zig(dst_ip) });
    std.debug.print("Proto: {d} (ICMP=1)\n", .{proto});

    if (proto != 1) {  // IPPROTO_ICMP
        std.debug.print("Not ICMP, skipping\n\n", .{});
        return 0;
    }

    // Parse ICMP header
    const icmp_type = buf[offset + ip_hlen];
    std.debug.print("ICMP Type: {d} (8=echo, 0=reply)\n", .{icmp_type});

    if (icmp_type != 8) {  // ICMP_ECHO
        std.debug.print("Not echo request, skipping\n\n", .{});
        return 0;
    }

    const icmp_id = std.mem.readInt(u16, buf[offset + ip_hlen + 4..][0..2], .big);
    const icmp_seq = std.mem.readInt(u16, buf[offset + ip_hlen + 6..][0..2], .big);
    std.debug.print("Echo Request! ID=0x{X:0>4} Seq={d}\n", .{ icmp_id, icmp_seq });

    // Build reply: swap IPs, change type to 0
    std.mem.writeInt(u32, buf[offset + 12..][0..4], dst_ip, .big);
    std.mem.writeInt(u32, buf[offset + 16..][0..4], src_ip, .big);
    buf[offset + ip_hlen] = 0;  // ICMP_ECHOREPLY

    // Recalculate checksums
    // IP checksum (set to 0 first)
    buf[offset + 10] = 0;
    buf[offset + 11] = 0;
    var sum: u32 = 0;
    const ip_words = ip_hlen / 2;
    var i: usize = 0;
    while (i < ip_words) : (i += 1) {
        sum += std.mem.readInt(u16, buf[offset + i * 2..][0..2], .big);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    const ip_checksum = @as(u16, @truncate(~sum));
    buf[offset + 10] = @as(u8, @truncate(ip_checksum >> 8));
    buf[offset + 11] = @as(u8, @truncate(ip_checksum & 0xFF));

    // ICMP checksum
    const icmp_len = ip_len - ip_hlen;
    buf[offset + ip_hlen + 2] = 0;
    buf[offset + ip_hlen + 3] = 0;
    sum = 0;
    const icmp_words = icmp_len / 2;
    i = 0;
    while (i < icmp_words) : (i += 1) {
        sum += std.mem.readInt(u16, buf[offset + ip_hlen + i * 2..][0..2], .big);
    }
    if (icmp_len % 2 == 1) {
        sum += @as(u32, buf[offset + ip_hlen + icmp_len - 1]) << 8;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    const icmp_checksum = @as(u16, @truncate(~sum));
    buf[offset + ip_hlen + 2] = @as(u8, @truncate(icmp_checksum >> 8));
    buf[offset + ip_hlen + 3] = @as(u8, @truncate(icmp_checksum & 0xFF));

    std.debug.print("Reply: {s} -> {s}\n\n", .{ ip2str_zig(dst_ip), ip2str_zig(src_ip) });

    return @as(usize, @intCast(n));
}

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    var tun_fd: c_int = undefined;
    var tun_name: [64]u8 = undefined;
    var buf = get_buffer();  // Get buffer from C helper
    var n: c_int = undefined;
    var err: c_int = undefined;

    std.debug.print("=== TUN ICMP Echo Reply Test (Zig + C Helper) ===\n\n", .{});

    // Clean up routes
    _ = delete_route_zig();

    // Create utun socket
    std.debug.print("Creating utun socket...\n", .{});
    const tun_name_ptr: [*]u8 = &tun_name;
    tun_fd = create_utun_socket(tun_name_ptr, tun_name.len);
    if (tun_fd < 0) {
        std.debug.print("Failed to create utun\n", .{});
        return error.FailedToCreateUtun;
    }

    const tun_name_z: [*:0]const u8 = @ptrCast(&tun_name);
    std.debug.print("Interface: {s}\n", .{tun_name_z});

    // Configure IP and peer
    _ = configure_ip(tun_name_z, "10.0.0.1");
    _ = configure_peer(tun_name_z, "10.0.0.2");
    _ = interface_up(tun_name_z);

    // Add route
    _ = add_route_zig(tun_name_z);

    // Verify route
    _ = verify_route_zig();

    // Set non-blocking
    _ = set_nonblocking(tun_fd);

    std.debug.print("\nListening for ICMP...\n", .{});
    std.debug.print("(Press Ctrl+C to stop)\n\n", .{});

    // Main loop
    while (true) {
        n = tun_read(tun_fd, &err);
        if (n < 0) {
            if (err == 35) {  // EAGAIN
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            std.debug.print("Read error\n", .{});
            break;
        }

        std.debug.print("=== Received {d} bytes ===\n", .{n});

        // Process packet in Zig layer
        const result = process_packet(buf[0..@as(usize, @intCast(n))]) catch {
            std.debug.print("Process error\n", .{});
            break;
        };
        _ = result;

        n = tun_write(tun_fd, n, &err);
        if (n < 0) {
            std.debug.print("Write error\n", .{});
        } else {
            std.debug.print("Sent {d} bytes\n\n", .{n});
        }
    }

    _ = tun_close(tun_fd);
}
