// test_icmp.zig - TUN ICMP Echo Reply Test (Pure Zig)
// Build: zig build-exe test_icmp.zig test_icmp_help.c -lc -I.
// Run: sudo ./test_icmp
//
// This version uses pure Zig for all logic, with only minimal C helpers
// for POSIX ioctl operations that Zig 0.13.0 doesn't support.

const std = @import("std");
const BUF_SIZE = 4096;

// ============================================================================
// C Function Declarations (ioctl - cannot be replaced in Zig 0.13.0)
// ============================================================================

extern "c" fn ioctl_get_flags(sock: c_int, ifname: [*:0]const u8, flags: *c_int) c_int;
extern "c" fn ioctl_set_flags(sock: c_int, ifname: [*:0]const u8, flags: c_int) c_int;
extern "c" fn ioctl_set_ip(sock: c_int, ifname: [*:0]const u8, ip: [*:0]const u8) c_int;
extern "c" fn ioctl_set_peer(sock: c_int, ifname: [*:0]const u8, peer: [*:0]const u8) c_int;

// ioctl for utun control info
extern "c" fn ioctl_get_ctl_info(sock: c_int, ctl_name: [*:0]const u8, name_len: usize, ctl_id: *u32) c_int;

// getsockopt for utun interface name
extern "c" fn getsockopt_ifname(sock: c_int, ifname: [*]u8, max_len: usize) c_int;

// ============================================================================
// Socket Functions (Pure Zig using std.posix)
// ============================================================================

// Create datagram socket for ioctl operations
fn socket_create() c_int {
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return -1;
    return fd;
}

// Create PF_SYSTEM socket for utun
fn socket_create_sys() c_int {
    const fd = std.posix.socket(std.posix.AF.SYSTEM, std.posix.SOCK.DGRAM, 2) catch return -1;
    return fd;
}

// Close socket
fn socket_close_zig(sock: c_int) void {
    std.posix.close(sock);
}

// ============================================================================
// Connect Function (Pure Zig using std.posix.connect)
// ============================================================================

// Connect to utun with control id
fn connect_utun(sock: c_int, ctl_id: u32) c_int {
    // Build sockaddr_ctl structure
    var addr: [32]u8 = undefined;
    @memset(&addr, 0);

    // sc_len = 32 for sockaddr_ctl
    addr[0] = 32;

    // sc_family = AF_SYSTEM (2)
    addr[1] = 2;

    // ss_sysaddr = AF_SYS_CONTROL (2)
    addr[2] = 2;

    // sc_id = ctl_id (little-endian for x86_64, but network order for portability)
    @memcpy(addr[4..8], std.mem.asBytes(&ctl_id));

    // sc_unit = 0 (auto-assign)
    addr[8] = 0;

    std.posix.connect(sock, @as(*const std.posix.sockaddr, @ptrCast(&addr)), 32) catch return -1;
    return 0;
}

// System command for routing (must use C - Zig 0.13.0 has no process.run())
extern "c" fn system(command: [*:0]const u8) c_int;

// C read/write for file descriptors created by C
extern "c" fn read(fd: c_int, buf: *anyopaque, nbytes: usize) c_int;
extern "c" fn write(fd: c_int, buf: *const anyopaque, nbytes: usize) c_int;
extern "c" var errno: c_int;

// ============================================================================
// Global Buffer (replaces C's g_buf)
// ============================================================================

var packet_buf: [BUF_SIZE]u8 = undefined;

// ============================================================================
// IP to String (Pure Zig)
// ============================================================================

var ip2str_buf1: [16]u8 = undefined;
var ip2str_buf2: [16]u8 = undefined;
var ip2str_use_first = true;

pub fn ip2str(ip: u32) [*:0]const u8 {
    // Network byte order: big-endian, so first byte is highest
    const b0 = (ip >> 24) & 0xFF;
    const b1 = (ip >> 16) & 0xFF;
    const b2 = (ip >> 8) & 0xFF;
    const b3 = ip & 0xFF;

    const buf = if (ip2str_use_first) &ip2str_buf1 else &ip2str_buf2;
    ip2str_use_first = !ip2str_use_first;

    const len = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ b0, b1, b2, b3 }) catch unreachable;
    buf[len.len] = 0;
    return @as([*:0]const u8, @ptrCast(buf));
}

// ============================================================================
// Route Operations (Pure Zig using std.process.run)
// ============================================================================

// Note: Zig 0.13.0 has no std.process.run(), only execv/execve which replace
// the current process. We must use C system() for route commands.

fn delete_route() c_int {
    return system("route -q -n delete -inet 10.0.0.2 2>/dev/null");
}

fn verify_route() c_int {
    return system("route -n get 10.0.0.2 2>&1");
}

fn add_route(tun_name: [*:0]const u8) c_int {
    var buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrintZ(&buf, "route -q -n add -inet 10.0.0.2/32 -iface {s} 2>&1", .{tun_name}) catch unreachable;
    return system(cmd);
}

// ============================================================================
// Socket I/O (Pure Zig using std.posix)
// ============================================================================

fn set_nonblocking(fd: c_int) c_int {
    const flags = std.posix.fcntl(fd, std.posix.F.GETFL, 0) catch return -1;
    // O_NONBLOCK on macOS is 0x0004
    _ = std.posix.fcntl(fd, std.posix.F.SETFL, flags | 0x0004) catch return -1;
    return 0;
}

fn tun_read(fd: c_int, error_code: *c_int) isize {
    const n = read(fd, &packet_buf, BUF_SIZE);
    if (n < 0) {
        error_code.* = errno;
        return -1;
    }
    error_code.* = 0;
    return @as(isize, @intCast(n));
}

fn tun_write(fd: c_int, len: isize, error_code: *c_int) isize {
    const n = write(fd, &packet_buf, @as(usize, @intCast(len)));
    if (n < 0) {
        error_code.* = errno;
        return -1;
    }
    error_code.* = 0;
    return @as(isize, @intCast(n));
}

fn tun_close(fd: c_int) void {
    std.posix.close(fd);
}

// ============================================================================
// POSIX Wrapper Functions (wraps C ioctl)
// ============================================================================

fn ioctl_get_flags_zig(sock: c_int, ifname: [*:0]const u8, flags: *c_int) c_int {
    return ioctl_get_flags(sock, ifname, flags);
}

fn ioctl_set_flags_zig(sock: c_int, ifname: [*:0]const u8, flags: c_int) c_int {
    return ioctl_set_flags(sock, ifname, flags);
}

fn ioctl_set_ip_zig(sock: c_int, ifname: [*:0]const u8, ip: [*:0]const u8) c_int {
    return ioctl_set_ip(sock, ifname, ip);
}

fn ioctl_set_peer_zig(sock: c_int, ifname: [*:0]const u8, peer: [*:0]const u8) c_int {
    return ioctl_set_peer(sock, ifname, peer);
}

// ioctl for utun control info (C wrapper)
fn ioctl_get_ctl_info_zig(sock: c_int, ctl_name: [*:0]const u8, ctl_id: *u32) c_int {
    return ioctl_get_ctl_info(sock, ctl_name, 0, ctl_id);
}

// ============================================================================
// High-level Interface Configuration
// ============================================================================

fn configure_ip(ifname: [*:0]const u8, ip: [*:0]const u8) c_int {
    const sock = socket_create();
    if (sock < 0) return -1;

    const ret = ioctl_set_ip_zig(sock, ifname, ip);
    socket_close_zig(sock);

    if (ret == 0) {
        std.debug.print("Set IP: {s}\n", .{ip});
    }
    return ret;
}

fn configure_peer(ifname: [*:0]const u8, peer: [*:0]const u8) c_int {
    const sock = socket_create();
    if (sock < 0) return -1;

    const ret = ioctl_set_peer_zig(sock, ifname, peer);
    socket_close_zig(sock);

    if (ret == 0) {
        std.debug.print("Set peer: {s}\n", .{peer});
    }
    return ret;
}

fn interface_up(ifname: [*:0]const u8) c_int {
    const sock = socket_create();
    if (sock < 0) return -1;

    var flags: c_int = 0;
    if (ioctl_get_flags_zig(sock, ifname, &flags) < 0) {
        socket_close_zig(sock);
        return -1;
    }

    flags |= 0x0100 | 0x0040;  // IFF_UP | IFF_RUNNING on macOS

    if (ioctl_set_flags_zig(sock, ifname, flags) < 0) {
        socket_close_zig(sock);
        return -1;
    }

    socket_close_zig(sock);
    std.debug.print("Interface up\n", .{});
    return 0;
}

fn create_utun_socket(ifname: [*]u8, max_len: usize) c_int {
    const sock = socket_create_sys();
    if (sock < 0) return -1;

    var ctl_id: u32 = 0;
    if (ioctl_get_ctl_info_zig(sock, "com.apple.net.utun_control", &ctl_id) < 0) {
        socket_close_zig(sock);
        return -1;
    }

    if (connect_utun(sock, ctl_id) < 0) {
        socket_close_zig(sock);
        return -1;
    }

    if (getsockopt_ifname(sock, ifname, max_len) < 0) {
        socket_close_zig(sock);
        return -1;
    }

    const ifname_z: [*:0]const u8 = @ptrCast(@as([*]u8, @alignCast(ifname)));
    std.debug.print("Created utun socket: {s}\n", .{ifname_z});
    return sock;
}

// ============================================================================
// Checksum (Pure Zig)
// ============================================================================

pub fn calc_sum(addr: [*]u16, len: c_int) u16 {
    var nleft = len;
    var sum: u32 = 0;
    var w = addr;

    while (nleft > 1) {
        sum += w.*;
        w += 1;
        nleft -= 2;
    }
    if (nleft == 1) {
        sum += @as(u32, w[0] & 0xFF);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return @as(u16, @truncate(~sum));
}

// ============================================================================
// Packet Processing (Pure Zig)
// ============================================================================

pub fn process_packet(n: isize) !isize {
    const buf = &packet_buf;

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

    // Parse IP header directly
    const vhl = buf[offset];
    const ip_hlen = (@as(usize, vhl) & 0x0F) * 4;
    const ip_len = std.mem.readInt(u16, buf[offset + 2..][0..2], .big);
    const proto = buf[offset + 9];
    const src_ip = std.mem.readInt(u32, buf[offset + 12..][0..4], .big);
    const dst_ip = std.mem.readInt(u32, buf[offset + 16..][0..4], .big);

    std.debug.print("IP: {s} -> {s}\n", .{ ip2str(src_ip), ip2str(dst_ip) });
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
    // IP checksum
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

    std.debug.print("Reply: {s} -> {s}\n\n", .{ ip2str(dst_ip), ip2str(src_ip) });

    return n;
}

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    var tun_fd: c_int = undefined;
    var tun_name: [64]u8 = undefined;
    var n: isize = undefined;
    var err: c_int = undefined;

    std.debug.print("=== TUN ICMP Echo Reply Test (Pure Zig) ===\n\n", .{});

    // Clean up routes
    _ = delete_route();

    // Create utun socket
    const tun_name_ptr: [*]u8 = &tun_name;
    tun_fd = create_utun_socket(tun_name_ptr, tun_name.len);
    if (tun_fd < 0) {
        std.debug.print("Failed to create utun\n", .{});
        return error.FailedToCreateUtun;
    }

    const tun_name_z: [*:0]const u8 = @ptrCast(&tun_name);

    // Configure IP and peer
    _ = configure_ip(tun_name_z, "10.0.0.1");
    _ = configure_peer(tun_name_z, "10.0.0.2");
    _ = interface_up(tun_name_z);

    // Add route
    _ = add_route(tun_name_z);

    // Verify route
    _ = verify_route();

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
            std.debug.print("Read error: {d}\n", .{err});
            break;
        }

        std.debug.print("=== Received {d} bytes ===\n", .{n});

        // Process packet in Zig layer
        const result = process_packet(n) catch {
            std.debug.print("Process error\n", .{});
            break;
        };
        if (result == 0) continue;

        n = tun_write(tun_fd, n, &err);
        if (n < 0) {
            std.debug.print("Write error: {d}\n", .{err});
        } else {
            std.debug.print("Sent {d} bytes\n\n", .{n});
        }
    }

    tun_close(tun_fd);
}
