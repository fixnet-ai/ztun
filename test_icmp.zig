// test_icmp.zig - TUN ICMP Echo Reply Test (100% Pure Zig)
// Build: zig build-exe test_icmp.zig macos_types.zig -lc -I.
// Run: sudo ./test_icmp
//
// This version uses 100% pure Zig for all logic, including macOS-specific
// types and structures for UTUN operations.

const std = @import("std");
const c = @import("std").c;
const macos = @import("macos_types.zig");

const BUF_SIZE = 4096;

// ============================================================================
// Minimal C Declarations (still required for getsockopt)
// ============================================================================

// getsockopt for utun interface name (Zig 0.13.0 doesn't expose this in std.posix)
extern "c" fn getsockopt(
    sock: c_int,
    level: c_int,
    optname: c_int,
    optval: ?*anyopaque,
    optlen: *c_uint,
) c_int;

// C read/write for file descriptors (required for C-created fd compatibility)
extern "c" fn read(fd: c_int, buf: *anyopaque, nbytes: usize) c_int;
extern "c" fn write(fd: c_int, buf: *const anyopaque, nbytes: usize) c_int;
extern "c" var errno: c_int;

// ============================================================================
// Constants
// ============================================================================

const UTUN_OPT_IFNAME = macos.UTUN_OPT_IFNAME;
const SYSPROTO_CONTROL = macos.SYSPROTO_CONTROL;

// ============================================================================
// UTUN Control Info (Pure Zig using c.ioctl)
// ============================================================================

fn ioctl_get_ctl_info(sock: c_int, ctl_name: [*:0]const u8, ctl_id: *u32) c_int {
    var info: macos.ctl_info = .{};
    info.setName(ctl_name);

    const req = @as(c_int, @bitCast(macos.CTLIOCGINFO));
    const ret = c.ioctl(sock, req, &info);
    if (ret < 0) return -1;

    ctl_id.* = info.ctl_id;
    return 0;
}

// ============================================================================
// Get Interface Name via getsockopt (Pure Zig)
// ============================================================================

fn getsockopt_ifname(sock: c_int, ifname: [*]u8, max_len: usize) c_int {
    var name_buf: [64]u8 = undefined;
    var name_len: c_uint = 64;

    const ret = getsockopt(sock, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &name_buf, &name_len);
    if (ret < 0) return -1;

    const copy_len = @min(@as(usize, @intCast(name_len)), max_len - 1);
    @memcpy(ifname[0..copy_len], name_buf[0..copy_len]);
    ifname[copy_len] = 0;

    return 0;
}

// ============================================================================
// System Command Execution using std.process.Child (Pure Zig)
// ============================================================================

var allocator: std.mem.Allocator = undefined;

fn run_command(argv: []const []const u8) !c_int {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    const term = try child.spawnAndWait();
    switch (term) {
        .Exited => |code| return code,
        else => return -1,
    }
}

fn delete_route() c_int {
    return run_command(&[_][]const u8{ "route", "-q", "-n", "delete", "-inet", "10.0.0.2" }) catch return -1;
}

fn verify_route() c_int {
    return run_command(&[_][]const u8{ "route", "-n", "get", "10.0.0.2" }) catch return -1;
}

fn add_route(tun_name: [*:0]const u8) c_int {
    const tun_name_z: [*:0]const u8 = @ptrCast(tun_name);
    return run_command(&[_][]const u8{ "route", "-q", "-n", "add", "-inet", "10.0.0.2/32", "-iface", std.mem.sliceTo(tun_name_z, 0) }) catch return -1;
}

// Configure interface using ifconfig
fn configure_interface(ifname: [*:0]const u8, ip: [*:0]const u8, peer: [*:0]const u8) c_int {
    const ifname_str = std.mem.sliceTo(ifname, 0);
    const ip_str = std.mem.sliceTo(ip, 0);
    const peer_str = std.mem.sliceTo(peer, 0);

    return run_command(&[_][]const u8{ "ifconfig", ifname_str, ip_str, peer_str }) catch return -1;
}

// ============================================================================
// Socket Functions (Pure Zig using std.posix)
// ============================================================================

fn socket_create() c_int {
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return -1;
    return fd;
}

fn socket_create_sys() c_int {
    const fd = std.posix.socket(macos.PF_SYSTEM, macos.SOCK_DGRAM, macos.SYSPROTO_CONTROL) catch return -1;
    return fd;
}

fn socket_close_zig(sock: c_int) void {
    std.posix.close(sock);
}

// ============================================================================
// Connect Function (Pure Zig using std.posix.connect)
// ============================================================================

fn connect_utun(sock: c_int, ctl_id: u32) c_int {
    const addr = macos.sockaddr_ctl.init(ctl_id, 0); // sc_unit = 0 (auto-assign)
    std.posix.connect(sock, @as(*const std.posix.sockaddr, @ptrCast(&addr)), @sizeOf(macos.sockaddr_ctl)) catch return -1;
    return 0;
}

// ============================================================================
// Global Buffer
// ============================================================================

var packet_buf: [BUF_SIZE]u8 = undefined;

// ============================================================================
// IP to String (Pure Zig)
// ============================================================================

var ip2str_buf1: [16]u8 = undefined;
var ip2str_buf2: [16]u8 = undefined;
var ip2str_use_first = true;

pub fn ip2str(ip: u32) [*:0]const u8 {
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
// Socket I/O (Pure Zig using C read/write)
// ============================================================================

fn set_nonblocking(fd: c_int) c_int {
    const flags = std.posix.fcntl(fd, std.posix.F.GETFL, 0) catch return -1;
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
// ioctl Functions (Pure Zig using c.ioctl)
// ============================================================================

fn ioctl_get_flags(sock: c_int, ifname: [*:0]const u8, flags: *c_int) c_int {
    var ifr: macos.ifreq = .{};
    ifr.setName(ifname);

    const req = @as(c_int, @bitCast(macos.SIOCGIFFLAGS));
    const ret = c.ioctl(sock, req, &ifr);
    if (ret < 0) return -1;

    flags.* = ifr.ifr_flags;
    return 0;
}

fn ioctl_set_flags(sock: c_int, ifname: [*:0]const u8, flags: c_int) c_int {
    var ifr: macos.ifreq = .{};
    ifr.setName(ifname);
    ifr.ifr_flags = flags;

    const req = @as(c_int, @bitCast(macos.SIOCSIFFLAGS));
    const ret = c.ioctl(sock, req, &ifr);
    return if (ret < 0) -1 else 0;
}

fn ioctl_set_ip(sock: c_int, ifname: [*:0]const u8, ip: [*:0]const u8) c_int {
    var ifr: macos.ifreq = .{};
    ifr.setName(ifname);

    // Parse IP string
    var parts: [4]u8 = undefined;
    var val: u32 = 0;
    var count: usize = 0;

    var i: usize = 0;
    while (ip[i] != 0) {
        const ch = ip[i];
        if (ch == '.') {
            parts[count] = @as(u8, @intCast(val));
            val = 0;
            count += 1;
        } else {
            val = val * 10 + (ch - '0');
        }
        i += 1;
    }
    if (count == 3) {
        parts[3] = @as(u8, @intCast(val));
        ifr.ifr_addr.sin_family = @as(u8, @intCast(std.posix.AF.INET));
        ifr.ifr_addr.sin_len = @sizeOf(macos.sockaddr_in);
        ifr.ifr_addr.sin_addr = parts;
    }

    const req = @as(c_int, @bitCast(macos.SIOCSIFADDR));
    const ret = c.ioctl(sock, req, &ifr);
    return if (ret < 0) -1 else 0;
}

fn ioctl_set_peer(sock: c_int, ifname: [*:0]const u8, peer: [*:0]const u8) c_int {
    var ifr: macos.ifreq = .{};
    ifr.setName(ifname);

    // Parse IP string
    var parts: [4]u8 = undefined;
    var val: u32 = 0;
    var count: usize = 0;

    var i: usize = 0;
    while (peer[i] != 0) {
        const ch = peer[i];
        if (ch == '.') {
            parts[count] = @as(u8, @intCast(val));
            val = 0;
            count += 1;
        } else {
            val = val * 10 + (ch - '0');
        }
        i += 1;
    }
    if (count == 3) {
        parts[3] = @as(u8, @intCast(val));
        ifr.ifr_dstaddr.sin_family = @as(u8, @intCast(std.posix.AF.INET));
        ifr.ifr_dstaddr.sin_len = @sizeOf(macos.sockaddr_in);
        ifr.ifr_dstaddr.sin_addr = parts;
    }

    const req = @as(c_int, @bitCast(macos.SIOCSIFDSTADDR));
    const ret = c.ioctl(sock, req, &ifr);
    return if (ret < 0) -1 else 0;
}

fn interface_up(ifname: [*:0]const u8) c_int {
    const sock = socket_create();
    if (sock < 0) return -1;

    var flags: c_int = 0;
    if (ioctl_get_flags(sock, ifname, &flags) < 0) {
        socket_close_zig(sock);
        return -1;
    }

    flags |= macos.IFF_UP | macos.IFF_RUNNING;

    if (ioctl_set_flags(sock, ifname, flags) < 0) {
        socket_close_zig(sock);
        return -1;
    }

    socket_close_zig(sock);
    std.debug.print("Interface up\n", .{});
    return 0;
}

// ============================================================================
// Create UTUN Socket
// ============================================================================

fn create_utun_socket(ifname: [*]u8, max_len: usize) c_int {
    const sock = socket_create_sys();
    if (sock < 0) return -1;

    var ctl_id: u32 = 0;
    if (ioctl_get_ctl_info(sock, "com.apple.net.utun_control", &ctl_id) < 0) {
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

    var offset: usize = 0;
    if (n >= 4 and buf[0] == 0 and buf[1] == 0) {
        offset = 4;
        std.debug.print("Skipped 4-byte utun header\n", .{});
    }

    if (n - @as(isize, @intCast(offset)) < 20) {
        std.debug.print("Packet too small\n\n", .{});
        return 0;
    }

    const vhl = buf[offset];
    const ip_hlen = (@as(usize, vhl) & 0x0F) * 4;
    const ip_len = std.mem.readInt(u16, buf[offset + 2..][0..2], .big);
    const proto = buf[offset + 9];
    const src_ip = std.mem.readInt(u32, buf[offset + 12..][0..4], .big);
    const dst_ip = std.mem.readInt(u32, buf[offset + 16..][0..4], .big);

    std.debug.print("IP: {s} -> {s}\n", .{ ip2str(src_ip), ip2str(dst_ip) });
    std.debug.print("Proto: {d} (ICMP=1)\n", .{proto});

    if (proto != 1) {
        std.debug.print("Not ICMP, skipping\n\n", .{});
        return 0;
    }

    const icmp_type = buf[offset + ip_hlen];
    std.debug.print("ICMP Type: {d} (8=echo, 0=reply)\n", .{icmp_type});

    if (icmp_type != 8) {
        std.debug.print("Not echo request, skipping\n\n", .{});
        return 0;
    }

    const icmp_id = std.mem.readInt(u16, buf[offset + ip_hlen + 4..][0..2], .big);
    const icmp_seq = std.mem.readInt(u16, buf[offset + ip_hlen + 6..][0..2], .big);
    std.debug.print("Echo Request! ID=0x{X:0>4} Seq={d}\n", .{ icmp_id, icmp_seq });

    std.mem.writeInt(u32, buf[offset + 12..][0..4], dst_ip, .big);
    std.mem.writeInt(u32, buf[offset + 16..][0..4], src_ip, .big);
    buf[offset + ip_hlen] = 0; // ICMP_ECHOREPLY

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
    allocator = std.heap.page_allocator;

    var tun_fd: c_int = undefined;
    var tun_name: [64]u8 = undefined;
    var n: isize = undefined;
    var err: c_int = undefined;

    std.debug.print("=== TUN ICMP Echo Reply Test (100% Pure Zig) ===\n\n", .{});

    _ = delete_route();

    const tun_name_ptr: [*]u8 = &tun_name;
    tun_fd = create_utun_socket(tun_name_ptr, tun_name.len);
    if (tun_fd < 0) {
        std.debug.print("Failed to create utun\n", .{});
        return error.FailedToCreateUtun;
    }

    const tun_name_z: [*:0]const u8 = @ptrCast(&tun_name);

    _ = configure_interface(tun_name_z, "10.0.0.1", "10.0.0.2");

    _ = add_route(tun_name_z);

    _ = verify_route();

    _ = set_nonblocking(tun_fd);

    std.debug.print("\nListening for ICMP...\n", .{});
    std.debug.print("(Press Ctrl+C to stop)\n\n", .{});

    while (true) {
        n = tun_read(tun_fd, &err);
        if (n < 0) {
            if (err == 35) {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            std.debug.print("Read error: {d}\n", .{err});
            break;
        }

        std.debug.print("=== Received {d} bytes ===\n", .{n});

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
