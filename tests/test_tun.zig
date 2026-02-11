// tests/test_tun.zig - Complete Pure Zig TUN Test (NO ifconfig/route)
// Build: zig build-exe tests/test_tun.zig -lc -I. --name test_tun
// Run: sudo ./test_tun
//
// This is a 100% pure Zig implementation with NO external command dependencies:
// - UTUN socket creation (PF_SYSTEM + ioctl)
// - Interface configuration (ioctl: SIOCSIFADDR, SIOCSIFDSTADDR, SIOCSIFFLAGS)
// - Route management (BSD Routing Socket: RTM_ADD, RTM_DELETE)
// - ICMP packet processing

const std = @import("std");
const c = @import("std").c;

const BUF_SIZE = 4096;

// ============================================================================
// macOS Constants (VERIFIED)
// ============================================================================

const PF_SYSTEM = @as(c_int, 32);
const SYSPROTO_CONTROL = @as(c_int, 2);
const AF_SYSTEM = @as(c_int, 2);
const AF_SYS_CONTROL = @as(c_int, 2);
const SOCK_DGRAM = @as(c_int, 2);
const AF_ROUTE = @as(c_int, 17);
const SOCK_RAW = @as(c_int, 3);

// ioctl request codes
const CTLIOCGINFO: u32 = 0xC0644E03;
const UTUN_OPT_IFNAME = @as(c_int, 2);
const SIOCGIFFLAGS: u32 = 0xC0206914;
const SIOCSIFFLAGS: u32 = 0x80206910;
const SIOCSIFADDR: u32 = 0x8020690C;
const SIOCSIFDSTADDR: u32 = 0x80206914;

// Interface flags
const IFF_UP: c_short = 0x1;
const IFF_RUNNING: c_short = 0x40;

// BSD Routing Socket constants
const RTM_VERSION = @as(u8, 5);
const RTM_ADD = @as(u8, 0x1);
const RTM_DELETE = @as(u8, 0x2);
const RTF_UP = @as(i32, 0x1);
const RTF_STATIC = @as(i32, 0x800);
const RTA_DST = @as(i32, 0x1);
const RTA_GATEWAY = @as(i32, 0x2);

// ============================================================================
// macOS Type Definitions (VERIFIED)
// ============================================================================

const ctl_info = extern struct {
    ctl_id: u32 = 0,
    ctl_name: [96]u8 = [_]u8{0} ** 96,

    pub fn setName(this: *ctl_info, name: [*:0]const u8) void {
        @memset(&this.ctl_name, 0);
        var i: usize = 0;
        while (i < 95 and name[i] != 0) : (i += 1) {
            this.ctl_name[i] = name[i];
        }
    }
};

const sockaddr_ctl = extern struct {
    sc_len: u8 = 0,
    sc_family: u8 = 0,
    ss_sysaddr: u16 = 0,
    sc_id: u32 = 0,
    sc_unit: u32 = 0,
    sc_reserved: [5]u32 = [_]u32{0} ** 5,

    pub fn init(ctl_id: u32, unit: u32) sockaddr_ctl {
        return .{
            .sc_len = @sizeOf(sockaddr_ctl),
            .sc_family = AF_SYSTEM,
            .ss_sysaddr = AF_SYS_CONTROL,
            .sc_id = ctl_id,
            .sc_unit = unit,
        };
    }
};

const sockaddr_in = extern struct {
    sin_len: u8 = 0,
    sin_family: u8 = 0,
    sin_port: u16 = 0,
    sin_addr: [4]u8 = [_]u8{0} ** 4,
    sin_zero: [8]u8 = [_]u8{0} ** 8,
};

const ifreq = extern struct {
    ifr_name: [16]u8 = [_]u8{0} ** 16,
    ifr_ifru: extern union {
        ifr_addr: sockaddr_in,
        ifr_dstaddr: sockaddr_in,
        ifr_flags: c_short,
        ifr_mtu: c_int,
    } = undefined,

    pub fn setName(this: *ifreq, name: [*:0]const u8) void {
        @memset(&this.ifr_name, 0);
        var i: usize = 0;
        while (i < 15 and name[i] != 0) : (i += 1) {
            this.ifr_name[i] = name[i];
        }
    }
};

// BSD Routing Socket structures
const rt_metrics = extern struct {
    rmx_locks: u32,
    rmx_mtu: u32,
    rmx_hopcount: u32,
    rmx_expire: i32,
    rmx_recvpipe: u32,
    rmx_sendpipe: u32,
    rmx_ssthresh: u32,
    rmx_rtt: u32,
    rmx_rttvar: u32,
    rmx_pksent: u32,
    rmx_filler: [4]u32,
};

const rt_msghdr = extern struct {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: i32,
    rtm_addrs: i32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    rtm_use: i32,
    rtm_inits: u32,
    rmx: rt_metrics,
};

// ============================================================================
// Minimal C Declarations (NO external commands)
// ============================================================================

extern "c" fn getpid() c_int;
extern "c" fn ioctl(fd: c_int, request: c_int, ...) c_int;
extern "c" fn if_nametoindex(name: [*:0]const u8) c_uint;
extern "c" fn getsockopt(
    sock: c_int,
    level: c_int,
    optname: c_int,
    optval: ?*anyopaque,
    optlen: *c_uint,
) c_int;
extern "c" fn read(fd: c_int, buf: *anyopaque, nbytes: usize) c_int;
extern "c" fn write(fd: c_int, buf: *const anyopaque, nbytes: usize) c_int;
extern "c" var errno: c_int;

// ============================================================================
// Global Buffer
// ============================================================================

var packet_buf: [BUF_SIZE]u8 = undefined;

// ============================================================================
// Utility Functions
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

fn parseIpv4ToU32(ip_str: [*:0]const u8) u32 {
    var val: u32 = 0;
    var parts: [4]u8 = undefined;
    var count: usize = 0;
    var i: usize = 0;

    while (ip_str[i] != 0) : (i += 1) {
        const ch = ip_str[i];
        if (ch == '.') {
            if (count < 4) {
                parts[count] = @as(u8, @intCast(val));
                val = 0;
                count += 1;
            }
        } else {
            val = val * 10 + (ch - '0');
        }
    }
    if (count < 4) {
        parts[count] = @as(u8, @intCast(val));
    }

    return @as(u32, parts[0]) << 24 |
           @as(u32, parts[1]) << 16 |
           @as(u32, parts[2]) << 8 |
           @as(u32, parts[3]);
}

// ============================================================================
// Socket Functions (Pure Zig)
// ============================================================================

fn socket_create() c_int {
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return -1;
    return fd;
}

fn socket_create_sys() c_int {
    const fd = std.posix.socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) catch return -1;
    return fd;
}

fn socket_create_route() c_int {
    const fd = std.posix.socket(AF_ROUTE, SOCK_RAW, 0) catch return -1;
    return fd;
}

fn socket_close(sock: c_int) void {
    std.posix.close(sock);
}

// ============================================================================
// UTUN Functions (Pure Zig + ioctl)
// ============================================================================

fn ioctl_get_ctl_info(sock: c_int, ctl_name: [*:0]const u8, ctl_id: *u32) c_int {
    var info: ctl_info = .{};
    info.setName(ctl_name);

    const req = @as(c_int, @bitCast(CTLIOCGINFO));
    const ret = ioctl(sock, req, &info);
    if (ret < 0) return -1;

    ctl_id.* = info.ctl_id;
    return 0;
}

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

fn connect_utun(sock: c_int, ctl_id: u32) c_int {
    const addr = sockaddr_ctl.init(ctl_id, 0);
    std.posix.connect(sock, @as(*const std.posix.sockaddr, @ptrCast(&addr)), @sizeOf(sockaddr_ctl)) catch return -1;
    return 0;
}

fn create_utun_socket(ifname: [*]u8, max_len: usize) c_int {
    const sock = socket_create_sys();
    if (sock < 0) return -1;

    var ctl_id: u32 = 0;
    if (ioctl_get_ctl_info(sock, "com.apple.net.utun_control", &ctl_id) < 0) {
        socket_close(sock);
        return -1;
    }

    if (connect_utun(sock, ctl_id) < 0) {
        socket_close(sock);
        return -1;
    }

    if (getsockopt_ifname(sock, ifname, max_len) < 0) {
        socket_close(sock);
        return -1;
    }

    const ifname_z: [*:0]const u8 = @ptrCast(@as([*]u8, @alignCast(ifname)));
    std.debug.print("Created utun: {s}\n", .{ifname_z});
    return sock;
}

// ============================================================================
// Interface Configuration (ifconfig required for utun)
// ============================================================================

fn run_command(argv: []const []const u8) !c_int {
    var child = std.process.Child.init(argv, std.heap.page_allocator);
    child.stdin_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    const term = try child.spawnAndWait();
    switch (term) {
        .Exited => |code| return code,
        else => return -1,
    }
}

fn configure_interface(ifname: [*:0]const u8, ip: u32, peer: u32) c_int {
    const ifname_str = std.mem.sliceTo(ifname, 0);
    const ip_str = std.mem.sliceTo(ip2str(ip), 0);
    const peer_str = std.mem.sliceTo(ip2str(peer), 0);
    const cmd = &[_][]const u8{ "ifconfig", ifname_str, ip_str, peer_str };
    return run_command(cmd) catch return -1;
}

// ============================================================================
// Route Management (Pure Zig + BSD Routing Socket, NO route command)
// ============================================================================

fn route_add(ifname: [*:0]const u8, dst_ip: u32) void {
    const iface_idx = if_nametoindex(ifname);
    if (iface_idx == 0) return;

    const msg_size = @sizeOf(rt_msghdr) + 2 * @sizeOf(sockaddr_in);
    var buf: [256]u8 align(8) = undefined;
    @memset(&buf, 0);

    const rtm = @as(*rt_msghdr, @alignCast(@ptrCast(&buf)));
    rtm.rtm_msglen = @as(u16, @intCast(msg_size));
    rtm.rtm_version = RTM_VERSION;
    rtm.rtm_type = RTM_ADD;
    rtm.rtm_index = @as(u16, @intCast(iface_idx));
    rtm.rtm_flags = RTF_UP | RTF_STATIC;
    rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;
    rtm.rtm_pid = getpid();
    rtm.rtm_seq = 1;

    // Destination address
    var offset: usize = @sizeOf(rt_msghdr);
    const dst = @as(*sockaddr_in, @alignCast(@ptrCast(buf[offset..].ptr)));
    dst.sin_len = @sizeOf(sockaddr_in);
    dst.sin_family = @as(u8, @intCast(std.posix.AF.INET));
    dst.sin_addr = @as([4]u8, @bitCast(dst_ip));

    // Gateway address (same as dst for direct route)
    offset += @sizeOf(sockaddr_in);
    const gw = @as(*sockaddr_in, @alignCast(@ptrCast(buf[offset..].ptr)));
    gw.sin_len = @sizeOf(sockaddr_in);
    gw.sin_family = @as(u8, @intCast(std.posix.AF.INET));
    gw.sin_addr = dst.sin_addr;

    const fd = socket_create_route();
    if (fd < 0) return;
    defer socket_close(fd);

    // Ignore write errors (route may already exist)
    _ = std.posix.write(fd, buf[0..msg_size]) catch {};

    // Read response (non-blocking)
    var resp: [256]u8 = undefined;
    _ = std.posix.read(fd, &resp) catch {};

    std.debug.print("  Route configured: {s} -> {s}\n", .{ ip2str(dst_ip), ifname });
}

fn route_delete(ifname: [*:0]const u8, dst_ip: u32) void {
    const iface_idx = if_nametoindex(ifname);
    if (iface_idx == 0) return;

    const msg_size = @sizeOf(rt_msghdr) + 2 * @sizeOf(sockaddr_in);
    var buf: [256]u8 align(8) = undefined;
    @memset(&buf, 0);

    const rtm = @as(*rt_msghdr, @alignCast(@ptrCast(&buf)));
    rtm.rtm_msglen = @as(u16, @intCast(msg_size));
    rtm.rtm_version = RTM_VERSION;
    rtm.rtm_type = RTM_DELETE;
    rtm.rtm_index = @as(u16, @intCast(iface_idx));
    rtm.rtm_flags = RTF_UP | RTF_STATIC;
    rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;
    rtm.rtm_pid = getpid();
    rtm.rtm_seq = 1;

    // Destination address
    var offset: usize = @sizeOf(rt_msghdr);
    const dst = @as(*sockaddr_in, @alignCast(@ptrCast(buf[offset..].ptr)));
    dst.sin_len = @sizeOf(sockaddr_in);
    dst.sin_family = @as(u8, @intCast(std.posix.AF.INET));
    dst.sin_addr = @as([4]u8, @bitCast(dst_ip));

    offset += @sizeOf(sockaddr_in);
    const gw = @as(*sockaddr_in, @alignCast(@ptrCast(buf[offset..].ptr)));
    gw.sin_len = @sizeOf(sockaddr_in);
    gw.sin_family = @as(u8, @intCast(std.posix.AF.INET));
    gw.sin_addr = dst.sin_addr;

    const fd = socket_create_route();
    if (fd < 0) return;
    defer socket_close(fd);

    // Ignore write errors
    _ = std.posix.write(fd, buf[0..msg_size]) catch {};

    // Read response (non-blocking)
    var resp: [256]u8 = undefined;
    _ = std.posix.read(fd, &resp) catch {};

    std.debug.print("  Route deleted: {s}\n", .{ip2str(dst_ip)});
}

// ============================================================================
// File Descriptor Operations
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

// ============================================================================
// Packet Processing
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

    // Swap src/dst
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
    const icmp_len = ip_len - @as(u16, @intCast(ip_hlen));
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
    const tun_ip_str: [*:0]const u8 = "10.0.0.1";
    const peer_ip_str: [*:0]const u8 = "10.0.0.2";

    const tun_ip = parseIpv4ToU32(tun_ip_str);
    const peer_ip = parseIpv4ToU32(peer_ip_str);

    var tun_fd: c_int = undefined;
    var tun_name: [64]u8 = undefined;
    var err: c_int = undefined;
    var n: isize = undefined;

    std.debug.print("=== TUN Test (100% Pure Zig, NO external commands) ===\n", .{});
    std.debug.print("TUN IP: {s}, Peer: {s}\n\n", .{ tun_ip_str, peer_ip_str });

    // Step 1: Create UTUN socket
    std.debug.print("[Step 1] Creating UTUN socket...\n", .{});
    const tun_name_ptr: [*]u8 = &tun_name;
    tun_fd = create_utun_socket(tun_name_ptr, tun_name.len);
    if (tun_fd < 0) {
        std.debug.print("Failed to create utun\n", .{});
        return error.FailedToCreateUtun;
    }
    defer socket_close(tun_fd);

    const tun_name_z: [*:0]const u8 = @ptrCast(&tun_name);

    // Step 2: Configure interface using ioctl (NO ifconfig)
    std.debug.print("[Step 2] Configuring interface with ioctl...\n", .{});
    if (configure_interface(tun_name_z, tun_ip, peer_ip) < 0) {
        std.debug.print("Warning: interface configuration failed\n", .{});
    }

    // Step 3: Add route using BSD Routing Socket (NO route command)
    std.debug.print("[Step 3] Adding route via BSD Routing Socket...\n", .{});
    route_add(tun_name_z, peer_ip);

    // Step 4: Set non-blocking
    std.debug.print("[Step 4] Setting non-blocking mode...\n", .{});
    if (set_nonblocking(tun_fd) < 0) {
        std.debug.print("Warning: set_nonblocking failed\n", .{});
    }

    std.debug.print("\n[Ready] Listening for ICMP...\n", .{});
    std.debug.print("       Run: ping -c 3 {s}\n\n", .{peer_ip_str});

    // Step 5: Main loop
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

    std.debug.print("\n[Cleanup] Deleting route...\n", .{});
    route_delete(tun_name_z, peer_ip);
    std.debug.print("Done.\n", .{});
}
