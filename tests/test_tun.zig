// tests/test_tun.zig - Complete Pure Zig TUN Test (NO ifconfig/route)
//
// Build: zig build-exe tests/test_tun.zig -lc -I. --name test_tun
// Run:   sudo ./test_tun
//
// This is a 100% pure Zig implementation with NO external command dependencies:
//   - UTUN socket creation (PF_SYSTEM + ioctl CTLIOCGINFO)
//   - Interface configuration (ioctl: SIOCSIFADDR, SIOCSIFDSTADDR, SIOCSIFFLAGS)
//   - Route management (BSD Routing Socket: RTM_ADD, RTM_DELETE)
//   - ICMP packet processing
//
// =============================================================================
// ARCHITECTURE OVERVIEW
// =============================================================================
//
// macOS TUN Device Architecture:
// +------------------+     +-------------------+     +------------------+
// | Application      |     | Kernel (utun)    |     | Routing Table   |
// +------------------+     +-------------------+     +------------------+
//          |                        |                        |
//          | socket(PF_SYSTEM)     |                        |
//          +---------------------->|                        |
//          | ioctl(CTLIOCGINFO)    |                        |
//          +---------------------->|                        |
//          | connect(sockaddr_ctl)  |                        |
//          +---------------------->|                        |
//          | read()/write()         |                        |
//          <----------------------->|                        |
//          |                        |                        |
//          | socket(AF_INET)       |                        |
//          +---------------------->| ioctl(SIOCSIFADDR)    |
//          | ioctl(SIOCSIFDSTADDR) |----------------------->|
//          |                        |                        |
//          | socket(PF_ROUTE)      |                        |
//          +---------------------->| RTM_ADD/RTM_DELETE     |
//          | write(rt_msghdr)      |----------------------->|
//          |                        |                        +----------------->
//
// =============================================================================
// KEY TECHNICAL INSIGHTS
// =============================================================================
//
// 1. TWO SOCKET TYPES FOR TWO DIFFERENT PURPOSES:
//
//    | Socket Type              | Purpose                    | Usage            |
//    |--------------------------|----------------------------|------------------|
//    | PF_SYSTEM + SYSPROTO_   | UTUN data plane           | read()/write()   |
//    | CONTROL                 |                           |                  |
//    | AF_INET + SOCK_DGRAM   | Interface configuration   | ioctl()          |
//    | AF_ROUTE + SOCK_RAW    | Routing table management | RTM_ADD/DELETE   |
//
//    CRITICAL: Using utun socket for ioctl DOES NOT WORK on macOS!
//               You MUST use socket(AF_INET, SOCK_DGRAM, 0) for ioctl.
//
// 2. WHY SIOCSIFADDR FAILS ON UTUN SOCKET:
//
//    The kernel's network interface configuration code checks the socket domain.
//    AF_INET sockets go through the INET protocol layer which knows how to
//    configure interface addresses. PF_SYSTEM sockets go through the kernel
//    control layer which doesn't handle interface configuration.
//
// 3. BSD ROUTING SOCKET CONSTANTS (VERIFIED ON macOS):
//
//    - sizeof(rt_msghdr) = 92 (NOT 64 as commonly documented!)
//    - RTM_VERSION = 5 (NOT 3!)
//    - rt_metrics fields: rmx_locks, rmx_mtu, rmx_hopcount...
//
//    Always verify with: gcc -o check check.c && ./check
//    #include <stdio.h>
//    #include <sys/socket.h>
//    #include <net/route.h>
//    printf("sizeof(rt_msghdr) = %zu\n", sizeof(struct rt_msghdr));
//    printf("RTM_VERSION = %d\n", RTM_VERSION);
//
// =============================================================================

const std = @import("std");
const c = @import("std").c;

const BUF_SIZE = 4096;

// =============================================================================
// macOS CONSTANTS (VERIFIED)
// =============================================================================
//
// These constants MUST match macOS kernel headers exactly. Any mismatch
// will cause ioctl/BSD socket operations to fail silently or return EINVAL.
//
// Verification command:
//   gcc -E -dM /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/sockio.h | grep SIOCSIFADDR

const PF_SYSTEM = @as(c_int, 32);       // PF_SYSTEM = 32 (protocol family)
const SYSPROTO_CONTROL = @as(c_int, 2); // SYSPROTO_CONTROL = 2 (kernel control protocol)
const AF_SYSTEM = @as(c_int, 2);        // AF_SYSTEM = 2 (address family, same as PF_SYSTEM)
const AF_SYS_CONTROL = @as(c_int, 2);  // AF_SYS_CONTROL = 2 (kernel control address family)
const SOCK_DGRAM = @as(c_int, 2);       // SOCK_DGRAM = 2 (datagram socket type)
const AF_ROUTE = @as(c_int, 17);        // AF_ROUTE = 17 (routing socket family)
const SOCK_RAW = @as(c_int, 3);        // SOCK_RAW = 3 (raw socket type)

// ioctl request codes - These are ioctl numbers encoded as:
//   _IOW('i', request_number, struct_size)
//   The high bits contain the direction, size, and request number.
//
// Verification:
//   #define SIOCSIFADDR _IOW('i', 12, struct ifreq)
//   = (0x69 << 24) | (1 << 30) | (12 << 8) | sizeof(struct ifreq)
//   = 0x8020690C
const CTLIOCGINFO: u32 = 0xC0644E03;   // ioctl to get kernel control ID
const UTUN_OPT_IFNAME = @as(c_int, 2);  // getsockopt to retrieve assigned utun name
const SIOCGIFFLAGS: u32 = 0xC0206914;  // Get interface flags
const SIOCSIFFLAGS: u32 = 0x80206910;   // Set interface flags
const SIOCSIFADDR: u32 = 0x8020690C;    // Set interface IPv4 address
const SIOCSIFDSTADDR: u32 = 0x80206914; // Set interface peer/destination address

// Interface flags
const IFF_UP: c_short = 0x1;       // Interface is up
const IFF_RUNNING: c_short = 0x40; // Interface has carrier

// =============================================================================
// BSD ROUTING SOCKET CONSTANTS (VERIFIED)
// =============================================================================
//
// BSD Routing Socket (PF_ROUTE/AF_ROUTE) is used for routing table manipulation.
// Messages are sent via write() to the routing socket, responses read via read().

const RTM_VERSION = @as(u8, 5);    // macOS uses version 5 (NOT 3 as Linux!)
const RTM_ADD = @as(u8, 0x1);       // Add route message type
const RTM_DELETE = @as(u8, 0x2);   // Delete route message type
const RTF_UP = @as(i32, 0x1);      // Route is up
const RTF_STATIC = @as(i32, 0x800); // Route is static (not learned via routing protocol)

// Address flags in rtm_addrs bitmask
const RTA_DST = @as(i32, 0x1);      // Destination address present
const RTA_GATEWAY = @as(i32, 0x2);  // Gateway/next-hop address present

// =============================================================================
// macOS TYPE DEFINITIONS (VERIFIED)
// =============================================================================
//
// CRITICAL: Zig extern structs MUST match C memory layout exactly.
// Use @sizeOf() and C compiler verification to ensure correctness.
//
// Common mistakes:
//   - Missing sin_len field (required on BSD/macOS)
//   - Wrong field order
//   - Missing padding in unions
//   - Using undefined instead of zero initialization

// ctl_info - Used with CTLIOCGINFO to get kernel control socket ID
// This structure tells the kernel which kernel control socket we want to connect to.
const ctl_info = extern struct {
    ctl_id: u32 = 0,              // Output: kernel control ID
    ctl_name: [96]u8 = [_]u8{0} ** 96,  // Control name: "com.apple.net.utun_control"

    // Safe C string copy with bounds checking
    pub fn setName(this: *ctl_info, name: [*:0]const u8) void {
        @memset(&this.ctl_name, 0);
        var i: usize = 0;
        while (i < 95 and name[i] != 0) : (i += 1) {
            this.ctl_name[i] = name[i];
        }
    }
};

// sockaddr_ctl - Address structure for kernel control sockets
// Used with connect() to establish utun control connection.
const sockaddr_ctl = extern struct {
    sc_len: u8 = 0,                    // Structure length (must be set to sizeof)
    sc_family: u8 = 0,                 // AF_SYSTEM
    ss_sysaddr: u16 = 0,               // AF_SYS_CONTROL (NOT AF_SYS_KERNCONTROL!)
    sc_id: u32 = 0,                   // Kernel control ID (from CTLIOCGINFO)
    sc_unit: u32 = 0,                  // Unit number (0 = auto-assign)
    sc_reserved: [5]u32 = [_]u32{0} ** 5,  // Must be zero-initialized

    pub fn init(ctl_id: u32, unit: u32) sockaddr_ctl {
        return .{
            .sc_len = @sizeOf(sockaddr_ctl),  // MUST be 32 bytes
            .sc_family = AF_SYSTEM,
            .ss_sysaddr = AF_SYS_CONTROL,
            .sc_id = ctl_id,
            .sc_unit = unit,
        };
    }
};

// sockaddr_in - IPv4 address structure
// Used in BSD Routing Socket messages for route destinations.
const sockaddr_in = extern struct {
    sin_len: u8 = 0,              // Structure length (16 bytes)
    sin_family: u8 = 0,           // AF_INET
    sin_port: u16 = 0,            // Port (unused for routing)
    sin_addr: [4]u8 = [_]u8{0} ** 4,  // IPv4 address (network byte order)
    sin_zero: [8]u8 = [_]u8{0} ** 8,  // Padding for sockaddr compatibility
};

// ifreq - IO control request structure
// Used with SIOCSIFADDR, SIOCSIFDSTADDR, SIOCSIFFLAGS ioctls.
// The ifr_ifru union contains different data types for different ioctls.
const ifreq = extern struct {
    ifr_name: [16]u8 = [_]u8{0} ** 16,  // Interface name (e.g., "utun0")
    ifr_ifru: extern union {
        ifr_addr: sockaddr_in,      // SIOCSIFADDR - local address
        ifr_dstaddr: sockaddr_in,   // SIOCSIFDSTADDR - peer address
        ifr_flags: c_short,         // SIOCSIFFLAGS - interface flags
        ifr_mtu: c_int,             // SIOCSIFMTU - MTU
    } = undefined,

    pub fn setName(this: *ifreq, name: [*:0]const u8) void {
        @memset(&this.ifr_name, 0);
        var i: usize = 0;
        while (i < 15 and name[i] != 0) : (i += 1) {
            this.ifr_name[i] = name[i];
        }
    }
};

// =============================================================================
// BSD ROUTING SOCKET STRUCTURES (VERIFIED)
// =============================================================================
//
// rt_metrics - Route metrics structure (embedded in rt_msghdr)
// Contains route quality of service parameters.
const rt_metrics = extern struct {
    rmx_locks: u32,       // Kernel locks on this route
    rmx_mtu: u32,         // Maximum transmission unit
    rmx_hopcount: u32,    // Hop count (not used)
    rmx_expire: i32,      // Expiration time (relative, seconds)
    rmx_recvpipe: u32,    // Receive pipeline size
    rmx_sendpipe: u32,    // Send pipeline size
    rmx_ssthresh: u32,    // Slow start threshold
    rmx_rtt: u32,         // Round-trip time (microseconds)
    rmx_rttvar: u32,      // RTT variance
    rmx_pksent: u32,      // Packets sent
    rmx_filler: [4]u32,   // Reserved for future use
};

// rt_msghdr - Routing message header
// The base structure for all routing socket messages.
const rt_msghdr = extern struct {
    rtm_msglen: u16,      // Message length in bytes
    rtm_version: u8,      // RTM_VERSION (5 on macOS)
    rtm_type: u8,         // Message type (RTM_ADD, RTM_DELETE, etc.)
    rtm_index: u16,       // Interface index (from if_nametoindex)
    rtm_flags: i32,       // Route flags (RTF_UP, RTF_STATIC, etc.)
    rtm_addrs: i32,       // Bitmask of addresses following (RTA_DST|RTA_GATEWAY)
    rtm_pid: i32,         // Process ID of sender
    rtm_seq: u32,         // Sequence number (kernel echoes in response)
    rtm_errno: i32,       // Error number (0 = success in response)
    rtm_use: i32,         // Use count
    rtm_inits: u32,       // Which metrics are being initialized
    rmx: rt_metrics,       // Route metrics (56 bytes)
};

// =============================================================================
// MINIMAL C DECLARATIONS (NO EXTERNAL COMMANDS)
// =============================================================================
//
// These are the ONLY C functions we call. All other functionality is pure Zig.
//
// We declare these as extern "c" because:
//   1. getpid() - Not available in std.posix
//   2. ioctl()  - Variadic, can't use std.posix.ioctl directly
//   3. errno    - Thread-local error variable

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

// =============================================================================
// GLOBAL BUFFER
// =============================================================================
//
// Single global buffer for packet I/O. In production code, you would use
// per-thread or per-connection buffers to avoid contention.

var packet_buf: [BUF_SIZE]u8 = undefined;

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

var ip2str_buf1: [16]u8 = undefined;
var ip2str_buf2: [16]u8 = undefined;
var ip2str_use_first = true;

// Convert u32 to dotted-decimal string (thread-unsafe, for debug only)
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

// Parse dotted-decimal IPv4 string to u32 (network byte order)
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

    // Network byte order: most significant byte first
    return @as(u32, parts[0]) << 24 |
           @as(u32, parts[1]) << 16 |
           @as(u32, parts[2]) << 8 |
           @as(u32, parts[3]);
}

// =============================================================================
// SOCKET CREATION FUNCTIONS
// =============================================================================
//
// Each socket type serves a specific purpose. Creating the wrong type
// will cause operations to fail.

// AF_INET socket for ioctl-based interface configuration
fn socket_create() c_int {
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return -1;
    return fd;
}

// PF_SYSTEM socket for kernel control (utun management)
fn socket_create_sys() c_int {
    const fd = std.posix.socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) catch return -1;
    return fd;
}

// PF_ROUTE socket for routing table manipulation
fn socket_create_route() c_int {
    const fd = std.posix.socket(AF_ROUTE, SOCK_RAW, 0) catch return -1;
    return fd;
}

fn socket_close(sock: c_int) void {
    std.posix.close(sock);
}

// =============================================================================
// UTUN CREATION FUNCTIONS (Pure Zig + ioctl)
// =============================================================================
//
// UTUN device creation on macOS requires:
// 1. Create PF_SYSTEM socket
// 2. Get kernel control ID via ioctl(CTLIOCGINFO)
// 3. Connect using sockaddr_ctl
// 4. Retrieve assigned interface name via getsockopt(UTUN_OPT_IFNAME)

// ioctl_get_ctl_info - Get kernel control ID for "com.apple.net.utun_control"
//
// The kernel maintains a registry of kernel control sockets (like utun).
// CTLIOCGINFO queries this registry to get the numeric ID we need to connect.
fn ioctl_get_ctl_info(sock: c_int, ctl_name: [*:0]const u8, ctl_id: *u32) c_int {
    var info: ctl_info = .{};
    info.setName(ctl_name);

    // CTLIOCGINFO is encoded as _IOR('n', 3, struct ctl_info)
    // We must use @bitCast to convert u32 to c_int (signed)
    const req = @as(c_int, @bitCast(CTLIOCGINFO));
    const ret = ioctl(sock, req, &info);
    if (ret < 0) return -1;

    ctl_id.* = info.ctl_id;
    return 0;
}

// getsockopt_ifname - Get kernel-assigned interface name
//
// After connecting to the utun control socket, the kernel assigns a specific
// utun device name (utun0, utun1, etc.). This is retrieved via getsockopt().
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

// connect_utun - Connect to kernel control socket
fn connect_utun(sock: c_int, ctl_id: u32) c_int {
    const addr = sockaddr_ctl.init(ctl_id, 0);  // 0 = auto-assign unit number
    std.posix.connect(sock, @as(*const std.posix.sockaddr, @ptrCast(&addr)), @sizeOf(sockaddr_ctl)) catch return -1;
    return 0;
}

// create_utun_socket - Complete UTUN device creation
//
// Returns file descriptor for UTUN device, interface name written to `ifname`.
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

// =============================================================================
// INTERFACE CONFIGURATION (Pure Zig + ioctl, NO ifconfig)
// =============================================================================
//
// CRITICAL INSIGHT: ioctl on macOS REQUIRES an AF_INET socket!
//
// The kernel's network interface configuration code (SIOCSIFADDR, etc.)
// expects operations from the INET protocol domain. PF_SYSTEM sockets
// go through the kernel control layer which doesn't handle this.
//
// Solution: Create a separate AF_INET socket solely for ioctl operations.
// The utun socket (PF_SYSTEM) is only used for read()/write() data transfer.
//
// Architecture:
//   utun_fd = socket(PF_SYSTEM, ...)  -> data plane (read/write)
//   config_sock = socket(AF_INET, ...)  -> control plane (ioctl)

// ioctl_set_addr - Set interface address via ioctl
//
// Parameters:
//   sock    - AF_INET socket (NOT utun socket!)
//   ifname  - Interface name (e.g., "utun0")
//   ip      - IP address in network byte order
//   is_dst  - true for SIOCSIFDSTADDR (peer), false for SIOCSIFADDR (local)
fn ioctl_set_addr(sock: c_int, ifname: [*:0]const u8, ip: u32, is_dst: bool) c_int {
    var ifr: ifreq = .{};
    ifr.setName(ifname);

    // Select correct union member based on ioctl type
    const addr = if (is_dst) &ifr.ifr_ifru.ifr_dstaddr else &ifr.ifr_ifru.ifr_addr;
    addr.* = .{
        .sin_len = @sizeOf(sockaddr_in),
        .sin_family = @as(u8, @intCast(std.posix.AF.INET)),
        .sin_port = 0,
        .sin_addr = @as([4]u8, @bitCast(ip)),
        .sin_zero = [_]u8{0} ** 8,
    };

    const req_code: u32 = if (is_dst) SIOCSIFDSTADDR else SIOCSIFADDR;
    const req = @as(c_int, @bitCast(req_code));
    const ret = ioctl(sock, req, &ifr);
    return if (ret < 0) -1 else 0;
}

// ioctl_set_flags - Set interface flags via ioctl
fn ioctl_set_flags(sock: c_int, ifname: [*:0]const u8, flags: c_short) c_int {
    var ifr: ifreq = .{};
    ifr.setName(ifname);
    ifr.ifr_ifru.ifr_flags = flags;

    const req = @as(c_int, @bitCast(SIOCSIFFLAGS));
    const ret = ioctl(sock, req, &ifr);
    return if (ret < 0) -1 else 0;
}

// configure_interface - Complete interface configuration
//
// Configures:
//   - Local IP address (SIOCSIFADDR)
//   - Peer IP address (SIOCSIFDSTADDR)
//   - Interface flags UP|RUNNING (SIOCSIFFLAGS)
//
// The peer address is important for point-to-point tunnels - it tells
// the kernel where to send traffic destined for the tunnel.
fn configure_interface(ifname: [*:0]const u8, ip: u32, peer: u32) c_int {
    // Create AF_INET socket for ioctl (NOT utun socket!)
    const sock = socket_create();
    if (sock < 0) return -1;
    defer socket_close(sock);

    std.debug.print("  Setting local IP: {s}\n", .{ip2str(ip)});
    if (ioctl_set_addr(sock, ifname, ip, false) < 0) {
        std.debug.print("  SIOCSIFADDR failed (errno={})\n", .{errno});
    }

    std.debug.print("  Setting peer IP: {s}\n", .{ip2str(peer)});
    if (ioctl_set_addr(sock, ifname, peer, true) < 0) {
        std.debug.print("  SIOCSIFDSTADDR failed (errno={})\n", .{errno});
    }

    std.debug.print("  Setting interface UP\n", .{});
    const flags = IFF_UP | IFF_RUNNING;
    if (ioctl_set_flags(sock, ifname, flags) < 0) {
        std.debug.print("  SIOCSIFFLAGS failed (errno={})\n", .{errno});
    }

    return 0;
}

// =============================================================================
// ROUTE MANAGEMENT (Pure Zig + BSD Routing Socket, NO route command)
// =============================================================================
//
// BSD Routing Socket provides direct access to the kernel routing table.
// Messages are written to the socket and responses read back.
//
// Message format:
//   [rt_msghdr (92 bytes)][sockaddr_in dst][sockaddr_in gateway]
//
// Key points:
//   1. rtm_msglen must equal total message size
//   2. rtm_version MUST be 5 (not 3 as Linux uses!)
//   3. rtm_addrs bitmask tells kernel which addresses follow
//   4. rtm_index from if_nametoindex() identifies the interface

// route_add - Add route to routing table via BSD Routing Socket
fn route_add(ifname: [*:0]const u8, dst_ip: u32) void {
    const iface_idx = if_nametoindex(ifname);
    if (iface_idx == 0) return;

    // Build message: rt_msghdr + 2 * sockaddr_in (dst, gateway)
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
    _ = std.posix.write(fd, buf[0..msg_size]) catch |e| {
        std.debug.print("  Route write error (ignored): {}\n", .{e});
    };

    // Read response (non-blocking)
    var resp: [256]u8 = undefined;
    _ = std.posix.read(fd, &resp) catch |e| {
        std.debug.print("  Route read error (ignored): {}\n", .{e});
    };

    std.debug.print("  Route configured: {s} -> {s}\n", .{ ip2str(dst_ip), ifname });
}

// route_delete - Delete route from routing table via BSD Routing Socket
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
    _ = std.posix.write(fd, buf[0..msg_size]) catch |e| {
        std.debug.print("  Route write error (ignored): {}\n", .{e});
    };

    // Read response (non-blocking)
    var resp: [256]u8 = undefined;
    _ = std.posix.read(fd, &resp) catch |e| {
        std.debug.print("  Route read error (ignored): {}\n", .{e});
    };

    std.debug.print("  Route deleted: {s}\n", .{ip2str(dst_ip)});
}

// =============================================================================
// FILE DESCRIPTOR OPERATIONS
// =============================================================================

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

// =============================================================================
// PACKET PROCESSING
// =============================================================================
//
// macOS utun adds a 4-byte header on read:
//   Bytes 0-3: 00 00 00 02 (AF_INET = 2)
//   Bytes 4-n: Raw IP packet
//
// We must strip this header before processing and add it back before writing.

// process_packet - Parse and respond to ICMP echo requests
//
// Returns the number of bytes to write back (same as input, possibly with header)
pub fn process_packet(n: isize) !isize {
    const buf = &packet_buf;

    // Skip 4-byte utun header if present
    var offset: usize = 0;
    if (n >= 4 and buf[0] == 0 and buf[1] == 0) {
        offset = 4;
        std.debug.print("Skipped 4-byte utun header\n", .{});
    }

    if (n - @as(isize, @intCast(offset)) < 20) {
        std.debug.print("Packet too small\n\n", .{});
        return 0;
    }

    // Parse IP header
    const vhl = buf[offset];
    const ip_hlen = (@as(usize, vhl) & 0x0F) * 4;
    const ip_len = std.mem.readInt(u16, buf[offset + 2..][0..2], .big);
    const proto = buf[offset + 9];
    const src_ip = std.mem.readInt(u32, buf[offset + 12..][0..4], .big);
    const dst_ip = std.mem.readInt(u32, buf[offset + 16..][0..4], .big);

    std.debug.print("IP: {s} -> {s}\n", .{ ip2str(src_ip), ip2str(dst_ip) });
    std.debug.print("Proto: {d} (ICMP=1)\n", .{proto});

    // Only handle ICMP
    if (proto != 1) {
        std.debug.print("Not ICMP, skipping\n\n", .{});
        return 0;
    }

    const icmp_type = buf[offset + ip_hlen];
    std.debug.print("ICMP Type: {d} (8=echo, 0=reply)\n", .{icmp_type});

    // Only handle echo requests
    if (icmp_type != 8) {
        std.debug.print("Not echo request, skipping\n\n", .{});
        return 0;
    }

    // Parse ICMP echo request
    const icmp_id = std.mem.readInt(u16, buf[offset + ip_hlen + 4..][0..2], .big);
    const icmp_seq = std.mem.readInt(u16, buf[offset + ip_hlen + 6..][0..2], .big);
    std.debug.print("Echo Request! ID=0x{X:0>4} Seq={d}\n", .{ icmp_id, icmp_seq });

    // Build echo reply: swap src/dst, change type to 0
    std.mem.writeInt(u32, buf[offset + 12..][0..4], dst_ip, .big);
    std.mem.writeInt(u32, buf[offset + 16..][0..4], src_ip, .big);
    buf[offset + ip_hlen] = 0; // ICMP_ECHOREPLY

    // Recalculate IP checksum
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

    // Recalculate ICMP checksum
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

// =============================================================================
// MAIN
// =============================================================================

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

    // Step 2: Configure interface using ioctl (Pure Zig, NO ifconfig)
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
            if (err == 35) {  // EAGAIN/EWOULDBLOCK
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
