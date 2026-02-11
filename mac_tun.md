# macOS TUN Development Guide

macOS TUN (utun) 开发的最终技术方案，基于 `tests/test_tun.zig` 验证。

---

## Architecture Overview

```
+------------------+     +-------------------+     +------------------+
| Application      |     | Kernel (utun)    |     | Routing Table   |
+------------------+     +-------------------+     +------------------+
         |                        |                        |
         | socket(PF_SYSTEM)     |                        |
         +---------------------->|                        |
         | ioctl(CTLIOCGINFO)    |                        |
         +---------------------->|                        |
         | connect(sockaddr_ctl)  |                        |
         +---------------------->|                        |
         | read()/write()         |                        |
         <----------------------->|                        |
         |                        |                        |
         | socket(AF_INET)       |                        |
         +---------------------->| ioctl(SIOCSIFADDR)    |
         | ioctl(SIOCSIFDSTADDR) |---------------------->|
         |                        |                        |
         | socket(PF_ROUTE)      |                        |
         +---------------------->| RTM_ADD/RTM_DELETE     |
         | write(rt_msghdr)      |---------------------->|
         |                        |                        +----------------->
```

---

## Core Principle

**macOS TUN (utun) is NOT Linux TUN.**

Key differences:
- Linux: Open `/dev/net/tunX`, read/write raw IP packets
- macOS: Create PF_SYSTEM socket, ioctl to get control ID, connect, then read/write

---

## Three Socket Types (CRITICAL)

| Socket Type | Domain | Purpose | Used For |
|-------------|--------|---------|----------|
| `PF_SYSTEM + SYSPROTO_CONTROL` | 32 | UTUN data plane | `read()`/`write()` packets |
| `AF_INET + SOCK_DGRAM` | 2 | Interface config | `ioctl(SIOCSIFADDR, ...)` |
| `AF_ROUTE + SOCK_RAW` | 17 | Routing table | `RTM_ADD`/`RTM_DELETE` messages |

**CRITICAL:** Using utun socket (PF_SYSTEM) for ioctl DOES NOT WORK on macOS!
You MUST use `socket(AF_INET, SOCK_DGRAM, 0)` for interface configuration.

**Why SIOCSIFADDR fails on utun socket:**

The kernel's network interface configuration code checks the socket domain. AF_INET sockets go through the INET protocol layer which knows how to configure interface addresses. PF_SYSTEM sockets go through the kernel control layer which doesn't handle interface configuration.

---

## Common Failure Reasons

### 1. CTLIOCGINFO Value Wrong

**Symptom:** ioctl returns -1, utun creation fails

**Wrong value:** `0xC0694803` (manually calculated, incorrect)
**Correct value:** `0xC0644E03` (sizeof(ctl_info) = 100)

**Verification:**
```c
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <stdio.h>
int main() {
    printf("CTLIOCGINFO = 0x%08X\n", CTLIOCGINFO);
    printf("sizeof(ctl_info) = %zu\n", sizeof(struct ctl_info));
    return 0;
}
```

Output:
```
CTLIOCGINFO = 0xC0644E03
sizeof(ctl_info) = 100
```

### 2. ioctl Request Code Too Large for c_int

**Symptom:** Compilation error: `type 'c_int' cannot represent integer value`

**Cause:** macOS ioctl codes like `SIOCGIFFLAGS = 0xC0206914` exceed signed 32-bit max (2147483647)

**Solution:** Use explicit type and bitCast:
```zig
const SIOCGIFFLAGS: u32 = 0xC0206914;

fn ioctl_get_flags(sock: c_int, ifname: [*:0]const u8, flags: *c_int) c_int {
    const req = @as(c_int, @bitCast(SIOCGIFFLAGS));
    const ret = c.ioctl(sock, req, &ifr);
    // ...
}
```

### 3. C String Iteration

**Symptom:** Compilation error: `unbounded for loop`

**Wrong:**
```zig
for (ip) |ch| { ... }
```

**Correct:**
```zig
var i: usize = 0;
while (ip[i] != 0) {
    const ch = ip[i];
    // ...
    i += 1;
}
```

### 4. sockaddr_ctl Initialization

**Symptom:** connect() fails or utun doesn't work

**Required fields (verified with test_tun.zig):**
```zig
const sockaddr_ctl = extern struct {
    sc_len: u8 = 0,
    sc_family: u8 = 0,
    ss_sysaddr: u16 = 0,  // Address family for kernel control
    sc_id: u32 = 0,
    sc_unit: u32 = 0,
    sc_reserved: [5]u32 = [_]u32{0} ** 5,

    pub fn init(ctl_id: u32, unit: u32) sockaddr_ctl {
        return .{
            .sc_len = @sizeOf(sockaddr_ctl),  // MUST be 32
            .sc_family = AF_SYSTEM,           // = 2
            .ss_sysaddr = AF_SYS_CONTROL,     // = 2 (NOT AF_SYS_KERNCONTROL)
            .sc_id = ctl_id,
            .sc_unit = unit,                  // 0 = auto-assign
        };
    }
};
```

**NOTE:** The `ss_sysaddr` field must be `AF_SYS_CONTROL` (2), NOT `AF_SYS_KERNCONTROL`.

### 5. Getting Interface Name

**Symptom:** utun created but name is empty

**Required:** Use getsockopt with SYSPROTO_CONTROL and UTUN_OPT_IFNAME

```zig
extern "c" fn getsockopt(
    sock: c_int,
    level: c_int,
    optname: c_int,
    optval: ?*anyopaque,
    optlen: *c_uint,
) c_int;

fn getsockopt_ifname(sock: c_int, ifname: [*]u8, max_len: usize) c_int {
    var name_buf: [64]u8 = undefined;
    var name_len: c_uint = 64;

    const ret = getsockopt(sock, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
        &name_buf, &name_len);
    if (ret < 0) return -1;

    const copy_len = @min(@as(usize, @intCast(name_len)), max_len - 1);
    @memcpy(ifname[0..copy_len], name_buf[0..copy_len]);
    ifname[copy_len] = 0;
    return 0;
}
```

### 6. C read/write vs std.posix.read

**Symptom:** Read returns 0 or wrong data

**Cause:** std.posix.read may not work correctly with file descriptors created by C functions

**Solution:** Use C's read/write:
```zig
extern "c" fn read(fd: c_int, buf: *anyopaque, nbytes: usize) c_int;
extern "c" fn write(fd: c_int, buf: *const anyopaque, nbytes: usize) c_int;
extern "c" var errno: c_int;

fn tun_read(fd: c_int, error_code: *c_int) isize {
    const n = read(fd, &packet_buf, BUF_SIZE);
    if (n < 0) {
        error_code.* = errno;
        return -1;
    }
    error_code.* = 0;
    return @as(isize, @intCast(n));
}
```

---

## BSD Routing Socket

BSD Routing Socket (PF_ROUTE/AF_ROUTE) allows direct manipulation of the routing table from user space.

### Verified Constants

**CRITICAL: Structure sizes and constants are DIFFERENT from documentation:**

| Item | Documented | Actual (Verified) |
|------|------------|------------------|
| `sizeof(rt_msghdr)` | 64 | **92** |
| `RTM_VERSION` | 3 | **5** |
| rt_metrics fields | rmx_refcnt, rmx_hops | **rmx_locks, rmx_mtu, rmx_hopcount** |

**Always verify with C compiler:**
```c
#include <stdio.h>
#include <sys/socket.h>
#include <net/route.h>

int main() {
    printf("sizeof(rt_msghdr) = %zu\n", sizeof(struct rt_msghdr));
    printf("sizeof(sockaddr_in) = %zu\n", sizeof(struct sockaddr_in));
    printf("RTM_VERSION = %d\n", RTM_VERSION);
    return 0;
}
```

Output on macOS:
```
sizeof(rt_msghdr) = 92
sizeof(sockaddr_in) = 16
RTM_VERSION = 5
```

### Verified Structure Layout

```zig
// rt_metrics - embedded in rt_msghdr (56 bytes)
const rt_metrics = extern struct {
    rmx_locks: u32,       // offset 0
    rmx_mtu: u32,         // offset 4
    rmx_hopcount: u32,    // offset 8
    rmx_expire: i32,      // offset 12
    rmx_recvpipe: u32,    // offset 16
    rmx_sendpipe: u32,    // offset 20
    rmx_ssthresh: u32,    // offset 24
    rmx_rtt: u32,         // offset 28
    rmx_rttvar: u32,      // offset 32
    rmx_pksent: u32,      // offset 36
    rmx_filler: [4]u32,   // offset 40 (16 bytes)
};

// rt_msghdr - routing message header (92 bytes)
const rt_msghdr = extern struct {
    rtm_msglen: u16,      // offset 0
    rtm_version: u8,      // offset 2 (MUST be 5 on macOS!)
    rtm_type: u8,         // offset 3
    rtm_index: u16,       // offset 4
    rtm_flags: i32,       // offset 8
    rtm_addrs: i32,       // offset 12
    rtm_pid: i32,         // offset 16
    rtm_seq: i32,         // offset 20
    rtm_errno: i32,       // offset 24
    rtm_use: i32,         // offset 28
    rtm_inits: u32,       // offset 32
    rmx: rt_metrics,       // offset 36 (56 bytes)
};
```

### Route Add Implementation (Pure Zig)

```zig
fn route_add(ifname: [*:0]const u8, dst_ip: u32) void {
    const iface_idx = if_nametoindex(ifname);
    if (iface_idx == 0) return;

    // Build message: rt_msghdr + 2 * sockaddr_in (dst, gateway)
    const msg_size = @sizeOf(rt_msghdr) + 2 * @sizeOf(sockaddr_in);
    var buf: [256]u8 align(8) = undefined;
    @memset(&buf, 0);

    const rtm = @as(*rt_msghdr, @ptrCast(@alignCast(&buf)));
    rtm.rtm_msglen = @as(u16, @intCast(msg_size));
    rtm.rtm_version = 5;  // macOS requires version 5!
    rtm.rtm_type = RTM_ADD;
    rtm.rtm_index = @as(u16, @intCast(iface_idx));
    rtm.rtm_flags = RTF_UP | RTF_STATIC;
    rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;
    rtm.rtm_pid = getpid();
    rtm.rtm_seq = 1;

    // Destination address
    var offset: usize = @sizeOf(rt_msghdr);
    const dst = @as(*sockaddr_in, @ptrCast(@alignCast(buf[offset..].ptr)));
    dst.sin_len = @sizeOf(sockaddr_in);
    dst.sin_family = @as(u8, @intCast(std.posix.AF.INET));
    dst.sin_addr = @as([4]u8, @bitCast(dst_ip));

    // Gateway address (same as dst for direct route)
    offset += @sizeOf(sockaddr_in);
    const gw = @as(*sockaddr_in, @ptrCast(@alignCast(buf[offset..].ptr)));
    gw.sin_len = @sizeOf(sockaddr_in);
    gw.sin_family = @as(u8, @intCast(std.posix.AF.INET));
    gw.sin_addr = dst.sin_addr;

    // Send via AF_ROUTE socket
    const fd = std.posix.socket(AF_ROUTE, SOCK_RAW, 0) catch return;
    defer std.posix.close(fd);
    _ = std.posix.write(fd, buf[0..msg_size]) catch {};
}
```

### Common Pitfalls

1. **Wrong struct size**: Leads to `EINVAL` on write. Always verify with C compiler.

2. **Wrong RTM_VERSION**: macOS uses version 5, not 3.

3. **Missing rtm_addrs**: The kernel uses this to know what sockaddr types follow.

4. **Byte order**: sockaddr_in.sin_addr must be in network byte order.

---

## Packet Format

**macOS utun adds 4-byte header on read:**

```
Bytes 0-3: 00 00 00 02  (AF_INET = 2)
Bytes 4-n: Raw IP packet (network byte order)
```

**Processing:**
```zig
fn process_packet(n: isize) !isize {
    const buf = &packet_buf;
    var offset: usize = 0;

    // Skip 4-byte utun header
    if (n >= 4 and buf[0] == 0 and buf[1] == 0) {
        offset = 4;
    }

    // Now buf[offset..] contains raw IP packet
    const ip_header = buf[offset..];
    const src_ip = std.mem.readInt(u32, ip_header[12..16], .big);
    // ...
}
```

---

## Route Configuration

For point-to-point utun interfaces, use ONLY `-iface`:

```bash
# CORRECT:
route add -inet 10.0.0.2/32 -iface utun4

# WRONG (causes routing via wrong interface):
route add -inet 10.0.0.2/32 -iface utun4 -gateway 10.0.0.2
```

---

## Complete Implementation

### macos_types.zig

```zig
const std = @import("std");

pub const PF_SYSTEM = @as(c_int, 32);
pub const SYSPROTO_CONTROL = @as(c_int, 2);
pub const AF_SYSTEM = @as(c_int, 2);
pub const AF_SYS_CONTROL = @as(c_int, 2);
pub const SOCK_DGRAM = @as(c_int, 2);
pub const AF_ROUTE = @as(c_int, 17);
pub const SOCK_RAW = @as(c_int, 3);

// MUST verify this value!
pub const CTLIOCGINFO: u32 = 0xC0644E03;
pub const UTUN_OPT_IFNAME = @as(c_int, 2);

pub const SIOCGIFFLAGS: u32 = 0xC0206914;
pub const SIOCSIFFLAGS: u32 = 0x80206910;
pub const SIOCSIFADDR: u32 = 0x8020690C;
pub const SIOCSIFDSTADDR: u32 = 0x80206914;

pub const IFF_UP: c_short = 0x1;
pub const IFF_RUNNING: c_short = 0x40;

pub const RTM_VERSION = @as(u8, 5);  // NOT 3!
pub const RTM_ADD = @as(u8, 0x1);
pub const RTM_DELETE = @as(u8, 0x2);
pub const RTF_UP = @as(i32, 0x1);
pub const RTF_STATIC = @as(i32, 0x800);
pub const RTA_DST = @as(i32, 0x1);
pub const RTA_GATEWAY = @as(i32, 0x2);

pub const sockaddr_ctl = extern struct {
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

pub const sockaddr_in = extern struct {
    sin_len: u8 = 0,
    sin_family: u8 = 0,
    sin_port: u16 = 0,
    sin_addr: [4]u8 = [_]u8{0} ** 4,
    sin_zero: [8]u8 = [_]u8{0} ** 8,
};

pub const ctl_info = extern struct {
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

pub const ifreq = extern struct {
    ifr_name: [16]u8 = [_]u8{0} ** 16,
    ifr_ifru: extern union {
        ifr_addr: sockaddr_in,
        ifr_dstaddr: sockaddr_in,
        ifr_flags: c_short,
    } = undefined,

    pub fn setName(this: *ifreq, name: [*:0]const u8) void {
        @memset(&this.ifr_name, 0);
        var i: usize = 0;
        while (i < 15 and name[i] != 0) : (i += 1) {
            this.ifr_name[i] = name[i];
        }
    }
};

pub const rt_metrics = extern struct {
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

pub const rt_msghdr = extern struct {
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
```

### Development Workflow

**Step 1: Create UTUN socket**
```zig
fn create_utun_socket(ifname: [*]u8, max_len: usize) c_int {
    const sock = socket_create_sys();  // PF_SYSTEM + SYSPROTO_CONTROL
    var ctl_id: u32 = 0;
    ioctl_get_ctl_info(sock, "com.apple.net.utun_control", &ctl_id);
    connect_utun(sock, ctl_id);
    getsockopt_ifname(sock, ifname, max_len);
    return sock;
}
```

**Step 2: Configure interface (NO ifconfig)**
```zig
fn configure_interface(ifname: [*:0]const u8, ip: u32, peer: u32) c_int {
    const sock = socket_create();  // AF_INET + SOCK_DGRAM (NOT utun!)
    ioctl_set_addr(sock, ifname, ip, false);       // SIOCSIFADDR
    ioctl_set_addr(sock, ifname, peer, true);      // SIOCSIFDSTADDR
    ioctl_set_flags(sock, ifname, IFF_UP | IFF_RUNNING);  // SIOCSIFFLAGS
    socket_close(sock);
    return 0;
}
```

**Step 3: Add route (NO route command)**
```zig
fn route_add(ifname: [*:0]const u8, dst_ip: u32) void {
    // Build rt_msghdr + sockaddr_in dst + sockaddr_in gateway
    // Send via AF_ROUTE + SOCK_RAW socket
}
```

---

## Verification Checklist

Before claiming functionality works:

- [ ] socket(PF_SYSTEM) returns valid fd (> 0)
- [ ] ioctl(CTLIOCGINFO) returns 0, ctl_id > 0
- [ ] connect() succeeds
- [ ] getsockopt() returns interface name (e.g., "utun4")
- [ ] socket(AF_INET) for ioctl succeeds
- [ ] ping receives ICMP echo request
- [ ] ping sends ICMP echo reply
- [ ] ping shows 0% packet loss

---

## Testing

```bash
# Build
zig build-exe tests/test_tun.zig -lc -I. --name test_tun

# Run
sudo ./test_tun &
ping -c 3 10.0.0.2

# Expected: 3 packets transmitted, 3 received, 0% loss
```

---

## References

- `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/kern_control.h`
- `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/sockio.h`
- `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/net/if.h`
- `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/net/route.h`
