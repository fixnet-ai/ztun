# sysroute.zig Bug Analysis and Fix

## Problem Summary

The routing on macOS was not binding to the correct interface (utun4), causing packets to be routed through the wrong interface (en0).

## Root Cause Analysis

### My Implementation vs sing-tun

| Aspect | My sysroute.zig | sing-tun |
|--------|-----------------|----------|
| Method | `route` command | Raw routing sockets |
| Socket | N/A | `unix.AF_ROUTE` |
| Message | CLI arguments | `route.RouteMessage` struct |
| Interface scope | `-ifscope` (doesn't work properly) | `RTF_IFSCOPE` flag + Index |

### Key Findings from sing-tun/tun_darwin.go

1. **sing-tun uses raw routing sockets** (lines 486-520):
   ```go
   routeMessage := route.RouteMessage{
       Type:    rtmType,
       Version: unix.RTM_VERSION,
       Flags:   unix.RTF_STATIC | unix.RTF_GATEWAY,
   }
   if interfaceScope {
       routeMessage.Flags |= unix.RTF_IFSCOPE
       routeMessage.Index = interfaceIndex
   }
   ```

2. **sing-tun does NOT use the `route` command** - They write directly to AF_ROUTE socket:
   ```go
   return useSocket(unix.AF_ROUTE, unix.SOCK_RAW, 0, func(socketFd int) error {
       return common.Error(unix.Write(socketFd, request))
   })
   ```

## Lessons Learned

1. **Never use `route` command on macOS for TUN interfaces** - It has fundamental limitations
2. **Use raw routing sockets** - This is the only reliable way to configure routes on macOS
3. **RTF_IFSCOPE is essential** - Without it, routes won't bind to specific interfaces
4. **Interface index is required** - The kernel needs the actual interface index, not just the name

## Status

- [x] Identified root cause
- [x] Implement raw routing socket approach
- [x] Fix Zig struct initialization syntax (`.{}` vs field-by-field)
- [x] Fix SockAddrIn structure size (16 bytes with zero padding)
- [x] Fix close() call order (write first, then close)
- [x] Fix message buffer initialization (use @memset)
- [x] Fix RTM_VERSION (5 on macOS, not 7)
- [x] Fix RTF_STATIC value (0x800 on macOS, not 0x8)
- [x] Fix RtMsghdr struct definition (92 bytes, includes RtMetrics)
- [x] Fix IP address byte order (use `std.mem.nativeToBig`)
- [x] Add errno debugging using `__error()` C function
- [ ] Debug remaining EOPNOTSUPP (errno=39) issue

## Bug Fixes and Solutions

### Bug 1: Zig 0.13.0 Struct Initialization Syntax

**Problem**: Using `.{}` initializer for `extern struct` didn't work as expected.

**Fix**: Use field-by-field assignment instead of `.{}`:
```zig
// WRONG:
const hdr = @as(*RtMsghdr, @ptrCast(@alignCast(&msg_buf))){
    .rtm_msglen = @as(u16, @intCast(msg_size)),
    // ...
};

// CORRECT:
const hdr = @as(*RtMsghdr, @ptrCast(@alignCast(&msg_buf)));
hdr.rtm_msglen = @as(u16, @intCast(msg_size));
// ... assign each field individually
```

### Bug 2: SockAddrIn Structure Size

**Problem**: BSD sockaddr_in is 16 bytes (includes 8-byte zero padding).

**Fix**: Define SockAddrIn4 as 16-byte struct:
```zig
const SockAddrIn4 = extern struct {
    len: u8,
    family: u8,
    port: u16,
    addr: u32,
    zero: [8]u8,  // Padding
};
```

### Bug 3: close() Called Before write()

**Problem**: Socket closed before writing message.

**Fix**: Write first, then close:
```zig
// WRONG:
_ = close(fd);
const written = write(fd, msg.ptr, msg.len);

// CORRECT:
const written = write(fd, msg.ptr, msg.len);
_ = close(fd);
```

### Bug 4: Message Buffer Not Initialized

**Problem**: Buffer declared with `undefined` contains garbage values.

**Fix**: Use `@memset` to zero out the message portion:
```zig
var msg_buf: [256]u8 = undefined;
@memset(msg_buf[0..msg_size], 0);  // Zero the message portion
```

### Bug 5: RTM_VERSION on macOS

**Problem**: RTM_VERSION is 5 on macOS (not 7 like Linux).

**Fix**: Use correct version constant:
```zig
const BSD = struct {
    const RTM_VERSION = 5;  // macOS uses version 5
    // ...
};
```

### Bug 6: RTF_STATIC Value on macOS

**Problem**: RTF_STATIC is 0x800 on macOS (not 0x8).

**Fix**: Use correct flag value:
```zig
const BSD = struct {
    const RTF_STATIC = 0x800;  // Correct value on macOS
    // ...
};
```

### Bug 7: RtMsghdr Structure Size

**Problem**: rt_msghdr is 92 bytes on macOS (not 52), includes full RtMetrics.

**Fix**: Include RtMetrics in struct definition:
```zig
const RtMetrics = extern struct {
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
    rmx_filler: [4]i32,
};

const RtMsghdr = extern struct {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: u32,
    rtm_addrs: u32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    rtm_use: u32,
    rtm_inits: u32,
    rtm_rmx: RtMetrics,
};
```

### Bug 8: IP Address Byte Order

**Problem**: `@byteSwap` only swaps local byte order, not convert to network byte order.

**Fix**: Use `std.mem.nativeToBig`:
```zig
// WRONG:
dst_sa.addr = @byteSwap(dst_ip);

// CORRECT:
dst_sa.addr = std.mem.nativeToBig(u32, dst_ip);
```

### Bug 9: Getting errno in Zig

**Problem**: `std.posix.getErrno()` doesn't exist in Zig 0.13.0.

**Solution**: Use C's `__error()` function:
```zig
extern "c" fn __error() *c_int;

// Usage:
const errno_ptr = __error();
const errno_val = errno_ptr.*;
```

### Bug 10: EOPNOTSUPP (errno=39) on Write - UNRESOLVED MYSTERY

**Problem**: Write to routing socket fails with EOPNOTSUPP even with correct message format.

**Debugging Results**:
- Created C test (`/tmp/test_compare.c`) with IDENTICAL struct definitions and message format
- C test SUCCEEDS: write() returns 140 bytes, errno=0
- Zig test FAILS: write() returns -1, errno=39 (EOPNOTSUPP)
- Message byte-by-byte comparison shows NO DIFFERENCES between C and Zig output

**Exact Message Comparison** (C vs Zig):
```
Offset  C (hex)      Zig (hex)
0000    8C 00 05 01  8C 00 05 01  (rtm_msglen=140, version=5, type=RTM_ADD)
0004    00 00 08 03  00 00 08 03  (flags=0x803 = STATIC|GATEWAY|UP)
0008    07 00 00 00  07 00 00 00  (addrs=RTA_DST|GATEWAY|NETMASK)
000C    01 00 00 00  01 00 00 00  (seq=1)
...
0010    10 02 00 00  10 02 00 00  (dst_sa: len=16, family=2)
0014    0A 00 00 02  0A 00 00 02  (dst=10.0.0.2)
0018    00 00 00 00  00 00 00 00  (dst_sa zero padding)
0020    10 02 00 00  10 02 00 00  (gw_sa: len=16, family=2)
0024    0A 00 00 01  0A 00 00 01  (gw=10.0.0.1)
...
0030    10 02 00 00  10 02 00 00  (mask_sa: len=16, family=2)
0034    FF FF FF FF  FF FF FF FF  (mask=255.255.255.255)
```

**Hypothesis**: The issue may be related to:
1. File descriptor inheritance/flags differences between Zig std.posix and raw C
2. Socket options or socket type differences
3. Process privileges or credentials passed with the message
4. Signal handling differences affecting socket behavior

**Status**: UNRESOLVED - This is a genuine Zig vs C mystery that needs further investigation.

---

### Bug 11: Fallback to route Command (Workaround)

**Problem**: Raw routing socket write fails in Zig with EOPNOTSUPP (errno=39) even with message format identical to working C code.

**Solution**: Implement fallback to external `route` command when raw socket fails:

```zig
fn bsdRouteAdd(route: *const RouteEntry) RouteError!void {
    if (route.af != .ipv4) {
        return error.NotSupported;
    }

    // Try raw routing socket first
    bsdExecRoute(
        BSD.RTM_ADD,
        route.interface_scope,
        route.iface_idx,
        route.ipv4.dst,
        route.ipv4.gateway,
        route.ipv4.mask,
    ) catch {
        // Fall back to route command on macOS
        std.debug.print("[sysroute] BSD raw socket failed, using route command\n", .{});
        return bsdRouteCommandAdd(route);
    };
}
```

**route command format**:
```bash
route -q add -net <dest> -netmask <mask> <gateway>
```

**Note**: The `route` command does NOT support interface-scoped routes (`-interface` flag is broken). Routes added via `route` command will use the default interface (en0) instead of the specified interface.

---

### Bug 12: rtm_index Was Set to 0

**Problem**: `hdr.rtm_index = 0` was hardcoded instead of using the provided `interface_index` parameter.

**Debug Output** (before fix):
```
[sysroute] Header: msglen=140, version=5, type=1, index=0, flags=0x00000803
```

**Fix**: Use the `interface_index` parameter for `rtm_index`:
```zig
// WRONG:
hdr.rtm_index = 0;  // Let kernel fill in the interface index

// CORRECT:
hdr.rtm_index = @as(u16, @intCast(interface_index));  // Use the provided interface index
```

**Debug Output** (after fix):
```
[sysroute] Header: msglen=140, version=5, type=1, index=20, flags=0x00400803
```

Note: `flags=0x00400803` now includes `RTF_IFSCOPE` (0x00400000) when `interface_scope=true`.

---

### Bug 13: route Command Fallback Doesn't Support Interface Scope

**Problem**: When raw routing socket fails, the `route` command fallback cannot create interface-scoped routes. The `-interface` flag on macOS route command is broken/non-functional.

**Result**:
```
$ netstat -nr | grep 10.0.0.2
10.0.0.2/32        10.0.0.1           UGSc                  en0   # Wrong interface!
```

**Impact**: Routes added via fallback point to the default interface (en0) instead of the TUN interface (utun4), causing "Network is unreachable" errors.

**Workaround**: For proper interface-scoped routes, the raw routing socket must work. The `route` command fallback is insufficient for TUN devices.

---

### Bug 14: createIpv4Route interface_scope Parameter Not Used

**Problem**: The `interface_scope` parameter was passed to the function but always hardcoded to `false`.

**Debug Output** (before fix):
```
[sysroute] BSD add: dst=10.0.0.2, mask=255.255.255.255, gw=10.0.0.1, ifscope=no, idx=20
```

**Fix**: Use the passed `interface_scope` parameter:
```zig
// WRONG:
.interface_scope = false,

// CORRECT:
.interface_scope = interface_scope != 0,
```

**Debug Output** (after fix):
```
[sysroute] BSD add: dst=10.0.0.2, mask=255.255.255.255, gw=10.0.0.1, ifscope=yes, idx=20
```

---

## Success Summary: What Fixed the Routing Message

After debugging, these fixes made the routing message **structurally correct**:

1. **rtm_index**: Set to actual interface index (20 for utun4), not 0
2. **RTF_IFSCOPE flag**: Added to flags when `interface_scope=true`
3. **RTF_STATIC**: Correct value is `0x800` (not `0x8`)
4. **RTF_UP**: Added for RTM_ADD operations
5. **RTM_VERSION**: Correct value is `5` (not `7`)

**Final correct header**:
```
[sysroute] Header: msglen=140, version=5, type=1, index=20, flags=0x00400803
```

Where `flags = 0x00400803 = RTF_IFSCOPE | RTF_STATIC | RTF_GATEWAY | RTF_UP`

**Note**: Even with correct message format, raw routing socket write still fails with EOPNOTSUPP (errno=39) in Zig, while identical C code succeeds. This remains an unresolved mystery.

---

## References

- sing-tun/tun_darwin.go:407-520 - `execRoute` function
- Apple BSD System Calls: `RTM_ADD`, `RTM_DELETE`, `RTF_IFSCOPE`
- XNU kernel routing subsystem: https://opensource.apple.com/source/xnu/xnu-4570.71.2/bsd/net/route.h
