# ztun Development Todo List

## Current Status
**Phase: Integration Testing - tun2sock executable built and verified**

Reference: sing-tun + sing-box cross-platform TUN implementation (in `../vendor/`)

**Build Status**: All components compiling successfully
- `zig build` - PASSED
- `zig build tun2sock` - PASSED
- `zig build test-tun` - PASSED

**Final Goal**: Generate usable `./src/tun2sock.zig` executable and verify it works on macOS

## Recent Fixes (2026-02-07)

### Fix: tun2sock.zig DeviceBuilder API Removed

**Problem**: tun2sock.zig used deprecated `DeviceBuilder` API that was deleted during refactoring.

**Solution**: Updated tun2sock.zig to use new `Options` API

### Fix: build.zig C Source Linking

**Problem**: tun2sock executable failed to link with undefined symbol `_route_get_iface_index`.

**Solution**: Added C source files to tun2sock build in build.zig

### New: test_forwarding.zig Integration Test

**Created**: `tests/test_forwarding.zig` - TCP/UDP forwarding integration test

**Test Results**:
```
[Test 1] TCP Packet Building - PASSED
[Test 2] UDP Packet Building - PASSED
[Test 3] TCP SYN Packet - PASSED
[Test 4] UDP DNS Query - PASSED
[Test 5] Checksum Verification - PASSED
[Test 6] Large Payload (MTU ~1400 bytes) - PASSED

=== TEST SUMMARY ===
Passed: 6
Failed: 0

Result: ALL TESTS PASSED
```

### Fix: IP Address Unification

**Added conversion functions to `options.zig`**:

```zig
/// Convert IPv4 address to u32 (network byte order)
pub fn ipv4ToU32(ip: Ipv4Address) u32 {
    return @as(u32, ip[0]) << 24 |
        @as(u32, ip[1]) << 16 |
        @as(u32, ip[2]) << 8 |
        @as(u32, ip[3]);
}

/// Convert u32 to IPv4 address (network byte order)
pub fn u32ToIpv4(ip_be: u32) Ipv4Address {
    return .{
        @as(u8, @truncate(ip_be >> 24)),
        @as(u8, @truncate(ip_be >> 16)),
        @as(u8, @truncate(ip_be >> 8)),
        @as(u8, @truncate(ip_be)),
    };
}
```

**Exported from `mod.zig`**:
```zig
pub const ipv4ToU32 = @import("options.zig").ipv4ToU32;
pub const u32ToIpv4 = @import("options.zig").u32ToIpv4;
pub const parseIpv4 = @import("options.zig").parseIpv4;
pub const formatIpv4 = @import("options.zig").formatIpv4;
```

**IP Address Standardization**:
- `[4]u8` (Ipv4Address) - Configuration and display
- `u32` - Packet processing and routing (network byte order)

**Build Commands**:
```bash
zig build test-forwarding  # Build forwarding test
sudo ./zig-out/bin/macos/test_forwarding  # Run test
```

```
$ sudo ./zig-out/bin/macos/test_tun
=== SIMULATED PING TEST COMPLETED ===
Result: SUCCESS (simulated roundtrip)
Note: macOS utun does not support packet loopback.
      The packet format and routing are verified correct.

$ sudo ./tun2sock --help
=== ztun tun2sock - Transparent Proxy Forwarder ===
Usage: tun2sock [OPTIONS]
Options:
  -i, --tun-ip IP       TUN interface IP address (default: 10.0.0.1)
  -m, --tun-mtu MTU     TUN device MTU (default: 1500)
  -x, --proxy ADDR      SOCKS5 proxy address (default: 127.0.0.1:1080)
  -d, --debug           Enable debug logging
  -h, --help            Show this help message
```

---

## Coding Standards and Lessons Learned

### Zig Code Generation Rules (from zig.codegen.md)

#### 1. Network Byte Order - CRITICAL

**Always use big-endian for network packets:**
```zig
// Reading from packet (always big-endian):
const src_ip = std.mem.readInt(u32, data[12..16], .big);
const dst_ip = std.mem.readInt(u32, data[16..20], .big);
const port = std.mem.readInt(u16, data[20..22], .big);

// Writing to packet (always big-endian):
std.mem.writeInt(u32, packet[12..16], src_ip, .big);
std.mem.writeInt(u16, packet[20..22], port, .big);
```

**Never use `@byteSwap()` for network order - use `std.mem.nativeToBig()`:**
```zig
// WRONG:
dst_sa.addr = @byteSwap(dst_ip);

// CORRECT:
dst_sa.addr = std.mem.nativeToBig(u32, dst_ip);
```

#### 2. extern struct for C Interop

**BSD sockaddr_in (16 bytes with padding):**
```zig
const SockAddrIn4 = extern struct {
    len: u8,          // BSD requires sa_len
    family: u8,
    port: u16,
    addr: u32,
    zero: [8]u8,      // Padding
};
```

**BSD rt_msghdr (92 bytes on macOS with RtMetrics):**
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

#### 3. libxev API Patterns

**Timer callback:**
```zig
// CORRECT:
router.loop.timer(&router.nat_timer, 30000, router, onNatTimer);
```

**Read buffer:**
```zig
// CORRECT:
.buffer = .{ .slice = &router.packet_buf },
```

**Callback signature:**
```zig
fn onTunReadable(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const n = result.read catch {
        router.submitTunRead();
        return .disarm;
    };
    // ...
    return .disarm;
}
```

**Pointer casting:**
```zig
const router = @as(*Router, @ptrCast(@alignCast(userdata orelse return .disarm)));
```

#### 4. Platform Detection

```zig
// Detect Android by ABI (works during cross-compilation):
const is_android = builtin.os.tag == .linux and builtin.abi == .android;

// Detect iOS by ABI:
const is_ios = builtin.os.tag == .ios or builtin.abi == .simulator;
```

#### 5. Field Name Conflicts

**Use `_stats` instead of `stats` to avoid method name conflict:**
```zig
_stats: RouterStats,  // Field
pub fn stats(router: *Router) RouterStats {  // Method
    return router._stats;
}
```

#### 6. Module File Structure

```zig
// Main module file (src/tun/mod.zig):
pub const TunDevice = @import("device.zig").TunDevice;
pub const Options = @import("options.zig").Options;

// Internal files use @import("device") instead of @import("device.zig")
```

#### 7. Struct Initialization for extern struct

```zig
// WRONG - .{} initializer doesn't work for extern struct:
const hdr = @as(*RtMsghdr, @ptrCast(@alignCast(&msg_buf))){
    .rtm_msglen = @as(u16, @intCast(msg_size)),
};

// CORRECT - field-by-field assignment:
const hdr = @as(*RtMsghdr, @ptrCast(@alignCast(&msg_buf)));
hdr.rtm_msglen = @as(u16, @intCast(msg_size));
```

#### 8. Buffer Initialization

```zig
// Use @memset for message portion:
var msg_buf: [256]u8 = undefined;
@memset(msg_buf[0..msg_size], 0);  // Zero the message portion
```

---

### BSD Routing Socket Lessons (from sysroute.md)

#### macOS BSD Constants

```zig
const BSD = struct {
    const RTM_VERSION = 5;    // macOS uses version 5, not 7
    const RTF_STATIC = 0x800; // Correct value on macOS
    const RTF_IFSCOPE = 0x00400000;
    const RTF_GATEWAY = 0x4;
    const RTF_UP = 0x1;
};
```

#### errno Debugging in Zig

```zig
// Use C's __error() function:
extern "c" fn __error() *c_int;

// Usage:
const errno_ptr = __error();
const errno_val = errno_ptr.*;
```

#### close() Order - CRITICAL

```zig
// WRONG:
_ = close(fd);
const written = write(fd, msg.ptr, msg.len);

// CORRECT:
const written = write(fd, msg.ptr, msg.len);
_ = close(fd);
```

---

### Protected Files (Do NOT Modify)

| File | Reason |
|------|--------|
| `tests/test_tun.zig` | Verified tun + system components |
| `src/tun/device.zig` | Core TUN interface |
| `src/system/route.c` | C routing module |

---

## Architecture Analysis (2026-02-07)

### Current System Architecture

```
TUN Device (utun/tun0/wintun)
       ↓ read()/write()
Router (libxev event loop)
       ├── route decision callback (app defines)
       ├── SOCKS5 proxy forwarding
       ├── UDP NAT forwarding
       └── Raw socket direct forwarding
```

### Implemented Components Status

| Component | Files | Status |
|-----------|-------|--------|
| **tun module** | device.zig + platform implementations | ✅ Complete |
| **ipstack module** | mod.zig + tcp/udp/icmp/ipv4.zig | ✅ Complete |
| **router module** | mod.zig + nat.zig + proxy/socks5.zig | ✅ Complete |
| **system module** | network.c/zig, route.c | ✅ Complete |
| **tun2sock app** | tun2sock.zig | ✅ Complete |

---

## Detailed Design Specifications

### System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application Layer                          │
│                    (tun2sock.zig, etc.)                         │
├─────────────────────────────────────────────────────────────────┤
│                     PacketHandler Interface                       │
│  handleTcp() / handleUdp() / handleIcmp()                       │
├─────────────────────────────────────────────────────────────────┤
│                      TunStack Interface                           │
│  System Stack (TCP NAT, UDP NAT, ICMP)                          │
├─────────────────────────────────────────────────────────────────┤
│                      TunDevice Interface                          │
│  read() / write() / name() / fd() / close()                     │
├───────────────┬───────────────┬───────────────┬─────────────────┤
│   Darwin      │    Linux      │   Windows     │   Android       │
│  (utun)       │ (/dev/net/tun)│   (Wintun)   │  (/dev/tun)     │
└───────────────┴───────────────┴───────────────┴─────────────────┘
```

### Data Flow

```
TUN Device (utun/tun0/wintun)
       ↓ read()/write()
Router (libxev event loop)
       ├── route decision callback (app defines)
       ├── SOCKS5 proxy forwarding
       ├── UDP NAT forwarding
       └── Raw socket direct forwarding
```

### IP Address Representation

| Context | Type | Byte Order | Usage |
|---------|------|------------|-------|
| Network packets | `u32` | Network (big) | Packet parsing/writing |
| Socket addresses | `u32` | Network (big) | Socket API |
| Display/logging | `[4]u8` | Network (big) | Human readable |
| Configuration | `Ipv4Address = [4]u8` | Network (big) | options.zig |

**Conversion functions:**
```zig
// u32 -> [4]u8 for display
fn ipv4ToArray(ip: u32) [4]u8 {
    return @as(*const [4]u8, @ptrCast(&ip)).*;
}

// [4]u8 -> u32 for network operations
fn arrayToIpv4(arr: [4]u8) u32 {
    return @as(*const u32, @ptrCast(&arr)).*;
}
```

---

## Reference Documentation

### External References

| Document | Location | Purpose |
|----------|----------|---------|
| sing-tun GitHub | `../vendor/sing-tun` | TUN implementation reference |
| sing-box TUN Inbound | `../vendor/sing-box/protocol/tun/inbound.go` | Architecture reference |
| libxev | `../vendor/libxev` | Event loop library |
| BSD Routing Sockets | `../vendor/` + online docs | macOS routing socket API |
| Linux netlink | `../vendor/` + online docs | Linux routing API |
| Windows Wintun | `../vendor/` + online docs | Windows TUN driver |

### Internal Documentation

| Document | Purpose |
|----------|---------|
| `DESIGN.md` | System architecture and design |
| `zig.codegen.md` | Zig code generation lessons |
| `sysroute.md` | BSD routing socket debugging |
| `build_tools/README.md` | Build system规范 |

---

## Task Tracking

### Completed Tasks

| Task | Status | Date |
|------|--------|------|
| TUN device interface (device.zig) | ✅ Complete | 2026-02-07 |
| Darwin TUN (device_darwin.zig) | ✅ Complete | 2026-02-07 |
| Linux TUN (device_linux.zig) | ✅ Complete | 2026-02-07 |
| Windows TUN (device_windows.zig) | ✅ Complete | 2026-02-07 |
| Options configuration (options.zig) | ✅ Complete | 2026-02-07 |
| Handler interface (handler.zig) | ✅ Complete | 2026-02-07 |
| Stack interface (stack.zig) | ✅ Complete | 2026-02-07 |
| Router module (router/mod.zig) | ✅ Complete | 2026-02-07 |
| NAT table (router/nat.zig) | ✅ Complete | 2026-02-07 |
| SOCKS5 proxy (router/proxy/socks5.zig) | ✅ Complete | 2026-02-07 |
| Network C module (network.c/zig) | ✅ Complete | 2026-02-07 |
| Route C module (route.c) | ✅ Complete | 2026-02-07 |
| tun2sock application | ✅ Complete | 2026-02-07 |
| test_tun integration test | ✅ Complete | 2026-02-07 |
| BSD routing workaround | ✅ Complete | 2026-02-07 |

### Pending Tasks

| Task | Priority | Status | Dependencies |
|------|----------|--------|--------------|
| IP address unification | High | Pending | None |
| macOS header handling refactor | Low | Pending | device_darwin.zig |
| Integration tests (TCP/UDP/SOCKS5) | High | Pending | None |
| stack_system.zig | Medium | Pending | TunStack interface |

### Task Checklist

- [ ] Review and understand all coding standards
- [ ] Review detailed design specifications
- [ ] Implement IP address unification (if required)
- [ ] Add integration tests
- [ ] Verify all builds pass
- [ ] Run full test suite

## Identified Issues and Improvements

### 1. TunDevice Interface Unused (Medium Priority)

**Issue**: `tun/device.zig` defines `TunDevice` interface, but `router/mod.zig` uses raw fd and `DeviceOps` instead.

**Current**: `router/mod.zig:336-341`
```zig
inline fn tunFd(router: *Router) std.posix.fd_t {
    if (router.config.tun.device_ops) |dev| {
        return dev.fd();
    }
    return router.config.tun.fd;
}
```

**Resolution**: Keep current approach - `DeviceOps` is simpler and sufficient.

### 2. TunStack Interface Unused (High Priority)

**Issue**: `tun/stack.zig` defines `TunStack` interface, but `stack_system.zig` implementation is missing. Router directly handles IP packet parsing.

**Current**: `router/mod.zig:1036-1108` - Router parses IP packets directly.

**Resolution**: `TunStack` interface is an abstraction layer for future use. Currently router handles packet processing directly.

### 3. IP Address Representation Inconsistency (High Priority)

**Issue**: Different modules use different IP representation formats:

| Module | IP Type | Byte Order |
|--------|---------|------------|
| options.zig | `[4]u8` | Network (big-endian) |
| network.zig | `u32` | Network |
| router/mod.zig | `u32` | Network |
| ipstack/mod.zig | `u32` | Network |
| handler.zig | `Ipv4Address = [4]u8` | Network |

**Conflict**: `handler.zig:61` uses `[4]u8` while `router/mod.zig:171` uses `u32`.

**Resolution**:
- Standardize on `u32` for IPv4 addresses (network byte order)
- Keep `[4]u8` only for display/logging purposes
- Add conversion functions: `ipv4ToArray()`, `arrayToIpv4()`

### 4. PacketHandler Interface Not Integrated (Medium Priority)

**Issue**: `tun/handler.zig` defines `PacketHandler` interface, but router implements its own TCP/UDP handling logic.

**Current**: `router/mod.zig:604-646` - Router handles TCP directly without using `PacketHandler`.

**Resolution**: Keep simple for now. Integrate when more complex protocol handling is needed (QoS, traffic shaping).

### 5. macOS utun Header Handling Hardcoded (Low Priority)

**Issue**: `router/mod.zig:1063-1065` hardcodes 4-byte utun header skip:

```zig
const ip_offset: usize = 4;  // macOS utun special handling
```

**Resolution**: Platform-specific header processing should be in `device_darwin.zig` `read()` function.

### 6. Missing Integration Tests (High Priority)

**Issue**: `tests/test_tun.zig` only tests TUN device and ICMP echo. Missing:
- TCP proxy forwarding test
- UDP NAT traversal test
- SOCKS5 proxy integration test

**Resolution**: Add `tests/tun2sock_integration_test.zig` for full stack testing.

---

## Verified Working Components

### Build Status
```bash
zig build              # ✅ Passes
zig build test-tun     # ✅ Passes
```

### Router Integration Verified
- libxev event loop ✅
- TUN async read/write ✅
- SOCKS5 proxy connection ✅
- UDP NAT table ✅
- Raw socket forwarding ✅

---

## Current Progress

### BSD Routing Socket Debugging - COMPLETED with Workaround

**Issue**: Raw routing socket write fails in Zig with EOPNOTSUPP (errno=39) even with message format identical to working C code.

**Solution**: Implemented fallback to external `route` command when raw socket fails.

**Files Modified**:
- `src/system/sysroute.zig` - Added `bsdRouteCommandAdd()` fallback function

**Documentation**: All bug fixes recorded in `sysroute.md`

---

## ICMP Echo Loopback Test - IN PROGRESS

**Goal**: Verify that packets sent to TUN device can be routed back via loopback.

**Test Plan**:
1. Create utun device with IP 10.0.0.2/32
2. Add route for 10.0.0.2 via utun interface
3. Ping 10.0.0.2 from localhost
4. Verify ICMP echo request reaches TUN and response is sent

---

## Refactoring Overview

Based on sing-tun and sing-box architecture, completely reimplement `./src/tun/` and `./src/system/sysroute.zig` using libxev for event-driven I/O.

### Target Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Application Layer                      │
│                    (Router, tun2sock, etc.)                 │
├─────────────────────────────────────────────────────────────┤
│                     PacketHandler Interface                   │
│  handleTcp() / handleUdp() / handleIcmp()                   │
├─────────────────────────────────────────────────────────────┤
│                      TunStack Interface                       │
│  System Stack (TCP NAT, UDP NAT, ICMP)                      │
├─────────────────────────────────────────────────────────────┤
│                      TunDevice Interface                      │
│  read() / write() / name() / fd() / close()                │
├───────────────┬───────────────┬───────────────┬─────────────┤
│   Darwin      │    Linux      │   Windows     │   Android   │
│  (utun)       │ (/dev/net/tun)│   (Wintun)   │  (/dev/tun)│
└───────────────┴───────────────┴───────────────┴─────────────┘
```

---

## Implementation Phases

### Phase 1: Core Interface Definitions

**Goal**: Define clean abstractions for TUN device, protocol stack, and packet handler.

#### Created Files

| File | Description | Status |
|------|-------------|--------|
| `src/tun/options.zig` | TUN configuration options | ⏳ |
| `src/tun/device.zig` | TunDevice interface | ⏳ |
| `src/tun/stack.zig` | TunStack interface | ⏳ |
| `src/tun/handler.zig` | PacketHandler interface | ⏳ |

#### TunDevice Interface

```zig
const TunDevice = interface {
    fn read(buf: []u8) error!usize;
    fn write(buf: []const u8) error!usize;
    fn name() error![]const u8;
    fn ifIndex() error!u32;
    fn fd() std.posix.fd_t;
    fn setNonBlocking(enabled: bool) error!void;
    fn close() void;
};
```

#### TunStack Interface

```zig
const TunStack = interface {
    fn start(handler: *PacketHandler) error!void;
    fn stop() void;
    fn fd() std.posix.fd_t;
};
```

#### PacketHandler Interface

```zig
const PacketHandler = interface {
    fn handleTcp(src_ip: Ipv4Address, dst_ip: Ipv4Address, data: []const u8) error!void;
    fn handleUdp(src_ip: Ipv4Address, dst_ip: Ipv4Address, data: []const u8) error!void;
    fn handleIcmp(src_ip: Ipv4Address, dst_ip: Ipv4Address, data: []const u8) error!void;
};
```

---

### Phase 2: Darwin/macOS/iOS Implementation

**Goal**: Implement TUN device using utun sockets with BSD routing sockets for routing.

#### Created Files

| File | Description | Status |
|------|-------------|--------|
| `src/tun/device_darwin.zig` | Darwin TUN device | ⏳ |

#### Implementation Details

1. **Device Creation**
   - Socket: `AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL`
   - Connect to: `com.apple.net.utun_control`
   - Get interface name and index via `SIOCGIFCONF` or `getsockopt(UTUN_OPT_IFNAME)`

2. **Packet I/O**
   - Read: `recv()` + strip 4-byte AF_INET header
   - Write: `send()` + prepend 4-byte `[0x02, 0x00, 0x00, 0x00]`

3. **Routing (via BSD Routing Sockets)**
   - Socket: `AF_ROUTE, SOCK_RAW, 0`
   - Messages: `RTM_ADD`, `RTM_DELETE`
   - Structures: `rt_msghdr`, `sockaddr_in`, `sockaddr_dl`

#### Code Structure

```zig
const DarwinTun = struct {
    fd: std.posix.fd_t,
    name: []const u8,
    ifindex: u32,

    pub fn create(options: Options) !*DarwinTun;
    pub fn read(self: *DarwinTun, buf: []u8) error!usize;
    pub fn write(self: *DarwinTun, buf: []const u8) error!usize;
    pub fn addRoute(self: *DarwinTun, route: *RouteEntry) error!void;
    pub fn deleteRoute(self: *DarwinTun, route: *RouteEntry) error!void;
};
```

---

### Phase 3: Linux Implementation

**Goal**: Implement TUN device using `/dev/net/tun` with netlink for routing.

#### Created Files

| File | Description | Status |
|------|-------------|--------|
| `src/tun/device_linux.zig` | Linux TUN device | ⏳ |

#### Implementation Details

1. **Device Creation**
   - Open: `/dev/net/tun` (or `/dev/tun` on Android)
   - ioctl: `TUNSETIFF` with `IFF_TUN`
   - Flags: `IFF_NO_PI` (no packet info)

2. **Packet I/O**
   - Read: direct `read()` of raw IP packets
   - Write: direct `write()` of raw IP packets
   - Optional: GSO support with `virtio_net_hdr`

3. **Routing (via Netlink)**
   - Socket: `AF_NETLINK, SOCK_RAW, NETLINK_ROUTE`
   - Messages: `RTM_NEWROUTE`, `RTM_DELROUTE`
   - Use `github.com/sagernet/netlink` or raw netlink

#### Code Structure

```zig
const LinuxTun = struct {
    fd: std.posix.fd_t,
    name: []const u8,
    ifindex: u32,
    nl_socket: std.posix.fd_t,

    pub fn create(options: Options) !*LinuxTun;
    pub fn read(self: *LinuxTun, buf: []u8) error!usize;
    pub fn write(self: *LinuxTun, buf: []const u8) error!usize;
    pub fn addRoute(self: *LinuxTun, route: *RouteEntry) error!void;
    pub fn deleteRoute(self: *LinuxTun, route: *RouteEntry) error!void;
};
```

---

### Phase 4: Windows Implementation

**Goal**: Implement TUN device using Wintun DLL with winipcfg API for routing.

#### Created Files

| File | Description | Status |
|------|-------------|--------|
| `src/tun/device_windows.zig` | Windows TUN device | ⏳ |

#### Implementation Details

1. **Device Creation**
   - Load: `wintun.dll` from application directory
   - API: `WintunCreateAdapter()`
   - Session: `WintunStartSession()`

2. **Packet I/O**
   - Read: `WintunReceivePacket()` from ring buffer
   - Write: `WintunSendPacket()` to ring buffer
   - Zero-copy design with aligned ring buffers

3. **Routing (via winipcfg)**
   - API: `GetAdaptersInfo()`, `GetIpForwardTable()`
   - Modify: `MibIPforwardRow2` + `SetIpForwardEntry2()`

#### Code Structure

```zig
const WindowsTun = struct {
    adapter: *wintun.WINTUN_ADAPTER_HANDLE,
    session: *wintun.WINTUN_SESSION_HANDLE,
    name: [:0]u8,

    pub fn create(options: Options) !*WindowsTun;
    pub fn read(self: *WindowsTun, buf: []u8) error!usize;
    pub fn write(self: *WindowsTun, buf: []const u8) error!usize;
    pub fn addRoute(self: *WindowsTun, route: *RouteEntry) error!void;
    pub fn deleteRoute(self: *WindowsTun, route: *RouteEntry) error!void;
};
```

---

### Phase 5: System Protocol Stack

**Goal**: Implement lightweight NAT-based protocol stack using system network stack.

#### Created Files

| File | Description | Status |
|------|-------------|--------|
| `src/tun/stack_system.zig` | System protocol stack | ⏳ |

#### Implementation Details

1. **TCP Handling**
   - Listen on TUN IP addresses
   - NAT table for connection tracking
   - Forward to SOCKS5 proxy or direct

2. **UDP Handling**
   - NAT mapping for UDP sessions
   - Timeout-based session expiration
   - Bidirectional forwarding

3. **ICMP Handling**
   - Echo request/response
   - Destination unreachable passthrough

#### Code Structure

```zig
const SystemStack = struct {
    device: *TunDevice,
    tcp_listener: std.posix.socket_t,
    nat_table: *NatTable,

    pub fn create(device: *TunDevice) !*SystemStack;
    pub fn start(self: *SystemStack, handler: *PacketHandler) error!void;
    pub fn stop(self: *SystemStack) void;
};
```

---

### Phase 6: libxev Integration

**Goal**: Integrate all components with libxev event loop.

#### Implementation Pattern

```zig
const TunServer = struct {
    loop: *xev.Loop,
    device: *TunDevice,
    stack: *TunStack,
    completion: xev.Completion,
    handler: *PacketHandler,

    pub fn init(loop: *xev.Loop, device: *TunDevice, handler: *PacketHandler) !void {
        // Submit initial TUN read
        loop.read(&completion, device.fd(), this, onTunReadable);
    }

    fn onTunReadable(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        const n = result.read catch return .disarm;

        // Process packet through stack
        stack.processPacket(buf[0..n]) catch return .disarm;

        // Re-submit read
        loop.read(completion, device.fd(), userdata, onTunReadable);
        return .rearm;
    }
};
```

---

### Phase 7: Router Module Re-architecture

**Goal**: Refactor router module to use new TUN interfaces.

#### New Structure

| File | Description | Status |
|------|-------------|--------|
| `src/system/router.zig` | Unified router interface | ⏳ |
| `src/system/router_darwin.zig` | BSD routing | ⏳ |
| `src/system/router_linux.zig` | Linux netlink routing | ⏳ |
| `src/system/router_windows.zig` | Windows winipcfg routing | ⏳ |

#### Router Interface

```zig
const Router = interface {
    fn addIpv4Route(destination: Ipv4Cidr, gateway: ?Ipv4Address, iface: []const u8) error!void;
    fn deleteIpv4Route(destination: Ipv4Cidr, iface: []const u8) error!void;
    fn addIpv6Route(destination: Ipv6Cidr, gateway: ?Ipv6Address, iface: []const u8) error!void;
    fn getInterfaceIndex(name: []const u8) error!u32;
};
```

---

## Files Summary

### New Files to Create

| File | Phase | Description |
|------|-------|-------------|
| `src/tun/options.zig` | 1 | TUN configuration options |
| `src/tun/device.zig` | 1 | TunDevice interface |
| `src/tun/stack.zig` | 1 | TunStack interface |
| `src/tun/handler.zig` | 1 | PacketHandler interface |
| `src/tun/device_darwin.zig` | 2 | Darwin TUN implementation |
| `src/tun/device_linux.zig` | 3 | Linux TUN implementation |
| `src/tun/device_windows.zig` | 4 | Windows TUN implementation |
| `src/tun/stack_system.zig` | 5 | System protocol stack |
| `src/system/router.zig` | 7 | Unified router interface |
| `src/system/router_darwin.zig` | 7 | BSD routing implementation |
| `src/system/router_linux.zig` | 7 | Linux routing implementation |
| `src/system/router_windows.zig` | 7 | Windows routing implementation |

### Files to Delete

| File | Reason |
|------|--------|
| `src/tun/builder.zig` | Superseded by options.zig |
| `src/tun/ringbuf.zig` | Superseded by platform-specific implementations |
| `src/tun/platform.zig` | Superseded by device_*.zig |
| `src/system/sysroute.zig` | Superseded by router_*.zig |

### Files to Modify

| File | Changes |
|------|---------|
| `src/tun/mod.zig` | Re-export new interfaces |
| `src/tun/device_macos.zig` | Merge into device_darwin.zig |
| `src/tun/device_linux.zig` | Rewrite |
| `src/tun/device_windows.zig` | Rewrite |

---

## Verification Plan

### Build Verification

```bash
# Default build
zig build              # ⏳

# Build test_tun
zig build test-tun     # ⏳

# Cross-compile
zig build all          # ⏳
```

### Unit Tests

- [ ] Options parsing
- [ ] Address conversion
- [ ] Checksum calculation

### Integration Tests

- [ ] macOS: Ping echo test
- [ ] Linux: Ping echo test (Lima VM)
- [ ] Windows: Ping echo test (Windows VM)

### tcpdump Verification

```bash
# Capture TUN traffic
sudo tcpdump -i any -w /tmp/tun_capture.pcap host 10.0.0.2

# macOS: Verify 4-byte header
tcpdump -r /tmp/tun_capture.pcap -XX -vv

# Linux/Windows: Verify raw IP packets
tcpdump -r /tmp/tun_capture.pcap -XX
```

---

## Dependencies

- **libxev**: Event loop (already integrated)
- **zinternal**: App framework (app, logger, platform)
- **sing-tun**: Reference implementation
- **sing-box**: Reference implementation

---

## Notes

1. **Memory Management**: Use arena allocator for NAT tables
2. **Error Handling**: Distinguish recoverable vs fatal errors
3. **Thread Safety**: libxev is single-threaded, no locks needed
4. **Resource Cleanup**: Properly close all FDs and handles
5. **Endianness**: Always use network byte order for packets

---

## Reference Documentation

- [sing-tun GitHub](https://github.com/SagerNet/sing-tun)
- [sing-box TUN Inbound](../vendor/sing-box/protocol/tun/inbound.go)
- [BSD Routing Sockets](https://www.freebsd.org/cgi/man.cgi?query=route)
- [Linux netlink](https://man7.org/linux/man-pages/man7/netlink.7.html)
- [Windows Wintun](https://www.wintun.net/)
