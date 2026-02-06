# ztun Development Todo List

## Current Status
**Phase: Full Refactoring - TUN Module Re-architecture**

Reference: sing-tun + sing-box cross-platform TUN implementation

Last Updated: 2026-02-06

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
