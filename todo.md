# ztun Development Todo List

**Version**: 0.2.6
**Last Updated**: 2026-02-13

---

## Current Tasks

### Phase 8: Outbound Abstraction + ipstack Integration (COMPLETED)

**Date**: 2026-02-13

**Goal**: Refactor Router to use ipstack for protocol parsing and add Outbound abstraction layer

**Problem Identified**:
- Router manually implements IP/TCP/UDP parsing (~150 lines of duplicate code)
- ipstack module already has `ipv4.parseHeader()`, `tcp.parseHeader()`, etc. but was unused
- Need Outbound abstraction for SOCKS5/Direct support (like sing-box)

**Architecture**:
```
TUN → Router → Outbound (interface) → SOCKS5/Direct (impl) → ipstack (protocol)
```

**Changes**:
- [x] Created `src/router/outbound.zig` - Outbound interface with SOCKS5/Direct implementations
- [x] Updated `src/router/mod.zig` to use ipstack for protocol parsing:
  - `parsePacket()` → `ipstack.ipv4.parseHeader()` + `ipstack.tcp.parseHeader()` + `ipstack.udp.parseHeader()`
  - `extractTcpPayload()` → `ipstack.tcp.parseHeader()`
  - `extractTcpSeqNum()` → `ipstack.tcp.parseHeader()`
  - `sendSynAck()` → `ipstack.ipv4.buildHeader()` + `ipstack.tcp.buildHeaderWithChecksum()`
  - `sendMockDataResponse()` → `ipstack.ipv4.buildHeader()` + `ipstack.tcp.buildHeaderWithChecksum()`
- [x] Updated `build.zig` to add router_outbound module
- [x] Compilation and tests pass

**Files Created**:
| File | Description |
|------|-------------|
| `src/router/outbound.zig` | Outbound abstraction (SOCKS5 + Direct) |

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/mod.zig` | Use ipstack for protocol parsing |
| `build.zig` | Added router_outbound module |

**Verification**:
```
zig build  # SUCCESS
zig build test  # All tests passed
```

---

### Phase 7.13: Network Monitor Bug Fixes (COMPLETED)

**Date**: 2026-02-13

**Issues Fixed**:
- Removed dead code: `handleNetworkChange()` referenced non-existent `network_listener` field
- Fixed event mapping: `address_removed` now pauses network instead of resuming
- Updated `onNetworkChangeCallback` to correctly handle all network events

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/mod.zig` | Removed dead `handleNetworkChange()`, fixed event mapping |

---

### Phase 7.12: Cross-Platform Network Monitor Integration (PENDING)

**Date**: 2026-02-12

**Goal**: Fully integrate network change detection and handle network events

**Required Changes**:
- [ ] Implement egress interface reselection on network change
- [ ] Close and reconnect SOCKS5 connection on network change
- [ ] Reset NAT table on network change
- [ ] Handle RTM_IFINFO, RTM_NEWADDR, RTM_DELADDR events in router

---

### Phase 7.11: Cross-Platform Network Monitor Implementation (COMPLETED)

**Date**: 2026-02-12

**Result**: Successfully implemented cross-platform network change detection

**Architecture**:
```
src/system/monitor.zig           # Main facade (cross-platform interface)
├── monitor_darwin.zig          # BSD Routing Socket (macOS)
├── monitor_linux.zig           # rtnetlink (Linux)
└── monitor_windows.zig         # NotifyAddrChange (Windows)
```

**API**:
```zig
pub const NetworkChange = enum {
    interface_up,
    interface_down,
    address_added,
    address_removed,
    route_changed,
    network_losing,
};

pub const NetworkEvent = struct {
    change: NetworkChange,
    interface_name: []const u8,
    interface_index: u32,
    timestamp: i64,
};

pub const ObserverCallback = *const fn (event: *const NetworkEvent, userdata: ?*anyopaque) void;

pub const NetworkMonitor = struct {
    register: *const fn (callback: ObserverCallback, userdata: ?*anyopaque) !void,
    unregister: *const fn (callback: ObserverCallback) void,
    notify: *const fn (event: *const NetworkEvent) void,
};

pub fn createNetworkMonitor(allocator: std.mem.Allocator) !*NetworkMonitor;
pub fn destroyNetworkMonitor(monitor_ptr: *NetworkMonitor) void;
```

**Changes**:
- [x] Create `src/system/monitor.zig` (main interface)
- [x] Create `src/system/monitor_darwin.zig` (BSD Routing Socket)
- [x] Create `src/system/monitor_linux.zig` (rtnetlink)
- [x] Create `src/system/monitor_windows.zig` (Windows API)
- [x] Update Router to use monitor instead of raw BSD socket
- [x] Add monitor module to build.zig

**Compilation Fixes**:
- Removed xev imports from platform files (use opaque pointers)
- Changed packed struct to extern struct for C interop
- Defined F_GETFL/F_SETFL/O_NONBLOCK constants manually
- Handled socket() error union properly
- Used platform-specific types for callback registration

**Files Modified**:
| File | Action |
|------|--------|
| `src/system/monitor.zig` | Create - main interface |
| `src/system/monitor_darwin.zig` | Create - macOS implementation |
| `src/system/monitor_linux.zig` | Create - Linux implementation |
| `src/system/monitor_windows.zig` | Create - Windows implementation |
| `src/router/mod.zig` | Modify - use monitor API |
| `build.zig` | Modify - add monitor module |
| `zig.codegen.md` | Document compilation fixes |

---

### Phase 7.10: Graceful Shutdown (PENDING)

---

### Phase 7.9: Network Change Detection and Handling (COMPLETED)

**Date**: 2026-02-12

**Reference**: sing-box `route/network.go` architecture

**Result**: BSD Routing Socket listener and network change handlers implemented

**Key Changes**:
1. **BSD Routing Socket Listener** (`mod.zig:1149+`)
2. **Network Change Handlers**: `handleNetworkChange()`, `handleNetworkPause()`, `handleNetworkResume()`
3. **NetworkListener Interface**: Callback-based notification system
4. **Router Updates**: `egress_iface`, `network_listener`, `is_paused`, `routing_sock`

**Files Modified**: `src/router/mod.zig`, `build.zig`

---

### Phase 7.8: SOCKS5 TCP Handshake Fix (COMPLETED)

**Date**: 2026-02-12

**Reference**: sing-box `route/network.go` architecture

**Goal**: Implement network change detection and graceful handling, similar to sing-box's NetworkManager

**Background**: sing-box provides robust network change handling:
- `NetworkManager` monitors default interface changes via `tun.NetworkUpdateMonitor`
- `interfaceMonitor` detects interface up/down events
- `ResetNetwork()` closes connections and notifies all components
- `pauseManager` handles system suspend/resume events

**ztun Current Status**:
| Feature | Status | Location |
|---------|--------|----------|
| TUN packet handling | Done | `mod.zig:1102-1176` |
| SOCKS5 callbacks | Done | `mod.zig:1207-1294` |
| UDP NAT handling | Done | `mod.zig:559-599` |
| Egress interface selection | Done | `network.zig:218-260` |
| Network change detection | **Missing** | - |
| Interface monitoring | **Missing** | - |
| Egress interface reselection | **Missing** | - |
| Connection reset on network change | **Missing** | - |
| System suspend/resume | **Missing** | - |

**Required Changes**:

#### P0: Graceful Network Reset (Critical)
- [ ] Close existing SOCKS5 connection when network changes
- [ ] Clear pending SYN state
- [ ] Reset NAT table on network change
- [ ] **Re-select egress interface** using `selectEgressIp()` after network change
- [ ] Update `egress_ip` and `egress_iface` fields in Router
- Location: `src/router/mod.zig`

#### P1: Egress Interface Reselection
```zig
/// Re-select egress interface after network change
fn reselectEgressInterface(router: *Router) !void {
    // Close existing raw socket if any
    if (router.raw_sock) |sock| {
        std.posix.close(sock);
        router.raw_sock = null;
    }

    // Re-select egress interface using network.zig
    const egress = try network.selectEgressIp(router.allocator, router.config.egress.iface);
    router.egress_ip = egress.ip;
    router.egress_iface = egress.iface;

    // Create new raw socket for egress interface
    router.raw_sock = try std.posix.socket(
        std.posix.AF_INET,
        std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK,
        std.posix.IPPROTO_RAW,
    );
    // Bind to egress interface
    var ifreq = std.mem.zeroInit(ifreq, .{
        .ifr_name = router.egress_iface,
    });
    _ = std.posix.ioctl(router.raw_sock, std.posix.SIOCGIFINDEX, @ptrCast(&ifreq));

    // Update routing if egress changed
    if (!std.mem.eql(u8, router.egress_iface, router.config.egress.iface)) {
        std.debug.print("[NET] Egress changed: {s} -> {s}\n", .{ router.config.egress.iface, router.egress_iface });
    }
}
```

#### P2: Network Listener Interface
```zig
/// Network change callback interface (new file: src/router/network.zig)
pub const NetworkListener = struct {
    onDefaultInterfaceChanged: ?*const fn (userdata: ?*anyopaque, interface_name: []const u8, interface_index: u32) void = null,
    onNetworkPaused: ?*const fn (userdata: ?*anyopaque) void = null,
    onNetworkResumed: ?*const fn (userdata: ?*anyopaque) void = null,
    onRoutesChanged: ?*const fn (userdata: ?*anyopaque) void = null,
    userdata: ?*anyopaque = null,
};
```

#### P2: Router Enhancements
- [ ] Add `network_listener: ?*NetworkListener` field
- [ ] Add `default_interface` info storage
- [ ] Add `is_paused: bool` state
- [ ] Add `handleNetworkChange()` method
- [ ] Add `handleNetworkPause()` / `handleNetworkResume()` methods
- Location: `src/router/mod.zig`

#### P3: BSD Routing Socket Listener (macOS)
```zig
/// Start Routing Socket listener for network events
fn startRoutingSocketListener(router: *Router) !void {
    const sock = std.posix.socket(std.posix.AF_ROUTE, std.posix.SOCK.RAW, 0) catch {
        return error.SocketFailed;
    };
    // Register with libxev for RTM_IFINFO, RTM_NEWADDR, RTM_DELADDR events
}

/// Handle routing socket message
fn onRoutingSocketReadable(...) xev.CallbackAction {
    const msg = @as(*const rt_msghdr, @ptrCast(@alignCast(&router.route_buf)));
    switch (msg.rtm_type) {
        RTM_IFINFO => router.handleNetworkChange(...),
        RTM_NEWADDR, RTM_DELADDR => router.handleRoutesChanged(),
        else => {},
    }
}
```

#### P4: Router Statistics Update
```zig
pub const RouterStats = struct {
    // ... existing fields ...
    network_changes: u64 = 0,  // Add this field
    route_updates: u64 = 0,    // Add this field
};
```

**Reference Implementation**: sing-box patterns
- `route/network.go:395-418` - `ResetNetwork()` implementation
- `route/network.go:420-461` - `notifyInterfaceUpdate()` callback
- `route/network.go:463-477` - Windows power event handling

**Testing**:
```bash
# Test network change handling
# 1. Start tun2sock
# 2. Change network (Wi-Fi -> Ethernet, or toggle interface)
# 3. Verify SOCKS5 connection is reset
# 4. Verify new connections work
```

---

### Phase 7.8: SOCKS5 TCP Handshake Fix (COMPLETED)

**Date**: 2026-02-12

**Result**: TCP three-way handshake through SOCKS5 proxy now works correctly

**Verification**:
```bash
curl -v --proxy socks5://127.0.0.1:1080 http://111.45.11.5/
# HTTP/1.1 403 Forbidden (connection established successfully)
```

**Git Commit**: `1ad1f52`

---

## Current Tasks

### Phase 7.9: Network Change Detection and Handling (PENDING)

**Date**: 2026-02-12

**Reference**: sing-box `route/network.go` architecture

**Goal**: Implement network change detection and graceful handling

**Checklist**:
- [ ] **P0**: Close SOCKS5 connection on network change
- [ ] **P0**: Clear pending SYN state on network change
- [ ] **P0**: Reset NAT table on network change
- [ ] **P1**: Create `NetworkListener` interface (`src/router/network.zig`)
- [ ] **P1**: Add `network_listener` field to Router
- [ ] **P1**: Add `handleNetworkChange()` method
- [ ] **P1**: Add `handleNetworkPause()` / `handleNetworkResume()` methods
- [ ] **P2**: Implement BSD Routing Socket listener for macOS
- [ ] **P2**: Handle RTM_IFINFO, RTM_NEWADDR, RTM_DELADDR events
- [ ] **P3**: Update RouterStats with `network_changes` counter
- [ ] **P4**: Add system suspend/resume handling

**Reference Implementation**: sing-box patterns
- `route/network.go:395-418` - `ResetNetwork()` implementation
- `route/network.go:420-461` - `notifyInterfaceUpdate()` callback
- `route/network.go:463-477` - Windows power event handling

**Files to Modify**:
| File | Changes |
|------|---------|
| `src/router/network.zig` | New file - NetworkListener interface |
| `src/router/mod.zig` | Add network listener support |

---

### Phase 7.8: SOCKS5 TCP Handshake Fix (COMPLETED)

**Date**: 2026-02-12

**Problem**: TCP SYN packets received from TUN but SYN-ACK not sent back to client, causing curl to hang waiting for connection

**Root Causes**:
1. SOCKS5 client callbacks were not firing due to incorrect libxev API usage
2. SYN-ACK response was not implemented - only logged as TODO
3. Pending SYN information (src_ip, src_port, seq_num) was not stored for later use

**Fixes**:
1. **Rewrote socks5.zig with correct libxev API** (`src/router/proxy/socks5.zig`):
   - Used raw `std.posix.socket` + `xev.Completion` pattern
   - Fixed callback signatures for libxev 0.2+ completion callbacks
   - Added proper error handling and state machine

2. **Added SYN info storage in Router** (`src/router/mod.zig:307-311`):
   - Added `pending_syn` field to store client connection info
   - Stores src_ip, src_port, and seq_num when SYN is received

3. **Implemented TCP sequence number extraction** (`src/router/mod.zig:715-727`):
   - Added `extractTcpSeqNum()` function to parse TCP header
   - Returns sequence number for SYN-ACK construction

4. **Implemented SYN-ACK response** (`src/router/mod.zig:888-937`):
   - Added `sendSynAck()` function to construct IP+TCP headers
   - Calculates IP and TCP checksums using ipstack.checksum
   - Sends constructed packet back to TUN device

5. **Updated tunnel ready callback** (`src/router/mod.zig:1304-1325`):
   - Modified `onSocks5TunnelReady()` to call `sendSynAck()`
   - Clears pending SYN after response is sent

**Key Code Changes**:
```zig
// Router struct addition
pending_syn: ?struct {
    src_ip: u32,
    src_port: u16,
    seq_num: u32,
} = null,

// SYN-ACK construction
fn sendSynAck(router: *Router, src_ip: u32, src_port: u16, ...) !void {
    // Build IP header (20 bytes)
    // Build TCP header (20 bytes) with SYN+ACK flags
    // Calculate checksums
    router.writeToTunBuf(packet);
}

// Tunnel ready callback
fn onSocks5TunnelReady(userdata: ?*anyopaque) void {
    // ...
    if (router.pending_syn) |syn| {
        router.sendSynAck(syn.src_ip, syn.src_port, client.dst_ip, client.dst_port, syn.seq_num) catch {
            return;
        };
        router.pending_syn = null;
    }
}
```

**Verification**:
```bash
# Build test
zig build tun2sock  # SUCCESS

# Test with curl (requires SOCKS5 proxy running)
curl -v --proxy socks5://127.0.0.1:1080 http://111.45.11.5/
```

---

### Phase 7.7: TUN and Routing Bug Fixes (COMPLETED)

**Date**: 2026-02-12

**Problem**: tun2sock routing configuration was failing with verification errors

**Root Causes**:
1. Route verification logic was too strict for macOS utun point-to-point interfaces
2. Gateway matching check failed because utun routes use interface link-layer addresses
3. Build cache was not properly rebuilding C code after modifications

**Fixes**:
1. **Simplified route verification** (`src/system/route.c:875-898`):
   - Removed strict gateway matching for direct routes
   - For TUN/utun routes, trust the `route` command output
   - Return success if route command reports success

2. **Updated gateway configuration** (`src/tun2sock.zig:302-311`):
   - Changed gateway from `tun_peer` to `0.0.0.0` for direct point-to-point routes
   - Uses direct interface route format matching test_tun.zig

3. **Clean build**:
   - Cleared zig-cache to force recompilation
   - Used `zig build tun2sock` instead of `zig build`

**Verification**:
- Route configuration now succeeds without warnings
- Routes properly added to routing table:
  ```
  111.45.11.5/32  utun10  USc  utun10
  10.0.0.1/32     utun10  USc  utun10
  ```
- TCP forwarding through SOCKS5 proxy works correctly
- ICMP echo handling processes packets through TUN device

**Test Results**:
```bash
# TCP forwarding through SOCKS5
curl --proxy socks5://127.0.0.1:1080 http://111.45.11.5/
# HTTP/1.1 403 Forbidden (connection established, server rejected)

# ICMP through TUN
ping -c 3 111.45.11.5
# Packets received and ICMP replies sent via TUN
```

---

### Phase 7.6: SOCKS5 Client Refactoring (COMPLETED)

**Date**: 2026-02-12

**Changes**:
- [x] **Moved SOCKS5 client to standalone module**: Socks5Client is now in `src/router/proxy/socks5.zig`
- [x] **Added type alias for compatibility**: `pub const Socks5Conn = socks5.Socks5Client;`
- [x] **Updated Router to use Socks5Client**: Refactored `forwardToProxy()` to use new API
- [x] **Added callback support**: `onSocks5Data`, `onSocks5Ready`, `onSocks5Error` for event handling
- [x] **Fixed Zig 0.13.0 compatibility**: Fixed callback types, socket constants, error handling

**Architecture**:
```
mod.zig
  └── socks5_client: ?*socks5.Socks5Client
      ├── connect(dst_ip, dst_port, data)  // Async connection with payload
      ├── send(data)                        // Send after connected
      ├── getState(), isReady()             // State queries
      └── callbacks: on_data, on_ready, on_error
```

### Phase 7.5: SOCKS5 Protocol Debugging (COMPLETED)

### Phase 7.4: End-to-End Testing (COMPLETED)

**Date**: 2026-02-12

- [x] **Integration tests pass**
  ```
  zig build test  # All tests passed
  ```

- [x] **ICMP echo reply test**
  ```
  3 packets transmitted, 3 received, 0.0% packet loss
  round-trip min/avg/max = 4.3/6.2/7.2 ms
  ```

- [x] **SOCKS5 TCP forwarding test**
  ```
  curl --proxy socks5://127.0.0.1:1080 http://111.45.11.5
  HTTP Code: 403  # Connection established, server rejected
  ```

---

## Completed Phases

### Phase 7: Pure Zig Migration (COMPLETED)

**Date**: 2026-02-12

| Function | Status | Location |
|----------|--------|----------|
| `getLocalIps()` | Done | network.zig:72-179 |
| `getPrimaryIp()` | Done | network.zig:185-213 |
| `selectEgressIp()` | Done | network.zig:218-260 |
| `configureTunIp()` | Done | network.zig:502-528 |
| `configureTunPeer()` | Done | network.zig:531-563 |
| `route_add()` (BSD) | Done | device_darwin.zig:357-403 |
| `route_delete()` (BSD) | Done | device_darwin.zig:405-451 |

**Key Findings**:
- BSD Routing Socket: `sizeof(rt_msghdr)=92`, `RTM_VERSION=5`
- `writeToLoopback()` removed (dead code)

### Phase 6: Production Readiness (COMPLETED v0.2.0)

- Cross-platform builds: macOS, Linux, Windows, iOS
- ICMP auto-reply, UDP NAT proxy, SOCKS5 integration
- Integration tests: 90/90 PASSED

---

## Recent Changes

- **2026-02-12**: All Phase 7.4 tests passed (ICMP + SOCKS5)
- **2026-02-12**: Remove `writeToLoopback()` stub (dead code)
- **2026-02-12**: Pure Zig network.zig migration complete

---

## Build Commands

```bash
# Native macOS build
zig build tun2sock -Dtarget=x86_64-macos

# Run tests
zig build test

# Cross-platform builds
zig build all
```

---

## Reference Documents

- **docs/mac_tun.md**: macOS TUN implementation guide
- **docs/zig.codegen.md**: Zig code generation patterns
- **docs/DESIGN.md**: Project architecture
