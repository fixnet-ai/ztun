# ztun Development Todo List

**Version**: 0.2.1
**Last Updated**: 2026-02-12

---

## Current Tasks

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
