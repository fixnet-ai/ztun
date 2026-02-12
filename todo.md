# ztun Development Todo List

**Version**: 0.2.7
**Last Updated**: 2026-02-13

---

## Current Tasks

### Phase 7.12: Cross-Platform Network Monitor Integration (PENDING)

**Date**: 2026-02-12

**Goal**: Fully integrate network change detection and handle network events

**Required Changes**:
- [ ] Implement egress interface reselection on network change
- [ ] Close and reconnect SOCKS5 connection on network change
- [ ] Reset NAT table on network change
- [ ] Handle RTM_IFINFO, RTM_NEWADDR, RTM_DELADDR events in router

---

### Phase 7.10: Graceful Shutdown (PENDING)

**Goal**: Implement graceful shutdown for all components

---

## Completed Phases

### Phase 9: ICMP Echo on macOS Fix (COMPLETED)

**Date**: 2026-02-13

**Goal**: Fix ICMP Echo Reply functionality on macOS

**Issues Fixed**:
1. **macOS utun header byte order**: Changed from big-endian to little-endian
   - Before: `00 00 00 02` (incorrect)
   - After: `02 00 00 00` (correct)

2. **Pointer alignment issues**: Changed from struct casting to direct byte-level access
   - `ipv4.zig`: `parseHeader()`, `buildHeader()`, `checksum()`
   - `tcp.zig`: `parseHeader()`, `buildHeader()`

3. **Data copy logic**: Fixed `writeToTunBuf` to always copy regardless of header_len

4. **ICMP checksum**: Fixed pseudo-header IP order (swap src/dst for reply)

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/mod.zig` | Fixed utun header byte order, data copy logic |
| `src/ipstack/ipv4.zig` | Byte-level access for header parsing/building |
| `src/ipstack/tcp.zig` | Byte-level access for header parsing/building |

**Verification**:
```
[TUN-CB] ICMP echo request detected, sending reply
[ICMP] Echo request received, sending reply
[TUN]   src=10.0.0.2 dst=10.0.0.1 proto=1
[ICMP] Reply sent successfully
```

**Git Commit**: `75be1de`

---

### Phase 8: Outbound Abstraction + ipstack Integration (COMPLETED)

**Date**: 2026-02-13

**Goal**: Refactor Router to use ipstack for protocol parsing and add Outbound abstraction layer

**Architecture**:
```
TUN → Router → Outbound (interface) → SOCKS5/Direct (impl) → ipstack (protocol)
```

**Files Created**:
| File | Description |
|------|-------------|
| `src/router/outbound.zig` | Outbound abstraction (SOCKS5 + Direct) |

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/mod.zig` | Use ipstack for protocol parsing |
| `build.zig` | Added router_outbound module |

---

### Phase 7.13: Network Monitor Bug Fixes (COMPLETED)

**Date**: 2026-02-13

**Issues Fixed**:
- Removed dead code: `handleNetworkChange()` referenced non-existent `network_listener` field
- Fixed event mapping: `address_removed` now pauses network instead of resuming
- Updated `onNetworkChangeCallback` to correctly handle all network events

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

**Files Created**:
| File | Description |
|------|-------------|
| `src/system/monitor.zig` | Main interface |
| `src/system/monitor_darwin.zig` | macOS implementation |
| `src/system/monitor_linux.zig` | Linux implementation |
| `src/system/monitor_windows.zig` | Windows implementation |

---

### Phase 7.9: Network Change Detection and Handling (COMPLETED)

**Date**: 2026-02-12

**Reference**: sing-box `route/network.go` architecture

**Result**: BSD Routing Socket listener and network change handlers implemented

---

### Phase 7.8: SOCKS5 TCP Handshake Fix (COMPLETED)

**Date**: 2026-02-12

**Result**: TCP three-way handshake through SOCKS5 proxy now works correctly

---

### Phase 7.7: TUN and Routing Bug Fixes (COMPLETED)

**Date**: 2026-02-12

**Result**: TUN routing configuration fixed for macOS utun interfaces

---

### Phase 7.6: SOCKS5 Client Refactoring (COMPLETED)

**Date**: 2026-02-12

**Result**: SOCKS5 client moved to standalone module `src/router/proxy/socks5.zig`

---

### Phase 7: Pure Zig Migration (COMPLETED)

**Date**: 2026-02-12

**Result**: All network functions migrated to pure Zig implementation

---

### Phase 6: Production Readiness (COMPLETED v0.2.0)

- Cross-platform builds: macOS, Linux, Windows, iOS
- ICMP auto-reply, UDP NAT proxy, SOCKS5 integration
- Integration tests: 90/90 PASSED

---

## Recent Changes

- **2026-02-13**: Phase 9 - ICMP Echo on macOS Fix (commit `75be1de`)
- **2026-02-13**: Phase 8 - Outbound Abstraction + ipstack Integration
- **2026-02-13**: Phase 7.13 - Network Monitor Bug Fixes

---

## Build Commands

```bash
# Native macOS build
zig build

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
