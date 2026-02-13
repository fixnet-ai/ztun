# ztun Development Todo List

**Version**: 0.2.7
**Last Updated**: 2026-02-13

---

## Current Tasks

### Phase 12: Graceful Shutdown (IN PROGRESS)

**Date**: 2026-02-13

**Goal**: Forward UDP traffic through SOCKS5 UDP Associate, DNS queries work correctly

**Key Changes Implemented**:

1. **SOCKS5 UDP Associate Client**
   - Added `Socks5UdpAssociate` struct in socks5.zig
   - UDP socket creation and binding to SOCKS5 proxy
   - `sendDatagram()` - Send UDP datagram with SOCKS5 UDP header encapsulation
   - `associate()` - Establish UDP relay binding with proxy
   - Async read callback for receiving datagrams from proxy

2. **SOCKS5 UDP Header Format**
   ```
   RSV(2) + ATYP(1) + DST.ADDR + DST.PORT(2) + DATA
   ATYP: 0x01=IPv4, 0x03=Domain, 0x04=IPv6
   ```

3. **UDP Session Tracking**
   - Added `Socks5UdpSession` struct for tracking UDP flows
   - `upsertUdpSession()` - Create/update session on outgoing UDP
   - `findUdpSession()` - Lookup session for response routing
   - Session table with configurable size (`udp_nat_size`)

4. **Router Integration**
   - Added `udp_sessions: []Socks5UdpSession` table
   - Added `udp_associate: ?*Socks5UdpAssociate` client
   - Added `forwardUdpToSocks5()` - Route UDP+SOCKS5 decisions
   - Added `handleSocks5UdpResponse()` - Forward responses to TUN
   - Added `initUdpAssociate()` - Initialize UDP relay
   - Updated `forwardPacket()` to route UDP packets to `forwardUdpToSocks5()`

5. **UDP Response Handling**
   - Parse SOCKS5 UDP response header
   - Extract source IP/port from proxy response
   - Lookup original session by destination
   - Rebuild IP+UDP packet with original 4-tuple
   - Write response back to TUN

6. **Network Change Recovery**
   - Fixed `handleNetworkPause()` to work with pool architecture
   - Close all SOCKS5 connections and UDP associate on pause

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/proxy/socks5.zig` | Added `Socks5UdpAssociate`, `UdpAssociateState`, UDP callbacks |
| `src/router/mod.zig` | UDP session tracking, SOCKS5 UDP routing, response handling |
| `src/router/route.zig` | (no changes needed) |

**Architecture**:
```
TUN UDP Packet → forwardPacket()
  └─ route_cb returns .Socks5
     └─ forwardUdpToSocks5()
        ├─ Lookup/create UDP session
        └─ udp_associate.sendDatagram() → SOCKS5 proxy

SOCKS5 UDP Response → onSocks5UdpData()
  └─ handleSocks5UdpResponse()
     ├─ Parse SOCKS5 UDP header
     ├─ Find session by 4-tuple
     └─ writeToTunBuf() → TUN
```

**Status**: COMPLETED

**Key Features Implemented**:
- SOCKS5 UDP Associate client with async handshake
- UDP datagram encapsulation (RSV + ATYP + DST.ADDR + DST.PORT + DATA)
- UDP session tracking for response routing
- DNS query identification (port 53)
- DNS request tracking with transaction ID
- DNS timeout detection and statistics
- UDP session timeout cleanup (60s)
- Periodic cleanup via NAT timer

---

### Phase 12: Graceful Shutdown (IN PROGRESS)

---

### Phase 12: Graceful Shutdown (IN PROGRESS)

**Goal**: Implement graceful shutdown for all components

**Required Changes**:
- [x] Signal handler (SIGINT/SIGTERM)
- [x] Stop libxev event loop gracefully
- [x] Send FIN to all TCP connections
- [x] Cleanup UDP NAT sessions
- [x] Close SOCKS5 connections
- [x] Destroy TUN device (via defer in main)
- [ ] Restore routing table

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

## Completed Phases

### Phase 10: TCP Full-Duplex Data Forwarding (COMPLETED)

**Date**: 2026-02-13

**Goal**: Ensure TCP traffic through SOCKS5 proxy works end-to-end with bidirectional data transfer

**Key Changes Implemented**:

1. **TCP Connection Pool Architecture**
   - Added `TcpConnEntry` struct for tracking active TCP connections by 4-tuple
   - Added `PendingTcpConn` struct for tracking connections during SOCKS5 handshake
   - Pool sizes configurable via `RouterConfig.tcp_pool_size`

2. **Replaced Single Connection with Pool**
   - Changed `socks5_conn: ?*Socks5Conn` → `socks5_pool: []*Socks5Conn`
   - Added `tcp_conn_pool: []TcpConnEntry` for connection state tracking
   - Added `pending_tcp_pool: []PendingTcpConn` for pending connections

3. **Async Connection Initiation**
   - Added `connectAsync()` method in socks5.zig for non-blocking SOCKS5 connect
   - Removed blocking `connectBlocking()` from critical path
   - Connection state transitions via libxev callbacks

4. **Connection State Machine Integration**
   - Using `connection.zig` state machine for TCP state tracking
   - Added `tcp_state: connection.State` to TcpConnEntry

5. **Callback Updates**
   - Updated callback signatures to include `client: *Socks5Client` parameter
   - `onSocks5Data()`, `onSocks5TunnelReady()`, `onSocks5Ready()`, `onSocks5Error()`
   - Callbacks can access 4-tuple via client fields

6. **New Router Methods**
   - `lookupTcpConnection()` - Find existing connection by 4-tuple
   - `findOrCreatePending()` - Get/create pending connection slot
   - `initiateSocks5Tunnel()` - Start async SOCKS5 connection
   - `registerTcpConnection()` - Register established connection
   - `removeTcpConnection()` - Clean up closed connection
   - `getPendingConnection()` / `clearPendingConnection()` - Pending management

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/mod.zig` | TCP connection pool, async connect, connection state integration |
| `src/router/proxy/socks5.zig` | Async connect, client 4-tuple fields, updated callbacks |

**Architecture**:
```
TUN Packet → forwardToProxy()
  ├─ lookupTcpConnection() - Check existing connection
  ├─ initiateSocks5Tunnel() - New async SOCKS5 connect
  │   └─ connectAsync() → libxev → onSocks5TunnelReady()
  │       └─ registerTcpConnection() → tcp_conn_pool
  └─ forwardTcpData() - Send data through established connection

Proxy Response → onSocks5Data()
  └─ Lookup by client.dst_ip:client.dst_port
     └─ writeToTunBuf() - Forward to TUN
```

---

### Phase 11: UDP over SOCKS5 + DNS Basic Handling (COMPLETED)

**Date**: 2026-02-13

**Goal**: Forward UDP traffic through SOCKS5 UDP Associate, DNS queries work correctly

**Key Changes Implemented**:

1. **SOCKS5 UDP Associate Client**
   - Added `Socks5UdpAssociate` struct with async handshake
   - Implemented `associateAsync()` for UDP ASSOCIATE request/reply
   - Added `onUdpAssociateReply()` callback for proxy response handling
   - Implemented `sendDatagram()` with SOCKS5 UDP header encapsulation

2. **UDP Session Tracking**
   - Added `Socks5UdpSession` struct for tracking UDP flows by 4-tuple
   - Implemented `upsertUdpSession()` and `findUdpSession()` methods
   - Added session timeout cleanup (60 seconds)

3. **DNS Support**
   - Added `isDnsQuery()` for DNS query identification (port 53)
   - Added `DnsRequest` struct for tracking DNS transactions
   - Implemented `extractDnsTxId()`, `trackDnsRequest()`, `checkDnsResponse()`
   - Added DNS statistics (queries, responses, timeouts)

4. **Router Integration**
   - Added `forwardUdpToSocks5()` for routing UDP+SOCKS5 decisions
   - Added `handleSocks5UdpResponse()` for response handling
   - Integrated DNS tracking into UDP forwarding path

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/proxy/socks5.zig` | Added `Socks5UdpAssociate`, `UdpAssociateState`, UDP callbacks, handshake |
| `src/router/mod.zig` | UDP session tracking, DNS tracking, SOCKS5 UDP routing |

---

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

- **2026-02-13**: Phase 11 - UDP over SOCKS5 + DNS (UDP Associate implementation)
- **2026-02-13**: Phase 10 - TCP Full-Duplex Data Forwarding (connection pool architecture)
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
