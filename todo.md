# ztun Development Todo List

**Version**: 0.2.7
**Last Updated**: 2026-02-13

---

## Current Tasks

### Phase 20: Log System (PENDING)

**Goal**: Production-grade logging with levels and structured output

---

## Completed Phases

### Phase 19: Connection Pool Optimization (COMPLETED)

**Date**: 2026-02-13

**Goal**: TCP connection pooling for SOCKS5 proxy with performance optimizations

**Key Changes Implemented**:

1. **Connection Pool Statistics**
   - Added `PoolStats` struct for tracking pool metrics
   - Added `tcp_connections_active`, `pool_connections`, `pool_hits`, `pool_misses`
   - Added `buffers_allocated`, `buffers_reused`, `buffers_freed` for buffer pooling
   - Added `keepalive_sent` and `keepalive_timeout` for Keep-Alive tracking

2. **Buffer Pooling**
   - Added `buffer_pool` field for pre-allocated buffers
   - Implemented `acquireBuffer()` and `releaseBuffer()` methods
   - Configurable pool size and buffer size via `RouterConfig`
   - Reduces memory allocation overhead

3. **Connection Warmup**
   - Added `warmupPoolConnections()` for pre-establishing SOCKS5 connections
   - Configurable warmup size via `pool_warmup_size`
   - Faster first request latency

4. **Keep-Alive Support**
   - Added `keepalive_timer` completion for periodic probes
   - Added `startKeepaliveTimer()` and `sendKeepaliveProbes()` methods
   - Configurable interval via `keepalive_interval`
   - Added `cleanupTimedOutConnections()` for idle connection removal

5. **Router Configuration Updates**
   - Added `pool_warmup_size` (default: 4)
   - Added `keepalive_interval` (default: 75 seconds)
   - Added `enable_buffer_pooling` (default: true)
   - Added `buffer_pool_size` (default: 32)
   - Added `buffer_size` (default: 4096)

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/mod.zig` | Added PoolStats, buffer pool, warmup, Keep-Alive methods |
| `RouterConfig` | Added pool optimization configuration options |

---

### Phase 18: IPv6 Support (COMPLETED)

**Date**: 2026-02-13

**Goal**: IPv6 packet parsing and ICMPv6 echo reply support

**Key Changes Implemented**:

1. **ICMPv6 Module** (`src/ipstack/icmpv6.zig`)
   - Created `Icmpv6Header`, `Icmpv6Echo`, `Icmpv6PacketTooBig`, etc.
   - Implemented `buildEchoReply()` and `buildEchoRequest()` with checksum
   - ICMPv6 checksum using pseudo-header (src_ip + dst_ip + length + next_header)
   - Type constants: ECHO_REQUEST=128, ECHO_REPLY=129, etc.

2. **IPv6 Packet Processing**
   - Added `processIpv6Packet()` in ipstack/mod.zig
   - Added `processIpv6UdpPacket()` for UDP over IPv6
   - Added `processIcmpv6Packet()` for ICMPv6 handling
   - Added `buildIcmpv6EchoReply()` and `ipv6UdpSend()` helpers

3. **Router Integration**
   - Added macOS UTUN header detection for IPv6 (AF_INET6=24 at byte 3)
   - Added `onIpv6PacketReceived()` placeholder for IPv6 packet handling
   - Added `fmtIpv6()` helper for IPv6 address formatting

4. **Callbacks Extension**
   - Added `OnIpv6Udp`, `OnIcmpv6`, `OnIcmpv6Echo` callback types
   - Added `invokeIpv6Udp()`, `invokeIcmpv6()`, `invokeIcmpv6Echo()` helpers
   - Updated `Callbacks` struct with new IPv6 callback fields

5. **Statistics**
   - Added `icmpv6_packets` and `ipv6_packets` counters to Statistics

**Files Created**:
| File | Description |
|------|-------------|
| `src/ipstack/icmpv6.zig` | ICMPv6 protocol utilities |

**Files Modified**:
| File | Changes |
|------|---------|
| `src/ipstack/mod.zig` | Added IPv6 packet processing functions |
| `src/ipstack/callbacks.zig` | Added IPv6 callbacks (OnIpv6Udp, OnIcmpv6, OnIcmpv6Echo) |
| `src/router/mod.zig` | Added UTUN IPv6 detection, IPv6 packet handler |
| `build.zig` | Added `ipstack_icmpv6` module |

---

### Phase 17: Rule Engine + Domain Matching (COMPLETED)

**Goal**: Domain and IP-based traffic routing rules

**Key Changes**:

1. **Rule Engine** (`src/rules.zig`)
   - `RuleSet` with priority-based rule evaluation
   - `RuleType`: ip_cidr, domain_suffix, domain_exact, domain_keyword
   - `RuleAction`: direct, proxy, block, dns

2. **Matching**
   - CIDR range matching for IPs
   - Domain suffix matching (e.g., "example.com" matches "sub.example.com")
   - Domain exact matching
   - Domain keyword matching

3. **GeoIP Support**
   - `GeoIpDb` structure for country-based routing
   - Placeholder for MaxMind DB integration

**Files Modified**:
| File | Changes |
|------|---------|
| `src/rules.zig` | New rule engine with domain/IP matching |

---

### Phase 16: Fake-IP + DNS Interception (COMPLETED)

**Goal**: Implement Fake-IP mode for DNS-based routing

**Key Changes**:

1. **DNS Module** (`src/dns.zig`)
   - `DnsModule` struct with Fake-IP pool management
   - `getFakeIp()` - allocate Fake-IP for domain
   - `lookupByIp()` - find domain by Fake-IP
   - `parseQuery()` - parse DNS query domain name
   - `buildResponse()` - build Fake-IP DNS response

2. **Fake-IP Range**
   - 198.18.0.0/15 (198.18.0.0 - 198.19.255.255)
   - Pool size configurable (default 8192 entries)
   - Thread-safe allocation

3. **DNS Features**
   - DNS query parsing with name compression support
   - Standard DNS response building
   - TTL support (default 300 seconds)

**Files Modified**:
| File | Changes |
|------|---------|
| `src/dns.zig` | New DNS module with Fake-IP support |

---

### Phase 15: JSON Configuration Support (COMPLETED)

**Goal**: Support JSON configuration file

**Key Changes**:

1. **Config Module** (`src/config.zig`)
   - `Config` struct for full configuration
   - `TunConfig`, `OutboundConfig`, `RouteConfig`, `DnsConfig`
   - JSON parsing with `parse()` function
   - Support for all major configuration sections

**Files Modified**:
| File | Changes |
|------|---------|
| `src/config.zig` | New JSON configuration parser |

---

### Phase 14: HTTP Proxy Support (COMPLETED)

**Goal**: Support HTTP CONNECT proxy as outbound

**Key Changes**:

1. **HTTP CONNECT Client** (`src/router/proxy/http.zig`)
   - `HttpClient` struct with async connect
   - HTTP CONNECT request/reply handling
   - `send()` and `recv()` for tunnel data
   - Support for 407 Proxy Authentication Required

2. **Outbound Integration** (`src/router/outbound.zig`)
   - Added `OutboundType.http` enum
   - Added `HttpOutbound` context
   - `httpConnect()`, `httpSend()`, `httpDestroy()`
   - `OutboundConfig.http_addr` field

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/proxy/http.zig` | New HTTP CONNECT client implementation |
| `src/router/outbound.zig` | Added HTTP outbound type and integration |

---

### Phase 13: Network Monitor Integration (COMPLETED)

**Goal**: Handle network changes automatically

**Key Features**:
- `handleNetworkPause()` - cleanup SOCKS5/UDP associate on network loss
- `handleNetworkResume()` - reselect egress interface
- `handleRoutesChanged()` - handle route updates
- `reselectEgressInterface()` - recreate raw socket

**Status**: Basic implementation complete. Connections will reconnect on new packets.

---

### Phase 12: Graceful Shutdown (COMPLETED)

**Goal**: Implement graceful shutdown for all components

**Key Features**:
- Signal handler for SIGINT/SIGTERM
- `stop()` method with graceful TCP FIN sending
- `RouterState.stopping` state for shutdown tracking
- Signal handler wired to global router pointer

**Files Modified**:
| File | Changes |
|------|---------|
| `src/router/mod.zig` | Added `stop()`, `sendFin()`, `RouterState.stopping` |
| `src/tun2socks.zig` | Added signal handler, global router pointer |

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

5. **New Router Methods**
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
