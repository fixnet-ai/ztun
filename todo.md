# ztun Development Todo List

## Current Status
**Phase: Router Core Implementation - Forwarding Handlers**

Last Updated: 2026-02-04

---

## Completed Modules

### tun Module (✅ Complete)
- [x] device_linux.zig - Linux TUN operations
- [x] device_macos.zig - macOS TUN operations
- [x] device_windows.zig - Windows TUN operations
- [x] ringbuf.zig - Ring buffer for batch I/O

### ipstack Module (✅ Complete)
- [x] checksum.zig - Internet checksum
- [x] ipv4.zig - IPv4 parsing/generation
- [x] ipv6.zig - IPv6 parsing/generation
- [x] tcp.zig - TCP protocol
- [x] udp.zig - UDP protocol
- [x] icmp.zig - ICMP protocol
- [x] connection.zig - TCP connection tracking
- [x] callbacks.zig - Protocol callbacks

### router Module (In Progress)

#### Phase 1: Foundation (✅ Complete)
- [x] route.zig - Route types and config structures
- [x] mod.zig - Router module entry
- [x] nat.zig - UDP NAT session table
- [x] proxy/socks5.zig - SOCKS5 protocol helpers

#### Phase 2: libxev Integration (✅ Complete)
- [x] libxev loop integration in mod.zig
- [x] TUN async read (libxev.IO)
- [x] TUN async write (libxev.IO)
- [x] NAT cleanup timer (30s interval)
- [x] ICMP echo handler
- [x] Packet parsing (4-tuple extraction)

#### Phase 3: Forwarding Handlers (In Progress)
- [ ] forwardToEgress() - Raw socket forwarding with SO_BINDTODEVICE
- [ ] forwardToProxy() - SOCKS5 proxy forwarding (TCP)
- [ ] forwardWithNat() - UDP NAT translation

#### Phase 4: TCP Connection Pool (Pending)
- [ ] tcp.zig - TCP connection pool
- [ ] Async TCP connect to proxy
- [ ] TCP data forwarding

---

## Application Layer

### tun2sock.zig (✅ Implemented)
- [x] Command line argument parsing
- [x] TUN device creation via DeviceBuilder
- [x] Egress interface detection
- [x] Route callback implementation
- [x] Router initialization and run loop
- [x] Statistics reporting

---

## File Reference

### Modified Files
- [src/router/mod.zig](src/router/mod.zig) - Router module (libxev integration complete)
- [src/router/route.zig](src/router/route.zig) - Route types
- [src/router/nat.zig](src/router/nat.zig) - NAT table (complete)
- [src/tun2sock.zig](src/tun2sock.zig) - TUN to SOCKS5 forwarding app

### New Files Created
- [src/router/tcp.zig](src/router/tcp.zig) - TCP connection pool (pending)

---

## Testing Strategy

### Unit Tests (tests/test_unit.zig)
- [x] NAT table operations
- [x] SOCKS5 protocol parsing
- [ ] TCP pool operations (pending)
- [ ] Route decision logic

### Integration Tests (tests/test_runner.zig)
- [x] TUN device tests
- [x] IP stack tests
- [ ] Router forwarding tests (pending)
- [ ] SOCKS5 proxy tests (pending)

### Manual Tests
- [ ] macOS TUN forwarding
- [ ] Linux TUN forwarding
- [ ] Android TUN forwarding
- [ ] iOS TUN forwarding

---

## Dependencies

### External
- libxev - Event loop (integrated)
- zinternal - App framework modules (app, platform, logger, signal, config, storage)

### Internal
- ztun.tun - TUN device operations
- ztun.ipstack - Packet parsing

---

## Build Verification

```bash
# Build native library
zig build              # ✅ Pass

# Build and run integration tests
zig build test         # ✅ Pass

# Build tun2sock application
zig build tun2sock     # ✅ Pass

# Build all platform static libraries
zig build all          # ⏳ (forwarding handlers pending)
```

---

## Next Steps

1. **Implement forwardToEgress()** - Raw socket with SO_BINDTODEVICE
   - Create raw socket
   - Bind to egress interface
   - Forward packet

2. **Implement forwardToProxy()** - SOCKS5 TCP forwarding
   - Connect to SOCKS5 proxy
   - Send connect request
   - Forward data bidirectionally

3. **Implement forwardWithNat()** - UDP NAT translation
   - Insert NAT session
   - Rewrite source IP/port
   - Forward to destination

4. **Implement tcp.zig** - TCP connection pool
   - Async TCP connection to proxy
   - Connection state machine
   - Data forwarding

5. **Test forwarding** - macOS TUN forwarding tests

---

## Notes

- Router is a FIXED forwarding engine - no plugin logic
- All config from application layer
- Uses libxev callbacks (not async/await)
- Egress traffic bypasses TUN (raw socket)
- ICMP echo handled immediately (ping response)
- NAT cleanup runs every 30 seconds
