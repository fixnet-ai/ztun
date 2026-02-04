# ztun Development Todo List

## Current Status
**Phase: Router Core Implementation**

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

#### Phase 2: libxev Integration (In Progress)
- [ ] libxev loop integration in mod.zig
- [ ] TUN async read (libxev.IO)
- [ ] TCP async connect/disconnect
- [ ] UDP async send/recv
- [ ] Timer for NAT session timeout

#### Phase 3: Router Core (Pending)
- [ ] TCP connection pool (src/router/tcp.zig)
- [ ] Route decision engine
- [ ] Packet forwarding logic
- [ ] Egress socket management

#### Phase 4: Proxy Backend (Pending)
- [ ] socks5.zig - Full SOCKS5 connection state machine
- [ ] http.zig - HTTP proxy backend (optional)

---

## Today's Tasks

### Priority 1: libxev Integration

#### 1.1 Update mod.zig with libxev Loop
```zig
// src/router/mod.zig additions needed:
const libxev = @import("libxev");

pub const Router = struct {
    loop: *libxev.Loop,
    tun_io: libxev.IO,
    tcp_io: libxev.IO,
    timer: libxev.Timer,
    // ... existing fields
};
```

#### 1.2 Implement TUN Async Read
```zig
// Add to mod.zig:
fn onTunReadable(self: *libxev.IO, revents: u32) void {
    // Read from TUN
    // Parse IP header
    // Make route decision
    // Forward packet
    // Resubmit read
}
```

#### 1.3 Add Timer for NAT Cleanup
```zig
// Add periodic timer callback:
fn onTimer(self: *libxev.Timer) void {
    // Cleanup expired NAT sessions
    // Resubmit timer
}
```

---

### Priority 2: TCP Connection Pool

#### 2.1 Create tcp.zig
```zig
// src/router/tcp.zig
pub const TcpConn = struct {
    fd: std.posix.fd_t,
    state: ConnState,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    // ...
};

pub const TcpPool = struct {
    connections: []TcpConn,
    // Pool management functions
};
```

---

## File Reference

### Modified Files
- [src/router/mod.zig](src/router/mod.zig) - Router module (needs libxev)
- [src/router/route.zig](src/router/route.zig) - Route types
- [src/router/nat.zig](src/router/nat.zig) - NAT table
- [src/router/proxy/socks5.zig](src/router/proxy/socks5.zig) - SOCKS5 helpers

### New Files Needed
- [src/router/tcp.zig](src/router/tcp.zig) - TCP connection pool
- [src/router/proxy/http.zig](src/router/proxy/http.zig) - HTTP proxy

---

## Testing Strategy

### Unit Tests (tests/test_unit.zig)
- [x] NAT table operations
- [x] SOCKS5 protocol parsing
- [ ] TCP pool operations
- [ ] Route decision logic

### Integration Tests (tests/test_runner.zig)
- [x] TUN device tests
- [x] IP stack tests
- [ ] Router forwarding tests
- [ ] SOCKS5 proxy tests

### Manual Tests
- [ ] macOS TUN forwarding
- [ ] Linux TUN forwarding
- [ ] Android TUN forwarding
- [ ] iOS TUN forwarding

---

## Dependencies

### External
- libxev - Event loop (add to build.zig.zon)

### Internal
- ztun.tun - TUN device operations
- ztun.ipstack - Packet parsing

---

## Build Verification

```bash
# Current status
zig build              # ✅ Pass
zig build test         # ✅ Pass
zig build all          # ⏳ (needs router completion)
```

---

## Next Steps

1. **Add libxev dependency** to build.zig.zon
2. **Update mod.zig** with libxev loop integration
3. **Implement onTunReadable** callback
4. **Create tcp.zig** with connection pool
5. **Implement forwardToEgress** with raw socket
6. **Implement forwardToProxy** for SOCKS5
7. **Add NAT timeout timer**
8. **Test on macOS** with real TUN device

---

## Notes

- Router is a FIXED forwarding engine - no plugin logic
- All config from application layer
- Uses libxev callbacks (not async/await)
- Egress traffic bypasses TUN (raw socket)
