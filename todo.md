# ztun Development Todo List

## Current Status

**Last Updated**: 2026-02-07

**Build Status**: All components compiling
- `zig build` - PASSED
- `zig build test-stack` - PASSED
- `zig build test-integration` - PASSED

---

## Linux TUN Testing Plan

### Test Strategy
**Approach**: Cross-compile on macOS → Run in Lima Linux VM

### Build Commands (macOS)

```bash
# Build SystemStack test for Linux x86_64
zig build test-stack -Dtarget=x86_64-linux-gnu

# Build integration test for Linux x86_64
zig build test -Dtarget=x86_64-linux-gnu

# Build test_runner for Linux x86_64
zig build test -Dtarget=x86_64-linux-gnu

# Build tun2sock for Linux x86_64
zig build tun2sock -Dtarget=x86_64-linux-gnu
```

### Lima VM Commands

```bash
# Start Lima VM
.lima/lima-start.sh

# Run tests directly (macOS directory is auto-mounted to Lima VM)
# Note: Lima auto-mounts macOS home directory to /Users/<username> in VM
.lima/lima-exec.sh sudo /Users/modasi/works/2025/fixnet/ztun/zig-out/bin/x86_64-linux-gnu/test_stack_core
.lima/lima-exec.sh sudo /Users/modasi/works/2025/fixnet/ztun/zig-out/bin/x86_64-linux-gnu/test_runner

# Or enter shell and run
.lima/lima-shell.sh
cd /Users/modasi/works/2025/fixnet/ztun
sudo ./zig-out/bin/x86_64-linux-gnu/test_stack_core
sudo ./zig-out/bin/x86_64-linux-gnu/test_runner
```

### Test Scenarios

| # | Test | Description | Expected Result |
|---|------|-------------|-----------------|
| 1 | TUN Device Creation | Create `/dev/net/tun` interface | Device created successfully |
| 2 | IPv4 Configuration | Set local IP 10.0.0.1/24 | IP configured correctly |
| 3 | Packet Send | Send ICMP/UDP/TCP packets | Packets sent without error |
| 4 | Packet Receive | Receive packets from TUN | Packets received correctly |
| 5 | SystemStack Process | Process packets through stack | Protocol callbacks invoked |
| 6 | Statistics | Verify packet counters | Counters increment correctly |

### Key Differences (Linux vs macOS)

| Aspect | macOS | Linux |
|--------|-------|-------|
| Device | `utunX` (BSD) | `/dev/net/tun` |
| Header | 4-byte AF_INET header | No header (raw IP) |
| API | `ioctl()` with `SIOC*` | `ioctl()` with `TUNSET*` |
| Permissions | `com.apple.net.utun` entitlement | `CAP_NET_ADMIN` capability |

### Debug Commands (Lima VM)

```bash
# Check TUN device
ls -la /dev/net/tun

# View interface
ip addr show tun0
ip link show tun0

# Capture traffic
tcpdump -i tun0 -w /tmp/tun_capture.pcap

# Trace system calls
strace -f -e trace=openat,ioctl ./test_stack_core
```

### Verification Checklist

- [ ] `/dev/net/tun` exists and is readable
- [ ] TUN device created without error
- [ ] IPv4 address configured (10.0.0.1)
- [ ] Packet send succeeds (ICMP/UDP/TCP)
- [ ] Packet receive succeeds (if loopback works)
- [ ] SystemStack processes packets
- [ ] No memory leaks detected
- [ ] All tests pass

---

## Active Tasks

| Task | Priority | Status | Notes |
|------|----------|--------|-------|
| Linux TUN testing | High | Pending | Lima VM testing |
| Windows TUN testing | High | Pending | Windows VM testing |

---

## Completed Tasks

| Task | Status | Date |
|------|--------|------|
| stack_core.zig (renamed from stack_system.zig) | ✅ Complete | 2026-02-07 |
| tun_stack.zig (renamed from stack.zig) | ✅ Complete | 2026-02-07 |
| Zig 0.13.0 compatibility fixes | ✅ Complete | 2026-02-07 |
| test_stack_system.zig | ✅ Complete | 2026-02-07 |
| TCP forwarding tests | ✅ Complete | 2026-02-07 |
| UDP NAT tests | ✅ Complete | 2026-02-07 |
| SOCKS5 proxy tests | ✅ Complete | 2026-02-07 |
| test_integration.zig | ✅ Complete | 2026-02-07 |
| IPv6 /128 peer handling | ✅ Complete | 2026-02-07 |
| IP address configuration | ✅ Complete | 2026-02-07 |

---

## Test Coverage

| Category | Tests | Status |
|----------|-------|--------|
| TCP Forwarding | 5 | ✅ Pass |
| UDP NAT | 4 | ✅ Pass |
| SOCKS5 Proxy | 7 | ✅ Pass |
| Route Decision | 2 | ✅ Pass |
| SystemStack | 1 | ✅ Pass |
| **Total** | **19** | ✅ All Pass |

---

## Build Commands

```bash
# Default build
zig build

# Run integration tests
zig build test-integration
sudo ./zig-out/bin/macos/test_integration

# Build forwarding test
zig build test-forwarding
sudo ./zig-out/bin/macos/test_forwarding

# Build TUN test
zig build test-tun
sudo ./zig-out/bin/macos/test_tun

# Build SystemStack test
zig build test-stack
sudo ./zig-out/bin/macos/test_stack_system
```

---

## Reference Documentation

| Document | Purpose |
|----------|---------|
| `DESIGN.md` | System architecture |
| `zig.codegen.md` | Zig code generation & debugging |
| `build_tools/README.md` | Build system |
| `docs/test-framework.md` | Testing standards |

---

## Notes

- All development experience documented in `zig.codegen.md`
- Testing and debugging guide in `zig.codegen.md`
- BSD routing issues resolved with workaround (see `zig.codegen.md`)
