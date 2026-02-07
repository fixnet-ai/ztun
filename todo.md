# ztun Development Todo List

## Current Status

**Last Updated**: 2026-02-07

**Build Status**: All components compiling
- `zig build` - PASSED
- `zig build test-integration` - PASSED

---

## Active Tasks

| Task | Priority | Status | Notes |
|------|----------|--------|-------|
| stack_system.zig | Medium | Pending | TunStack interface implementation |
| Linux TUN testing | High | Pending | Lima VM testing |
| Windows TUN testing | High | Pending | Windows VM testing |

---

## Completed Tasks

| Task | Status | Date |
|------|--------|------|
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
| **Total** | **18** | ✅ All Pass |

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
