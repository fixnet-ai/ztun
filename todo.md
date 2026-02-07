# ztun Development Todo List

**Version**: 0.1.4
**Last Updated**: 2026-02-08

---

## Release v0.1.4 - Cross-Platform Testing

**Date**: 2026-02-08

### Changes
- Fixed cross-compilation output paths for Linux/Windows targets
- Fixed Windows deployment script to recognize `windows/` directory
- Updated Lima VM and Windows VM testing workflows
- All tests passing on Linux x86_64 (Lima VM) and Windows x86_64

### Test Results

| Platform | Target | Test | Result |
|----------|--------|------|--------|
| macOS | Native | ztun_test_runner | 16/16 PASSED |
| Linux x86_64 | Lima VM | test_stack_core | PASSED |
| Linux x86_64 | Lima VM | ztun_test_runner | 16/16 PASSED |
| Windows x86_64 | VM | ztun_test_runner | 16/16 PASSED |

---

## Build Commands

```bash
# Native (macOS)
zig build              # Build + run unit tests
zig build test         # Build test_runner to bin/macos/

# Cross-compile to Linux
zig build test -Dtarget=x86_64-linux-gnu

# Cross-compile to Windows
zig build test -Dtarget=x86_64-windows-gnu

# Other test binaries
zig build test-stack       # test_stack_core
zig build test-tun         # test_tun
zig build test-forwarding  # test_forwarding
zig build test-integration # test_integration
```

## VM Testing

### Linux (Lima VM)

```bash
# Start VM
.lima/lima-start.sh

# Run tests (macOS dir auto-mounted)
.lima/lima-exec.sh sudo /Users/modasi/works/2025/fixnet/ztun/zig-out/bin/linux-gnu/ztun_test_runner
.lima/lima-exec.sh sudo /Users/modasi/works/2025/fixnet/ztun/zig-out/bin/linux-gnu/test_stack_core
```

### Windows VM

```bash
# Deploy
.windows/windows-deploy.sh

# Run
.windows/windows-exec.sh ztun_test_runner
```

---

## Project Structure

```
ztun/
├── src/
│   ├── main.zig              # Library entry point
│   ├── tun2sock.zig          # TUN to SOCKS5 forwarding app
│   ├── tun/                  # TUN device module
│   │   ├── mod.zig          # Main module
│   │   ├── device.zig       # TunDevice/DeviceOps interfaces
│   │   ├── device_linux.zig # Linux implementation
│   │   ├── device_darwin.zig # macOS/iOS implementation
│   │   ├── device_windows.zig # Windows implementation
│   │   ├── device_ios.zig   # iOS PacketFlow wrapper
│   │   ├── options.zig     # TUN configuration
│   │   ├── tun_stack.zig    # TunStack interface
│   │   └── handler.zig      # PacketHandler interface
│   ├── router/               # Forwarding engine
│   │   ├── mod.zig          # Router with libxev
│   │   ├── route.zig        # Route types
│   │   ├── nat.zig          # UDP NAT table
│   │   └── proxy/socks5.zig # SOCKS5 protocol
│   ├── ipstack/              # IP protocol stack
│   │   ├── mod.zig          # IP stack entry
│   │   ├── checksum.zig     # Internet checksum
│   │   ├── ipv4.zig         # IPv4 parsing/building
│   │   ├── ipv6.zig         # IPv6 parsing/building
│   │   ├── tcp.zig          # TCP protocol
│   │   ├── udp.zig          # UDP protocol
│   │   ├── icmp.zig         # ICMP protocol
│   │   ├── connection.zig   # TCP connection state
│   │   ├── callbacks.zig     # Protocol callbacks
│   │   └── stack_core.zig   # SystemStack test
│   └── system/              # System utilities
│       ├── sysroute.zig     # Routing table
│       └── network.zig      # Network interfaces
├── tests/
│   ├── test_framework.zig    # Shared test framework
│   ├── test_unit.zig         # Unit tests
│   ├── test_runner.zig       # Integration tests
│   ├── test_tun.zig          # Ping echo test
│   ├── test_stack_core.zig   # SystemStack test
│   ├── test_forwarding.zig    # TCP/UDP/SOCKS5 test
│   └── test_integration.zig   # Full integration test
├── build.zig                 # Build script
├── build.zig.zon            # Build dependencies
├── CLAUDE.md                # Project rules
├── README.md                # Quick start guide
├── DESIGN.md                # Architecture docs
└── todo.md                  # This file
```
