# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5] - 2026-02-12

### Added

- **Cross-Platform Network Monitor** (`src/system/monitor.zig`)
  - BSD Routing Socket implementation for macOS
  - rtnetlink implementation for Linux
  - NotifyAddrChange implementation for Windows
  - Observer pattern for network change callbacks
  - Router integration for network change detection

### Changed

- Network change detection now uses centralized monitor API
- Router removed BSD Routing Socket code (replaced with monitor)

### Fixed

- Compilation errors with packed struct containing extern struct
- xev module not available in nested imports
- socket() error union handling
- F_GETFL/F_SETFL/O_NONBLOCK constants not available in std.posix

## [0.2.0] - 2026-02-08

### Added

- Cross-platform support: macOS, Linux, Windows, iOS
- Transparent proxy routing with route filtering
- ICMP auto-reply for ping support
- UDP NAT proxy for DNS and other UDP traffic
- SOCKS5 proxy integration for TCP forwarding

### Fixed

- network.c loopback check (removed incorrect ntohl())
- device_linux.zig double byte order conversion
- device_darwin.zig peer address overflow
- device_darwin.zig struct assignment safety
- macOS utun 4-byte header stripping
- iOS cross-platform compilation support

### Changed

- Version bump to 0.2.0

### Testing

- Integration tests: 90/90 PASSED
- Forwarding tests: 30/30 PASSED
- TUN tests: 3/3 SUCCESS
- No memory leaks detected

## [0.1.0] - 2026-01-XX

### Added

- Initial release
- TUN device abstraction for macOS/Linux/Windows
- Basic IP packet handling
