//! ztun - Cross-platform TUN device library
//!
//! A synchronous, cross-platform TUN device library implemented in pure Zig.
//!
//! # Quick Start
//!
//! ```zig
//! const tun = @import("ztun");
//!
//! // Create a TUN device
//! var builder = tun.DeviceBuilder.init();
//! builder.setName("tun0");
//! builder.setMtu(1500);
//! builder.setIpv4(.{10, 0, 0, 1}, 24, null);
//!
//! var device = try builder.build();
//! defer device.destroy();
//!
//! // Send/receive packets
//! var buf: [1500]u8 = undefined;
//! const n = try device.recv(&buf);
//! ```
//!
//! # Supported Platforms
//!
//! - Linux (using /dev/net/tun)
//! - macOS (using utun sockets)
//! - BSD variants (future)

const tun = @import("tun.zig");

// Export public API
pub const DeviceBuilder = tun.DeviceBuilder;
pub const Device = tun.Device;
pub const TunError = tun.TunError;
