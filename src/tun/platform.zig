//! platform.zig - Platform abstraction layer
//!
//! Re-exports platform-specific implementations based on the current OS.

pub usingnamespace switch (@import("builtin").os.tag) {
    .linux => @import("device_linux.zig"),
    .macos => @import("device_macos.zig"),
    .windows => @import("device_windows.zig"),
    else => struct {},
};
