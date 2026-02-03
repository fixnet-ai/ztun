//! test_ios.zig - Standalone iOS Simulator test
//! Uses only C library imports to avoid Zig runtime initialization issues

const std = @import("std");
const builtin = @import("builtin");

// C imports only - no Zig memory allocation
const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
});

pub fn main() !void {
    // Print banner
    _ = c.printf("=== ztun iOS Simulator Standalone Test ===\n");
    _ = c.printf("OS: %s, ABI: %s\n", @tagName(builtin.target.os.tag), @tagName(builtin.abi));
    _ = c.printf("ztun is a TUN library for desktop platforms.\n");
    _ = c.printf("iOS does not expose TUN/UTUN to applications.\n");

    // Simple malloc/free test
    const ptr = c.malloc(16);
    if (ptr != null) {
        _ = c.printf("malloc: OK\n");
        c.free(ptr);
        _ = c.printf("free: OK\n");
    } else {
        _ = c.printf("malloc: FAILED\n");
        return error.MallocFailed;
    }

    _ = c.printf("iOS Simulator build verification: PASSED\n");
}
