//! ringbuf.zig - Cross-platform Ring Buffer for TUN optimization
//!
//! Provides efficient ring buffer operations with automatic wrap-around handling.
//! Supports Windows (Wintun), Linux, and macOS.
//!
//! Key features:
//! - Linear memory access without boundary checks (virtual wrap-around)
//! - Batch processing support for high-throughput scenarios
//! - Cache-line aligned for optimal CPU cache behavior

const std = @import("std");
const builtin = @import("builtin");

// Platform-specific types
const windows = if (builtin.os.tag == .windows) std.os.windows else struct {};
const posix = if (builtin.os.tag != .windows) std.posix else struct {};

pub const RingBuffer = struct {
    ptr: [*]u8,      // Points to mapped memory
    capacity: usize, // Physical memory size (page-aligned)
    owned: bool,     // Whether we own the memory and should free it

    /// Create a ring buffer with the given capacity
    /// capacity: requested buffer size (will be page-aligned)
    pub fn init(capacity: usize) !RingBuffer {
        const page_size = std.mem.page_size;
        const aligned_capacity = std.mem.alignForward(usize, capacity, page_size);

        if (builtin.os.tag == .windows) {
            return initWindows(aligned_capacity);
        } else {
            return initPosix(aligned_capacity);
        }
    }

    /// Windows implementation using VirtualAlloc
    fn initWindows(capacity: usize) !RingBuffer {
        const win = windows;
        const kernel32 = win.kernel32;

        // Allocate committed memory
        const base_ptr = kernel32.VirtualAlloc(
            null,
            capacity,
            win.MEM_COMMIT | win.MEM_RESERVE,
            win.PAGE_READWRITE,
        ) orelse return error.AllocFailed;

        return .{
            .ptr = @as([*]u8, @ptrCast(base_ptr)),
            .capacity = capacity,
            .owned = true,
        };
    }

    /// POSIX implementation using mmap
    fn initPosix(capacity: usize) !RingBuffer {
        const mm = std.posix;

        // Use anonymous mapping
        const map_flags = std.c.MAP{ .ANONYMOUS = true, .TYPE = .PRIVATE, .FIXED = false };
        const addr = try mm.mmap(null, capacity, mm.PROT.READ | mm.PROT.WRITE, map_flags, -1, 0);

        return .{
            .ptr = @as([*]u8, @ptrCast(addr.ptr)),
            .capacity = capacity,
            .owned = true,
        };
    }

    /// Free resources
    pub fn deinit(self: *RingBuffer) void {
        if (!self.owned) return;

        if (builtin.os.tag == .windows) {
            const win = windows;
            const kernel32 = win.kernel32;
            _ = kernel32.VirtualFree(self.ptr, 0, win.MEM_RELEASE);
        } else {
            const aligned_ptr = @as([*]align(4096) u8, @alignCast(self.ptr));
            posix.munmap(aligned_ptr[0..self.capacity]);
        }

        self.* = undefined;
    }

    /// Get slices for writing at the given offset (may return 1 or 2 slices)
    pub fn getWriteSlices(self: *const RingBuffer, offset: usize, len: usize) struct { len: usize, slices: [2][]u8 } {
        const pos = offset % self.capacity;
        const remaining = self.capacity - pos;

        if (len <= remaining) {
            return .{ .len = 1, .slices = .{ self.ptr[pos .. pos + len], undefined } };
        } else {
            return .{ .len = 2, .slices = .{ self.ptr[pos..self.capacity], self.ptr[0 .. len - remaining] } };
        }
    }

    /// Get slices for reading at the given offset (may return 1 or 2 slices)
    pub fn getReadSlices(self: *const RingBuffer, offset: usize, len: usize) struct { len: usize, slices: [2][]const u8 } {
        const pos = offset % self.capacity;
        const remaining = self.capacity - pos;

        if (len <= remaining) {
            return .{ .len = 1, .slices = .{ self.ptr[pos .. pos + len], undefined } };
        } else {
            return .{ .len = 2, .slices = .{ self.ptr[pos..self.capacity], self.ptr[0 .. len - remaining] } };
        }
    }

    /// Copy data into the ring buffer (handles wrap-around automatically)
    pub fn write(self: *const RingBuffer, offset: usize, data: []const u8) void {
        const result = self.getWriteSlices(offset, data.len);
        var src_offset: usize = 0;
        for (0..result.len) |i| {
            const slice = result.slices[i];
            @memcpy(slice, data[src_offset..][0..slice.len]);
            src_offset += slice.len;
        }
    }

    /// Copy data from the ring buffer (handles wrap-around automatically)
    pub fn read(self: *const RingBuffer, offset: usize, buf: []u8) void {
        const result = self.getReadSlices(offset, buf.len);
        var dst_offset: usize = 0;
        for (0..result.len) |i| {
            const slice = result.slices[i];
            @memcpy(buf[dst_offset..][0..slice.len], slice);
            dst_offset += slice.len;
        }
    }

    /// Calculate how many bytes can be read before wrap-around at given offset
    pub fn availableBeforeWrap(self: *const RingBuffer, offset: usize) usize {
        return self.capacity - (offset % self.capacity);
    }
};

test "RingBuffer init and basic operations" {
    const page_size = std.mem.page_size;
    const capacity = page_size * 4;

    var rb = try RingBuffer.init(capacity);
    defer rb.deinit();

    // Test that capacity is page-aligned
    try std.testing.expectEqual(0, rb.capacity % page_size);

    // Write data at offset 0
    const test_data = "Hello, Ring Buffer!";
    rb.write(0, test_data);

    // Read back
    var read_buf: [100]u8 = undefined;
    rb.read(0, read_buf[0..test_data.len]);
    try std.testing.expectEqualStrings(test_data, read_buf[0..test_data.len]);

    // Test wrap-around write near end
    rb.write(rb.capacity - 10, test_data);
    rb.read(rb.capacity - 10, read_buf[0..test_data.len]);
    try std.testing.expectEqualStrings(test_data, read_buf[0..test_data.len]);

    // Test slices
    const slices = rb.getWriteSlices(rb.capacity - 5, 10);
    try std.testing.expectEqual(2, slices.len);
    try std.testing.expectEqual(5, slices.slices[0].len);
    try std.testing.expectEqual(5, slices.slices[1].len);
}
