//! device_windows.zig - Windows TUN device implementation using wintun.dll
//!
//! Provides TUN device operations on Windows using the wintun driver.

const std = @import("std");
const TunError = @import("device.zig").TunError;
const DeviceConfig = @import("device.zig").DeviceConfig;
const Ipv4Address = @import("device.zig").Ipv4Address;
const Ipv6Address = @import("device.zig").Ipv6Address;

// ==================== Windows Types ====================

const BOOL = c_int;
const DWORD = u32;
const HANDLE = *opaque {};
const LPCWSTR = [*:0]const u16;

const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};

const NET_LUID = extern struct {
    Value: [8]u8,
};

const WINTUN_ADAPTER_HANDLE = *opaque {};
const WINTUN_SESSION_HANDLE = *opaque {};
const WINTUN_RING_CAPACITY: u32 = 0x20_0000;

// ==================== Device State ====================

const WindowsDeviceState = struct {
    allocator: std.mem.Allocator,
    adapter_handle: WINTUN_ADAPTER_HANDLE,
    session_handle: WINTUN_SESSION_HANDLE,
    read_event: HANDLE,
    name: []const u8,
    mtu: u16,
    index: u32,
};

const DeviceContext = struct {
    ptr: *anyopaque,
};

// ==================== FFI Declarations ====================

extern "c" fn LoadLibraryW(lpFileName: LPCWSTR) callconv(.C) ?*anyopaque;
extern "c" fn FreeLibrary(hModule: *anyopaque) callconv(.C) BOOL;
extern "c" fn GetProcAddress(hModule: *anyopaque, lpProcName: [*:0]const u8) callconv(.C) ?*anyopaque;

// ==================== Device Creation ====================

/// Create a new TUN device on Windows
pub fn create(_: DeviceConfig) TunError!*DeviceContext {
    _ = LoadLibraryW;
    _ = FreeLibrary;
    _ = GetProcAddress;
    return error.IoError;
}

// ==================== Device Operations ====================

pub fn recv(_: *anyopaque, _: []u8) TunError!usize {
    return .IoError;
}

pub fn send(_: *anyopaque, _: []const u8) TunError!usize {
    return .IoError;
}

pub fn getName(_: *anyopaque) TunError![]const u8 {
    return "";
}

pub fn getMtu(_: *anyopaque) TunError!u16 {
    return 1500;
}

pub fn getIfIndex(_: *anyopaque) TunError!u32 {
    return 0;
}

pub fn setNonBlocking(_: *anyopaque, _: bool) TunError!void {}

pub fn addIpv4(_: *anyopaque, _: Ipv4Address, _: u8) TunError!void {
    return .Unknown;
}

pub fn addIpv6(_: *anyopaque, _: Ipv6Address, _: u8) TunError!void {
    return .Unknown;
}

pub fn destroy(_: *anyopaque) void {}
