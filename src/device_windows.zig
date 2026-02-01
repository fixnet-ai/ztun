//! device_windows.zig - Windows TUN device implementation using wintun.dll
//!
//! Provides TUN device operations on Windows using the wintun driver.
//! Requires wintun.dll to be in the application directory.

const std = @import("std");
const TunError = @import("device.zig").TunError;
const DeviceConfig = @import("device.zig").DeviceConfig;
const Ipv4Address = @import("device.zig").Ipv4Address;
const Ipv6Address = @import("device.zig").Ipv6Address;
const DeviceContext = @import("device.zig").DeviceContext;

// ==================== Windows Types ====================

const BOOL = c_int;
const DWORD = u32;
const UINT = u32;
const HANDLE = *opaque {};
const LPCWSTR = [*:0]const u16;
const LPCSTR = [*:0]const u8;

// GUID structure
const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};

// WINTUN types
const WINTUN_ADAPTER_HANDLE = *opaque {};
const WINTUN_SESSION_HANDLE = *opaque {};
const WINTUN_RING_CAPACITY: u32 = 0x20_0000;

// ==================== Device State ====================

const WindowsDeviceState = struct {
    wintun_dll: HANDLE,
    adapter_handle: WINTUN_ADAPTER_HANDLE,
    session_handle: WINTUN_SESSION_HANDLE,
    read_event: HANDLE,
    name: []const u8,
    mtu: u16,
    index: u32,
    allocator: std.mem.Allocator,
};

// ==================== FFI Declarations ====================

extern "c" fn LoadLibraryW(lpFileName: LPCWSTR) callconv(.C) ?HANDLE;
extern "c" fn FreeLibrary(hModule: HANDLE) callconv(.C) BOOL;
extern "c" fn GetProcAddress(hModule: HANDLE, lpProcName: LPCSTR) callconv(.C) ?*anyopaque;

// Wintun function typedefs
const WINTUN_CREATE_ADAPTER_FUNC = *const fn (
    LPCWSTR,
    LPCSTR,
    ?*const GUID,
    DWORD,
) callconv(.C) WINTUN_ADAPTER_HANDLE;

const WINTUN_CLOSE_ADAPTER_FUNC = *const fn (WINTUN_ADAPTER_HANDLE) callconv(.C) void;
const WINTUN_GET_ADAPTER_INDEX_FUNC = *const fn (WINTUN_ADAPTER_HANDLE, *DWORD) callconv(.C) BOOL;
const WINTUN_SET_MTU_FUNC = *const fn (WINTUN_ADAPTER_HANDLE, DWORD) callconv(.C) BOOL;
const WINTUN_SET_IPV4_FUNC = *const fn (WINTUN_ADAPTER_HANDLE, DWORD, DWORD, DWORD) callconv(.C) BOOL;
const WINTUN_START_SESSION_FUNC = *const fn (WINTUN_ADAPTER_HANDLE, DWORD) callconv(.C) WINTUN_SESSION_HANDLE;
const WINTUN_STOP_SESSION_FUNC = *const fn (WINTUN_SESSION_HANDLE) callconv(.C) void;
const WINTUN_GET_READ_WAIT_EVENT_FUNC = *const fn (WINTUN_SESSION_HANDLE) callconv(.C) HANDLE;
const WINTUN_RECEIVE_PACKET_FUNC = *const fn (WINTUN_SESSION_HANDLE, *DWORD, *?*anyopaque) callconv(.C) ?*anyopaque;
const WINTUN_RELEASE_RECEIVE_PACKET_FUNC = *const fn (WINTUN_SESSION_HANDLE, *anyopaque) callconv(.C) void;
const WINTUN_ALLOCATE_SEND_PACKET_FUNC = *const fn (WINTUN_SESSION_HANDLE, DWORD) callconv(.C) ?*anyopaque;
const WINTUN_SEND_PACKET_FUNC = *const fn (WINTUN_SESSION_HANDLE, *anyopaque) callconv(.C) void;

// ==================== Helper Functions ====================

/// Convert ASCII string to UTF-16
fn toWideString(allocator: std.mem.Allocator, str: []const u8) ![]u16 {
    const wide_len = try std.unicode.utf8ToUtf16LeAllocLen(str);
    const wide = try allocator.alloc(u16, wide_len + 1);
    std.unicode.utf8ToUtf16Le(wide, str) catch unreachable;
    wide[wide_len] = 0;
    return wide;
}

/// Free wide string
fn freeWideString(allocator: std.mem.Allocator, wide: []u16) void {
    allocator.free(wide);
}

/// Load Wintun function pointer
fn loadWintunFunc(_: std.mem.Allocator, dll: HANDLE, name: [*:0]const u8, T: type) !T {
    const addr = GetProcAddress(dll, name) orelse {
        return error.NotFound;
    };
    return @as(T, @ptrCast(@alignCast(addr)));
}

// ==================== Device Creation ====================

/// Create a new TUN device on Windows
pub fn create(config: DeviceConfig) TunError!*DeviceContext {
    const allocator = std.heap.page_allocator;

    // Load wintun.dll
    const dll_name = toWideString(allocator, "wintun.dll") catch {
        return error.IoError;
    };
    defer freeWideString(allocator, dll_name);
    const dll = LoadLibraryW(dll_name.ptr) orelse {
        return error.IoError;
    };
    errdefer _ = FreeLibrary(dll);

    // Load Wintun functions
    const WintunCreateAdapter = loadWintunFunc(allocator, dll, "WintunCreateAdapter", WINTUN_CREATE_ADAPTER_FUNC) catch {
        return error.IoError;
    };
    const WintunCloseAdapter = loadWintunFunc(allocator, dll, "WintunCloseAdapter", WINTUN_CLOSE_ADAPTER_FUNC) catch {
        return error.IoError;
    };
    const WintunGetAdapterIndex = loadWintunFunc(allocator, dll, "WintunGetAdapterIndex", WINTUN_GET_ADAPTER_INDEX_FUNC) catch {
        return error.IoError;
    };
    const WintunSetMtu = loadWintunFunc(allocator, dll, "WintunSetMtu", WINTUN_SET_MTU_FUNC) catch {
        return error.IoError;
    };
    const WintunSetIpv4 = loadWintunFunc(allocator, dll, "WintunSetIpv4Address", WINTUN_SET_IPV4_FUNC) catch {
        return error.IoError;
    };
    const WintunStartSession = loadWintunFunc(allocator, dll, "WintunStartSession", WINTUN_START_SESSION_FUNC) catch {
        return error.IoError;
    };
    const WintunStopSession = loadWintunFunc(allocator, dll, "WintunStopSession", WINTUN_STOP_SESSION_FUNC) catch {
        return error.IoError;
    };
    const WintunGetReadWaitEvent = loadWintunFunc(allocator, dll, "WintunGetReadWaitEvent", WINTUN_GET_READ_WAIT_EVENT_FUNC) catch {
        return error.IoError;
    };
    const WintunReceivePacket = loadWintunFunc(allocator, dll, "WintunReceivePacket", WINTUN_RECEIVE_PACKET_FUNC) catch {
        return error.IoError;
    };
    const WintunReleaseReceivePacket = loadWintunFunc(allocator, dll, "WintunReleaseReceivePacket", WINTUN_RELEASE_RECEIVE_PACKET_FUNC) catch {
        return error.IoError;
    };
    const WintunAllocateSendPacket = loadWintunFunc(allocator, dll, "WintunAllocateSendPacket", WINTUN_ALLOCATE_SEND_PACKET_FUNC) catch {
        return error.IoError;
    };
    const WintunSendPacket = loadWintunFunc(allocator, dll, "WintunSendPacket", WINTUN_SEND_PACKET_FUNC) catch {
        return error.IoError;
    };
    _ = WintunGetReadWaitEvent; // unused, but loaded
    _ = WintunReceivePacket;
    _ = WintunReleaseReceivePacket;
    _ = WintunAllocateSendPacket;
    _ = WintunSendPacket;

    // Use default adapter name or custom
    const name_str = config.name orelse "ztun0";
    const adapter_name_wide = toWideString(allocator, name_str) catch {
        return error.IoError;
    };
    defer freeWideString(allocator, adapter_name_wide);

    const tunnel_type = "ztun";

    // Get MTU
    const mtu = config.mtu orelse 1500;

    // Convert IPv4 address to DWORD
    var ipv4_addr: DWORD = 0;
    var ipv4_prefix: DWORD = 24;
    var peer_addr: DWORD = 0;

    if (config.ipv4) |ipv4| {
        ipv4_prefix = ipv4.prefix;
        // Pack IPv4 address bytes into DWORD (network byte order)
        ipv4_addr = @as(DWORD, ipv4.address[0]) |
                    @as(DWORD, ipv4.address[1]) << 8 |
                    @as(DWORD, ipv4.address[2]) << 16 |
                    @as(DWORD, ipv4.address[3]) << 24;
        // Peer address is local + 1
        peer_addr = ipv4_addr + 1;
    }

    // Create Wintun adapter
    const adapter = WintunCreateAdapter(
        adapter_name_wide.ptr,
        tunnel_type,
        null, // Use default GUID
        WINTUN_RING_CAPACITY,
    );
    if (adapter == null) {
        return error.IoError;
    }

    // Start session
    const session = WintunStartSession(adapter, WINTUN_RING_CAPACITY);
    if (session == null) {
        WintunCloseAdapter(adapter);
        return error.IoError;
    }

    // Set MTU
    if (WintunSetMtu(adapter, mtu) == 0) {
        // MTU set failed, but continue
    }

    // Set IPv4 address
    if (config.ipv4) |_| {
        if (WintunSetIpv4(adapter, ipv4_addr, peer_addr, ipv4_prefix) == 0) {
            // IPv4 set failed, but continue
        }
    }

    // Get adapter index
    var index: DWORD = 0;
    if (WintunGetAdapterIndex(adapter, &index) == 0) {
        index = 0;
    }

    // Copy adapter name
    const name_copy = allocator.alloc(u8, name_str.len + 1) catch {
        WintunStopSession(session);
        WintunCloseAdapter(adapter);
        return error.IoError;
    };
    @memcpy(name_copy[0..name_str.len], name_str);
    name_copy[name_str.len] = 0;

    // Allocate context
    const ctx = allocator.create(DeviceContext) catch {
        allocator.free(name_copy);
        WintunStopSession(session);
        WintunCloseAdapter(adapter);
        return error.IoError;
    };

    // Allocate state
    const state = allocator.create(WindowsDeviceState) catch {
        allocator.destroy(ctx);
        allocator.free(name_copy);
        WintunStopSession(session);
        WintunCloseAdapter(adapter);
        return error.IoError;
    };

    state.* = .{
        .wintun_dll = dll,
        .adapter_handle = adapter,
        .session_handle = session,
        .read_event = null,
        .name = name_copy[0..name_str.len],
        .mtu = mtu,
        .index = index,
        .allocator = allocator,
    };

    ctx.* = .{ .ptr = state };

    return ctx;
}

// ==================== Device Operations ====================

/// Helper to cast device pointer to state
inline fn toState(device_ptr: *anyopaque) *WindowsDeviceState {
    return @as(*WindowsDeviceState, @alignCast(@ptrCast(device_ptr)));
}

/// Receive a packet from the TUN device
pub fn recv(device_ptr: *anyopaque, buf: []u8) TunError!usize {
    const state = toState(device_ptr);

    // Load functions from DLL
    const WintunReceivePacket = loadWintunFunc(
        state.allocator,
        state.wintun_dll,
        "WintunReceivePacket",
        WINTUN_RECEIVE_PACKET_FUNC,
    ) catch return error.IoError;
    const WintunReleaseReceivePacket = loadWintunFunc(
        state.allocator,
        state.wintun_dll,
        "WintunReleaseReceivePacket",
        WINTUN_RELEASE_RECEIVE_PACKET_FUNC,
    ) catch return error.IoError;

    var size: DWORD = 0;
    var packet: ?*anyopaque = undefined;

    const result = WintunReceivePacket(state.session_handle, &size, &packet);
    if (result == null) {
        return error.IoError;
    }

    const packet_size = @as(usize, @intCast(size));
    if (packet_size > buf.len) {
        WintunReleaseReceivePacket(state.session_handle, packet.?);
        return error.IoError;
    }

    @memcpy(buf[0..packet_size], @as([*]u8, @ptrCast(packet.?))[0..packet_size]);
    WintunReleaseReceivePacket(state.session_handle, packet.?);

    return packet_size;
}

/// Send a packet to the TUN device
pub fn send(device_ptr: *anyopaque, packet_buf: []const u8) TunError!usize {
    const state = toState(device_ptr);

    // Load functions from DLL
    const WintunAllocateSendPacket = loadWintunFunc(
        state.allocator,
        state.wintun_dll,
        "WintunAllocateSendPacket",
        WINTUN_ALLOCATE_SEND_PACKET_FUNC,
    ) catch return error.IoError;
    const WintunSendPacket = loadWintunFunc(
        state.allocator,
        state.wintun_dll,
        "WintunSendPacket",
        WINTUN_SEND_PACKET_FUNC,
    ) catch return error.IoError;

    const packet = WintunAllocateSendPacket(state.session_handle, @as(DWORD, @intCast(packet_buf.len)));
    if (packet == null) {
        return error.IoError;
    }

    @memcpy(@as([*]u8, @ptrCast(packet))[0..packet_buf.len], packet_buf);
    WintunSendPacket(state.session_handle, packet);

    return packet_buf.len;
}

/// Get the device name
pub fn getName(device_ptr: *anyopaque) TunError![]const u8 {
    const state = toState(device_ptr);
    return state.name;
}

/// Get the device MTU
pub fn getMtu(device_ptr: *anyopaque) TunError!u16 {
    const state = toState(device_ptr);
    return state.mtu;
}

/// Get the interface index
pub fn getIfIndex(device_ptr: *anyopaque) TunError!u32 {
    const state = toState(device_ptr);
    return state.index;
}

/// Set non-blocking mode (not applicable for Wintun)
pub fn setNonBlocking(_: *anyopaque, _: bool) TunError!void {}

/// Add an IPv4 address at runtime
pub fn addIpv4(_: *anyopaque, _: Ipv4Address, _: u8) TunError!void {
    return error.Unknown;
}

/// Add an IPv6 address at runtime
pub fn addIpv6(_: *anyopaque, _: Ipv6Address, _: u8) TunError!void {
    return error.Unknown;
}

/// Destroy the device and clean up resources
pub fn destroy(device_ptr: *anyopaque) void {
    const state = toState(device_ptr);
    const allocator = state.allocator;

    // Load functions from DLL
    const WintunStopSession = loadWintunFunc(
        allocator,
        state.wintun_dll,
        "WintunStopSession",
        WINTUN_STOP_SESSION_FUNC,
    ) catch return;
    const WintunCloseAdapter = loadWintunFunc(
        allocator,
        state.wintun_dll,
        "WintunCloseAdapter",
        WINTUN_CLOSE_ADAPTER_FUNC,
    ) catch return;

    // Stop session
    if (state.session_handle != null) {
        WintunStopSession(state.session_handle);
    }

    // Close adapter
    if (state.adapter_handle != null) {
        WintunCloseAdapter(state.adapter_handle);
    }

    // Free DLL
    if (state.wintun_dll != null) {
        _ = FreeLibrary(state.wintun_dll);
    }

    // Free name copy
    allocator.free(state.name);

    // Free state and context
    allocator.destroy(state);
    allocator.destroy(@as(*DeviceContext, @ptrCast(device_ptr)));
}
