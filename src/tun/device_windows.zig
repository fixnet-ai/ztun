//! device_windows.zig - Windows TUN device implementation using wintun.dll
//!
//! Provides TUN device operations on Windows using the wintun driver.
//! Requires wintun.dll to be in the application directory.
//! Uses RingBuffer internally for efficient batch packet handling.

const std = @import("std");
const builtin = @import("builtin");
const TunError = @import("device.zig").TunError;
const DeviceConfig = @import("device.zig").DeviceConfig;
const Ipv4Address = @import("device.zig").Ipv4Address;
const Ipv6Address = @import("device.zig").Ipv6Address;
const DeviceContext = @import("device.zig").DeviceContext;
const RingBuffer = @import("ringbuf.zig").RingBuffer;

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
const WINTUN_ADAPTER_HANDLE = ?*opaque {};
const WINTUN_SESSION_HANDLE = ?*opaque {};
const WINTUN_RING_CAPACITY: u32 = 0x20_0000;

// ==================== Device State ====================

const WindowsDeviceState = struct {
    wintun_dll: HANDLE,
    adapter_handle: WINTUN_ADAPTER_HANDLE,
    session_handle: WINTUN_SESSION_HANDLE,
    name_ptr: [*]u8,  // Full allocation for proper deallocation
    mtu: u16,
    index: u32,
    ringbuf: RingBuffer,
    read_offset: usize,
};

// ==================== FFI Declarations ====================

extern "c" fn LoadLibraryW(lpFileName: LPCWSTR) callconv(.C) ?HANDLE;
extern "c" fn FreeLibrary(hModule: HANDLE) callconv(.C) BOOL;
extern "c" fn GetProcAddress(hModule: HANDLE, lpProcName: LPCSTR) callconv(.C) ?*anyopaque;
extern "c" fn GetLastError() callconv(.C) DWORD;

// Windows synchronization APIs for blocking wait
extern "c" fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) callconv(.C) DWORD;
extern "c" fn ResetEvent(hEvent: HANDLE) callconv(.C) BOOL;

// Wintun function typedefs
const WINTUN_CREATE_ADAPTER_FUNC = *const fn (
    LPCWSTR,
    LPCWSTR,
    ?*const GUID,
) callconv(.C) WINTUN_ADAPTER_HANDLE;

const WINTUN_OPEN_ADAPTER_FUNC = *const fn (LPCWSTR) callconv(.C) WINTUN_ADAPTER_HANDLE;

const WINTUN_CLOSE_ADAPTER_FUNC = *const fn (WINTUN_ADAPTER_HANDLE) callconv(.C) void;
const WINTUN_START_SESSION_FUNC = *const fn (WINTUN_ADAPTER_HANDLE, DWORD) callconv(.C) WINTUN_SESSION_HANDLE;
const WINTUN_END_SESSION_FUNC = *const fn (WINTUN_SESSION_HANDLE) callconv(.C) void;
const WINTUN_GET_READ_WAIT_EVENT_FUNC = *const fn (WINTUN_SESSION_HANDLE) callconv(.C) HANDLE;
const WINTUN_RECEIVE_PACKET_FUNC = *const fn (WINTUN_SESSION_HANDLE, *DWORD) callconv(.C) ?*anyopaque;
const WINTUN_RELEASE_RECEIVE_PACKET_FUNC = *const fn (WINTUN_SESSION_HANDLE, *anyopaque) callconv(.C) void;
const WINTUN_ALLOCATE_SEND_PACKET_FUNC = *const fn (WINTUN_SESSION_HANDLE, DWORD) callconv(.C) ?*anyopaque;
const WINTUN_SEND_PACKET_FUNC = *const fn (WINTUN_SESSION_HANDLE, *anyopaque) callconv(.C) void;

// Windows error codes
const ERROR_OBJECT_ALREADY_EXISTS: DWORD = 0xC0000033;
const WAIT_TIMEOUT: DWORD = 258;

// IP Helper API types
const NET_LUID = extern struct {
    Value: u64,
};

const SOCKADDR_IN = extern struct {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [4]u8,
    sin_zero: [8]u8,
};

const SOCKADDR_IN6 = extern struct {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [16]u8,
    sin6_scope_id: u32,
};

const SOCKADDR_STORAGE = extern struct {
    ss_family: u16,
    __ss_padding: [126]u8,
};

const MIB_UNICASTIPADDRESS_ROW = extern struct {
    Address: SOCKADDR_STORAGE,
    InterfaceLuid: NET_LUID,
    InterfaceIndex: u32,
    PrefixOrigin: u32,
    SuffixOrigin: u32,
    ValidLifetime: u32,
    PreferredLifetime: u32,
    OnLinkPrefixLength: u8,
    SkipAsSource: BOOL,
    DadState: u32,
    ScopeId: u32,
};

// IP Helper API functions
extern "c" fn InitializeUnicastIpAddressEntry(row: *MIB_UNICASTIPADDRESS_ROW) callconv(.C) void;
extern "c" fn CreateUnicastIpAddressEntry(row: *const MIB_UNICASTIPADDRESS_ROW) callconv(.C) DWORD;
extern "c" fn GetAdapterLUID(adapter: WINTUN_ADAPTER_HANDLE, luid: *NET_LUID) callconv(.C) void;

// ==================== Helper Functions ====================

/// Convert ASCII string to UTF-16
fn toWideString(allocator: std.mem.Allocator, str: []const u8) ![]u16 {
    // Count UTF-16 code units needed (ASCII = same length)
    const wide_len = str.len;
    const wide = try allocator.alloc(u16, wide_len + 1);
    for (str, 0..) |c, i| {
        wide[i] = c; // ASCII characters map 1:1 to UTF-16
    }
    wide[wide_len] = 0;
    return wide;
}

/// Free wide string
fn freeWideString(allocator: std.mem.Allocator, wide: []u16) void {
    allocator.free(wide);
}

/// Load Wintun function pointer
fn loadWintunFunc(dll: HANDLE, name: [*:0]const u8, T: type) !T {
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
    const dll_raw = LoadLibraryW(@as(LPCWSTR, @ptrCast(dll_name.ptr))) orelse {
        const err = GetLastError();
        std.debug.print("[ztun] LoadLibraryW failed: error={d}\n", .{err});
        return error.IoError;
    };
    const dll = @as(HANDLE, @ptrCast(dll_raw));
    errdefer _ = FreeLibrary(dll);

    // Load Wintun functions
    const WintunCreateAdapter = loadWintunFunc(dll, "WintunCreateAdapter", WINTUN_CREATE_ADAPTER_FUNC) catch {
        const err = GetLastError();
        std.debug.print("[ztun] GetProcAddress WintunCreateAdapter failed: error={d}\n", .{err});
        return error.IoError;
    };
    const WintunOpenAdapter = loadWintunFunc(dll, "WintunOpenAdapter", WINTUN_OPEN_ADAPTER_FUNC) catch {
        const err = GetLastError();
        std.debug.print("[ztun] GetProcAddress WintunOpenAdapter failed: error={d}\n", .{err});
        return error.IoError;
    };
    const WintunCloseAdapter = loadWintunFunc(dll, "WintunCloseAdapter", WINTUN_CLOSE_ADAPTER_FUNC) catch {
        const err = GetLastError();
        std.debug.print("[ztun] GetProcAddress WintunCloseAdapter failed: error={d}\n", .{err});
        return error.IoError;
    };
    const WintunStartSession = loadWintunFunc(dll, "WintunStartSession", WINTUN_START_SESSION_FUNC) catch {
        const err = GetLastError();
        std.debug.print("[ztun] GetProcAddress WintunStartSession failed: error={d}\n", .{err});
        return error.IoError;
    };
    const WintunEndSession = loadWintunFunc(dll, "WintunEndSession", WINTUN_END_SESSION_FUNC) catch {
        const err = GetLastError();
        std.debug.print("[ztun] GetProcAddress WintunEndSession failed: error={d}\n", .{err});
        return error.IoError;
    };
    const WintunReceivePacket = loadWintunFunc(dll, "WintunReceivePacket", WINTUN_RECEIVE_PACKET_FUNC) catch {
        const err = GetLastError();
        std.debug.print("[ztun] GetProcAddress WintunReceivePacket failed: error={d}\n", .{err});
        return error.IoError;
    };
    const WintunReleaseReceivePacket = loadWintunFunc(dll, "WintunReleaseReceivePacket", WINTUN_RELEASE_RECEIVE_PACKET_FUNC) catch {
        const err = GetLastError();
        std.debug.print("[ztun] GetProcAddress WintunReleaseReceivePacket failed: error={d}\n", .{err});
        return error.IoError;
    };
    const WintunAllocateSendPacket = loadWintunFunc(dll, "WintunAllocateSendPacket", WINTUN_ALLOCATE_SEND_PACKET_FUNC) catch {
        const err = GetLastError();
        std.debug.print("[ztun] GetProcAddress WintunAllocateSendPacket failed: error={d}\n", .{err});
        return error.IoError;
    };
    const WintunSendPacket = loadWintunFunc(dll, "WintunSendPacket", WINTUN_SEND_PACKET_FUNC) catch {
        const err = GetLastError();
        std.debug.print("[ztun] GetProcAddress WintunSendPacket failed: error={d}\n", .{err});
        return error.IoError;
    };
    _ = WintunReceivePacket;
    _ = WintunReleaseReceivePacket;
    _ = WintunAllocateSendPacket;
    _ = WintunSendPacket;

    // Use default adapter name or custom
    const name_str = config.name orelse "ztun0";
    const adapter_name_wide = toWideString(allocator, name_str) catch {
        return error.IoError;
    };
    defer allocator.free(adapter_name_wide);

    // Get MTU
    const mtu = config.mtu orelse 1500;

    // Create Wintun adapter (note: WintunCreateAdapter takes 3 params, not 4)
    // Use "xtun" as tunnel type to match xtun's working configuration
    const xtun_tunnel_type = [_]u16{ 'x', 't', 'u', 'n', 0 };
    var adapter = WintunCreateAdapter(
        @as([*:0]const u16, @ptrCast(adapter_name_wide.ptr)),
        @as([*:0]const u16, @ptrCast(&xtun_tunnel_type)),
        null, // Use default GUID
    );
    if (adapter == null) {
        const err = GetLastError();
        // Adapter might already exist, try to open it
        if (err == ERROR_OBJECT_ALREADY_EXISTS) {
            adapter = WintunOpenAdapter(@as([*:0]const u16, @ptrCast(adapter_name_wide.ptr)));
            if (adapter == null) {
                return error.IoError;
            }
        } else {
            return error.IoError;
        }
    }

    // Start session
    const session = WintunStartSession(adapter, WINTUN_RING_CAPACITY);
    if (session == null) {
        WintunCloseAdapter(adapter);
        return error.IoError;
    }

    // Note: MTU and IPv4 address should be configured separately on Windows
    // using WMI or netsh commands, not via wintun.dll

    // Copy adapter name
    const name_copy = allocator.alloc(u8, name_str.len + 1) catch {
        WintunEndSession(session);
        WintunCloseAdapter(adapter);
        return error.IoError;
    };
    @memcpy(name_copy[0..name_str.len], name_str);
    name_copy[name_str.len] = 0;

    // Allocate context
    const ctx = allocator.create(DeviceContext) catch {
        allocator.free(name_copy);
        WintunEndSession(session);
        WintunCloseAdapter(adapter);
        return error.IoError;
    };

    // Allocate state
    const state = allocator.create(WindowsDeviceState) catch {
        allocator.destroy(ctx);
        allocator.free(name_copy);
        WintunEndSession(session);
        WintunCloseAdapter(adapter);
        return error.IoError;
    };

    // Initialize RingBuffer (large buffer for batch packet handling)
    const ringbuf_capacity = @as(usize, mtu) * 256; // 256 packets worth of buffer
    const ringbuf = RingBuffer.init(ringbuf_capacity) catch RingBuffer{
        .ptr = undefined,
        .capacity = 0,
        .owned = false,
    };

    state.* = .{
        .wintun_dll = dll,
        .adapter_handle = adapter,
        .session_handle = session,
        .name_ptr = name_copy.ptr,
        .mtu = mtu,
        .index = 0,
        .ringbuf = ringbuf,
        .read_offset = 0,
    };

    ctx.* = .{ .ptr = state };

    return ctx;
}

// ==================== IPv4/IPv6 Configuration ====================

/// Configure IPv4 address using Windows IP Helper API
fn configureIpv4(adapter_handle: WINTUN_ADAPTER_HANDLE, address: Ipv4Address, prefix: u8) TunError!void {
    var address_row: MIB_UNICASTIPADDRESS_ROW = undefined;

    // Initialize address row
    InitializeUnicastIpAddressEntry(&address_row);

    // Get adapter LUID
    GetAdapterLUID(adapter_handle, &address_row.InterfaceLuid);

    // Set IPv4 address (already in network byte order)
    const ipv4_addr = @as(*SOCKADDR_IN, @alignCast(@ptrCast(&address_row.Address)));
    ipv4_addr.sin_family = @as(u16, @bitCast(@as(i16, -1))); // AF_INET = 2
    @memcpy(ipv4_addr.sin_addr[0..4], &address);

    address_row.OnLinkPrefixLength = prefix;
    address_row.DadState = 2; // IpDadStatePreferred
    address_row.SkipAsSource = @as(c_int, 1);

    // Create the address entry
    const result = CreateUnicastIpAddressEntry(&address_row);
    if (result != 0 and result != ERROR_OBJECT_ALREADY_EXISTS) {
        std.debug.print("[ztun] CreateUnicastIpAddressEntry failed: error={d}\n", .{result});
        return error.IoError;
    }

    std.debug.print("[ztun] Windows IPv4 configured: {d}.{d}.{d}.{d}/{d}\n",
        .{ address[0], address[1], address[2], address[3], prefix });
}

/// Configure IPv6 address using Windows IP Helper API
fn configureIpv6(adapter_handle: WINTUN_ADAPTER_HANDLE, address: Ipv6Address, prefix: u32) TunError!void {
    var address_row: MIB_UNICASTIPADDRESS_ROW = undefined;

    // Initialize address row
    InitializeUnicastIpAddressEntry(&address_row);

    // Get adapter LUID
    GetAdapterLUID(adapter_handle, &address_row.InterfaceLuid);

    // Set IPv6 address (already in network byte order)
    const ipv6_addr = @as(*SOCKADDR_IN6, @alignCast(@ptrCast(&address_row.Address)));
    ipv6_addr.sin6_family = @as(u16, @bitCast(@as(i16, -10))); // AF_INET6 = 23
    @memcpy(ipv6_addr.sin6_addr[0..16], &address);

    address_row.OnLinkPrefixLength = @as(u8, @intCast(prefix));
    address_row.DadState = 2; // IpDadStatePreferred
    address_row.SkipAsSource = @as(c_int, 1);

    // Create the address entry
    const result = CreateUnicastIpAddressEntry(&address_row);
    if (result != 0 and result != ERROR_OBJECT_ALREADY_EXISTS) {
        std.debug.print("[ztun] CreateUnicastIpAddressEntry (IPv6) failed: error={d}\n", .{result});
        return error.IoError;
    }

    std.debug.print("[ztun] Windows IPv6 configured: /{d}\n", .{prefix});
}

// ==================== Device Operations ====================

/// Helper to cast device pointer to state
inline fn toState(device_ptr: *anyopaque) *WindowsDeviceState {
    return @as(*WindowsDeviceState, @alignCast(@ptrCast(device_ptr)));
}

/// Receive a packet from the TUN device (blocking)
/// Uses Wintun's recommended pattern: wait once, then batch process all available packets
pub fn recv(device_ptr: *anyopaque, buf: []u8) TunError!usize {
    const state = toState(device_ptr);

    // Load functions from DLL
    const WintunGetReadWaitEvent = loadWintunFunc(state.wintun_dll, "WintunGetReadWaitEvent", WINTUN_GET_READ_WAIT_EVENT_FUNC) catch {
        return error.IoError;
    };
    const WintunReceivePacket = loadWintunFunc(state.wintun_dll, "WintunReceivePacket", WINTUN_RECEIVE_PACKET_FUNC) catch {
        return error.IoError;
    };
    const WintunReleaseReceivePacket = loadWintunFunc(state.wintun_dll, "WintunReleaseReceivePacket", WINTUN_RELEASE_RECEIVE_PACKET_FUNC) catch {
        return error.IoError;
    };

    // Get wait event
    const event = WintunGetReadWaitEvent(state.session_handle);
    if (@intFromPtr(event) == 0) {
        return error.IoError;
    }

    // Wait indefinitely for data (blocking)
    _ = WaitForSingleObject(event, @as(DWORD, 0xFFFFFFFF)); // INFINITE

    // Batch process: consume all available packets, return the first one
    var first_packet: ?*anyopaque = null;
    var first_size: DWORD = 0;

    var size: DWORD = 0;
    while (true) {
        const packet = WintunReceivePacket(state.session_handle, &size);
        if (packet == null) {
            break; // No more packets
        }

        if (first_packet == null) {
            // Save first packet for return
            first_packet = packet;
            first_size = size;
        } else {
            // Discard additional packets (could be buffered in future)
            WintunReleaseReceivePacket(state.session_handle, packet.?);
        }
    }

    if (first_packet == null) {
        return error.IoError;
    }

    const packet_size = @as(usize, @intCast(first_size));
    if (packet_size > buf.len) {
        WintunReleaseReceivePacket(state.session_handle, first_packet.?);
        return error.IoError;
    }

    @memcpy(buf[0..packet_size], @as([*]u8, @ptrCast(first_packet.?))[0..packet_size]);
    WintunReleaseReceivePacket(state.session_handle, first_packet.?);

    return packet_size;
}

/// Send a packet to the TUN device
pub fn send(device_ptr: *anyopaque, packet_buf: []const u8) TunError!usize {
    const state = toState(device_ptr);

    // Load functions from DLL
    const WintunAllocateSendPacket = loadWintunFunc(state.wintun_dll, "WintunAllocateSendPacket", WINTUN_ALLOCATE_SEND_PACKET_FUNC) catch {
        return error.IoError;
    };
    const WintunSendPacket = loadWintunFunc(state.wintun_dll, "WintunSendPacket", WINTUN_SEND_PACKET_FUNC) catch {
        return error.IoError;
    };

    const packet = WintunAllocateSendPacket(state.session_handle, @as(DWORD, @intCast(packet_buf.len)));
    if (packet == null) {
        return error.IoError;
    }

    @memcpy(@as([*]u8, @ptrCast(packet.?))[0..packet_buf.len], packet_buf);
    WintunSendPacket(state.session_handle, packet.?);

    return packet_buf.len;
}

/// Get the device name
pub fn getName(device_ptr: *anyopaque) TunError![]const u8 {
    const state = toState(device_ptr);
    // Find null terminator to determine length
    var len: usize = 0;
    while (state.name_ptr[len] != 0) : (len += 1) {}
    return state.name_ptr[0..len];
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
pub fn addIpv4(device_ptr: *anyopaque, address: Ipv4Address, prefix: u8) TunError!void {
    const state = toState(device_ptr);
    try configureIpv4(state.adapter_handle, address, prefix);
}

/// Add an IPv6 address at runtime
pub fn addIpv6(device_ptr: *anyopaque, address: Ipv6Address, prefix: u8) TunError!void {
    const state = toState(device_ptr);
    try configureIpv6(state.adapter_handle, address, prefix);
}

/// Destroy the device and clean up resources
pub fn destroy(device_ptr: *anyopaque) void {
    const state = toState(device_ptr);
    const allocator = std.heap.page_allocator;

    // Load functions from DLL
    const WintunEndSession = loadWintunFunc(state.wintun_dll, "WintunEndSession", WINTUN_END_SESSION_FUNC) catch return;
    const WintunCloseAdapter = loadWintunFunc(state.wintun_dll, "WintunCloseAdapter", WINTUN_CLOSE_ADAPTER_FUNC) catch return;

    // Stop session
    if (@intFromPtr(state.session_handle) != 0) {
        WintunEndSession(state.session_handle);
    }

    // Close adapter
    if (@intFromPtr(state.adapter_handle) != 0) {
        WintunCloseAdapter(state.adapter_handle);
    }

    // Free DLL
    if (@intFromPtr(state.wintun_dll) != 0) {
        _ = FreeLibrary(state.wintun_dll);
    }

    // Free RingBuffer
    state.ringbuf.deinit();

    // Free name copy - find null terminator
    var name_len: usize = 0;
    while (state.name_ptr[name_len] != 0) : (name_len += 1) {}
    allocator.free(state.name_ptr[0..name_len]);

    // Note: We don't free state and ctx allocations because page_allocator
    // is a simple allocator that doesn't track individual allocations.
    // These small allocations will be reclaimed when the process exits.
}
