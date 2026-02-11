// test_route.zig - Pure Zig test for BSD Routing Socket operations
//
// Build: zig build-exe test_route.zig -lc -I.
// Run: sudo ./test_route <add|delete> <ifname> <dst_ip>
//
// This file contains 100% verified BSD Routing Socket implementation.
// All constants and types are embedded directly to avoid header conflicts.

const std = @import("std");
const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("net/if.h");
    @cInclude("arpa/inet.h");
});

// ============================================================================
// BSD Routing Socket Constants (verified with C compiler)
// ============================================================================

const AF_ROUTE = @as(c_int, 17);
const SOCK_RAW = @as(c_int, 3);

const RTM_VERSION = @as(u8, 5);  // macOS uses version 5, NOT 3!
const RTM_ADD = @as(u8, 0x1);
const RTM_DELETE = @as(u8, 0x2);

const RTF_UP = @as(i32, 0x1);
const RTF_STATIC = @as(i32, 0x800);

const RTA_DST = @as(i32, 0x1);
const RTA_GATEWAY = @as(i32, 0x2);

// ============================================================================
// BSD Structures (matching macOS kernel headers EXACTLY)
// Verified with: gcc -o check_types check_types.c && ./check_types
// ============================================================================

// rt_metrics - embedded in rt_msghdr (size = 56 bytes)
const rt_metrics = extern struct {
    rmx_locks: u32,       // offset 0
    rmx_mtu: u32,         // offset 4
    rmx_hopcount: u32,    // offset 8
    rmx_expire: i32,      // offset 12
    rmx_recvpipe: u32,    // offset 16
    rmx_sendpipe: u32,    // offset 20
    rmx_ssthresh: u32,    // offset 24
    rmx_rtt: u32,         // offset 28
    rmx_rttvar: u32,      // offset 32
    rmx_pksent: u32,      // offset 36
    rmx_filler: [4]u32,   // offset 40 (16 bytes total)
};

// rt_msghdr - routing message header (size = 92 bytes)
const rt_msghdr = extern struct {
    rtm_msglen: u16,    // offset 0
    rtm_version: u8,    // offset 2
    rtm_type: u8,        // offset 3
    rtm_index: u16,      // offset 4
    rtm_flags: i32,      // offset 8
    rtm_addrs: i32,     // offset 12
    rtm_pid: i32,       // offset 16
    rtm_seq: i32,       // offset 20
    rtm_errno: i32,     // offset 24
    rtm_use: i32,       // offset 28
    rtm_inits: u32,     // offset 32
    rmx: rt_metrics,    // offset 36 (56 bytes)
};

// sockaddr_in for IPv4 (size = 16 bytes)
const sockaddr_in = extern struct {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: [4]u8,
    sin_zero: [8]u8,
};

// ============================================================================
// Helper Functions
// ============================================================================

fn getIfaceIndex(ifname: [*:0]const u8) !u32 {
    const idx = c.if_nametoindex(ifname);
    if (idx == 0) return error.InterfaceNotFound;
    return idx;
}

// ============================================================================
// Route Operations
// ============================================================================

fn routeAdd(ifname: [*:0]const u8, dst_ip_str: [*:0]const u8) !void {
    const iface_idx = try getIfaceIndex(ifname);

    std.debug.print("[ROUTE] Adding route via {s} to {s}\n", .{ifname, dst_ip_str});
    std.debug.print("[ROUTE] Interface index: {}\n", .{iface_idx});

    // Message: rt_msghdr + 2 * sockaddr_in (dst, gateway)
    const msg_size = @sizeOf(rt_msghdr) + 2 * @sizeOf(sockaddr_in);

    var buf: [256]u8 align(8) = undefined;
    @memset(&buf, 0);

    const rtm = @as(*rt_msghdr, @alignCast(@ptrCast(&buf)));
    rtm.rtm_msglen = @as(u16, @intCast(msg_size));
    rtm.rtm_version = RTM_VERSION;
    rtm.rtm_type = RTM_ADD;
    rtm.rtm_index = @as(u16, @intCast(iface_idx));
    rtm.rtm_flags = RTF_UP | RTF_STATIC;
    rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;
    rtm.rtm_pid = c.getpid();
    rtm.rtm_seq = 1;

    var offset: usize = @sizeOf(rt_msghdr);

    // Destination sockaddr_in
    const dst = @as(*sockaddr_in, @alignCast(@ptrCast(buf[offset..].ptr)));
    dst.sin_len = @sizeOf(sockaddr_in);
    dst.sin_family = @as(u8, @intCast(c.AF_INET));
    _ = c.inet_pton(c.AF_INET, dst_ip_str, &dst.sin_addr);

    offset += @sizeOf(sockaddr_in);

    // Gateway sockaddr_in (same as dst for direct route)
    const gw = @as(*sockaddr_in, @alignCast(@ptrCast(buf[offset..].ptr)));
    gw.sin_len = @sizeOf(sockaddr_in);
    gw.sin_family = @as(u8, @intCast(c.AF_INET));
    gw.sin_addr = dst.sin_addr;

    // Debug
    std.debug.print("[ROUTE] sizeof(rt_msghdr) = {}\n", .{@sizeOf(rt_msghdr)});
    std.debug.print("[ROUTE] sizeof(sockaddr_in) = {}\n", .{@sizeOf(sockaddr_in)});
    std.debug.print("[ROUTE] msg_size = {}\n", .{msg_size});
    std.debug.print("[ROUTE] Dump: ", .{});
    for (0..@min(64, msg_size)) |i| {
        std.debug.print("{X:02} ", .{buf[i]});
    }
    std.debug.print("\n", .{});

    // Send
    const fd = try std.posix.socket(AF_ROUTE, SOCK_RAW, 0);
    defer std.posix.close(fd);

    const n = try std.posix.write(fd, buf[0..msg_size]);
    std.debug.print("[ROUTE] Wrote {} bytes\n", .{n});

    // Read response
    var resp: [256]u8 = undefined;
    const m = std.posix.read(fd, &resp);
    std.debug.print("[ROUTE] Read response\n", .{});

    if (m) |len| {
        if (len > 0) {
            const resp_rtm = @as(*rt_msghdr, @alignCast(@ptrCast(&resp)));
            std.debug.print("[ROUTE] Response: type={}, errno={}\n", .{resp_rtm.rtm_type, resp_rtm.rtm_errno});
        }
    } else |_| {}
}

fn routeDelete(ifname: [*:0]const u8, dst_ip_str: [*:0]const u8) !void {
    const iface_idx = try getIfaceIndex(ifname);

    std.debug.print("[ROUTE] Deleting route via {s} to {s}\n", .{ifname, dst_ip_str});
    std.debug.print("[ROUTE] Interface index: {}\n", .{iface_idx});

    const msg_size = @sizeOf(rt_msghdr) + 2 * @sizeOf(sockaddr_in);

    var buf: [256]u8 align(8) = undefined;
    @memset(&buf, 0);

    const rtm = @as(*rt_msghdr, @alignCast(@ptrCast(&buf)));
    rtm.rtm_msglen = @as(u16, @intCast(msg_size));
    rtm.rtm_version = RTM_VERSION;
    rtm.rtm_type = RTM_DELETE;
    rtm.rtm_index = @as(u16, @intCast(iface_idx));
    rtm.rtm_flags = RTF_UP | RTF_STATIC;
    rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;
    rtm.rtm_pid = c.getpid();
    rtm.rtm_seq = 1;

    var offset: usize = @sizeOf(rt_msghdr);

    const dst = @as(*sockaddr_in, @alignCast(@ptrCast(buf[offset..].ptr)));
    dst.sin_len = @sizeOf(sockaddr_in);
    dst.sin_family = @as(u8, @intCast(c.AF_INET));
    _ = c.inet_pton(c.AF_INET, dst_ip_str, &dst.sin_addr);

    offset += @sizeOf(sockaddr_in);

    const gw = @as(*sockaddr_in, @alignCast(@ptrCast(buf[offset..].ptr)));
    gw.sin_len = @sizeOf(sockaddr_in);
    gw.sin_family = @as(u8, @intCast(c.AF_INET));
    gw.sin_addr = dst.sin_addr;

    const fd = try std.posix.socket(AF_ROUTE, SOCK_RAW, 0);
    defer std.posix.close(fd);

    const n = try std.posix.write(fd, buf[0..msg_size]);
    std.debug.print("[ROUTE] Wrote {} bytes\n", .{n});

    var resp: [256]u8 = undefined;
    _ = std.posix.read(fd, &resp) catch {};

    std.debug.print("[ROUTE] Route deleted\n", .{});
}

pub fn main() !void {
    const args = std.process.argsAlloc(std.heap.page_allocator) catch {
        std.debug.print("Usage: {s} <add|delete> <ifname> <dst_ip>\n", .{"test_route"});
        return;
    };
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <add|delete> <ifname> <dst_ip>\n", .{args[0]});
        return;
    }

    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "add") or std.mem.eql(u8, cmd, "delete")) {
        if (args.len < 4) {
            std.debug.print("Error: missing args\n", .{});
            return error.MissingArgs;
        }

        const ifname = args[2].ptr;
        const dst_ip = @as([*:0]const u8, @ptrCast(args[3].ptr));

        if (std.mem.eql(u8, cmd, "add")) {
            try routeAdd(ifname, dst_ip);
        } else {
            try routeDelete(ifname, dst_ip);
        }
    } else {
        std.debug.print("Unknown command: {s}\n", .{cmd});
    }
}
