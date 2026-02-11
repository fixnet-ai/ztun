//! network.zig - 网络接口模块
//!
//! 提供跨平台的网络接口获取和路由管理功能
//!
//! 使用示例：
//! ```zig
//! const network = @import("network");
//!
//! // 获取所有本地 IP
//! const ips = try network.getLocalIps(allocator);
//! defer allocator.free(ips);
//! for (ips) |ip_info| {
//!     std.debug.print("IP: {s}\n", .{ip_info.ip});
//! }
//!
//! // 获取主出口 IP
//! const primary_ip = try network.getPrimaryIp(allocator);
//! defer allocator.free(primary_ip);
//! std.debug.print("Primary: {s}\n", .{primary_ip});
//!
//! // 配置系统路由（使用结构化 API）
//! const routes = &[_]network.RouteEntry{
//!     .{ .dst = 0x0A000000, .mask = 0xFFFFFFFF, .gateway = 0, .iface_idx = 2, .metric = 100 },
//! };
//! try network.addRoutes(routes);
//! ```

const std = @import("std");
const builtin = @import("builtin");

// ==================== C 外部函数声明 ====================

/// 本地 IP 地址信息
pub const IpInfo = extern struct {
    ip: [64]u8, // IP 地址字符串（IPv4 或 IPv6）
    is_ipv6: c_int, // 是否为 IPv6
    is_loopback: c_int, // 是否为回环地址
};

// ==================== network.c 外部函数 ====================

/// 获取所有本地 IP 地址（跨平台）
extern fn get_local_ips(ips: [*]IpInfo, max_count: c_int) c_int;

/// 获取主出口 IP（通过创建 UDP socket 连接到外部地址探测）
extern fn get_primary_ip(ip_buf: [*]u8, buf_len: usize) c_int;

/// 根据目标 IP 选择出口 IP（通过连接到目标 IP 来探测实际出口）
extern fn select_egress_ip_for_target(target_ip: [*:0]const u8, ip_buf: [*]u8, buf_len: usize) c_int;

// ==================== route.c 外部函数 ====================

/// 地址族枚举（与 C route_entry_t 对应）
pub const RouteAddressFamily = enum(u8) {
    ipv4 = 2, // AF_INET
    ipv6 = 10, // AF_INET6
};

/// IPv6 地址（128位，16字节）
pub const Ipv6Addr = extern struct {
    addr: [16]u8,
};

/// IPv6 前缀掩码（128位，16字节）
pub const Ipv6Prefix = extern struct {
    prefix: [16]u8,
};

/// IPv4 路由数据
pub const RouteIpv4 = extern struct {
    dst: u32,
    mask: u32,
    gateway: u32,
};

/// IPv6 路由数据
pub const RouteIpv6 = extern struct {
    dst: Ipv6Addr,
    mask: Ipv6Prefix,
    gateway: Ipv6Addr,
    prefix_len: u8,
};

/// 路由条目结构体（与 C route.h 中的 route_entry_t 对应，支持 IPv4/IPv6）
pub const RouteEntry = extern struct {
    family: RouteAddressFamily,

    /// IPv4/IPv6 地址联合体
    un: extern union {
        ipv4: RouteIpv4,
        ipv6: RouteIpv6,
    },

    iface_idx: u32,
    metric: c_int,
};

/// 创建 IPv4 路由条目
pub fn ipv4Route(dst: u32, mask: u32, gateway: u32, iface_idx: u32, metric: c_int) RouteEntry {
    return .{
        .family = .ipv4,
        .un = .{ .ipv4 = .{ .dst = dst, .mask = mask, .gateway = gateway } },
        .iface_idx = iface_idx,
        .metric = metric,
    };
}

/// 创建 IPv6 路由条目
pub fn ipv6Route(dst: [16]u8, prefix_len: u8, gateway: [16]u8, iface_idx: u32, metric: c_int) RouteEntry {
    var mask: [16]u8 = undefined;
    ipv6PrefixToMask(prefix_len, &mask);

    return .{
        .family = .ipv6,
        .un = .{
            .ipv6 = .{
                .dst = Ipv6Addr{ .addr = dst },
                .mask = Ipv6Prefix{ .prefix = mask },
                .gateway = Ipv6Addr{ .addr = gateway },
                .prefix_len = prefix_len,
            },
        },
        .iface_idx = iface_idx,
        .metric = metric,
    };
}

/// 将 IPv6 前缀长度转换为掩码
pub fn ipv6PrefixToMask(prefix_len: u8, mask_out: *[16]u8) void {
    // First, zero out the entire mask
    @memset(mask_out, 0);

    if (prefix_len == 0) {
        return;
    }

    const pl = @min(prefix_len, 128);

    const full_bytes = pl / 8;
    const partial_bits = pl % 8;

    // Set full bytes to 0xFF
    var i: usize = 0;
    while (i < full_bytes) : (i += 1) {
        mask_out[i] = 0xFF;
    }

    if (partial_bits > 0) {
        // partial_bits is 1-7, so (8 - partial_bits) is 1-7
        const shift: u3 = @intCast(8 - partial_bits);
        mask_out[full_bytes] = @as(u8, 0xFF) << shift;
    }
}

/// 添加路由
extern fn route_add(route: *const RouteEntry) c_int;

/// 删除路由
extern fn route_delete(route: *const RouteEntry) c_int;

/// 验证路由是否存在
extern fn route_verify(route: *const RouteEntry) c_int;

/// 查询路由表
extern fn route_list(routes: ?[*]RouteEntry, max_count: c_int) c_int;

/// 通过设备名获取接口索引
extern fn route_get_iface_index(ifname: [*:0]const u8) c_int;

/// 初始化路由模块
extern fn route_init() c_int;

/// 清理路由模块资源
extern fn route_cleanup() void;

/// Windows: 检查是否有管理员权限
extern fn route_has_admin_privileges() c_int;

/// 配置 TUN 接口 IP 地址 (BSD/macOS)
extern fn configure_tun_ip(ifname: [*:0]const u8, ip_addr: [*:0]const u8) c_int;

/// 配置 TUN 接口对端地址 (BSD/macOS 点对点)
/// 对于 macOS utun 设备，这使用 SIOCSIFDSTADDR 设置目标/对端地址
/// 这对正确路由至关重要 - 内核需要知道对端地址才能正确路由回复包
extern fn configure_tun_peer(ifname: [*:0]const u8, peer_addr: [*:0]const u8) c_int;

// ==================== Zig 包装函数 ====================

/// 获取所有本地 IP 地址
///
/// 返回需要调用者释放内存
pub fn getLocalIps(alloc: std.mem.Allocator) ![]IpInfo {
    // 使用临时数组获取 IP 数量
    var temp_ips: [16]IpInfo = undefined;
    const count = get_local_ips(&temp_ips, 16);
    if (count <= 0) return error.NoLocalIps;

    // 分配合适大小的数组
    const ips = try alloc.alloc(IpInfo, @intCast(count));
    errdefer alloc.free(ips);

    // 复制临时数组的数据
    @memcpy(ips, temp_ips[0..@intCast(count)]);

    return ips[0..@intCast(count)];
}

/// 获取主出口 IP（通过 UDP 探测获取系统默认出口）
///
/// 返回需要调用者释放内存
pub fn getPrimaryIp(alloc: std.mem.Allocator) ![]u8 {
    var buf: [64]u8 = undefined;
    if (get_primary_ip(&buf, buf.len) != 0) {
        return error.GetPrimaryIpFailed;
    }
    // 使用 sliceTo 获取以 null 结尾的字符串长度
    const len = std.mem.sliceTo(buf[0..], 0).len;
    return try alloc.dupe(u8, buf[0..len]);
}

/// 根据目标 IP 选择最佳出口 IP
///
/// 通过连接到目标地址探测实际使用的出口 IP
pub fn selectEgressIp(alloc: std.mem.Allocator, target_ip: []const u8) ![]u8 {
    // 将 target_ip 转换为 sentinel-terminated 字符串
    const target_z = try alloc.dupeZ(u8, target_ip);
    defer alloc.free(target_z);

    var buf: [64]u8 = undefined;
    if (select_egress_ip_for_target(target_z, &buf, buf.len) != 0) {
        return error.SelectEgressIpFailed;
    }
    const len = std.mem.sliceTo(buf[0..], 0).len;
    return try alloc.dupe(u8, buf[0..len]);
}

/// 获取指定网络接口的 IP
///
/// iface_name: 接口名称（如 "eth0", "en0"）
pub fn getInterfaceIp(alloc: std.mem.Allocator, iface_name: []const u8) ![]u8 {
    _ = iface_name;
    _ = alloc;
    // TODO: 需要在 C 层实现按接口名获取 IP
    return error.NotImplemented;
}

/// 配置 TUN 接口 IP 地址
///
/// 在 macOS 上，TUN 接口需要先配置 IP 地址才能添加路由
pub fn configureTunIp(ifname: [*:0]const u8, ip_addr: [*:0]const u8) c_int {
    return configure_tun_ip(ifname, ip_addr);
}

/// 配置 TUN 接口对端地址 (BSD/macOS)
///
/// 对于 macOS utun 设备，这设置目标/对端地址使用 SIOCSIFDSTADDR
/// 这对正确路由至关重要
pub fn configureTunPeer(ifname: [*:0]const u8, peer_addr: [*:0]const u8) c_int {
    return configure_tun_peer(ifname, peer_addr);
}

// ==================== 系统路由管理（新 API）====================

/// 添加单条路由
///
/// 使用系统 API（而非 shell 命令）添加路由
/// 添加后立即验证路由是否真正存在于系统中
pub fn addRoute(route: *const RouteEntry) !void {
    if (route_add(route) != 0) {
        return error.RouteAddFailed;
    }

    // 验证路由是否真正添加成功
    std.time.sleep(10 * std.time.ns_per_ms); // 短暂等待让系统更新路由表
    const verified = route_verify(route);
    if (verified < 0) {
        return error.RouteVerifyError;
    }
    if (verified == 0) {
        return error.RouteNotFoundAfterAdd;
    }
}

/// 删除单条路由
///
/// 使用系统 API（而非 shell 命令）删除路由
pub fn deleteRoute(route: *const RouteEntry) !void {
    if (route_delete(route) != 0) {
        return error.RouteDeleteFailed;
    }
}

/// 验证路由是否存在于系统中
///
/// 用于验证路由添加操作是否真正成功
pub fn verifyRoute(route: *const RouteEntry) !bool {
    const result = route_verify(route);
    if (result < 0) {
        return error.RouteVerifyError;
    }
    return result == 1;
}

/// 批量添加路由
///
/// 使用系统 API 批量添加路由，失败时回滚已添加的路由
/// 每条路由添加后立即验证是否真正存在于系统中
pub fn addRoutes(routes: []const RouteEntry) !void {
    // 初始化路由模块
    if (route_init() != 0) {
        return error.RouteInitFailed;
    }
    defer route_cleanup();

    // 逐条添加路由
    var added: usize = 0;
    errdefer {
        // 失败时回滚已添加的路由
        while (added > 0) : (added -= 1) {
            _ = route_delete(&routes[added - 1]);
        }
    }

    for (routes, 0..) |*route, i| {
        if (route_add(route) != 0) {
            return error.RouteAddFailed;
        }
        added += 1;

        // 验证路由是否真正添加成功
        std.time.sleep(10 * std.time.ns_per_ms); // 短暂等待
        // Use index-based access to avoid pointer issues
        const verified = route_verify(&routes[i]);
        if (verified < 0) {
            return error.RouteVerifyError;
        }
        if (verified == 0) {
            return error.RouteNotFoundAfterAdd;
        }
    }
}

/// 批量删除路由
///
/// 使用系统 API 批量删除路由，忽略不存在的路由
pub fn deleteRoutes(routes: []const RouteEntry) void {
    for (routes) |*route| {
        _ = route_delete(route);
    }
}

/// 查询路由表
///
/// 使用系统 API 查询路由表，返回所有路由条目
pub fn listRoutes(alloc: std.mem.Allocator) ![]RouteEntry {
    // 先调用一次获取数量
    const count = route_list(null, 0);
    if (count <= 0) return error.NoRoutes;

    // 分配合适大小的数组
    const routes = try alloc.alloc(RouteEntry, @intCast(count));
    errdefer alloc.free(routes);

    // 实际获取路由
    const actual_count = route_list(routes.ptr, count);
    if (actual_count <= 0) {
        alloc.free(routes);
        return error.GetRoutesFailed;
    }

    return routes[0..@intCast(actual_count)];
}

/// 获取接口索引
///
/// 通过接口名称获取系统分配的接口索引
pub fn getInterfaceIndex(ifname: []const u8) !u32 {
    // 将 ifname 转换为 C 字符串
    const ifname_z = try std.heap.page_allocator.dupeZ(u8, ifname);
    defer std.heap.page_allocator.free(ifname_z);

    const idx = route_get_iface_index(ifname_z);
    if (idx < 0) {
        return error.InterfaceNotFound;
    }
    return @intCast(idx);
}

// ==================== 路由工具函数 ====================

/// 将 IPv4 CIDR 字符串解析为 RouteEntry
///
/// 示例: "192.168.1.0/24" -> IPv4 RouteEntry
pub fn parseRouteIpv4(cidr: []const u8, iface_idx: u32, gateway: u32) !RouteEntry {
    const slash_idx = std.mem.indexOf(u8, cidr, "/") orelse return error.InvalidCidrFormat;

    const ip_str = cidr[0..slash_idx];
    const prefix_str = cidr[slash_idx + 1 ..];

    // 使用现有的 parseIp 函数
    const dst = try parseIp(ip_str);

    const prefix_len = try std.fmt.parseInt(u8, prefix_str, 10);
    if (prefix_len > 32) return error.InvalidPrefixLength;

    // 计算 IPv4 子网掩码
    const mask: u32 = if (prefix_len == 0)
        0
    else if (prefix_len == 32)
        0xFFFFFFFF
    else
        (~(@as(u32, 0))) << @intCast(32 - prefix_len);

    return ipv4Route(dst, mask, gateway, iface_idx, 100);
}

/// 将 IPv6 CIDR 字符串解析为 RouteEntry
///
/// 示例: "2001:db8::/32" -> IPv6 RouteEntry
pub fn parseRouteIpv6(cidr: []const u8, iface_idx: u32, gateway: [16]u8) !RouteEntry {
    const slash_idx = std.mem.indexOf(u8, cidr, "/") orelse return error.InvalidCidrFormat;

    const ip_str = cidr[0..slash_idx];
    const prefix_str = cidr[slash_idx + 1 ..];

    const addr = try std.net.Ip6Address.parse(ip_str, 0);
    var dst: [16]u8 = undefined;
    @memcpy(dst[0..16], addr.sa.addr[0..16]);

    const prefix_len = try std.fmt.parseInt(u8, prefix_str, 10);
    if (prefix_len > 128) return error.InvalidPrefixLength;

    return ipv6Route(dst, prefix_len, gateway, iface_idx, 100);
}

/// 将 CIDR 字符串解析为 RouteEntry（自动检测 IPv4/IPv6）
///
/// 示例:
///   "192.168.1.0/24" -> IPv4 RouteEntry
///   "2001:db8::/32" -> IPv6 RouteEntry
///
/// 注意: gateway 参数只用于 IPv4，IPv6 网关设为全零
pub fn parseRoute(cidr: []const u8, iface_idx: u32, gateway: u32) !RouteEntry {
    // 检测是否为 IPv6（包含 ':'）
    const is_ipv6 = std.mem.indexOf(u8, cidr, ":") != null;

    if (is_ipv6) {
        // IPv6 路由（网关设为全零）
        const slash_idx = std.mem.indexOf(u8, cidr, "/") orelse return error.InvalidCidrFormat;
        const ip_str = cidr[0..slash_idx];
        const prefix_str = cidr[slash_idx + 1 ..];

        // Ip6Address.parse 需要 address 和 port 参数
        const addr = try std.net.Ip6Address.parse(ip_str, 0);
        var dst: [16]u8 = undefined;
        @memcpy(dst[0..16], addr.sa.addr[0..16]);

        const prefix_len = try std.fmt.parseInt(u8, prefix_str, 10);
        if (prefix_len > 128) return error.InvalidPrefixLength;

        const zero_gateway = [_]u8{0} ** 16;
        return ipv6Route(dst, prefix_len, zero_gateway, iface_idx, 100);
    } else {
        // IPv4 路由
        return parseRouteIpv4(cidr, iface_idx, gateway);
    }
}

/// 将 IP 字符串解析为 u32 (network byte order)
pub fn parseIp(ip_str: []const u8) !u32 {
    // 手动解析 IPv4 地址: "192.168.1.1" -> u32
    var parts: [4]u8 = undefined;
    var part_idx: usize = 0;
    var current: u16 = 0;

    for (ip_str) |c| {
        if (c == '.') {
            if (part_idx >= 4) return error.InvalidIpAddress;
            if (current > 255) return error.InvalidIpAddress;
            parts[part_idx] = @intCast(current);
            part_idx += 1;
            current = 0;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
        } else {
            return error.InvalidIpAddress;
        }
    }

    // Last part
    if (part_idx != 3) return error.InvalidIpAddress;
    if (current > 255) return error.InvalidIpAddress;
    parts[3] = @intCast(current);

    // Convert to u32 (network byte order)
    return (@as(u32, parts[0]) << 24) |
        (@as(u32, parts[1]) << 16) |
        (@as(u32, parts[2]) << 8) |
        @as(u32, parts[3]);
}

// ==================== 便捷路由配置函数 ====================

/// 配置系统路由指向 TUN 设备（兼容旧 API）
///
/// 参数:
///   tun_idx: 网卡设备索引（优先使用）
///   tun_name: TUN 设备名称（tun_idx 为 null 时使用）
///   route_config: 路由配置，多个 CIDR 用逗号分隔，如 "0.0.0.0/1,128.0.0.0/1"
///   gateway: 网关地址（0 表示直连）
///
/// 使用系统 API 而非 shell 命令
pub fn configSystemRoute(
    tun_idx: ?u32,
    tun_name: ?[]const u8,
    route_config: []const u8,
    gateway: u32,
) !void {

    // Windows 权限检查
    if (builtin.os.tag == .windows) {
        if (route_has_admin_privileges() == 0) {
            return error.AdminPrivilegesRequired;
        }
    }

    // 获取接口索引
    const iface_idx = tun_idx orelse blk: {
        if (tun_name == null) return error.TunNameRequired;
        break :blk try getInterfaceIndex(tun_name.?);
    };

    // 解析路由配置
    var iter = std.mem.split(u8, route_config, ",");
    var routes = std.ArrayList(RouteEntry).init(std.heap.page_allocator);
    defer routes.deinit();

    while (iter.next()) |cidr| {
        const trimmed = std.mem.trim(u8, cidr, " \t");
        if (trimmed.len == 0) continue;

        const route = try parseRoute(trimmed, iface_idx, gateway);
        std.debug.print("[NET] Route parsed: cidr={s} dst=0x{X:0>8} mask=0x{X:0>8} gateway=0x{X:0>8} iface={d}\n",
            .{ trimmed, route.un.ipv4.dst, route.un.ipv4.mask, route.un.ipv4.gateway, route.iface_idx });
        try routes.append(route);
    }

    // 批量添加路由
    try addRoutes(routes.items);
}

/// 清除系统路由（通过接口索引）
///
/// 使用系统 API 而非 shell 命令
/// 直接使用接口索引，避免名称解析问题
pub fn cleanSystemRouteByIndex(route_config: []const u8, tun_idx: u32, gateway: u32) void {

    // Android 沙箱不支持路由操作
    if (builtin.os.tag == .linux and builtin.abi == .android) {
        return;
    }

    // 解析路由配置并删除
    var iter = std.mem.split(u8, route_config, ",");
    while (iter.next()) |cidr| {
        const trimmed = std.mem.trim(u8, cidr, " \t");
        if (trimmed.len == 0) continue;

        if (parseRoute(trimmed, tun_idx, gateway)) |route| {
            _ = route_delete(&route);
        } else |_| {
            // 忽略解析错误
            continue;
        }
    }
}

/// 清除系统路由（兼容旧 API）
///
/// 使用系统 API 而非 shell 命令
pub fn cleanSystemRoute(route_config: []const u8, tun_name: ?[]const u8, gateway: u32) void {

    // Android 沙箱不支持路由操作
    if (builtin.os.tag == .linux and builtin.abi == .android) {
        return;
    }

    // 获取接口索引（忽略错误）
    const iface_idx = if (tun_name) |name| blk: {
        const ifname_z = std.heap.page_allocator.dupeZ(u8, name) catch {
            break :blk null;
        };
        defer std.heap.page_allocator.free(ifname_z);
        const idx = route_get_iface_index(ifname_z);
        if (idx >= 0)
            break :blk @as(?u32, @intCast(idx))
        else
            break :blk null;
    } else null;

    if (iface_idx == null) return;

    // 解析路由配置并删除
    var iter = std.mem.split(u8, route_config, ",");
    while (iter.next()) |cidr| {
        const trimmed = std.mem.trim(u8, cidr, " \t");
        if (trimmed.len == 0) continue;

        if (parseRoute(trimmed, iface_idx.?, gateway)) |route| {
            _ = route_delete(&route);
        } else |_| {
            // 忽略解析错误
            continue;
        }
    }
}
