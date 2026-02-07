// route.c - Cross-platform routing management implementation
//
// Uses system APIs for routing table operations, no shell commands:
// - Linux: Netlink sockets (NETLINK_ROUTE)
// - macOS/iOS: Routing sockets (PF_ROUTE)
// - Windows: IP Helper API (iphlpapi.dll)

#include "route.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Debug macro - only enabled in debug builds
#ifdef DEBUG
#define ROUTE_DEBUG(fmt, ...) fprintf(stderr, "[ROUTE] " fmt "\n", ##__VA_ARGS__)
#else
#define ROUTE_DEBUG(fmt, ...)
#endif

#define ROUTE_ERROR(fmt, ...) fprintf(stderr, "[ROUTE ERROR] " fmt "\n", ##__VA_ARGS__)
#define ROUTE_WARN(fmt, ...) fprintf(stderr, "[ROUTE WARN] " fmt "\n", ##__VA_ARGS__)
#define ROUTE_INFO(fmt, ...) fprintf(stderr, "[ROUTE] " fmt "\n", ##__VA_ARGS__)

// ==================== 平台头文件 ====================

#ifdef OS_UNIX
    #include <unistd.h>
    #include <fcntl.h>
    #include <time.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

#ifdef PLATFORM_LINUX
    #include <linux/netlink.h>
    #include <linux/rtnetlink.h>
    #include <sys/ioctl.h>
    #include <linux/if.h>
#endif

// iOS (including simulator) doesn't have net/route.h in its SDK
#if defined(PLATFORM_MACOS)
    #include <net/route.h>
    #include <net/if.h>
    #include <net/if_dl.h>
    #include <sys/sysctl.h>
    #include <ifaddrs.h>
#elif defined(PLATFORM_IOS)
    // iOS doesn't provide route management APIs
    #include <net/if.h>
    #include <ifaddrs.h>
#endif

#ifdef OS_WIN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #include <stdio.h>
#endif

// ==================== 全局状态 ====================

static int g_route_initialized = 0;

#ifdef PLATFORM_LINUX
    static int g_netlink_sock = -1;
    static int g_netlink_timeout_ms = 5000; // 默认 5 秒超时
#endif

#ifdef PLATFORM_WINDOWS
    static int g_winsock_initialized = 0;
#endif

// ==================== 工具函数 ====================

/// 将 CIDR 转换为子网掩码
static uint32_t cidr_to_mask(int prefix_len) {
    if (prefix_len <= 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFF;
    return htonl(~(0xFFFFFFFF >> prefix_len));
}

/// 打印 IPv4 地址（用于调试）
static const char* ipv4_to_str(uint32_t ip, char* buf, size_t buf_len) {
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntop(AF_INET, &addr, buf, buf_len);
}

/// 打印 IPv6 地址（用于调试）
static const char* ipv6_to_str(const uint8_t* addr, char* buf, size_t buf_len) {
    struct in6_addr in6;
    memcpy(in6.s6_addr, addr, 16);
    return inet_ntop(AF_INET6, &in6, buf, buf_len);
}

/// 计算 IPv6 前缀掩码
void route_ipv6_prefix_to_mask(uint8_t prefix_len, uint8_t* mask_out) {
    memset(mask_out, 0, 16);

    if (prefix_len == 0) return;
    if (prefix_len > 128) prefix_len = 128;

    int full_bytes = prefix_len / 8;
    int partial_bits = prefix_len % 8;

    memset(mask_out, 0xFF, full_bytes);

    if (partial_bits > 0) {
        mask_out[full_bytes] = (uint8_t)(0xFF << (8 - partial_bits));
    }
}

/// 创建 IPv6 路由条目
int route_create_ipv6(const uint8_t* dst, uint8_t prefix_len,
                      const uint8_t* gateway, uint32_t iface_idx,
                      int metric, route_entry_t* route_out) {
    if (!dst || !route_out) {
        ROUTE_ERROR("route_create_ipv6: NULL pointer");
        return -1;
    }

    memset(route_out, 0, sizeof(route_entry_t));
    route_out->family = ROUTE_AF_INET6;

    memcpy(route_out->ipv6.dst.addr, dst, 16);
    route_out->ipv6.prefix_len = prefix_len;

    if (gateway) {
        memcpy(route_out->ipv6.gateway.addr, gateway, 16);
    }

    route_ipv6_prefix_to_mask(prefix_len, route_out->ipv6.mask.prefix);

    route_out->iface_idx = iface_idx;
    route_out->metric = metric;

    return 0;
}

// ==================== 平台特定实现 ====================

// ========================================
// Linux: Netlink Sockets
// ========================================

#ifdef PLATFORM_LINUX

/// 初始化 Netlink socket
static int netlink_init(void) {
    if (g_netlink_sock >= 0) {
        return 0; // 已初始化
    }

    // 创建 Netlink socket
    g_netlink_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (g_netlink_sock < 0) {
        ROUTE_ERROR("Failed to create netlink socket: errno=%d (%s)",
                   errno, strerror(errno));
        return -1;
    }

    // Set non-blocking mode
    int flags = fcntl(g_netlink_sock, F_GETFL, 0);
    if (flags < 0 || fcntl(g_netlink_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        ROUTE_WARN("Failed to set non-blocking mode: errno=%d", errno);
    }

    // Bind socket
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_ROUTE;
    addr.nl_pid = getpid();

    if (bind(g_netlink_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ROUTE_ERROR("Failed to bind netlink socket: errno=%d (%s)",
                   errno, strerror(errno));
        close(g_netlink_sock);
        g_netlink_sock = -1;
        return -1;
    }

    // Set receive buffer
    int rcvbuf_size = 1024 * 64; // 64KB
    if (setsockopt(g_netlink_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
        ROUTE_WARN("Failed to set receive buffer size");
    }

    ROUTE_DEBUG("Netlink socket initialized (fd=%d)", g_netlink_sock);
    return 0;
}

/// 发送 Netlink 路由消息（支持 IPv4/IPv6）
static int netlink_send_route_msg(int cmd, const route_entry_t* route) {
    if (netlink_init() < 0) {
        return -1;
    }

    if (!route) {
        ROUTE_ERROR("netlink_send_route_msg: NULL route");
        return -1;
    }

    char buf[2048];  // 增加缓冲区大小以支持 IPv6
    struct nlmsghdr* nh;
    struct rtmsg* rt;
    struct rtattr* rta;
    char ip_str[64];

    memset(buf, 0, sizeof(buf));
    nh = (struct nlmsghdr*)buf;

    // 设置 Netlink 消息头
    nh->nlmsg_type = cmd; // RTM_NEWROUTE 或 RTM_DELROUTE
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nh->nlmsg_pid = getpid();
    nh->nlmsg_seq = time(NULL);

    // 设置路由消息
    rt = (struct rtmsg*)NLMSG_DATA(nh);

    int is_ipv6 = (route->family == ROUTE_AF_INET6);
    rt->rtm_family = is_ipv6 ? AF_INET6 : AF_INET;
    rt->rtm_table = RT_TABLE_MAIN;
    rt->rtm_protocol = RTPROT_BOOT;
    rt->rtm_scope = RT_SCOPE_UNIVERSE;
    rt->rtm_type = RTN_UNICAST;

    // 添加目标地址属性
    rta = (struct rtattr*)((char*)nh + nh->nlmsg_len);

    if (is_ipv6) {
        // IPv6 路由
        rt->rtm_dst_len = route->ipv6.prefix_len;

        rta->rta_type = RTA_DST;
        rta->rta_len = RTA_LENGTH(16);
        memcpy(RTA_DATA(rta), route->ipv6.dst.addr, 16);
        nh->nlmsg_len += RTA_LENGTH(16);

        // 添加网关属性（如果非零）
        int has_gateway = 0;
        for (int i = 0; i < 16; i++) {
            if (route->ipv6.gateway.addr[i] != 0) {
                has_gateway = 1;
                break;
            }
        }

        if (has_gateway) {
            rta = (struct rtattr*)((char*)nh + nh->nlmsg_len);
            rta->rta_type = RTA_GATEWAY;
            rta->rta_len = RTA_LENGTH(16);
            memcpy(RTA_DATA(rta), route->ipv6.gateway.addr, 16);
            nh->nlmsg_len += RTA_LENGTH(16);
            rt->rtm_scope = RT_SCOPE_UNIVERSE;
        } else {
            rt->rtm_scope = RT_SCOPE_LINK;
        }

        ROUTE_DEBUG("[ROUTE] Sending IPv6 %s: dst=%s/%u, iface=%u",
                   (cmd == RTM_NEWROUTE) ? "RTM_NEWROUTE" : "RTM_DELROUTE",
                   ipv6_to_str(route->ipv6.dst.addr, ip_str, sizeof(ip_str)),
                   route->ipv6.prefix_len, route->iface_idx);
    } else {
        // IPv4 路由
        uint32_t mask = route->ipv4.mask;
        int prefix_len = 0;
        while (mask) {
            prefix_len += (mask & 1);
            mask >>= 1;
        }
        rt->rtm_dst_len = prefix_len;

        rta->rta_type = RTA_DST;
        rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
        memcpy(RTA_DATA(rta), &route->ipv4.dst, sizeof(uint32_t));
        nh->nlmsg_len += RTA_LENGTH(sizeof(uint32_t));

        // 添加网关属性（如果非零）
        if (route->ipv4.gateway != 0) {
            rta = (struct rtattr*)((char*)nh + nh->nlmsg_len);
            rta->rta_type = RTA_GATEWAY;
            rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
            memcpy(RTA_DATA(rta), &route->ipv4.gateway, sizeof(uint32_t));
            nh->nlmsg_len += RTA_LENGTH(sizeof(uint32_t));
            rt->rtm_scope = RT_SCOPE_UNIVERSE;
        } else {
            rt->rtm_scope = RT_SCOPE_LINK;
        }

        ROUTE_DEBUG("[ROUTE] Sending IPv4 %s: dst=%s, gateway=%s, iface=%u",
                   (cmd == RTM_NEWROUTE) ? "RTM_NEWROUTE" : "RTM_DELROUTE",
                   ipv4_to_str(route->ipv4.dst, ip_str, sizeof(ip_str)),
                   ipv4_to_str(route->ipv4.gateway, ip_str, sizeof(ip_str)),
                   route->iface_idx);
    }

    // 添加接口索引属性
    rta = (struct rtattr*)((char*)nh + nh->nlmsg_len);
    rta->rta_type = RTA_OIF;
    rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
    memcpy(RTA_DATA(rta), &route->iface_idx, sizeof(uint32_t));
    nh->nlmsg_len += RTA_LENGTH(sizeof(uint32_t));

    // 发送消息
    ssize_t sent = send(g_netlink_sock, buf, nh->nlmsg_len, 0);
    if (sent < 0) {
        ROUTE_ERROR("[ROUTE] Failed to send netlink message: errno=%d (%s)",
                   errno, strerror(errno));
        return -1;
    }

    if ((size_t)sent != nh->nlmsg_len) {
        ROUTE_ERROR("[ROUTE] Partial send: %zd/%u bytes", sent, nh->nlmsg_len);
        return -1;
    }

    // 等待 ACK 响应
    char recv_buf[4096];
    ssize_t recv_len = recv(g_netlink_sock, recv_buf, sizeof(recv_buf), 0);
    if (recv_len < 0) {
        ROUTE_ERROR("[ROUTE] Failed to receive netlink response: errno=%d", errno);
        return -1;
    }

    // 检查 ACK
    struct nlmsghdr* resp = (struct nlmsghdr*)recv_buf;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr* err = NLMSG_DATA(resp);
        if (err->error < 0) {
            ROUTE_ERROR("[ROUTE] Netlink error: %s", strerror(-err->error));
            return -1;
        }
    }

    ROUTE_DEBUG("[ROUTE] Route operation completed successfully");
    return 0;
}

/// 查询接口索引
static int linux_get_iface_index(const char* ifname) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ROUTE_ERROR("[ROUTE] Failed to create socket for iface lookup: errno=%d", errno);
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        ROUTE_ERROR("[ROUTE] Failed to get interface index for %s: errno=%d",
                   ifname, errno);
        close(sock);
        return -1;
    }

    close(sock);
    ROUTE_DEBUG("[ROUTE] Interface %s has index %d", ifname, ifr.ifr_ifindex);
    return ifr.ifr_ifindex;
}

#endif // PLATFORM_LINUX

// ========================================
// macOS: Routing Sockets
// ========================================

#ifdef PLATFORM_MACOS

/// macOS: 添加路由（支持 IPv4/IPv6）
static int bsd_route_add(const route_entry_t* route) {
    int sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (sock < 0) {
        ROUTE_ERROR("[ROUTE] Failed to create routing socket: errno=%d (%s)",
                   errno, strerror(errno));
        return -1;
    }

    char msg[2048];  // 增加缓冲区以支持 IPv6
    struct rt_msghdr* rtm = (struct rt_msghdr*)msg;
    memset(msg, 0, sizeof(msg));

    // 设置路由消息头
    rtm->rtm_msglen = sizeof(struct rt_msghdr);
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = RTM_ADD;
    rtm->rtm_flags = RTF_UP | RTF_STATIC;
    rtm->rtm_pid = getpid();
    rtm->rtm_seq = 1;

    int is_ipv6 = (route->family == ROUTE_AF_INET6);
    char* ptr = (char*)(rtm + 1);
    char ip_str[64];

    if (is_ipv6) {
        // IPv6 路由
        rtm->rtm_flags |= RTF_CLONING;
        rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_IFP;

        // 检查是否有网关
        int has_gateway = 0;
        for (int i = 0; i < 16; i++) {
            if (route->ipv6.gateway.addr[i] != 0) {
                has_gateway = 1;
                break;
            }
        }

        if (has_gateway) {
            rtm->rtm_flags |= RTF_GATEWAY;
        } else {
            rtm->rtm_flags |= RTF_CLONING;
        }

        // 目标地址 (sockaddr_in6)
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)ptr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_len = sizeof(struct sockaddr_in6);
        memcpy(&sa6->sin6_addr, route->ipv6.dst.addr, 16);
        ptr += sizeof(struct sockaddr_in6);
        rtm->rtm_msglen += sizeof(struct sockaddr_in6);

        // 网关地址
        sa6 = (struct sockaddr_in6*)ptr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_len = sizeof(struct sockaddr_in6);
        if (has_gateway) {
            memcpy(&sa6->sin6_addr, route->ipv6.gateway.addr, 16);
        }
        ptr += sizeof(struct sockaddr_in6);
        rtm->rtm_msglen += sizeof(struct sockaddr_in6);

        // 掩码
        sa6 = (struct sockaddr_in6*)ptr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_len = sizeof(struct sockaddr_in6);
        memcpy(&sa6->sin6_addr, route->ipv6.mask.prefix, 16);
        ptr += sizeof(struct sockaddr_in6);
        rtm->rtm_msglen += sizeof(struct sockaddr_in6);

        ROUTE_DEBUG("[ROUTE] Sending IPv6 RTM_ADD: dst=%s/%u, iface=%u",
                   ipv6_to_str(route->ipv6.dst.addr, ip_str, sizeof(ip_str)),
                   route->ipv6.prefix_len, route->iface_idx);
    } else {
        // IPv4 路由
        rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_IFP;

        if (route->ipv4.gateway != 0) {
            rtm->rtm_flags |= RTF_GATEWAY;
        } else {
            rtm->rtm_flags |= RTF_CLONING;
        }

        struct sockaddr_in* sa;

        // 目标地址
        sa = (struct sockaddr_in*)ptr;
        sa->sin_family = AF_INET;
        sa->sin_len = sizeof(struct sockaddr_in);
        sa->sin_addr.s_addr = route->ipv4.dst;
        ptr += sizeof(struct sockaddr_in);
        rtm->rtm_msglen += sizeof(struct sockaddr_in);

        // 网关地址
        sa = (struct sockaddr_in*)ptr;
        sa->sin_family = AF_INET;
        sa->sin_len = sizeof(struct sockaddr_in);
        sa->sin_addr.s_addr = route->ipv4.gateway ? route->ipv4.gateway : route->ipv4.dst;
        ptr += sizeof(struct sockaddr_in);
        rtm->rtm_msglen += sizeof(struct sockaddr_in);

        // 掩码
        sa = (struct sockaddr_in*)ptr;
        sa->sin_family = AF_INET;
        sa->sin_len = sizeof(struct sockaddr_in);
        sa->sin_addr.s_addr = route->ipv4.mask;
        ptr += sizeof(struct sockaddr_in);
        rtm->rtm_msglen += sizeof(struct sockaddr_in);

        ROUTE_DEBUG("[ROUTE] Sending IPv4 RTM_ADD: dst=%s, gateway=%s, iface=%u",
                   ipv4_to_str(route->ipv4.dst, ip_str, sizeof(ip_str)),
                   ipv4_to_str(route->ipv4.gateway, ip_str, sizeof(ip_str)),
                   route->iface_idx);
    }

    // 设置接口索引
    rtm->rtm_index = (unsigned short)route->iface_idx;

    // 发送消息
    ssize_t ret = write(sock, msg, rtm->rtm_msglen);
    close(sock);

    if (ret < 0 || (size_t)ret != rtm->rtm_msglen) {
        ROUTE_ERROR("[ROUTE] Failed to send routing message: ret=%zd, errno=%d",
                   ret, errno);
        return -1;
    }

    ROUTE_DEBUG("[ROUTE] Route added successfully");
    return 0;
}

/// macOS/iOS: 删除路由（支持 IPv4/IPv6）
static int bsd_route_delete(const route_entry_t* route) {
    int sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (sock < 0) {
        ROUTE_ERROR("[ROUTE] Failed to create routing socket: errno=%d", errno);
        return -1;
    }

    char msg[2048];
    struct rt_msghdr* rtm = (struct rt_msghdr*)msg;
    memset(msg, 0, sizeof(msg));

    // 设置路由消息头
    rtm->rtm_msglen = sizeof(struct rt_msghdr);
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = RTM_DELETE;
    rtm->rtm_flags = RTF_UP | RTF_STATIC;
    rtm->rtm_pid = getpid();
    rtm->rtm_seq = 1;

    int is_ipv6 = (route->family == ROUTE_AF_INET6);
    char* ptr = (char*)(rtm + 1);
    char ip_str[64];

    if (is_ipv6) {
        // IPv6 路由
        rtm->rtm_addrs = RTA_DST | RTA_GATEWAY;

        // 目标地址
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)ptr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_len = sizeof(struct sockaddr_in6);
        memcpy(&sa6->sin6_addr, route->ipv6.dst.addr, 16);
        ptr += sizeof(struct sockaddr_in6);
        rtm->rtm_msglen += sizeof(struct sockaddr_in6);

        // 网关地址
        sa6 = (struct sockaddr_in6*)ptr;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_len = sizeof(struct sockaddr_in6);
        memcpy(&sa6->sin6_addr, route->ipv6.gateway.addr, 16);
        ptr += sizeof(struct sockaddr_in6);
        rtm->rtm_msglen += sizeof(struct sockaddr_in6);

        ROUTE_DEBUG("[ROUTE] Sending IPv6 RTM_DELETE: dst=%s",
                   ipv6_to_str(route->ipv6.dst.addr, ip_str, sizeof(ip_str)));
    } else {
        // IPv4 路由
        rtm->rtm_addrs = RTA_DST | RTA_GATEWAY;

        struct sockaddr_in* sa;

        // 目标地址
        sa = (struct sockaddr_in*)ptr;
        sa->sin_family = AF_INET;
        sa->sin_len = sizeof(struct sockaddr_in);
        sa->sin_addr.s_addr = route->ipv4.dst;
        ptr += sizeof(struct sockaddr_in);
        rtm->rtm_msglen += sizeof(struct sockaddr_in);

        // 网关地址
        sa = (struct sockaddr_in*)ptr;
        sa->sin_family = AF_INET;
        sa->sin_len = sizeof(struct sockaddr_in);
        sa->sin_addr.s_addr = route->ipv4.gateway ? route->ipv4.gateway : route->ipv4.dst;
        ptr += sizeof(struct sockaddr_in);
        rtm->rtm_msglen += sizeof(struct sockaddr_in);

        ROUTE_DEBUG("[ROUTE] Sending IPv4 RTM_DELETE: dst=%s",
                   ipv4_to_str(route->ipv4.dst, ip_str, sizeof(ip_str)));
    }

    ssize_t ret = write(sock, msg, rtm->rtm_msglen);
    close(sock);

    if (ret < 0 || (size_t)ret != rtm->rtm_msglen) {
        ROUTE_ERROR("[ROUTE] Failed to send RTM_DELETE: ret=%zd, errno=%d", ret, errno);
        return -1;
    }

    ROUTE_DEBUG("[ROUTE] Route deleted successfully");
    return 0;
}

/// macOS/iOS: 查询接口索引
static int bsd_get_iface_index(const char* ifname) {
    struct ifaddrs* ifaddr = NULL;
    if (getifaddrs(&ifaddr) < 0) {
        ROUTE_ERROR("[ROUTE] getifaddrs failed: errno=%d (%s)", errno, strerror(errno));
        return -1;
    }

    int iface_idx = -1;
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, ifname) == 0) {
            // macOS: 使用 if_nametoindex 获取索引
            iface_idx = if_nametoindex(ifname);
            break;
        }
    }

    freeifaddrs(ifaddr);

    if (iface_idx < 0) {
        ROUTE_ERROR("[ROUTE] Interface %s not found", ifname);
    } else {
        ROUTE_DEBUG("[ROUTE] Interface %s has index %d", ifname, iface_idx);
    }

    return iface_idx;
}

/// macOS: 查询路由表
/// 返回实际获取的路由数量，失败返回 -1
static int bsd_route_list(route_entry_t* routes, int max_count) {
    int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    size_t len;
    char* buf = NULL;
    int count = 0;

    // 首先获取所需缓冲区大小
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        ROUTE_ERROR("[ROUTE] sysctl size failed: errno=%d (%s)", errno, strerror(errno));
        return -1;
    }

    // 分配缓冲区
    buf = malloc(len);
    if (!buf) {
        ROUTE_ERROR("[ROUTE] malloc failed");
        return -1;
    }

    // 获取路由表
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        ROUTE_ERROR("[ROUTE] sysctl get failed: errno=%d (%s)", errno, strerror(errno));
        free(buf);
        return -1;
    }

    // 解析路由表
    char* next = buf;
    char* limit = buf + len;

    while (next < limit) {
        struct rt_msghdr* rtm = (struct rt_msghdr*)next;

        if (rtm->rtm_msglen == 0) {
            break;
        }

        // 只处理已激活的路由
        if ((rtm->rtm_flags & RTF_UP) == 0) {
            next += rtm->rtm_msglen;
            continue;
        }

        // 解析 sockaddr 结构
        struct sockaddr* sa = (struct sockaddr*)(rtm + 1);

        // 提取目标地址、掩码、网关和接口信息
        struct sockaddr_in* dst = NULL;
        struct sockaddr_in* mask = NULL;
        struct sockaddr_in* gateway = NULL;
        int iface_idx = 0;

        // 遍历所有 sockaddr
        for (int i = 0; i < RTAX_MAX; i++) {
            if ((rtm->rtm_addrs & (1 << i)) == 0) continue;

            if (sa->sa_family == AF_INET) {
                struct sockaddr_in* sa_in = (struct sockaddr_in*)sa;
                switch (i) {
                    case RTAX_DST:
                        dst = sa_in;
                        break;
                    case RTAX_NETMASK:
                        mask = sa_in;
                        break;
                    case RTAX_GATEWAY:
                        gateway = sa_in;
                        break;
                }
            } else if (sa->sa_family == AF_LINK) {
                struct sockaddr_dl* sdl = (struct sockaddr_dl*)sa;
                iface_idx = sdl->sdl_index;
            }

            // 移动到下一个 sockaddr
            sa = (struct sockaddr*)((char*)sa + (sa->sa_len ? sa->sa_len : sizeof(struct sockaddr)));
        }

        // 填充路由条目（仅当 routes 不为 null 且未达到 max_count）
        if (dst) {
            if (routes && count < max_count) {
                routes[count].family = ROUTE_AF_INET;
                routes[count].ipv4.dst = dst->sin_addr.s_addr;
                routes[count].ipv4.mask = mask ? mask->sin_addr.s_addr : 0xFFFFFFFF;
                routes[count].ipv4.gateway = gateway ? gateway->sin_addr.s_addr : 0;
                routes[count].iface_idx = iface_idx;
                routes[count].metric = 0;

                char dst_str[32], mask_str[32];
                ROUTE_DEBUG("[ROUTE] Route: dst=%s mask=%s gateway=%s iface=%d",
                           inet_ntop(AF_INET, &dst->sin_addr, dst_str, sizeof(dst_str)),
                           mask ? inet_ntop(AF_INET, &mask->sin_addr, mask_str, sizeof(mask_str)) : "255.255.255.255",
                           gateway ? inet_ntoa(gateway->sin_addr) : "0.0.0.0",
                           iface_idx);
            }
            count++;
        }

        next += rtm->rtm_msglen;
    }

    free(buf);
    ROUTE_INFO("[ROUTE] Listed %d routes", count);
    return count;
}

#endif // PLATFORM_MACOS

// ========================================
// Windows: IP Helper API
// ========================================

#ifdef PLATFORM_WINDOWS

/// 初始化 Winsock
static int winsock_init(void) {
    if (g_winsock_initialized) {
        return 0;
    }

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        ROUTE_ERROR("[ROUTE] WSAStartup failed");
        return -1;
    }

    g_winsock_initialized = 1;
    ROUTE_DEBUG("[ROUTE] Winsock initialized");
    return 0;
}

/// Windows: 添加 IPv4 路由
static int windows_route_add_ipv4(const route_entry_t* route) {
    MIB_IPFORWARDROW row;
    memset(&row, 0, sizeof(row));

    row.dwForwardDest = route->ipv4.dst;
    row.dwForwardMask = route->ipv4.mask;
    row.dwForwardNextHop = route->ipv4.gateway ? route->ipv4.gateway : route->ipv4.dst;
    row.dwForwardIfIndex = route->iface_idx;
    row.dwForwardType = route->ipv4.gateway ? MIB_IPROUTE_TYPE_INDIRECT : MIB_IPROUTE_TYPE_DIRECT;
    row.dwForwardProto = MIB_IPPROTO_NETMGMT;
    row.dwForwardAge = 0;
    row.dwForwardNextHopAS = 0;
    row.dwForwardMetric1 = route->metric > 0 ? route->metric : 1;
    row.dwForwardMetric2 = 0;
    row.dwForwardMetric3 = 0;
    row.dwForwardMetric4 = 0;
    row.dwForwardMetric5 = 0;

    char ip_buf[16];
    ROUTE_DEBUG("[ROUTE] CreateIpForwardEntry (IPv4): dst=%s, mask=%s, gateway=%s, iface=%u",
               ipv4_to_str(row.dwForwardDest, ip_buf, sizeof(ip_buf)),
               ipv4_to_str(row.dwForwardMask, ip_buf, sizeof(ip_buf)),
               ipv4_to_str(row.dwForwardNextHop, ip_buf, sizeof(ip_buf)),
               route->iface_idx);

    DWORD status = CreateIpForwardEntry(&row);
    if (status != NO_ERROR) {
        if (status == ERROR_OBJECT_ALREADY_EXISTS) {
            ROUTE_WARN("[ROUTE] Route already exists (may be OK)");
            return 0;
        }
        ROUTE_ERROR("[ROUTE] CreateIpForwardEntry failed: status=%lu", status);
        return -1;
    }

    return 0;
}

/// Windows: 添加 IPv6 路由
static int windows_route_add_ipv6(const route_entry_t* route) {
    // Windows Vista+ 使用 CreateIpForwardEntry2
    // 需要动态加载函数以支持旧系统

    typedef DWORD (WINAPI *PFN_CreateIpForwardEntry2)(PMIB_IPFORWARD_ROW2);
    typedef DWORD (WINAPI *PFN_FreeMibTable)(PVOID);

    static HMODULE h_iphlpapi = NULL;
    static PFN_CreateIpForwardEntry2 pCreateIpForwardEntry2 = NULL;
    static PFN_FreeMibTable pFreeMibTable = NULL;

    if (!h_iphlpapi) {
        h_iphlpapi = LoadLibraryA("iphlpapi.dll");
        if (!h_iphlpapi) {
            ROUTE_ERROR("[ROUTE] Failed to load iphlpapi.dll");
            return -1;
        }

        pCreateIpForwardEntry2 = (PFN_CreateIpForwardEntry2)
            GetProcAddress(h_iphlpapi, "CreateIpForwardEntry2");
        pFreeMibTable = (PFN_FreeMibTable)
            GetProcAddress(h_iphlpapi, "FreeMibTable");
    }

    if (!pCreateIpForwardEntry2) {
        ROUTE_ERROR("[ROUTE] IPv6 routing not supported on this Windows version");
        return -1;
    }

    MIB_IPFORWARD_ROW2 row;
    memset(&row, 0, sizeof(row));

    // MIB_IPFORWARD_ROW2 不需要 l3Protocol 字段
    row.InterfaceIndex = route->iface_idx;

    // 设置目标前缀
    row.DestinationPrefix.PrefixLength = route->ipv6.prefix_len;
    row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    memcpy(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte,
           route->ipv6.dst.addr, 16);

    // 检查是否有网关
    int has_gateway = 0;
    for (int i = 0; i < 16; i++) {
        if (route->ipv6.gateway.addr[i] != 0) {
            has_gateway = 1;
            break;
        }
    }

    if (has_gateway) {
        row.NextHop.Ipv6.sin6_family = AF_INET6;
        memcpy(row.NextHop.Ipv6.sin6_addr.u.Byte, route->ipv6.gateway.addr, 16);
    }

    // 设置 Metric
    row.Metric = route->metric > 0 ? route->metric : 1;

    char ip_str[64];
    ROUTE_DEBUG("[ROUTE] CreateIpForwardEntry2 (IPv6): dst=%s/%u, iface=%u",
               ipv6_to_str(route->ipv6.dst.addr, ip_str, sizeof(ip_str)),
               route->ipv6.prefix_len, route->iface_idx);

    DWORD status = pCreateIpForwardEntry2(&row);
    if (status != NO_ERROR && status != ERROR_OBJECT_ALREADY_EXISTS) {
        ROUTE_ERROR("[ROUTE] CreateIpForwardEntry2 failed: status=%lu", status);
        return -1;
    }

    return 0;
}

/// Windows: 添加路由（支持 IPv4/IPv6）
static int windows_route_add(const route_entry_t* route) {
    if (winsock_init() < 0) {
        return -1;
    }

    if (route->family == ROUTE_AF_INET6) {
        return windows_route_add_ipv6(route);
    } else {
        return windows_route_add_ipv4(route);
    }
}

/// Windows: 删除 IPv4 路由
static int windows_route_delete_ipv4(const route_entry_t* route) {
    PMIB_IPFORWARDTABLE table = NULL;
    ULONG size = 0;

    // 第一次调用获取所需大小
    DWORD result = GetIpForwardTable(NULL, &size, FALSE);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        ROUTE_ERROR("[ROUTE] GetIpForwardTable (size query) failed: %lu", result);
        return -1;
    }

    table = (PMIB_IPFORWARDTABLE)malloc(size);
    if (!table) {
        ROUTE_ERROR("[ROUTE] Memory allocation failed");
        return -1;
    }

    result = GetIpForwardTable(table, &size, FALSE);
    if (result != NO_ERROR) {
        ROUTE_ERROR("[ROUTE] GetIpForwardTable failed: %lu", result);
        free(table);
        return -1;
    }

    // 查找匹配的路由
    MIB_IPFORWARDROW target_row;
    int found = 0;

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_IPFORWARDROW* row = &table->table[i];
        if (row->dwForwardDest == route->ipv4.dst &&
            row->dwForwardMask == route->ipv4.mask &&
            row->dwForwardIfIndex == route->iface_idx) {
            memcpy(&target_row, row, sizeof(MIB_IPFORWARDROW));
            found = 1;
            break;
        }
    }

    free(table);

    if (!found) {
        ROUTE_WARN("[ROUTE] Route not found for deletion (may be OK)");
        return 0;
    }

    char ip_buf[16];
    ROUTE_DEBUG("[ROUTE] DeleteIpForwardEntry (IPv4): dst=%s",
               ipv4_to_str(target_row.dwForwardDest, ip_buf, sizeof(ip_buf)));

    result = DeleteIpForwardEntry(&target_row);
    if (result != NO_ERROR) {
        ROUTE_ERROR("[ROUTE] DeleteIpForwardEntry failed: %lu", result);
        return -1;
    }

    return 0;
}

/// Windows: 删除 IPv6 路由
static int windows_route_delete_ipv6(const route_entry_t* route) {
    typedef DWORD (WINAPI *PFN_DeleteIpForwardEntry2)(PMIB_IPFORWARD_ROW2);
    typedef DWORD (WINAPI *PFN_GetIpForwardTable2)(ADDRESS_FAMILY, PMIB_IPFORWARD_TABLE2*);
    typedef DWORD (WINAPI *PFN_FreeMibTable)(PVOID);

    static PFN_DeleteIpForwardEntry2 pDeleteIpForwardEntry2 = NULL;
    static PFN_GetIpForwardTable2 pGetIpForwardTable2 = NULL;
    static PFN_FreeMibTable pFreeMibTable = NULL;

    // 首次调用时加载函数
    if (!pDeleteIpForwardEntry2) {
        HMODULE h_iphlpapi = LoadLibraryA("iphlpapi.dll");
        if (!h_iphlpapi) {
            ROUTE_ERROR("[ROUTE] Failed to load iphlpapi.dll");
            return -1;
        }

        pDeleteIpForwardEntry2 = (PFN_DeleteIpForwardEntry2)
            GetProcAddress(h_iphlpapi, "DeleteIpForwardEntry2");
        pGetIpForwardTable2 = (PFN_GetIpForwardTable2)
            GetProcAddress(h_iphlpapi, "GetIpForwardTable2");
        pFreeMibTable = (PFN_FreeMibTable)
            GetProcAddress(h_iphlpapi, "FreeMibTable");
    }

    if (!pDeleteIpForwardEntry2 || !pGetIpForwardTable2) {
        ROUTE_ERROR("[ROUTE] IPv6 routing not supported on this Windows version");
        return -1;
    }

    PMIB_IPFORWARD_TABLE2 table = NULL;
    DWORD result = pGetIpForwardTable2(AF_INET6, &table);
    if (result != NO_ERROR) {
        ROUTE_ERROR("[ROUTE] GetIpForwardTable2 failed: %lu", result);
        return -1;
    }

    // 查找匹配的路由
    MIB_IPFORWARD_ROW2* target_row = NULL;
    char ip_str[64];

    for (ULONG i = 0; i < table->NumEntries; i++) {
        MIB_IPFORWARD_ROW2* row = &table->Table[i];

        if (row->DestinationPrefix.PrefixLength != route->ipv6.prefix_len) {
            continue;
        }

        // 比较目标地址
        if (memcmp(row->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte,
                   route->ipv6.dst.addr, 16) != 0) {
            continue;
        }

        if (row->InterfaceIndex != route->iface_idx) {
            continue;
        }

        target_row = row;
        break;
    }

    int ret = 0;
    if (target_row) {
        ROUTE_DEBUG("[ROUTE] DeleteIpForwardEntry2 (IPv6): dst=%s",
                   ipv6_to_str(route->ipv6.dst.addr, ip_str, sizeof(ip_str)));

        result = pDeleteIpForwardEntry2(target_row);
        if (result != NO_ERROR) {
            ROUTE_ERROR("[ROUTE] DeleteIpForwardEntry2 failed: %lu", result);
            ret = -1;
        }
    } else {
        ROUTE_WARN("[ROUTE] IPv6 route not found for deletion (may be OK)");
    }

    if (pFreeMibTable) {
        pFreeMibTable(table);
    } else {
        free(table);
    }

    return ret;
}

/// Windows: 删除路由（支持 IPv4/IPv6）
static int windows_route_delete(const route_entry_t* route) {
    if (winsock_init() < 0) {
        return -1;
    }

    if (route->family == ROUTE_AF_INET6) {
        return windows_route_delete_ipv6(route);
    } else {
        return windows_route_delete_ipv4(route);
    }
}

// Windows: 查询 IPv4 路由表
static int windows_route_list_ipv4(route_entry_t* routes, int max_count) {
    PMIB_IPFORWARDTABLE table = NULL;
    ULONG size = 0;

    ROUTE_DEBUG("[ROUTE] Querying IPv4 routing table (max_count=%d)...", max_count);

    // 第一次调用获取所需大小
    DWORD result = GetIpForwardTable(NULL, &size, FALSE);
    ROUTE_DEBUG("[ROUTE] GetIpForwardTable size query result=%lu, size=%lu", result, size);

    if (result != ERROR_INSUFFICIENT_BUFFER) {
        ROUTE_ERROR("[ROUTE] GetIpForwardTable (size query) failed: %lu", result);
        return -1;
    }

    table = (PMIB_IPFORWARDTABLE)malloc(size);
    if (!table) {
        ROUTE_ERROR("[ROUTE] Memory allocation failed");
        return -1;
    }

    result = GetIpForwardTable(table, &size, FALSE);
    ROUTE_DEBUG("[ROUTE] GetIpForwardTable data result=%lu, entries=%lu", result, table->dwNumEntries);

    if (result != NO_ERROR) {
        ROUTE_ERROR("[ROUTE] GetIpForwardTable failed: %lu", result);
        free(table);
        return -1;
    }

    // 如果只是查询数量（routes 为 null），返回路由数量
    if (routes == NULL) {
        int count = (int)table->dwNumEntries;
        free(table);
        ROUTE_INFO("[ROUTE] Route count query: %d entries", count);
        return count;
    }

    ROUTE_DEBUG("[ROUTE] Converting %lu routes to internal format...", table->dwNumEntries);

    // 转换路由表到我们的格式
    int count = 0;
    for (DWORD i = 0; i < table->dwNumEntries && count < max_count; i++) {
        MIB_IPFORWARDROW* row = &table->table[i];

        ROUTE_DEBUG("[ROUTE] Route %lu: dst=%08lx mask=%08lx gateway=%08lx ifidx=%lu metric=%lu",
                   i, row->dwForwardDest, row->dwForwardMask,
                   row->dwForwardNextHop, row->dwForwardIfIndex, row->dwForwardMetric1);

        routes[count].family = ROUTE_AF_INET;
        routes[count].ipv4.dst = row->dwForwardDest;
        routes[count].ipv4.mask = row->dwForwardMask;
        routes[count].ipv4.gateway = row->dwForwardNextHop;
        routes[count].iface_idx = (int)row->dwForwardIfIndex;
        routes[count].metric = (int)row->dwForwardMetric1;

        count++;
    }

    free(table);
    ROUTE_INFO("[ROUTE] Listed %d IPv4 routes", count);
    return count;
}

// Windows: 查询路由表（支持 IPv4/IPv6）
static int windows_route_list(route_entry_t* routes, int max_count) {
    ROUTE_INFO("[ROUTE] windows_route_list called: routes=%p, max_count=%d", routes, max_count);

    if (winsock_init() < 0) {
        ROUTE_ERROR("[ROUTE] winsock_init failed");
        return -1;
    }

    // 当前只实现 IPv4
    return windows_route_list_ipv4(routes, max_count);
}

/// Windows: 检查管理员权限
int route_has_admin_privileges(void) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return 0;
    }

    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    PSID admin_sid = NULL;
    BOOL is_admin = FALSE;

    if (AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_sid)) {
        if (!CheckTokenMembership(NULL, admin_sid, &is_admin)) {
            is_admin = FALSE;
        }
        FreeSid(admin_sid);
    }

    CloseHandle(hToken);
    return is_admin ? 1 : 0;
}

/// Windows: 查询接口索引（支持 IPv4/IPv6）
static int windows_get_iface_index(const char* ifname) {
    // Windows 使用接口名称或 GUID
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);

    if (!pAddresses) {
        ROUTE_ERROR("[ROUTE] Memory allocation failed");
        return -1;
    }

    // 使用 AF_UNSPEC 获取所有适配器（IPv4 和 IPv6）
    DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
                                        NULL, pAddresses, &outBufLen);
    if (result == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (!pAddresses) return -1;
        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
                                      NULL, pAddresses, &outBufLen);
    }

    if (result != NO_ERROR) {
        ROUTE_ERROR("[ROUTE] GetAdaptersAddresses failed: %lu", result);
        free(pAddresses);
        return -1;
    }

    int iface_idx = -1;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;

    // Debug: Print all adapters to help identify Wintun adapter
    ROUTE_INFO("[ROUTE] Looking for interface: %s", ifname);

    while (pCurrAddresses) {
        // Print adapter info for debugging
        if (pCurrAddresses->Description) {
            ROUTE_INFO("[ROUTE] Found adapter: %s (description: %ls)", pCurrAddresses->AdapterName, pCurrAddresses->Description);
        }

        // 匹配适配器名称（AdapterName 是 char*，格式为 GUID）
        if (strcmp(pCurrAddresses->AdapterName, ifname) == 0) {
            iface_idx = (int)pCurrAddresses->Ipv6IfIndex;
            if (iface_idx <= 0) {
                iface_idx = (int)pCurrAddresses->IfIndex;
            }
            ROUTE_INFO("[ROUTE] Interface %s has index %d (by AdapterName)", ifname, iface_idx);
            break;
        }

        // 同时也匹配描述/友好名称（Wintun 适配器使用此字段）
        // Description 是 WCHAR*，需要转换为比较
        if (pCurrAddresses->Description) {
            // 转换 ifname 到宽字符
            WCHAR wide_ifname[256];
            MultiByteToWideChar(CP_UTF8, 0, ifname, -1, wide_ifname, 256);

            if (wcscmp(pCurrAddresses->Description, wide_ifname) == 0) {
                iface_idx = (int)pCurrAddresses->Ipv6IfIndex;
                if (iface_idx <= 0) {
                    iface_idx = (int)pCurrAddresses->IfIndex;
                }
                ROUTE_INFO("[ROUTE] Interface %s has index %d (by Description)", ifname, iface_idx);
                break;
            }
        }

        pCurrAddresses = pCurrAddresses->Next;
    }

    free(pAddresses);

    if (iface_idx < 0) {
        ROUTE_ERROR("[ROUTE] Interface %s not found", ifname);
    }

    return iface_idx;
}

#endif // PLATFORM_WINDOWS

// ==================== 公共 API 实现 ====================

/// 初始化路由模块
int route_init(void) {
    if (g_route_initialized) {
        return 0;
    }

#ifdef PLATFORM_LINUX
    if (netlink_init() < 0) {
        return -1;
    }
#endif

#ifdef PLATFORM_WINDOWS
    if (winsock_init() < 0) {
        return -1;
    }
#endif

    g_route_initialized = 1;
    ROUTE_DEBUG("[ROUTE] Route module initialized");
    return 0;
}

/// 清理路由模块资源
void route_cleanup(void) {
#ifdef PLATFORM_LINUX
    if (g_netlink_sock >= 0) {
        close(g_netlink_sock);
        g_netlink_sock = -1;
    }
#endif

#ifdef PLATFORM_WINDOWS
    if (g_winsock_initialized) {
        WSACleanup();
        g_winsock_initialized = 0;
    }
#endif

    g_route_initialized = 0;
    ROUTE_DEBUG("[ROUTE] Route module cleaned up");
}

/// 添加路由
int route_add(const route_entry_t* route) {
    if (!route) {
        ROUTE_ERROR("[ROUTE] route_add: NULL pointer");
        return -1;
    }

    if (!g_route_initialized) {
        route_init();
    }

#ifdef PLATFORM_LINUX
    return netlink_send_route_msg(RTM_NEWROUTE, route);
#endif

#ifdef PLATFORM_MACOS
    return bsd_route_add(route);
#endif

#ifdef PLATFORM_IOS
    // iOS doesn't support route management due to sandbox restrictions
    ROUTE_ERROR("[ROUTE] Route operations not supported on iOS");
    return -1;
#endif

#ifdef PLATFORM_WINDOWS
    return windows_route_add(route);
#endif

#ifdef PLATFORM_OTHER
    ROUTE_ERROR("[ROUTE] Route operations not supported on this platform");
    return -1;
#endif
}

/// 删除路由
int route_delete(const route_entry_t* route) {
    if (!route) {
        ROUTE_ERROR("[ROUTE] route_delete: NULL pointer");
        return -1;
    }

    if (!g_route_initialized) {
        route_init();
    }

#ifdef PLATFORM_LINUX
    return netlink_send_route_msg(RTM_DELROUTE, route);
#endif

#ifdef PLATFORM_MACOS
    return bsd_route_delete(route);
#endif

#ifdef PLATFORM_IOS
    // iOS doesn't support route management due to sandbox restrictions
    ROUTE_ERROR("[ROUTE] Route operations not supported on iOS");
    return -1;
#endif

#ifdef PLATFORM_WINDOWS
    return windows_route_delete(route);
#endif

#ifdef PLATFORM_OTHER
    ROUTE_ERROR("[ROUTE] Route operations not supported on this platform");
    return -1;
#endif
}

/// 查询路由表
int route_list(route_entry_t* routes, int max_count) {
    if (!g_route_initialized) {
        route_init();
    }

#ifdef PLATFORM_MACOS
    return bsd_route_list(routes, max_count);
#endif

#ifdef PLATFORM_LINUX
    // TODO: Linux implementation
    ROUTE_WARN("[ROUTE] route_list not yet implemented for Linux");
    return 0;
#endif

#ifdef PLATFORM_WINDOWS
    return windows_route_list(routes, max_count);
#endif

    ROUTE_WARN("[ROUTE] route_list not yet implemented for this platform");
    return 0;
}

/// 查询接口索引
int route_get_iface_index(const char* ifname) {
    if (!ifname || !*ifname) {
        ROUTE_ERROR("[ROUTE] route_get_iface_index: Invalid interface name");
        return -1;
    }

#ifdef PLATFORM_LINUX
    return linux_get_iface_index(ifname);
#endif

#ifdef PLATFORM_MACOS
    return bsd_get_iface_index(ifname);
#endif

#ifdef PLATFORM_IOS
    // iOS doesn't support route operations
    ROUTE_ERROR("[ROUTE] Interface index query not supported on iOS");
    return -1;
#endif

#ifdef PLATFORM_WINDOWS
    return windows_get_iface_index(ifname);
#endif

#ifdef PLATFORM_OTHER
    ROUTE_ERROR("[ROUTE] Interface index query not supported on this platform");
    return -1;
#endif
}

#ifdef PLATFORM_LINUX

/// 设置 Netlink 超时
void route_set_timeout(int timeout_ms) {
    g_netlink_timeout_ms = timeout_ms;
    ROUTE_DEBUG("[ROUTE] Netlink timeout set to %d ms", timeout_ms);
}

#endif // PLATFORM_LINUX
