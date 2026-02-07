// network.c - Cross-platform network interface access
//
// Provides cross-platform network interface IP address retrieval:
// - Linux/macOS: getifaddrs()
// - Windows: GetAdaptersAddresses()

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

// Debug macro - only enabled in debug builds
#ifdef DEBUG
#define NET_DEBUG(fmt, ...) fprintf(stderr, "[NETWORK] " fmt "\n", ##__VA_ARGS__)
#else
#define NET_DEBUG(fmt, ...)
#endif

#define NET_ERROR(fmt, ...) fprintf(stderr, "[NETWORK ERROR] " fmt "\n", ##__VA_ARGS__)
#define NET_WARN(fmt, ...) fprintf(stderr, "[NETWORK WARN] " fmt "\n", ##__VA_ARGS__)
#define NET_INFO(fmt, ...) fprintf(stderr, "[NETWORK] " fmt "\n", ##__VA_ARGS__)

// ==================== 平台检测 ====================

#if !defined(PLATFORM_LINUX) && !defined(PLATFORM_MACOS) && !defined(PLATFORM_WINDOWS) && \
    !defined(OS_UNIX) && !defined(OS_WIN)

    #if defined(__linux__)
        #define PLATFORM_LINUX 1
        #define OS_UNIX 1
    #elif defined(__APPLE__)
        #define PLATFORM_MACOS 1
        #define OS_UNIX 1
    #elif defined(_WIN32) || defined(_WIN64)
        #define PLATFORM_WINDOWS 1
        #define OS_WIN 1
    #else
        #define PLATFORM_OTHER 1
    #endif

#endif

// ==================== 头文件 ====================

#ifdef OS_UNIX
    #include <ifaddrs.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <net/if.h>
#endif

#ifdef OS_WIN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
#endif

// ==================== 类型定义 ====================

/// 本地 IP 地址信息
typedef struct {
    char ip[64];        // IP 地址字符串（IPv4 或 IPv6）
    int is_ipv6;        // 是否为 IPv6
    int is_loopback;    // 是否为回环地址
} ip_info_t;

// ==================== 获取所有本地 IP ====================

/// 获取所有本地 IP 地址（跨平台）
/// ips: 输出数组，最多存储 max_count 个
/// max_count: 数组最大容量
/// 返回: 实际获取的 IP 数量，失败返回 -1
int get_local_ips(ip_info_t* ips, int max_count) {
    if (!ips || max_count <= 0) return -1;

    int count = 0;

#ifdef OS_UNIX
    // POSIX 系统使用 getifaddrs()
    struct ifaddrs* ifaddr = NULL;
    struct ifaddrs* ifa = NULL;

    if (getifaddrs(&ifaddr) == -1) {
        NET_ERROR("[NETWORK] getifaddrs() failed: errno=%d (%s)", errno, strerror(errno));
        return -1;
    }

    // 遍历所有接口
    for (ifa = ifaddr; ifa != NULL && count < max_count; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        int family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {
            // IPv4
            struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ips[count].ip, sizeof(ips[count].ip));
            ips[count].is_ipv6 = 0;
            ips[count].is_loopback = (ntohl(addr->sin_addr.s_addr) >> 24) == 127;
            count++;
        } else if (family == AF_INET6) {
            // IPv6
            struct sockaddr_in6* addr = (struct sockaddr_in6*)ifa->ifa_addr;
            inet_ntop(AF_INET6, &addr->sin6_addr, ips[count].ip, sizeof(ips[count].ip));
            ips[count].is_ipv6 = 1;
            ips[count].is_loopback = IN6_IS_ADDR_LOOPBACK(&addr->sin6_addr);
            count++;
        }
    }

    freeifaddrs(ifaddr);

#elif defined(OS_WIN)
    // Windows 使用 GetAdaptersAddresses()
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        NET_ERROR("[NETWORK] WSAStartup failed");
        return -1;
    }

    // 获取适配器地址
    ULONG out_buf_len = 15000;
    PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)malloc(out_buf_len);

    if (adapters == NULL) {
        WSACleanup();
        return -1;
    }

    DWORD result = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX,
        NULL,
        adapters,
        &out_buf_len);

    if (result != ERROR_SUCCESS) {
        NET_ERROR("[NETWORK] GetAdaptersAddresses failed: %lu", result);
        free(adapters);
        WSACleanup();
        return -1;
    }

    // 遍历所有适配器
    PIP_ADAPTER_ADDRESSES current_adapter = adapters;
    while (current_adapter != NULL && count < max_count) {
        PIP_ADAPTER_UNICAST_ADDRESS first_unicast = current_adapter->FirstUnicastAddress;

        while (first_unicast != NULL && count < max_count) {
            int family = first_unicast->Address.lpSockaddr->sa_family;

            if (family == AF_INET) {
                struct sockaddr_in* addr = (struct sockaddr_in*)first_unicast->Address.lpSockaddr;
                inet_ntop(AF_INET, &addr->sin_addr, ips[count].ip, sizeof(ips[count].ip));
                ips[count].is_ipv6 = 0;
                ips[count].is_loopback = (ntohl(addr->sin_addr.s_addr) >> 24) == 127;
                count++;
            } else if (family == AF_INET6) {
                struct sockaddr_in6* addr = (struct sockaddr_in6*)first_unicast->Address.lpSockaddr;
                inet_ntop(AF_INET6, &addr->sin6_addr, ips[count].ip, sizeof(ips[count].ip));
                ips[count].is_ipv6 = 1;
                ips[count].is_loopback = IN6_IS_ADDR_LOOPBACK(&addr->sin6_addr);
                count++;
            }

            first_unicast = first_unicast->Next;
        }

        current_adapter = current_adapter->Next;
    }

    free(adapters);
    WSACleanup();

#else
    NET_ERROR("[NETWORK] Unsupported platform");
    return -1;
#endif

    NET_DEBUG("[NETWORK] Found %d local IP addresses", count);
    return count;
}

// ==================== 获取主出口 IP ====================

/// 获取主出口 IP（通过创建 UDP socket 连接到外部地址探测）
/// ip_buf: 输出缓冲区，至少 64 字节
/// buf_len: 缓冲区大小
/// 返回: 0 成功，-1 失败
int get_primary_ip(char* ip_buf, size_t buf_len) {
    if (!ip_buf || buf_len < 16) {
        NET_ERROR("[NETWORK] Invalid buffer for primary IP");
        return -1;
    }

    int sockfd = -1;
    int result = -1;

#ifdef OS_UNIX
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);  // 连接到公网端口
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");  // Google DNS

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        NET_ERROR("[NETWORK] socket() failed: errno=%d (%s)", errno, strerror(errno));
        goto cleanup;
    }

    // 连接（不发送数据）
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        NET_ERROR("[NETWORK] connect() failed: errno=%d (%s)", errno, strerror(errno));
        goto cleanup;
    }

    // 获取本地地址
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sockfd, (struct sockaddr*)&local_addr, &addr_len) < 0) {
        NET_ERROR("[NETWORK] getsockname() failed: errno=%d (%s)", errno, strerror(errno));
        goto cleanup;
    }

    // 转换为字符串
    if (!inet_ntop(AF_INET, &local_addr.sin_addr, ip_buf, buf_len)) {
        NET_ERROR("[NETWORK] inet_ntop() failed");
        goto cleanup;
    }

    NET_DEBUG("[NETWORK] Primary IP: %s", ip_buf);
    result = 0;

#elif defined(OS_WIN)
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        NET_ERROR("[NETWORK] WSAStartup failed");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        WSACleanup();
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        NET_ERROR("[NETWORK] connect() failed: errno=%d", WSAGetLastError());
        goto cleanup;
    }

    struct sockaddr_in local_addr;
    int addr_len = sizeof(local_addr);
    if (getsockname(sockfd, (struct sockaddr*)&local_addr, &addr_len) < 0) {
        NET_ERROR("[NETWORK] getsockname() failed: errno=%d", WSAGetLastError());
        goto cleanup;
    }

    if (!inet_ntop(AF_INET, &local_addr.sin_addr, ip_buf, buf_len)) {
        NET_ERROR("[NETWORK] inet_ntop() failed");
        goto cleanup;
    }

    NET_DEBUG("[NETWORK] Primary IP: %s", ip_buf);
    result = 0;

cleanup:
    if (sockfd >= 0) closesocket(sockfd);
    WSACleanup();
    return result;

#else
    NET_ERROR("[NETWORK] Unsupported platform");
    return -1;
#endif

#ifdef OS_UNIX
cleanup:
    if (sockfd >= 0) close(sockfd);
    return result;
#endif
}

// ==================== 根据目标 IP 选择出口 IP ====================

/// 检查 IP 是否是私有地址（RFC1918 或类似）
static int is_private_ip(uint32_t ip) {
    // Network byte order to host byte order
    uint32_t h_ip = ntohl(ip);

    // 10.0.0.0/8
    if ((h_ip & 0xFF000000) == 0x0A000000) return 1;

    // 172.16.0.0/12
    if ((h_ip & 0xFFF00000) == 0xAC100000) return 1;

    // 192.168.0.0/16
    if ((h_ip & 0xFFFF0000) == 0xC0A80000) return 1;

    return 0;
}

/// 检查接口名称是否是 TUN 设备
static int is_tun_device(const char* ifname) {
    if (!ifname) return 0;

    // Check for TUN device prefixes
    const char* tun_prefixes[] = {"tun", "utun", "wg", "wintun", "tap", NULL};
    for (int i = 0; tun_prefixes[i] != NULL; i++) {
        if (strncmp(ifname, tun_prefixes[i], strlen(tun_prefixes[i])) == 0) {
            return 1;
        }
    }
    return 0;
}

/// 根据目标 IP 选择出口 IP（遍历接口，排除 TUN/utun/wintun 设备）
/// target_ip: 目标 IP 地址（如 "111.45.11.5"）- 仅用于日志
/// ip_buf: 输出缓冲区，至少 64 字节
/// buf_len: 缓冲区大小
/// 返回: 0 成功，-1 失败
int select_egress_ip_for_target(const char* target_ip, char* ip_buf, size_t buf_len) {
    if (!ip_buf || buf_len < 16) {
        NET_ERROR("[NETWORK] Invalid buffer for egress IP selection");
        return -1;
    }

#ifdef OS_UNIX
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        NET_ERROR("[NETWORK] getifaddrs failed: errno=%d (%s)", errno, strerror(errno));
        return -1;
    }

    // Find first non-TUN, non-loopback IPv4 interface
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // Skip TUN/utun/wintun devices
        if (is_tun_device(ifa->ifa_name)) {
            continue;
        }

        // Skip loopback
        if (ifa->ifa_flags & IFF_LOOPBACK) {
            continue;
        }

        // Only consider IPv4 addresses
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;

            // Convert to string
            if (!inet_ntop(AF_INET, &addr->sin_addr, ip_buf, buf_len)) {
                NET_ERROR("[NETWORK] inet_ntop() failed for interface %s", ifa->ifa_name);
                freeifaddrs(ifaddr);
                return -1;
            }

            // Skip obvious private IPs (may still be VPN)
            if (is_private_ip(addr->sin_addr.s_addr)) {
                NET_DEBUG("[NETWORK] Skipping private IP %s on interface %s",
                          ip_buf, ifa->ifa_name);
                continue;
            }

            NET_DEBUG("[NETWORK] Found physical egress IP: %s (interface: %s)",
                      ip_buf, ifa->ifa_name);
            freeifaddrs(ifaddr);

            if (target_ip) {
                NET_DEBUG("[NETWORK] Egress IP for %s: %s", target_ip, ip_buf);
            }
            return 0;
        }
    }

    freeifaddrs(ifaddr);

    // Fallback: if no public IP found, try to find first non-TUN private IP
    NET_WARN("[NETWORK] No public egress IP found, checking private IPs...");
    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // Skip TUN/utun/wintun devices
        if (is_tun_device(ifa->ifa_name)) {
            continue;
        }

        // Skip loopback
        if (ifa->ifa_flags & IFF_LOOPBACK) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;

            if (!inet_ntop(AF_INET, &addr->sin_addr, ip_buf, buf_len)) {
                continue;
            }

            NET_WARN("[NETWORK] Using private egress IP: %s (interface: %s)",
                      ip_buf, ifa->ifa_name);
            freeifaddrs(ifaddr);

            if (target_ip) {
                NET_DEBUG("[NETWORK] Egress IP for %s: %s", target_ip, ip_buf);
            }
            return 0;
        }
    }

    freeifaddrs(ifaddr);
    NET_ERROR("[NETWORK] No suitable egress IP found");
    return -1;

#elif defined(OS_WIN)
    // Windows implementation using GetAdaptersAddresses
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    int ret = -1;

    // Allocate memory for adapter addresses
    pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (pAddresses == NULL) {
        NET_ERROR("[NETWORK] Memory allocation failed");
        return -1;
    }

    // Get adapter addresses
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (pAddresses == NULL) {
            NET_ERROR("[NETWORK] Memory allocation failed (retry)");
            return -1;
        }
    }

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddresses, &outBufLen) != NO_ERROR) {
        NET_ERROR("[NETWORK] GetAdaptersAddresses failed");
        free(pAddresses);
        return -1;
    }

    // Iterate through adapters
    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        // Skip TUN/wintun devices
        if (is_tun_device(pCurrAddresses->AdapterName)) {
            pCurrAddresses = pCurrAddresses->Next;
            continue;
        }

        // Loop through unicast addresses
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
        while (pUnicast) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)pUnicast->Address.lpSockaddr;

                if (!inet_ntop(AF_INET, &addr->sin_addr, ip_buf, buf_len)) {
                    continue;
                }

                NET_DEBUG("[NETWORK] Found physical egress IP: %s", ip_buf);
                free(pAddresses);

                if (target_ip) {
                    NET_DEBUG("[NETWORK] Egress IP for %s: %s", target_ip, ip_buf);
                }
                return 0;
            }
            pUnicast = pUnicast->Next;
        }
        pCurrAddresses = pCurrAddresses->Next;
    }

    free(pAddresses);
    NET_ERROR("[NETWORK] No suitable egress IP found on Windows");
    return -1;

#else
    NET_ERROR("[NETWORK] Unsupported platform");
    return -1;
#endif
}
