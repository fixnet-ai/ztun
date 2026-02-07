// route.h - Cross-platform routing management API
//
// Provides cross-platform routing table operations using system APIs:
// - Linux: Netlink sockets (NETLINK_ROUTE)
// - macOS/iOS: Routing sockets (PF_ROUTE)
// - Windows: IP Helper API (iphlpapi.dll)
//
// Design principles:
// - Direct system API calls, no shell commands
// - Cross-platform unified interface
// - Thread-safe (internal locks)
// - Returns -1 on error, 0 on success

#ifndef ROUTE_H
#define ROUTE_H

#include <stdint.h>

// ==================== Platform Detection ====================

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

// ==================== 类型定义 ====================

/// Address family
typedef enum {
    ROUTE_AF_INET = 2,   // IPv4
    ROUTE_AF_INET6 = 10, // IPv6
} route_address_family_t;

/// IPv6 address (128-bit)
typedef struct {
    uint8_t addr[16];    // 16-byte IPv6 address
} route_ipv6_addr_t;

/// IPv6 prefix (128-bit mask)
typedef struct {
    uint8_t prefix[16];  // 16-byte prefix mask
} route_ipv6_prefix_t;

/// Route entry structure (cross-platform, supports IPv4/IPv6)
typedef struct {
    route_address_family_t family;  // Address family (IPv4 or IPv6)

    union {
        struct {
            uint32_t dst;        // IPv4 destination address (network byte order)
            uint32_t mask;       // IPv4 subnet mask (network byte order)
            uint32_t gateway;    // IPv4 gateway (network byte order, 0 means direct)
        } ipv4;

        struct {
            route_ipv6_addr_t dst;     // IPv6 destination address
            route_ipv6_prefix_t mask;  // IPv6 prefix mask
            route_ipv6_addr_t gateway; // IPv6 gateway (zero means direct)
            uint8_t prefix_len;        // IPv6 prefix length (0-128)
        } ipv6;
    };

    uint32_t iface_idx;  // Interface index
    int      metric;     // Route priority
} route_entry_t;

// ==================== Public API ====================

/// Add a route
///
/// Parameters:
///   route: Route entry (destination, mask, gateway, interface index)
///
/// Returns:
///   0 on success, -1 on error
int route_add(const route_entry_t* route);

/// Delete a route
///
/// Parameters:
///   route: Route entry (must match destination, mask, gateway exactly)
///
/// Returns:
///   0 on success, -1 on error
int route_delete(const route_entry_t* route);

/// Query routing table
///
/// Parameters:
///   routes: Output array
///   max_count: Maximum array capacity
///
/// Returns:
///   Actual route count, -1 on error
int route_list(route_entry_t* routes, int max_count);

/// Get interface index by device name
///
/// Parameters:
///   ifname: Interface name (e.g., "utun0", "eth0", "en0")
///
/// Returns:
///   Interface index (positive), -1 on error
int route_get_iface_index(const char* ifname);

/// Initialize route module (optional, auto-called)
///
/// Returns:
///   0 on success, -1 on error
int route_init(void);

/// Cleanup route module resources
void route_cleanup(void);

// ==================== IPv6 Helper Functions ====================

/// Create IPv6 route entry (convenience function)
///
/// Parameters:
///   dst: IPv6 destination address (16 bytes)
///   prefix_len: Prefix length (0-128)
///   gateway: IPv6 gateway (16 bytes, zero means direct)
///   iface_idx: Interface index
///   metric: Route priority
///   route_out: Output route entry
///
/// Returns:
///   0 on success, -1 on error
int route_create_ipv6(const uint8_t* dst, uint8_t prefix_len,
                      const uint8_t* gateway, uint32_t iface_idx,
                      int metric, route_entry_t* route_out);

/// Calculate IPv6 prefix mask
///
/// Parameters:
///   prefix_len: Prefix length (0-128)
///   mask_out: Output mask (16 bytes)
void route_ipv6_prefix_to_mask(uint8_t prefix_len, uint8_t* mask_out);

// ==================== Platform-Specific API ====================

#ifdef PLATFORM_LINUX

/// Linux: Set Netlink socket timeout (milliseconds)
void route_set_timeout(int timeout_ms);

#endif // PLATFORM_LINUX

#ifdef PLATFORM_WINDOWS

/// Windows: Check admin privileges
/// Returns: 1 if admin, 0 otherwise
int route_has_admin_privileges(void);

#endif // PLATFORM_WINDOWS

#endif // ROUTE_H
