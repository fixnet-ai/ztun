// test_icmp_help.c - Minimal C Helper for TUN ICMP Echo Reply Test
// Build: zig build-exe test_icmp.zig test_icmp_help.c -lc -I.
//
// This file contains ONLY the C wrappers that Zig cannot replace:
// - POSIX ioctl operations (Zig 0.13.0 doesn't support ioctl)
// - PF_SYSTEM socket for macOS utun
//
// All packet processing logic is now in pure Zig.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if.h>

#define BUF_SIZE 4096

// UTUN options (from xnu/private/api/if_utun.h)
#ifndef UTUN_OPT_IFNAME
#define UTUN_OPT_IFNAME 2
#endif

// ============================================================================
// POSIX ioctl Wrappers (required because Zig 0.13.0 doesn't support ioctl)
// ============================================================================

// Create datagram socket for ioctl operations
int socket_create(void) {
    return socket(AF_INET, SOCK_DGRAM, 0);
}

// Close socket
int socket_close(int sock) {
    return close(sock);
}

// Get interface flags via ioctl
int ioctl_get_flags(int sock, const char *ifname, int *flags) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        return -1;
    }

    *flags = ifr.ifr_flags;
    return 0;
}

// Set interface flags via ioctl
int ioctl_set_flags(int sock, const char *ifname, int flags) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ifr.ifr_flags = flags;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        return -1;
    }

    return 0;
}

// Set interface IP address via ioctl
int ioctl_set_ip(int sock, const char *ifname, const char *ip) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_len = sizeof(struct sockaddr_in);
    inet_pton(AF_INET, ip, &addr->sin_addr);

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        fprintf(stderr, "SIOCSIFADDR failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

// Set interface peer address via ioctl
int ioctl_set_peer(int sock, const char *ifname, const char *peer) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_dstaddr;
    addr->sin_family = AF_INET;
    addr->sin_len = sizeof(struct sockaddr_in);
    inet_pton(AF_INET, peer, &addr->sin_addr);

    if (ioctl(sock, SIOCSIFDSTADDR, &ifr) < 0) {
        fprintf(stderr, "SIOCSIFDSTADDR failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

// ============================================================================
// UTUN Wrapper Functions (PF_SYSTEM socket for macOS)
// ============================================================================

// Create PF_SYSTEM socket for utun
int socket_create_sys(void) {
    return socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
}

// Get control info via ioctl
int ioctl_get_ctl_info(int sock, char *ctl_name, size_t name_len, uint32_t *ctl_id) {
    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, ctl_name, sizeof(info.ctl_name));

    if (ioctl(sock, CTLIOCGINFO, &info) < 0) {
        return -1;
    }

    *ctl_id = info.ctl_id;
    return 0;
}

// Connect to utun with control id
int connect_utun(int sock, uint32_t ctl_id) {
    struct sockaddr_ctl addr;
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = ctl_id;
    addr.sc_unit = 0;  // Auto-assign

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return -1;
    }

    return 0;
}

// Get interface name from kernel via getsockopt
int getsockopt_ifname(int sock, char *ifname, size_t max_len) {
    char assigned_name[IFNAMSIZ];
    socklen_t name_len = sizeof(assigned_name);

    if (getsockopt(sock, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
                   assigned_name, &name_len) < 0) {
        return -1;
    }

    strlcpy(ifname, assigned_name, max_len);
    return 0;
}
