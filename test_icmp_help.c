// test_icmp_help.c - Complete TUN ICMP Echo Reply Implementation
// Build: gcc -c test_icmp_help.c -o test_icmp_help.o
// This file contains ALL the logic from test_icmp.c as callable C functions

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>

#define BUF_SIZE 4096

// UTUN options (from xnu/private/api/if_utun.h)
#ifndef UTUN_OPT_IFNAME
#define UTUN_OPT_IFNAME 2
#endif

// IPv4 header (avoid macro conflicts)
typedef struct {
    uint8_t  vhl;     // version + header length
    uint8_t  tos;     // type of service
    uint16_t len;     // total length
    uint16_t id;      // identification
    uint16_t off;     // fragment offset
    uint8_t  ttl;     // time to live
    uint8_t  proto;   // protocol
    uint16_t sum;     // checksum
    uint32_t src;     // source address
    uint32_t dst;     // destination address
} iphdr_t;

// ICMP header (avoid macro conflicts)
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
} icmphdr_t;

// Global buffer for packet processing (shared with Zig)
static unsigned char g_buf[BUF_SIZE];
static int g_buf_len = 0;

// Create utun socket and get actual interface name
int create_utun_socket(char *ifname, size_t max_len) {
    struct sockaddr_ctl addr;
    int sock;

    // Create control socket
    sock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (sock < 0) {
        return -1;
    }

    // Get control info
    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, "com.apple.net.utun_control", sizeof(info.ctl_name));

    if (ioctl(sock, CTLIOCGINFO, &info) < 0) {
        close(sock);
        return -1;
    }

    // Connect to utun
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;  // Auto-assign

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    // Get kernel-assigned interface name
    char assigned_name[IFNAMSIZ];
    socklen_t name_len = sizeof(assigned_name);
    if (getsockopt(sock, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
                   assigned_name, &name_len) < 0) {
        close(sock);
        return -1;
    }

    strlcpy(ifname, assigned_name, max_len);
    printf("Created utun socket: %s\n", ifname);
    return sock;
}

// ============================================================================
// POSIX Wrapper Functions (for Zig interoperability)
// ============================================================================

// Create a datagram socket for ioctl operations
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
// High-level Configuration Functions
// ============================================================================

// Configure interface IP (uses ioctl wrappers)
int configure_ip(const char *ifname, const char *ip) {
    int sock = socket_create();
    if (sock < 0) return -1;

    int ret = ioctl_set_ip(sock, ifname, ip);
    socket_close(sock);

    if (ret == 0) {
        printf("Set IP: %s\n", ip);
    }
    return ret;
}

// Configure peer (destination) address (uses ioctl wrappers)
int configure_peer(const char *ifname, const char *peer) {
    int sock = socket_create();
    if (sock < 0) return -1;

    int ret = ioctl_set_peer(sock, ifname, peer);
    socket_close(sock);

    if (ret == 0) {
        printf("Set peer: %s\n", peer);
    }
    return ret;
}

// Bring interface up (uses ioctl wrappers)
int interface_up(const char *ifname) {
    int sock = socket_create();
    if (sock < 0) return -1;

    int flags;
    if (ioctl_get_flags(sock, ifname, &flags) < 0) {
        socket_close(sock);
        return -1;
    }

    flags |= IFF_UP | IFF_RUNNING;

    if (ioctl_set_flags(sock, ifname, flags) < 0) {
        socket_close(sock);
        return -1;
    }

    socket_close(sock);
    printf("Interface up\n");
    return 0;
}

// Calculate checksum
uint16_t calc_sum(uint16_t *addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        sum += *(uint8_t *)w;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

// Convert IP to string
const char *ip2str(uint32_t ip) {
    static char buf[16];
    uint8_t *p = (uint8_t *)&ip;
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return buf;
}

// Get buffer pointer for Zig to use
unsigned char *get_buffer(void) {
    return g_buf;
}

// Get buffer size constant
int get_buffer_size(void) {
    return BUF_SIZE;
}

// Add route via system command
int add_route(const char *tun_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "route -q -n add -inet 10.0.0.2/32 -iface %s 2>&1", tun_name);
    printf("Adding route: %s\n", cmd);
    return system(cmd);
}

// Delete existing route
int delete_route(void) {
    return system("route -q -n delete -inet 10.0.0.2 2>/dev/null");
}

// Verify route
int verify_route(void) {
    printf("Verifying route:\n");
    return system("route -n get 10.0.0.2 2>&1");
}

// Set non-blocking on socket
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Read from socket (returns bytes read, or -1 on error)
int tun_read(int fd, int *error_code) {
    int n = read(fd, g_buf, BUF_SIZE);
    if (n < 0) {
        *error_code = errno;
    } else {
        *error_code = 0;
    }
    g_buf_len = n;
    return n;
}

// Write to socket (returns bytes written, or -1 on error)
int tun_write(int fd, int len, int *error_code) {
    int n = write(fd, g_buf, len);
    if (n < 0) {
        *error_code = errno;
    } else {
        *error_code = 0;
    }
    return n;
}

// Close socket
int tun_close(int fd) {
    return close(fd);
}

// Process packet in C layer (complete processing, returns 0 if handled)
// Zig calls this to delegate packet processing to C
int process_packet_c(int len) {
    unsigned char *buf = g_buf;
    int n = len;

    // Skip macOS utun 4-byte header if present
    int offset = 0;
    if (n >= 4 && buf[0] == 0 && buf[1] == 0) {
        offset = 4;
        printf("Skipped 4-byte utun header\n");
    }

    if (n - offset < 20) {
        printf("Packet too small\n\n");
        return 0;
    }

    iphdr_t *ip = (iphdr_t *)(buf + offset);
    int ip_hlen = (ip->vhl & 0x0F) * 4;
    int ip_len = ntohs(ip->len);

    uint32_t src = ip->src;
    uint32_t dst = ip->dst;

    printf("IP: %s -> %s\n", ip2str(src), ip2str(dst));
    printf("Proto: %d (ICMP=1)\n", ip->proto);

    if (ip->proto != IPPROTO_ICMP) {
        printf("Not ICMP, skipping\n\n");
        return 0;
    }

    icmphdr_t *icmp = (icmphdr_t *)(buf + offset + ip_hlen);

    printf("ICMP Type: %d (8=echo, 0=reply)\n", icmp->type);

    if (icmp->type != ICMP_ECHO) {
        printf("Not echo request, skipping\n\n");
        return 0;
    }

    printf("Echo Request! ID=0x%04X Seq=%d\n",
           ntohs(icmp->id), ntohs(icmp->seq));

    // Build reply: swap IPs, change type to 0
    // CRITICAL: src = original dst, dst = original src
    ip->src = dst;  // Reply source = original destination
    ip->dst = src;  // Reply destination = original source
    icmp->type = ICMP_ECHOREPLY;

    // Recalculate checksums
    ip->sum = 0;
    ip->sum = calc_sum((uint16_t *)ip, ip_hlen);

    int icmp_len = ip_len - ip_hlen;
    icmp->sum = 0;
    icmp->sum = calc_sum((uint16_t *)icmp, icmp_len);

    printf("Reply: %s -> %s\n\n", ip2str(dst), ip2str(src));

    // Return modified length (same as original, includes header if present)
    return n;
}
