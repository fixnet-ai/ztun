// utun_types.h - TUN interface types for Zig cImport
// This file is included in Zig via @cImport(@cInclude("utun_types.h"))

#pragma once

#include <sys/types.h>
#include <stdint.h>

// ctl_info structure for ioctl(CTLIOCGINFO)
typedef struct {
    uint32_t ctl_id;
    char ctl_name[96];
} ctl_info;

// sockaddr_ctl structure for utun socket
typedef struct {
    uint8_t sc_len;
    uint8_t sc_family;
    uint16_t ss_sysaddr;
    uint32_t sc_id;
    uint32_t sc_unit;
} sockaddr_ctl;

// sockaddr_in structure for IP configuration
typedef struct {
    uint8_t sin_len;
    uint8_t sin_family;
    uint16_t sin_port;
    uint8_t sin_addr[4];
    uint8_t sin_zero[8];
} sockaddr_in;

// IP header structure
typedef struct {
    uint8_t vhl;        // version + header length
    uint8_t tos;        // type of service
    uint16_t len;       // total length
    uint16_t id;        // identification
    uint16_t off;       // fragment offset
    uint8_t ttl;        // time to live
    uint8_t proto;      // protocol
    uint16_t sum;       // checksum
    uint32_t src;       // source address
    uint32_t dst;       // destination address
} iphdr;

// ICMP header structure
typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} icmphdr;
