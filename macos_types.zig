// macos_types.zig - macOS kernel control types generated via zig translate-c
// This file provides Zig bindings for macOS-specific types used in UTUN operations.

const std = @import("std");

// ============================================================================
// POSIX Constants
// ============================================================================

pub const PF_SYSTEM = @as(c_int, 32);
pub const SYSPROTO_CONTROL = @as(c_int, 2);
pub const AF_SYSTEM = @as(c_int, 2);
pub const AF_SYS_CONTROL = @as(c_int, 2);
pub const SOCK_DGRAM = @as(c_int, 2);

// ioctl request code for CTLIOCGINFO
// _IOWR('N', 3, struct_ctl_info) = 0xC0644E03 (sizeof(ctl_info) = 100)
pub const CTLIOCGINFO: u32 = 0xC0644E03;

// UTUN option for interface name
pub const UTUN_OPT_IFNAME = @as(c_int, 2);

// ============================================================================
// ctl_info structure (for CTLIOCGINFO ioctl)
// From /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/kern_control.h
// ============================================================================

pub const ctl_info = extern struct {
    ctl_id: u32 = 0,
    ctl_name: [96]u8 = [_]u8{0} ** 96,

    // Helper to set ctl_name from a null-terminated string
    pub fn setName(this: *ctl_info, name: [*:0]const u8) void {
        @memset(&this.ctl_name, 0);
        var i: usize = 0;
        while (i < 95 and name[i] != 0) : (i += 1) {
            this.ctl_name[i] = name[i];
        }
    }
};

// ============================================================================
// sockaddr_ctl structure (for PF_SYSTEM connect)
// From /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/netinet/kpi_ipclip.h
// ============================================================================

pub const sockaddr_ctl = extern struct {
    sc_len: u8 = 0,
    sc_family: u8 = 0,
    ss_sysaddr: u16 = 0,
    sc_id: u32 = 0,
    sc_unit: u32 = 0,
    sc_reserved: [5]u32 = [_]u32{0} ** 5,

    pub fn init(ctl_id: u32, unit: u32) sockaddr_ctl {
        return .{
            .sc_len = @sizeOf(sockaddr_ctl),
            .sc_family = AF_SYSTEM,
            .ss_sysaddr = AF_SYS_CONTROL,
            .sc_id = ctl_id,
            .sc_unit = unit,
        };
    }
};

// ============================================================================
// ifreq structure (for ioctl operations)
// From /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/net/if.h
// ============================================================================

pub const IFNAMSIZ = 16;
pub const IFR_SIZE = 32;

// BSD sockaddr_in (used in ifreq)
const sockaddr_in_impl = extern struct {
    sin_len: u8 = 0,
    sin_family: u8 = 0,
    sin_port: u16 = 0,
    sin_addr: [4]u8 = [_]u8{0} ** 4,
    sin_zero: [8]u8 = [_]u8{0} ** 8,
};

pub const ifreq = extern struct {
    ifr_name: [16]u8 = [_]u8{0} ** 16,
    ifr_ifru: extern union {
        ifr_addr: sockaddr_in_impl,
        ifr_dstaddr: sockaddr_in_impl,
        ifr_flags: c_short,
        ifr_metric: c_int,
        ifr_mtu: c_int,
        ifr_broadaddr: sockaddr_in_impl,
        ifr_netmask: sockaddr_in_impl,
        ifr_media: c_int,
        ifr_data: *anyopaque,
    } = undefined,

    pub fn init() ifreq {
        return .{};
    }

    pub fn setName(this: *ifreq, name: [*:0]const u8) void {
        @memset(&this.ifr_name, 0);
        var i: usize = 0;
        while (i < 15 and name[i] != 0) : (i += 1) {
            this.ifr_name[i] = name[i];
        }
    }
};

// ============================================================================
// ioctl Request Codes
// From /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/sockio.h
// ============================================================================

pub const SIOCGIFFLAGS: u32 = 0xC0206914;    // _IOWR('i', 17, struct ifreq)
pub const SIOCSIFFLAGS: u32 = 0x80206910;    // _IOW('i', 16, struct ifreq)
pub const SIOCSIFADDR: u32 = 0x8020690C;      // _IOW('i', 12, struct ifreq)
pub const SIOCSIFDSTADDR: u32 = 0x80206914;   // _IOW('i', 14, struct ifreq)

// Interface flags (from net/if.h)
pub const IFF_UP: c_short = 0x1;
pub const IFF_RUNNING: c_short = 0x40;
