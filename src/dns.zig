//! dns.zig - DNS Module with Fake-IP Support
//!
//! Provides DNS query handling with optional Fake-IP mode.
//! In Fake-IP mode, DNS queries return synthetic IP addresses for routing.
//!
//! Fake-IP Range: 198.18.0.0/15 (198.18.0.0 - 198.19.255.255)

const std = @import("std");

// DNS constants
const DNS_PORT = 53;
const FAKE_IP_START = 0xC6120200; // 198.18.2.0 (network byte order)
const FAKE_IP_END = 0xC613FFFF; // 198.19.255.255
const FAKE_IP_COUNT = 0x1FE00; // 130816 addresses

// Fake-IP pool
var fake_ip_counter: u32 = 0;
var fake_ip_mutex: std.Thread.Mutex = .{};

// DNS header structure (12 bytes)
const DnsHeader = packed struct {
    transaction_id: u16,
    flags: u16,
    questions: u16,
    answer_rrs: u16,
    authority_rrs: u16,
    additional_rrs: u16,
};

// DNS question
const DnsQuestion = struct {
    name: []const u8,
    qtype: u16,
    qclass: u16,
};

// DNS resource record
const DnsRecord = struct {
    name: []const u8,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdlength: u16,
    rdata: []const u8,
};

/// DNS response type
pub const DnsResponse = struct {
    /// Transaction ID
    tx_id: u16,
    /// Fake IP assigned (network byte order)
    fake_ip: u32,
    /// Original domain name
    domain: []const u8,
    /// Response buffer
    data: []const u8,
};

/// Fake-IP entry
const FakeIpEntry = struct {
    ip: u32,
    domain: []const u8,
    created_at: i64,
};

/// DNS module configuration
pub const DnsConfig = struct {
    /// Enable Fake-IP mode
    enabled: bool = false,

    /// Fake-IP pool size
    pool_size: usize = 8192,

    /// Fake-IP lease timeout in seconds
    timeout: u32 = 300,
};

/// DNS module state
pub const DnsModule = struct {
    /// Configuration
    config: DnsConfig,

    /// Allocator
    allocator: std.mem.Allocator,

    /// Fake-IP entries
    fake_entries: []FakeIpEntry,

    /// Free fake IP queue
    free_ips: []u32,

    /// Current position in free IP queue
    free_ip_pos: usize = 0,

    /// Create DNS module
    pub fn create(allocator: std.mem.Allocator, config: DnsConfig) !*DnsModule {
        const module = try allocator.create(DnsModule);
        errdefer allocator.destroy(module);

        const entry_count = config.pool_size;
        const fake_entries = try allocator.alloc(FakeIpEntry, entry_count);
        errdefer allocator.free(fake_entries);

        const free_ips = try allocator.alloc(u32, entry_count);
        errdefer allocator.free(free_ips);

        // Initialize free IP queue
        for (0..entry_count) |i| {
            const offset = @as(u32, @intCast(i));
            free_ips[i] = FAKE_IP_START + offset;
        }

        // Initialize entries
        for (fake_entries) |*entry| {
            entry.* = .{
                .ip = 0,
                .domain = &[_]u8{},
                .created_at = 0,
            };
        }

        return module;
    }

    /// Destroy DNS module
    pub fn destroy(module: *DnsModule, allocator: std.mem.Allocator) void {
        // Free domains
        for (module.fake_entries) |*entry| {
            if (entry.domain.len > 0) {
                allocator.free(entry.domain);
            }
        }
        allocator.free(module.fake_entries);
        allocator.free(module.free_ips);
        allocator.destroy(module);
    }

    /// Get a Fake-IP for a domain
    pub fn getFakeIp(module: *DnsModule, domain: []const u8) u32 {
        // Check if domain already has a Fake-IP
        for (module.fake_entries) |*entry| {
            if (entry.domain.len > 0 and std.mem.eql(u8, entry.domain, domain)) {
                entry.created_at = std.time.timestamp();
                return entry.ip;
            }
        }

        // Find free slot
        fake_ip_mutex.lock();
        defer fake_ip_mutex.unlock();

        for (module.fake_entries) |*entry| {
            if (entry.ip == 0) {
                const owned_domain = allocator.dupe(u8, domain) catch return 0;
                entry.* = .{
                    .ip = module.getNextFreeIp(),
                    .domain = owned_domain,
                    .created_at = std.time.timestamp(),
                };
                return entry.ip;
            }
        }

        // Pool full, return last IP
        return 0xC612FFFF;
    }

    /// Get next free IP from queue
    fn getNextFreeIp(module: *DnsModule) u32 {
        if (module.free_ip_pos >= module.free_ips.len) {
            module.free_ip_pos = 0;
        }
        const ip = module.free_ips[module.free_ip_pos];
        module.free_ip_pos += 1;
        return ip;
    }

    /// Look up domain by Fake-IP
    pub fn lookupByIp(module: *DnsModule, ip: u32) ?[]const u8 {
        for (module.fake_entries) |*entry| {
            if (entry.ip == ip and entry.domain.len > 0) {
                return entry.domain;
            }
        }
        return null;
    }

    /// Parse DNS query and extract domain name
    pub fn parseQuery(module: *DnsModule, data: []const u8, tx_id: *u16) !?[]const u8 {
        if (data.len < 12) return error.PacketTooSmall;

        const header = @as(*const DnsHeader, @ptrCast(data[0..12].ptr)).*;
        tx_id.* = header.transaction_id;

        // Check if it's a query (QR=0)
        if ((header.flags & 0x8000) != 0) {
            return error.NotQuery;
        }

        // Parse domain name from question section
        const name = try parseDomainName(data, 12);
        return name;
    }

    /// Build DNS response with Fake-IP
    pub fn buildResponse(module: *DnsModule, query_data: []const u8, tx_id: u16, fake_ip: u32) ![]const u8 {
        const domain = try module.parseQuery(query_data, &@as(u16, 0)) orelse {
            return error.InvalidQuery;
        };

        // Build response header
        var response: [512]u8 = undefined;
        var offset: usize = 0;

        // Header
        const header = @as(*DnsHeader, @ptrCast(response[0..12].ptr)).*;
        std.mem.copy(u8, response[0..12], query_data[0..12]);
        const resp_header = @as(*DnsHeader, @ptrCast(response[0..12].ptr)).*;
        resp_header.transaction_id = tx_id;
        resp_header.flags = 0x8580; // QR=1, RA=1, RD=1 (standard response)
        resp_header.questions = 1;
        resp_header.answer_rrs = 1;
        resp_header.authority_rrs = 0;
        resp_header.additional_rrs = 0;
        offset = 12;

        // Copy question section
        offset = try encodeDomainName(response[0..], domain, offset);
        response[offset] = 0x00; // QTYPE: A
        response[offset + 1] = 0x01;
        offset += 2;
        response[offset] = 0x00; // QCLASS: IN
        response[offset + 1] = 0x01;
        offset += 2;

        // Answer section
        offset = try encodeDomainName(response[0..], domain, offset);
        response[offset] = 0x00; // TYPE: A
        response[offset + 1] = 0x01;
        offset += 2;
        response[offset] = 0x00; // CLASS: IN
        response[offset + 1] = 0x01;
        offset += 2;

        // TTL: 300 seconds
        response[offset] = 0x00;
        response[offset + 1] = 0x00;
        response[offset + 2] = 0x01;
        response[offset + 3] = 0x2C; // 300
        offset += 4;

        // RDLENGTH: 4 (IPv4)
        response[offset] = 0x00;
        response[offset + 1] = 0x04;
        offset += 2;

        // RDATA: Fake-IP
        std.mem.writeInt(u32, response[offset .. offset + 4], fake_ip, .big);
        offset += 4;

        return response[0..offset];
    }
};

/// Parse domain name from DNS packet (supports compression)
fn parseDomainName(data: []const u8, offset: usize) ![]const u8 {
    var name: [256]u8 = undefined;
    var name_len: usize = 0;
    var pos = offset;

    while (pos < data.len) {
        const len = data[pos];

        if (len == 0) {
            // End of name
            pos += 1;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            // Compression pointer
            if (pos + 1 >= data.len) return error.InvalidCompression;
            const ptr = @as(u16, len & 0x3F) << 8 | @as(u16, data[pos + 1]);
            const compressed = try parseDomainName(data, ptr);
            @memcpy(name[name_len .. name_len + compressed.len], compressed);
            name_len += compressed.len;
            pos += 2;
            break;
        }

        // Regular label
        pos += 1;
        if (pos + len > data.len) return error.InvalidName;
        @memcpy(name[name_len .. name_len + len], data[pos .. pos + len]);
        name_len += len;
        name[name_len] = '.';
        name_len += 1;
        pos += len;
    }

    // Remove trailing dot
    if (name_len > 0 and name[name_len - 1] == '.') {
        name_len -= 1;
    }

    return name[0..name_len];
}

/// Encode domain name into DNS packet format
fn encodeDomainName(buf: []u8, domain: []const u8, offset: usize) !usize {
    var pos = offset;
    var label_start: usize = 0;

    for (domain, 0..) |c, i| {
        if (c == '.') {
            const label_len = i - label_start;
            buf[pos] = @as(u8, @intCast(label_len));
            pos += 1;
            @memcpy(buf[pos .. pos + label_len], domain[label_start..i]);
            pos += label_len;
            label_start = i + 1;
        }
    }

    // Last label
    const last_label_len = domain.len - label_start;
    buf[pos] = @as(u8, @intCast(last_label_len));
    pos += 1;
    @memcpy(buf[pos .. pos + last_label_len], domain[label_start..]);
    pos += last_label_len;

    // End of name
    buf[pos] = 0;
    pos += 1;

    return pos;
}

/// Format IP for logging
fn fmtIp(ip: u32) [15]u8 {
    var buf: [15]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{}.{}.{}.{}", .{
        @as(u8, @truncate(ip >> 24)),
        @as(u8, @truncate(ip >> 16)),
        @as(u8, @truncate(ip >> 8)),
        @as(u8, @truncate(ip)),
    }) catch unreachable;
    return buf;
}

// Error set
pub const DnsError = error{
    PacketTooSmall,
    NotQuery,
    InvalidQuery,
    InvalidName,
    InvalidCompression,
    OutOfMemory,
};
