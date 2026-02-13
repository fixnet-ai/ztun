//! rules.zig - Rule Engine for Traffic Routing
//!
//! Provides domain-based and IP-based routing rules.
//! Supports exact match, suffix match, and CIDR matching.

const std = @import("std");

/// Rule action
pub const RuleAction = enum(u8) {
    /// Direct connection (bypass proxy)
    direct = 0,
    /// Route through proxy
    proxy = 1,
    /// Block traffic
    block = 2,
    /// DNS query
    dns = 3,
};

/// Rule type
pub const RuleType = enum(u8) {
    /// Match by IP CIDR
    ip_cidr = 0,
    /// Match by domain suffix (e.g., "example.com")
    domain_suffix = 1,
    /// Match by domain exact
    domain_exact = 2,
    /// Match by domain keyword
    domain_keyword = 3,
    /// Match by GeoIP
    geoip = 4,
    /// Match by process name
    process = 5,
};

/// Single rule
pub const Rule = struct {
    /// Rule type
    rtype: RuleType,
    /// Rule value (CIDR, domain, etc.)
    value: []const u8,
    /// Action to take
    action: RuleAction,
    /// Priority (higher = checked first)
    priority: u8 = 0,
};

/// Rule set (collection of rules)
pub const RuleSet = struct {
    /// Rules in this set
    rules: []const Rule,

    /// Default action if no rules match
    default_action: RuleAction,

    /// Create rule set
    pub fn init(rules: []const Rule, default_action: RuleAction) RuleSet {
        return RuleSet{
            .rules = rules,
            .default_action = default_action,
        };
    }

    /// Evaluate packet against rules
    pub fn evaluate(set: RuleSet, domain: ?[]const u8, ip: u32) RuleAction {
        // Check rules in priority order
        for (set.rules) |rule| {
            if (matchRule(rule, domain, ip)) {
                return rule.action;
            }
        }
        return set.default_action;
    }
};

/// Check if rule matches
fn matchRule(rule: Rule, domain: ?[]const u8, ip: u32) bool {
    return switch (rule.rtype) {
        .ip_cidr => matchIpCidr(rule.value, ip),
        .domain_suffix => matchDomainSuffix(domain, rule.value),
        .domain_exact => matchDomainExact(domain, rule.value),
        .domain_keyword => matchDomainKeyword(domain, rule.value),
        else => false,
    };
}

/// Match IP against CIDR rule
fn matchIpCidr(rule_value: []const u8, ip: u32) bool {
    // Parse CIDR: "192.168.0.0/16"
    const slash_idx = std.mem.indexOf(u8, rule_value, "/") orelse return false;
    const prefix_str = rule_value[0..slash_idx];
    const prefix_len = std.fmt.parseInt(u8, rule_value[slash_idx + 1 ..], 10) catch return false;

    // Parse IP
    const ip_val = parseIp(prefix_str) orelse return false;

    // Calculate mask
    const mask: u32 = if (prefix_len == 0) 0 else ~@as(u32, 0) << (32 - prefix_len);

    return (ip & mask) == (ip_val & mask);
}

/// Match domain suffix (e.g., "example.com" matches "sub.example.com")
fn matchDomainSuffix(domain: ?[]const u8, suffix: []const u8) bool {
    const d = domain orelse return false;

    if (d.len < suffix.len + 1) return false; // +1 for leading dot

    // Check if domain ends with .suffix
    if (std.mem.endsWith(u8, d, suffix)) {
        // Ensure it's a proper suffix (either exact match or preceded by dot)
        if (d.len == suffix.len) return true; // exact match
        if (d[d.len - suffix.len - 1] == '.') return true;
    }

    return false;
}

/// Match domain exactly
fn matchDomainExact(domain: ?[]const u8, exact: []const u8) bool {
    const d = domain orelse return false;
    return std.mem.eql(u8, d, exact);
}

/// Match domain containing keyword
fn matchDomainKeyword(domain: ?[]const u8, keyword: []const u8) bool {
    const d = domain orelse return false;
    return std.mem.indexOf(u8, d, keyword) != null;
}

/// Parse IPv4 address string to u32
fn parseIp(ip_str: []const u8) ?u32 {
    var parts: [4]u8 = undefined;
    var part_idx: usize = 0;
    var val: u32 = 0;

    for (ip_str) |c| {
        if (c == '.') {
            if (part_idx >= 4) return null;
            parts[part_idx] = @as(u8, @truncate(val));
            val = 0;
            part_idx += 1;
        } else if (c >= '0' and c <= '9') {
            val = val * 10 + (c - '0');
            if (val > 255) return null;
        } else {
            return null;
        }
    }

    if (part_idx >= 4) return null;
    parts[part_idx] = @as(u8, @truncate(val));

    if (part_idx != 3) return null;

    return @as(u32, parts[0]) << 24 |
        @as(u32, parts[1]) << 16 |
        @as(u32, parts[2]) << 8 |
        @as(u32, parts[3]);
}

/// GeoIP entry
const GeoIpEntry = struct {
    ip_start: u32,
    ip_end: u32,
    country_code: [2]u8,
};

/// Simple GeoIP database (in production, use MaxMind DB)
pub const GeoIpDb = struct {
    /// Entries
    entries: []const GeoIpEntry,

    /// Create geoIP database
    pub fn create(allocator: std.mem.Allocator) !*GeoIpDb {
        const db = try allocator.create(GeoIpDb);
        // Empty database for now - in production, load from MaxMind DB
        db.* = .{
            .entries = &[_]GeoIpEntry{},
        };
        return db;
    }

    /// Look up IP and return country code
    pub fn lookup(db: *GeoIpDb, ip: u32) ?[2]u8 {
        _ = db;
        _ = ip;
        // TODO: Implement actual GeoIP lookup
        return null;
    }

    /// Destroy database
    pub fn destroy(db: *GeoIpDb, allocator: std.mem.Allocator) void {
        allocator.free(db.entries);
        allocator.destroy(db);
    }
};
