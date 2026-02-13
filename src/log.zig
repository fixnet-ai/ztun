//! log.zig - Production-Grade Logging System
//!
//! Provides structured logging with multiple levels and outputs.
//! Supports console output, file output, and structured JSON logs.
//!
//! # Usage
//!
//! ```zig
//! const log = @import("log");
//!
//! // Initialize logger
//! var logger = try log.Logger.init(allocator, .{
//!     .level = .info,
//!     .output = .console,
//! });
//! defer logger.deinit();
//!
//! // Log messages
//! logger.info("Connection established", .{});
//! logger.debug("Packet: {s}:{} -> {s}:{}", .{src_ip, src_port, dst_ip, dst_port});
//! ```

const std = @import("std");
const builtin = @import("builtin");

/// Log levels (RFC 5424 syslog-inspired)
pub const Level = enum(u8) {
    /// Error conditions - immediate attention needed
    error = 3,
    /// Warning conditions - potential issues
    warn = 4,
    /// Informational messages - normal operation
    info = 6,
    /// Debug messages - troubleshooting
    debug = 7,
    /// Trace messages - detailed debugging
    trace = 8,
};

/// Log output destinations
pub const Output = enum(u8) {
    /// Console output (stderr)
    console = 0,
    /// Log file (rotating)
    file = 1,
    /// JSON structured output
    json = 2,
    /// Both console and file
    both = 3,
};

/// Log entry structure
pub const Entry = struct {
    /// Log level
    level: Level,
    /// Timestamp (nanoseconds since epoch)
    timestamp: i64,
    /// Message
    message: []const u8,
    /// Module name (optional)
    module: ?[]const u8 = null,
    /// File name (for debug)
    file: ?[]const u8 = null,
    /// Line number (for debug)
    line: ?usize = null,
    /// Connection 4-tuple (for connection logs)
    conn: ?ConnectionInfo = null,
};

/// Connection information for structured logging
pub const ConnectionInfo = struct {
    /// Source IP (network byte order)
    src_ip: u32,
    /// Source port
    src_port: u16,
    /// Destination IP
    dst_ip: u32,
    /// Destination port
    dst_port: u16,
    /// Protocol (TCP=6, UDP=17)
    protocol: u8,
    /// Route decision (direct, proxy, block)
    decision: []const u8,
};

/// Logger configuration
pub const Config = struct {
    /// Minimum log level
    level: Level = .info,
    /// Output destination
    output: Output = .console,
    /// Log file path (if output includes file)
    file_path: ?[]const u8 = null,
    /// Maximum log file size (bytes)
    max_file_size: usize = 10 * 1024 * 1024, // 10MB
    /// Maximum number of log files (rotation)
    max_files: usize = 3,
    /// Enable timestamps
    enable_timestamp: bool = true,
    /// Enable module names
    enable_module: bool = true,
    /// Enable source location (file:line)
    enable_location: bool = false,
    /// Output buffer size
    buffer_size: usize = 8192,
};

/// Logger state
pub const Logger = struct {
    /// Configuration
    config: Config,
    /// Allocator
    allocator: std.mem.Allocator,
    /// Log file handle (if enabled)
    log_file: ?std.fs.File = null,
    /// Output buffer
    buffer: std.ArrayListUnmanaged(u8) = .{},
    /// Buffer mutex (for thread safety - simplified with atomics)
    buffered: bool = false,
    /// Current log file size
    file_size: usize = 0,
    /// Statistics
    stats: LoggerStats = .{},
};

/// Logger statistics
pub const LoggerStats = struct {
    messages_written: u64 = 0,
    bytes_written: u64 = 0,
    errors: u64 = 0,
    rotations: u64 = 0,
    dropped: u64 = 0,
};

/// Initialize logger
pub fn init(allocator: std.mem.Allocator, config: Config) !Logger {
    var logger = Logger{
        .config = config,
        .allocator = allocator,
        .log_file = null,
        .buffer = std.ArrayListUnmanaged(u8){},
        .buffered = false,
        .file_size = 0,
        .stats = .{},
    };

    // Initialize output buffer
    try logger.buffer.ensureTotalCapacity(allocator, config.buffer_size);

    // Open log file if needed
    if (config.output == .file or config.output == .both) {
        if (config.file_path) |path| {
            logger.log_file = std.fs.createFileAbsolute(
                path,
                .{ .truncate = true },
            ) catch |err| {
                std.debug.print("[LOG] Warning: Failed to open log file: {}\n", .{err});
            };
        }
    }

    return logger;
}

/// Deinitialize logger
pub fn deinit(logger: *Logger) void {
    // Flush buffer
    logger.flush() catch {};

    // Close log file
    if (logger.log_file) |*file| {
        file.close();
        logger.log_file = null;
    }

    // Free buffer
    logger.buffer.deinit(logger.allocator);

    logger.* = undefined;
}

/// Log a message at specified level
pub fn log(logger: *Logger, level: Level, message: []const u8) void {
    if (@intFromEnum(level) < @intFromEnum(logger.config.level)) {
        return;
    }

    logger.writeEntry(.{
        .level = level,
        .timestamp = std.time.nanoTimestamp(),
        .message = message,
    }) catch |err| {
        logger.stats.errors += 1;
        if (logger.stats.errors == 1) {
            std.debug.print("[LOG] First error: {}\n", .{err});
        }
    };
}

/// Log with format string
pub fn logFmt(logger: *Logger, level: Level, comptime format: []const u8, args: anytype) void {
    if (@intFromEnum(level) < @intFromEnum(logger.config.level)) {
        return;
    }

    var buf: [1024]u8 = undefined;
    const message = std.fmt.bufPrint(&buf, format, args) catch {
        logger.stats.dropped += 1;
        return;
    };

    logger.log(level, message);
}

/// Log error message
pub fn error(logger: *Logger, message: []const u8) void {
    logger.log(.error, message);
}

/// Log warning message
pub fn warn(logger: *Logger, message: []const u8) void {
    logger.log(.warn, message);
}

/// Log informational message
pub fn info(logger: *Logger, message: []const u8) void {
    logger.log(.info, message);
}

/// Log debug message
pub fn debug(logger: *Logger, message: []const u8) void {
    logger.log(.debug, message);
}

/// Log trace message
pub fn trace(logger: *Logger, message: []const u8) void {
    logger.log(.trace, message);
}

/// Log connection information
pub fn logConn(
    logger: *Logger,
    level: Level,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
    decision: []const u8,
    message: []const u8,
) void {
    if (@intFromEnum(level) < @intFromEnum(logger.config.level)) {
        return;
    }

    logger.writeEntry(.{
        .level = level,
        .timestamp = std.time.nanoTimestamp(),
        .message = message,
        .conn = .{
            .src_ip = src_ip,
            .src_port = src_port,
            .dst_ip = dst_ip,
            .dst_port = dst_port,
            .protocol = protocol,
            .decision = decision,
        },
    }) catch |err| {
        logger.stats.errors += 1;
        _ = err;
    };
}

/// Write log entry to output
fn writeEntry(logger: *Logger, entry: Entry) !void {
    // Format the entry
    var line_buf: [1024]u8 = undefined;
    const line = try formatEntry(&line_buf, entry, logger.config);

    // Write to outputs
    switch (logger.config.output) {
        .console, .both => {
            try logger.writeConsole(line);
        },
        .file, .both => {
            try logger.writeFile(line);
        },
        .json => {
            var json_buf: [2048]u8 = undefined;
            const json_line = try formatJsonEntry(&json_buf, entry, logger.config);
            try logger.writeConsole(json_line);
        },
    }

    logger.stats.messages_written += 1;
    logger.stats.bytes_written += line.len;
}

/// Format entry as human-readable line
fn formatEntry(buf: []u8, entry: Entry, config: Config) ![]const u8 {
    var offset: usize = 0;

    // Timestamp
    if (config.enable_timestamp) {
        const ts = std.fmt.bufPrint(buf[offset..], "[{d:0>15}] ", .{entry.timestamp}) catch {
            return "[<timestamp too long>]";
        };
        offset += ts.len;
    }

    // Level
    const level_str = switch (entry.level) {
        .error => "ERROR",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DEBUG",
        .trace => "TRACE",
    };
    const level_fmt = std.fmt.bufPrint(buf[offset..], "[{s}] ", .{level_str}) catch {
        return "[<level too long>]";
    };
    offset += level_fmt.len;

    // Module
    if (config.enable_module and entry.module) |mod| {
        const mod_fmt = std.fmt.bufPrint(buf[offset..], "[{s}] ", .{mod}) catch {
            return "[<module too long>]";
        };
        offset += mod_fmt.len;
    }

    // Location
    if (config.enable_location and entry.file) |file| {
        const loc_fmt = std.fmt.bufPrint(buf[offset..], "[{s}:{d}] ", .{ file, entry.line orelse 0 }) catch {
            return "[<location too long>]";
        };
        offset += loc_fmt.len;
    }

    // Connection info
    if (entry.conn) |conn| {
        const ip_fmt = std.fmt.bufPrint(
            buf[offset..],
            "[{d}.{d}.{d}.{d}:{d} -> {d}.{d}.{d}.{d}:{d} {s}] ",
            .{
                @as(u8, @truncate(conn.src_ip >> 24)), @as(u8, @truncate(conn.src_ip >> 16)),
                @as(u8, @truncate(conn.src_ip >> 8)), @as(u8, @truncate(conn.src_ip)),
                conn.src_port,
                @as(u8, @truncate(conn.dst_ip >> 24)), @as(u8, @truncate(conn.dst_ip >> 16)),
                @as(u8, @truncate(conn.dst_ip >> 8)), @as(u8, @truncate(conn.dst_ip)),
                conn.dst_port,
                conn.decision,
            },
        ) catch {
            return "[<conn too long>]";
        };
        offset += ip_fmt.len;
    }

    // Message
    if (offset + entry.message.len < buf.len) {
        @memcpy(buf[offset..][0..entry.message.len], entry.message);
        offset += entry.message.len;
        buf[offset] = '\n';
        offset += 1;
    }

    return buf[0..offset];
}

/// Format entry as JSON
fn formatJsonEntry(buf: []u8, entry: Entry, config: Config) ![]const u8 {
    _ = config;
    var offset: usize = 0;

    // Opening brace
    buf[offset] = '{';
    offset += 1;

    // Timestamp
    offset += try std.fmt.bufPrint(buf[offset..], "\"ts\":{d},", .{entry.timestamp});

    // Level
    const level_str = switch (entry.level) {
        .error => "error",
        .warn => "warn",
        .info => "info",
        .debug => "debug",
        .trace => "trace",
    };
    offset += try std.fmt.bufPrint(buf[offset..], "\"level\":\"{s}\",", .{level_str});

    // Message
    offset += try std.fmt.bufPrint(buf[offset..], "\"msg\":\"{s}\"", .{entry.message});

    // Module
    if (entry.module) |mod| {
        offset += try std.fmt.bufPrint(buf[offset..], ",\"module\":\"{s}\"", .{mod});
    }

    // Connection info
    if (entry.conn) |conn| {
        offset += try std.fmt.bufPrint(
            buf[offset..],
            ",\"conn\":{{\"src\":\"{d}.{d}.{d}.{d}:{d}\",\"dst\":\"{d}.{d}.{d}.{d}:{d}\",\"proto\":{d},\"decision\":\"{s}\"}}",
            .{
                @as(u8, @truncate(conn.src_ip >> 24)), @as(u8, @truncate(conn.src_ip >> 16)),
                @as(u8, @truncate(conn.src_ip >> 8)), @as(u8, @truncate(conn.src_ip)),
                conn.src_port,
                @as(u8, @truncate(conn.dst_ip >> 24)), @as(u8, @truncate(conn.dst_ip >> 16)),
                @as(u8, @truncate(conn.dst_ip >> 8)), @as(u8, @truncate(conn.dst_ip)),
                conn.dst_port,
                conn.protocol,
                conn.decision,
            },
        );
    }

    // Closing brace + newline
    buf[offset] = '}';
    offset += 1;
    buf[offset] = '\n';
    offset += 1;

    return buf[0..offset];
}

/// Write to console (stderr)
fn writeConsole(logger: *Logger, line: []const u8) !void {
    const stderr = std.io.getStdErr();
    try stderr.writeAll(line);
}

/// Write to log file with rotation
fn writeFile(logger: *Logger, line: []const u8) !void {
    if (logger.log_file) |*file| {
        // Check rotation
        if (logger.file_size + line.len > logger.config.max_file_size) {
            try logger.rotateLogFile();
        }

        try file.writeAll(line);
        logger.file_size += line.len;
    }
}

/// Rotate log files
fn rotateLogFile(logger: *Logger) !void {
    logger.stats.rotations += 1;

    // Close current file
    if (logger.log_file) |*file| {
        file.close();
        logger.log_file = null;
    }

    // Remove oldest file if at limit
    if (logger.config.file_path) |base_path| {
        const oldest = try std.fmt.allocPrint(
            logger.allocator,
            "{s}.{d}",
            .{ base_path, logger.config.max_files },
        );
        defer logger.allocator.free(oldest);

        std.fs.deleteFileAbsolute(oldest) catch {};

        // Rename files
        var i: usize = logger.config.max_files - 1;
        while (i > 0) : (i -= 1) {
            const old = try std.fmt.allocPrint(logger.allocator, "{s}.{d}", .{ base_path, i });
            defer logger.allocator.free(old);

            const new = try std.fmt.allocPrint(logger.allocator, "{s}.{d}", .{ base_path, i + 1 });
            defer logger.allocator.free(new);

            std.fs.renameAbsolute(old, new) catch {};
        }

        // Rename current to .1
        const new_path = try std.fmt.allocPrint(logger.allocator, "{s}.1", .{base_path});
        defer logger.allocator.free(new_path);

        std.fs.renameAbsolute(base_path, new_path) catch {};
    }

    // Open new file
    if (logger.config.file_path) |path| {
        logger.log_file = std.fs.createFileAbsolute(path, .{ .truncate = true }) catch null;
        logger.file_size = 0;
    }
}

/// Flush buffered output
pub fn flush(logger: *Logger) !void {
    if (logger.buffer.items.len > 0) {
        if (logger.log_file) |*file| {
            try file.writeAll(logger.buffer.items);
        }
        logger.buffer.clearRetainingCapacity();
    }
}

/// Get logger statistics
pub fn getStats(logger: *Logger) LoggerStats {
    return logger.stats;
}

/// Set minimum log level at runtime
pub fn setLevel(logger: *Logger, level: Level) void {
    logger.config.level = level;
}

/// Create a scoped logger for a module
pub fn scoped(logger: *Logger, module: []const u8) ScopedLogger {
    return .{
        .parent = logger,
        .module = module,
    };
}

/// Scoped logger with module name prepended
pub const ScopedLogger = struct {
    parent: *Logger,
    module: []const u8,

    pub fn log(self: *ScopedLogger, level: Level, message: []const u8) void {
        if (@intFromEnum(level) < @intFromEnum(self.parent.config.level)) {
            return;
        }

        self.parent.writeEntry(.{
            .level = level,
            .timestamp = std.time.nanoTimestamp(),
            .message = message,
            .module = self.module,
        }) catch |_| {
            self.parent.stats.errors += 1;
        };
    }

    pub fn error(self: *ScopedLogger, message: []const u8) void {
        self.log(.error, message);
    }

    pub fn warn(self: *ScopedLogger, message: []const u8) void {
        self.log(.warn, message);
    }

    pub fn info(self: *ScopedLogger, message: []const u8) void {
        self.log(.info, message);
    }

    pub fn debug(self: *ScopedLogger, message: []const u8) void {
        self.log(.debug, message);
    }

    pub fn trace(self: *ScopedLogger, message: []const u8) void {
        self.log(.trace, message);
    }
};

// Unit tests
test "Log level ordering" {
    try std.testing.expect(@intFromEnum(Level.error) < @intFromEnum(Level.warn));
    try std.testing.expect(@intFromEnum(Level.warn) < @intFromEnum(Level.info));
    try std.testing.expect(@intFromEnum(Level.info) < @intFromEnum(Level.debug));
    try std.testing.expect(@intFromEnum(Level.debug) < @intFromEnum(Level.trace));
}

test "Logger init/deinit" {
    const allocator = std.testing.allocator;
    const config = Config{};

    var logger = try init(allocator, config);
    defer deinit(&logger);

    try std.testing.expect(logger.buffer.capacity > 0);
}

test "Log message filtering" {
    const allocator = std.testing.allocator;
    var logger = try init(allocator, .{
        .level = .warn,
    });
    defer deinit(&logger);

    // These should be filtered out
    logger.trace("trace message");
    logger.debug("debug message");
    logger.info("info message");

    // This should pass
    logger.warn("warn message");
    logger.error("error message");

    const stats = getStats(&logger);
    // Only warn and error should be counted
    try std.testing.expectEqual(@as(u64, 2), stats.messages_written);
}

test "Format entry" {
    var buf: [256]u8 = undefined;
    const line = try formatEntry(&buf, .{
        .level = .info,
        .timestamp = 1234567890,
        .message = "test message",
        .module = "test_module",
    }, .{
        .enable_timestamp = true,
        .enable_module = true,
        .enable_location = false,
    });

    try std.testing.expect(std.mem.indexOf(u8, line, "test message") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "INFO") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "test_module") != null);
}

test "Format connection entry" {
    var buf: [512]u8 = undefined;
    const line = try formatEntry(&buf, .{
        .level = .debug,
        .timestamp = 1234567890,
        .message = "Connection established",
        .conn = .{
            .src_ip = 0x7F000001, // 127.0.0.1
            .src_port = 12345,
            .dst_ip = 0x7F000001,
            .dst_port = 80,
            .protocol = 6,
            .decision = "proxy",
        },
    }, .{
        .enable_timestamp = true,
        .enable_module = false,
        .enable_location = false,
    });

    try std.testing.expect(std.mem.indexOf(u8, line, "127.0.0.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "proxy") != null);
}

test "Scoped logger" {
    const allocator = std.testing.allocator;
    var logger = try init(allocator, .{});
    defer deinit(&logger);

    const scoped = logger.scoped("my_module");
    scoped.info("scoped message");

    const stats = getStats(&logger);
    try std.testing.expectEqual(@as(u64, 1), stats.messages_written);
}
