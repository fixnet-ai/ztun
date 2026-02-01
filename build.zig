//! build.zig - Build script for ztun
//!
//! Build commands:
//!   zig build              - Build native library and unit tests
//!   zig build test         - Build test_runner executable to zig-out/bin
//!   zig build all          - Build for all supported targets
//!
//! Note: test_runner requires root privileges. Run with:
//!   sudo ./zig-out/bin/test_runner

const std = @import("std");
const framework = @import("build_tools/build_framework.zig");

// ==================== Project Configuration ====================

const c_sources = &[_][]const u8{
    // No C sources - pure Zig implementation
};

const cflags = &[_][]const u8{
    "-std=c99",
    "-Wall",
    "-Wextra",
    "-O2",
};

const cinclude_dirs = &[_][]const u8{
    "src",
};

const zig_modules = &[_]framework.ZigModule{
    .{
        .name = "tun",
        .file = "src/tun.zig",
        .deps = &[_][]const u8{ "builder", "device", "platform", "device_linux", "device_macos", "device_windows" },
    },
    .{
        .name = "device",
        .file = "src/device.zig",
        .deps = &[_][]const u8{ "device_linux", "device_macos", "device_windows" },
    },
    .{
        .name = "device_linux",
        .file = "src/device_linux.zig",
        .deps = &[_][]const u8{ "device" },
    },
    .{
        .name = "device_macos",
        .file = "src/device_macos.zig",
        .deps = &[_][]const u8{ "device", "device_linux" },
    },
    .{
        .name = "device_windows",
        .file = "src/device_windows.zig",
        .deps = &[_][]const u8{ "device" },
    },
    .{
        .name = "builder",
        .file = "src/builder.zig",
        .deps = &[_][]const u8{ "device" },
    },
    .{
        .name = "platform",
        .file = "src/platform.zig",
        .deps = &[_][]const u8{},
    },
};

const test_files = &[_]framework.TestSpec{
    .{
        .name = "test_unit",
        .desc = "Unit tests",
        .file = "tests/test_unit.zig",
        .exe_name = null,
    },
    .{
        .name = "test_runner",
        .desc = "Integration tests",
        .file = "tests/test_runner.zig",
        .exe_name = "test_runner",
    },
};

const config = framework.ProjectConfig{
    .name = "ztun",
    .root_source_file = std.Build.LazyPath{ .cwd_relative = "src/main.zig" },
    .c_sources = c_sources,
    .cflags = cflags,
    .cinclude_dirs = cinclude_dirs,
    .zig_modules = zig_modules,
    .test_files = test_files,
};

// ==================== Build Functions ====================

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build native static library
    const lib = framework.buildNativeLib(b, target, optimize, config);
    b.installArtifact(lib);

    // Build unit tests (default step)
    framework.buildUnitTests(b, target, optimize, config);

    // Build test_runner executable (not auto-run, requires sudo)
    buildTestRunner(b, target, optimize, config);

    // Build all targets (no tests)
    const all_targets_step = b.step("all", "Build for all supported targets");
    const build_all = framework.buildAllTargets(b, optimize, config, &framework.standard_targets, &framework.standard_target_names);
    all_targets_step.dependOn(build_all);
}

/// Build test_runner executable to zig-out/bin (manual run with sudo)
fn buildTestRunner(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, cfg: framework.ProjectConfig) void {
    const test_runner_spec = for (cfg.test_files) |spec| {
        if (spec.exe_name != null) {
            break spec;
        }
    } else return;

    const test_runner = b.addExecutable(.{
        .name = test_runner_spec.exe_name.?,
        .root_source_file = b.path(test_runner_spec.file),
        .target = target,
        .optimize = optimize,
    });
    test_runner.linkLibC();

    // Add Zig modules
    const modules = framework.createModules(b, cfg);
    var iter = modules.map.iterator();
    while (iter.next()) |entry| {
        test_runner.root_module.addImport(entry.key_ptr.*, entry.value_ptr.*);
    }

    // Install to zig-out/bin
    const install_step = b.addInstallArtifact(test_runner, .{});

    // Test step only builds, does not run (requires sudo)
    const test_step = b.step("test", "Build test_runner executable (run with: sudo ./zig-out/bin/test_runner)");
    test_step.dependOn(&install_step.step);
}
