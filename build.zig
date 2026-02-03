//! build.zig - Build script for ztun
//!
//! Build commands:
//!   zig build              - Build native library and unit tests
//!   zig build test         - Build test_runner executable to bin/macos/
//!   zig build all          - Build static libraries for all targets
//!   zig build all-tests    - Build test_runner for all targets
//!
//! Output structure:
//!   zig-out/
//!   ├── lib/                    # Static libraries by platform
//!   │   ├── x86_64-linux-gnu/
//!   │   ├── aarch64-linux-gnu/
//!   │   ├── x86_64-macos/
//!   │   ├── aarch64-macos/
//!   │   ├── x86_64-windows-gnu/
//!   │   └── ...
//!   └── bin/                    # Test executables by platform
//!       ├── macos/              # Native macOS
//!       ├── linux-gnu/          # Cross-compiled Linux
//!       ├── windows/            # Cross-compiled Windows
//!       └── ...
//!
//! Note: test_runner requires root privileges. Run with:
//!   sudo ./zig-out/bin/macos/ztun_test_runner
//!   # Or on Linux VM:
//!   sudo /opt/ztest/ztun_test_runner

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

    // Build native static library to zig-out/
    const lib = framework.buildNativeLib(b, target, optimize, config);
    b.installArtifact(lib);

    // Build unit tests (default step)
    framework.buildUnitTests(b, target, optimize, config);

    // Build test_runner executable to bin/{os}/
    framework.buildTestRunner(b, target, optimize, config);

    // Build all static library targets (no tests)
    const all_targets_step = b.step("all", "Build static libraries for all supported targets");
    const build_all = framework.buildAllTargets(b, optimize, config, &framework.standard_targets, &framework.standard_target_names);
    all_targets_step.dependOn(build_all);

    // Build all test_runner targets for VM deployment
    const all_tests_step = b.step("all-tests", "Build test_runner for all supported targets");
    const build_all_tests = framework.buildAllTests(b, optimize, config, &framework.standard_targets, &framework.standard_target_names);
    all_tests_step.dependOn(build_all_tests);

    // ==================== Android Build Steps ====================

    // Build standalone Android test executable (minimal C imports)
    const android_test_step = b.step("android-test", "Build standalone Android test executable");

    const android_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .android,
    });

    const android_test = b.addExecutable(.{
        .name = "test_android",
        .root_source_file = b.path("tests/test_android.zig"),
        .target = android_target,
        .optimize = std.builtin.OptimizeMode.ReleaseSmall,
    });

    // Set sysroot for Android NDK
    const ndk_sysroot = "/Users/modasi/Library/Android/sdk/ndk/25.1.8937393/toolchains/llvm/prebuilt/darwin-x86_64/sysroot";

    // Add include paths for C imports
    android_test.root_module.addCSourceFiles(.{
        .files = &[_][]const u8{},
        .flags = &[_][]const u8{ "-isysroot", ndk_sysroot },
    });
    android_test.root_module.addSystemIncludePath(.{ .cwd_relative = ndk_sysroot ++ "/usr/include" });
    android_test.root_module.addSystemIncludePath(.{ .cwd_relative = ndk_sysroot ++ "/usr/include/x86_64-linux-android" });

    // Add library paths
    android_test.root_module.addLibraryPath(.{ .cwd_relative = ndk_sysroot ++ "/usr/lib/x86_64-linux-android/21" });
    android_test.root_module.addLibraryPath(.{ .cwd_relative = ndk_sysroot ++ "/usr/lib/x86_64-linux-android" });

    // Link libraries - must use linkLibC() with libc file for Android
    android_test.linkLibC();
    android_test.setLibCFile(.{ .cwd_relative = "/Users/modasi/.zvm/0.13.0/libc/x86_64-linux-android.txt" });
    android_test.linkSystemLibrary("log");

    // Install to bin/x86_64-linux-android/
    const android_install = b.addInstallArtifact(android_test, .{
        .dest_dir = .{ .override = .{ .custom = b.dupe("bin/x86_64-linux-android") } },
    });
    android_test_step.dependOn(&android_install.step);

    // Build test_runner for Android with full ztun modules
    const android_runner_step = b.step("android-runner", "Build test_runner for Android with full ztun modules");

    const android_runner = b.addExecutable(.{
        .name = "test_runner",
        .root_source_file = b.path("tests/test_runner.zig"),
        .target = android_target,
        .optimize = std.builtin.OptimizeMode.ReleaseSmall,
    });

    // Add Zig modules
    const modules = framework.createModules(b, config);
    var iter = modules.map.iterator();
    while (iter.next()) |entry| {
        android_runner.root_module.addImport(entry.key_ptr.*, entry.value_ptr.*);
    }

    // Add C sources with sysroot
    android_runner.root_module.addCSourceFiles(.{
        .files = config.c_sources,
        .flags = &[_][]const u8{ "-std=c99", "-Wall", "-Wextra", "-O2", "-isysroot", ndk_sysroot },
    });
    android_runner.root_module.addSystemIncludePath(.{ .cwd_relative = ndk_sysroot ++ "/usr/include" });
    android_runner.root_module.addSystemIncludePath(.{ .cwd_relative = ndk_sysroot ++ "/usr/include/x86_64-linux-android" });
    android_runner.root_module.addSystemIncludePath(.{ .cwd_relative = "src" });

    // Add library paths
    android_runner.root_module.addLibraryPath(.{ .cwd_relative = ndk_sysroot ++ "/usr/lib/x86_64-linux-android/21" });
    android_runner.root_module.addLibraryPath(.{ .cwd_relative = ndk_sysroot ++ "/usr/lib/x86_64-linux-android" });

    // Link libraries
    android_runner.linkLibC();
    android_runner.setLibCFile(.{ .cwd_relative = "/Users/modasi/.zvm/0.13.0/libc/x86_64-linux-android.txt" });
    android_runner.linkSystemLibrary("log");

    // Install
    const runner_install = b.addInstallArtifact(android_runner, .{
        .dest_dir = .{ .override = .{ .custom = b.dupe("bin/x86_64-linux-android") } },
    });
    android_runner_step.dependOn(&runner_install.step);

    // ==================== iOS Simulator Build Steps ====================

    // Build standalone iOS Simulator test executable
    const ios_test_step = b.step("ios-test", "Build standalone iOS Simulator test executable");

    const ios_sim_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .ios,
        .abi = .simulator,
    });

    const ios_test = b.addExecutable(.{
        .name = "test_ios",
        .root_source_file = b.path("tests/test_ios.zig"),
        .target = ios_sim_target,
        .optimize = std.builtin.OptimizeMode.ReleaseSmall,
    });

    // Set sysroot for iOS Simulator SDK
    const ios_sim_sysroot = "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator26.0.sdk";

    // Add include paths for C imports
    ios_test.root_module.addCSourceFiles(.{
        .files = &[_][]const u8{},
        .flags = &[_][]const u8{ "-isysroot", ios_sim_sysroot },
    });
    ios_test.root_module.addSystemIncludePath(.{ .cwd_relative = ios_sim_sysroot ++ "/usr/include" });

    // Link libraries
    ios_test.linkLibC();
    ios_test.setLibCFile(.{ .cwd_relative = "/Users/modasi/.zvm/0.13.0/libc/x86_64-ios-simulator.txt" });

    // Install to bin/x86_64-ios-sim/
    const ios_install = b.addInstallArtifact(ios_test, .{
        .dest_dir = .{ .override = .{ .custom = b.dupe("bin/x86_64-ios-sim") } },
    });
    ios_test_step.dependOn(&ios_install.step);

    // Build test_runner for iOS Simulator with full ztun modules
    const ios_runner_step = b.step("ios-runner", "Build test_runner for iOS Simulator with full ztun modules");

    const ios_runner = b.addExecutable(.{
        .name = "test_runner",
        .root_source_file = b.path("tests/test_runner.zig"),
        .target = ios_sim_target,
        .optimize = std.builtin.OptimizeMode.ReleaseSmall,
    });

    // Add Zig modules
    const ios_modules = framework.createModules(b, config);
    var ios_iter = ios_modules.map.iterator();
    while (ios_iter.next()) |entry| {
        ios_runner.root_module.addImport(entry.key_ptr.*, entry.value_ptr.*);
    }

    // Add C sources with sysroot
    ios_runner.root_module.addCSourceFiles(.{
        .files = config.c_sources,
        .flags = &[_][]const u8{ "-std=c99", "-Wall", "-Wextra", "-O2", "-isysroot", ios_sim_sysroot },
    });
    ios_runner.root_module.addSystemIncludePath(.{ .cwd_relative = ios_sim_sysroot ++ "/usr/include" });
    ios_runner.root_module.addSystemIncludePath(.{ .cwd_relative = "src" });

    // Link libraries
    ios_runner.linkLibC();
    ios_runner.setLibCFile(.{ .cwd_relative = "/Users/modasi/.zvm/0.13.0/libc/x86_64-ios-simulator.txt" });

    // Install
    const ios_runner_install = b.addInstallArtifact(ios_runner, .{
        .dest_dir = .{ .override = .{ .custom = b.dupe("bin/x86_64-ios-sim") } },
    });
    ios_runner_step.dependOn(&ios_runner_install.step);
}
