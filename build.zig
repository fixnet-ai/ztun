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
    "src/system/route.c",
    "src/system/network.c",
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
        .file = "src/tun/mod.zig",
        .deps = &[_][]const u8{ "device", "device_linux", "device_darwin", "device_windows" },
    },
    .{
        .name = "device",
        .file = "src/tun/device.zig",
        .deps = &[_][]const u8{ "device_linux", "device_darwin", "device_windows" },
    },
    .{
        .name = "device_linux",
        .file = "src/tun/device_linux.zig",
        .deps = &[_][]const u8{"device"},
    },
    .{
        .name = "device_darwin",
        .file = "src/tun/device_darwin.zig",
        .deps = &[_][]const u8{"device"},
    },
    .{
        .name = "device_windows",
        .file = "src/tun/device_windows.zig",
        .deps = &[_][]const u8{"device"},
    },
    // IP stack submodules (all in src/ipstack/)
    .{
        .name = "ipstack_checksum",
        .file = "src/ipstack/checksum.zig",
        .deps = &[_][]const u8{},
    },
    .{
        .name = "ipstack_ipv4",
        .file = "src/ipstack/ipv4.zig",
        .deps = &[_][]const u8{"ipstack_checksum"},
    },
    .{
        .name = "ipstack_ipv6",
        .file = "src/ipstack/ipv6.zig",
        .deps = &[_][]const u8{"ipstack_checksum"},
    },
    .{
        .name = "ipstack_tcp",
        .file = "src/ipstack/tcp.zig",
        .deps = &[_][]const u8{ "ipstack_checksum", "ipstack_ipv4" },
    },
    .{
        .name = "ipstack_udp",
        .file = "src/ipstack/udp.zig",
        .deps = &[_][]const u8{ "ipstack_checksum", "ipstack_ipv4" },
    },
    .{
        .name = "ipstack_icmp",
        .file = "src/ipstack/icmp.zig",
        .deps = &[_][]const u8{ "ipstack_checksum", "ipstack_ipv4", "ipstack_ipv6" },
    },
    .{
        .name = "ipstack_callbacks",
        .file = "src/ipstack/callbacks.zig",
        .deps = &[_][]const u8{"ipstack_connection"},
    },
    .{
        .name = "ipstack_connection",
        .file = "src/ipstack/connection.zig",
        .deps = &[_][]const u8{},
    },
    .{
        .name = "ipstack",
        .file = "src/ipstack/mod.zig",
        .deps = &[_][]const u8{
            "ipstack_checksum",
            "ipstack_ipv4",
            "ipstack_ipv6",
            "ipstack_tcp",
            "ipstack_udp",
            "ipstack_icmp",
            "ipstack_callbacks",
            "ipstack_connection",
            "tun",
        },
    },
    // System stack (TunStack interface wrapper for StaticIpstack)
    .{
        .name = "stack_system",
        .file = "src/ipstack/stack_core.zig",
        .deps = &[_][]const u8{ "tun", "ipstack" },
    },
    // Router submodules (all in src/router/)
    .{
        .name = "router_route",
        .file = "src/router/route.zig",
        .deps = &[_][]const u8{},
    },
    .{
        .name = "router_nat",
        .file = "src/router/nat.zig",
        .deps = &[_][]const u8{},
    },
    .{
        .name = "router_socks5",
        .file = "src/router/proxy/socks5.zig",
        .deps = &[_][]const u8{"router_route"},
    },
    .{
        .name = "router",
        .file = "src/router/mod.zig",
        .deps = &[_][]const u8{
            "router_route",
            "router_nat",
            "router_socks5",
            "ipstack",
            "monitor",
        },
    },
    // System modules (all in src/system/)
    .{
        .name = "network",
        .file = "src/system/network.zig",
        .deps = &[_][]const u8{},
    },
    .{
        .name = "monitor",
        .file = "src/system/monitor.zig",
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

    // Build tun2sock executable to bin/{os}/
    const tun2sock_step = b.step("tun2sock", "Build tun2sock application");
    const tun2sock = b.addExecutable(.{
        .name = "tun2sock",
        .root_source_file = b.path("src/tun2sock.zig"),
        .target = target,
        .optimize = optimize,
    });
    tun2sock.linkLibC();
    // Add C source files (route.c, network.c)
    tun2sock.root_module.addCSourceFiles(.{
        .files = config.c_sources,
        .flags = config.cflags,
    });
    tun2sock.root_module.addSystemIncludePath(.{ .cwd_relative = "src" });
    // Add Zig modules
    const all_modules = framework.createModules(b, config);
    var tun2sock_iter = all_modules.map.iterator();
    while (tun2sock_iter.next()) |entry| {
        tun2sock.root_module.addImport(entry.key_ptr.*, entry.value_ptr.*);
    }
    // Add libxev dependency and add xev module to router module
    const libxev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });
    // Add xev module to router module's dependencies
    if (all_modules.map.get("router")) |router_mod| {
        router_mod.addImport("xev", libxev.module("xev"));
    }
    tun2sock.root_module.addImport("xev", libxev.module("xev"));
    // Add zinternal dependency (exports "app", "platform", "logger", etc.)
    const zinternal = b.dependency("zinternal", .{
        .target = target,
        .optimize = optimize,
    });
    tun2sock.root_module.addImport("app", zinternal.module("app"));
    tun2sock.root_module.addImport("platform", zinternal.module("platform"));
    tun2sock.root_module.addImport("logger", zinternal.module("logger"));
    tun2sock.root_module.addImport("signal", zinternal.module("signal"));
    tun2sock.root_module.addImport("config", zinternal.module("config"));
    tun2sock.root_module.addImport("storage", zinternal.module("storage"));
    // Install to bin/linux-gnu/ for cross-compiled targets
    const bin_dir = if (target.result.os.tag == .linux) "bin/linux-gnu" else "bin/macos";
    const tun2sock_install = b.addInstallArtifact(tun2sock, .{
        .dest_dir = .{ .override = .{ .custom = bin_dir } },
    });
    tun2sock_step.dependOn(&tun2sock_install.step);

    // Build test_http_server executable for TUN testing
    const test_http_step = b.step("test-http-server", "Build simple HTTP 200 server for testing");
    const test_http = b.addExecutable(.{
        .name = "test_http_server",
        .root_source_file = b.path("tests/test_http_server.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_http.linkLibC();
    const test_http_bin_dir = if (target.result.os.tag == .linux) "bin/linux-gnu" else "bin/macos";
    const test_http_install = b.addInstallArtifact(test_http, .{
        .dest_dir = .{ .override = .{ .custom = test_http_bin_dir } },
    });
    test_http_step.dependOn(&test_http_install.step);

    // Build test_tun executable to bin/{os}/
    const test_tun_step = b.step("test-tun", "Build ping echo test application");
    const test_tun = b.addExecutable(.{
        .name = "test_tun",
        .root_source_file = b.path("tests/test_tun.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_tun.linkLibC();
    // Add C source files (route.c, network.c)
    test_tun.root_module.addCSourceFiles(.{
        .files = config.c_sources,
        .flags = config.cflags,
    });
    test_tun.root_module.addSystemIncludePath(.{ .cwd_relative = "src" });
    // Add Zig modules (includes network)
    var test_tun_iter = all_modules.map.iterator();
    while (test_tun_iter.next()) |entry| {
        test_tun.root_module.addImport(entry.key_ptr.*, entry.value_ptr.*);
    }
    // Add libxev dependency
    test_tun.root_module.addImport("xev", libxev.module("xev"));
    // Install to bin/linux-gnu/ for cross-compiled targets
    const test_tun_bin_dir = if (target.result.os.tag == .linux) "bin/linux-gnu" else "bin/macos";
    const test_tun_install = b.addInstallArtifact(test_tun, .{
        .dest_dir = .{ .override = .{ .custom = test_tun_bin_dir } },
    });
    test_tun_step.dependOn(&test_tun_install.step);

    // Build forwarding integration test executable
    const test_forwarding_step = b.step("test-forwarding", "Build TCP/UDP/SOCKS5 forwarding test");
    const test_forwarding = b.addExecutable(.{
        .name = "test_forwarding",
        .root_source_file = b.path("tests/test_forwarding.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_forwarding.linkLibC();
    test_forwarding.root_module.addCSourceFiles(.{
        .files = config.c_sources,
        .flags = config.cflags,
    });
    test_forwarding.root_module.addSystemIncludePath(.{ .cwd_relative = "src" });
    var test_forwarding_iter = all_modules.map.iterator();
    while (test_forwarding_iter.next()) |entry| {
        test_forwarding.root_module.addImport(entry.key_ptr.*, entry.value_ptr.*);
    }
    test_forwarding.root_module.addImport("xev", libxev.module("xev"));
    const test_forwarding_install = b.addInstallArtifact(test_forwarding, .{
        .dest_dir = .{ .override = .{ .custom = b.dupe(if (target.result.os.tag == .linux) "bin/linux-gnu" else "bin/macos") } },
    });
    test_forwarding_step.dependOn(&test_forwarding_install.step);

    // Build full integration test executable (TCP/UDP/SOCKS5)
    const test_integration_step = b.step("test-integration", "Build full integration test");
    const test_integration = b.addExecutable(.{
        .name = "test_integration",
        .root_source_file = b.path("tests/test_integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_integration.linkLibC();
    test_integration.root_module.addCSourceFiles(.{
        .files = config.c_sources,
        .flags = config.cflags,
    });
    test_integration.root_module.addSystemIncludePath(.{ .cwd_relative = "src" });
    var test_integration_iter = all_modules.map.iterator();
    while (test_integration_iter.next()) |entry| {
        test_integration.root_module.addImport(entry.key_ptr.*, entry.value_ptr.*);
    }
    test_integration.root_module.addImport("xev", libxev.module("xev"));
    const test_integration_install = b.addInstallArtifact(test_integration, .{
        .dest_dir = .{ .override = .{ .custom = b.dupe(if (target.result.os.tag == .linux) "bin/linux-gnu" else "bin/macos") } },
    });
    test_integration_step.dependOn(&test_integration_install.step);

    // Build SystemStack protocol stack test executable
    const test_stack_step = b.step("test-stack", "Build SystemStack protocol test");
    const test_stack = b.addExecutable(.{
        .name = "test_stack_core",
        .root_source_file = b.path("tests/test_stack_core.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_stack.linkLibC();
    test_stack.root_module.addCSourceFiles(.{
        .files = config.c_sources,
        .flags = config.cflags,
    });
    test_stack.root_module.addSystemIncludePath(.{ .cwd_relative = "src" });
    var test_stack_iter = all_modules.map.iterator();
    while (test_stack_iter.next()) |entry| {
        test_stack.root_module.addImport(entry.key_ptr.*, entry.value_ptr.*);
    }
    test_stack.root_module.addImport("xev", libxev.module("xev"));
    const test_stack_install = b.addInstallArtifact(test_stack, .{
        .dest_dir = .{ .override = .{ .custom = b.dupe(if (target.result.os.tag == .linux) "bin/linux-gnu" else "bin/macos") } },
    });
    test_stack_step.dependOn(&test_stack_install.step);

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
