// wallet-zig: the wallet's state inside the skein VM (issue #29), in Zig over bsvz.
//
//   zig build test         the library and the vector corpus, native
//   zig build test-wasm    the same tests built for wasm32-wasi, run under Node's WASI
//   zig build program      the handler program (wasm32-wasi) → zig-out/bin/wallet.wasm
//
// bsvz comes from ../.build/bsvz (scripts/fetch-bsvz.sh pins and patches it).
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = libModule(b, target, optimize);
    _ = lib;

    // Native tests.
    const tests = b.addTest(.{ .root_module = testModule(b, target, optimize) });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run the library tests and the vector corpus");
    test_step.dependOn(&run_tests.step);

    // The same tests for wasm32-wasi, run with Node's WASI (scripts/run-wasi.mjs).
    const wasi = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .wasi });
    const wasm_tests = b.addTest(.{ .root_module = testModule(b, wasi, optimize) });
    const run_wasm = b.addSystemCommand(&.{ "node", "--no-warnings" });
    run_wasm.addFileArg(b.path("scripts/run-wasi.mjs"));
    run_wasm.addArtifactArg(wasm_tests);
    const wasm_step = b.step("test-wasm", "Run the tests built for wasm32-wasi under Node's WASI");
    wasm_step.dependOn(&run_wasm.step);

    // The handler program.
    const prog = b.addExecutable(.{
        .name = "wallet",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/program.zig"),
            .target = wasi,
            .optimize = .ReleaseSafe,
            .strip = true,
            .imports = &.{.{ .name = "wallet", .module = libModule(b, wasi, .ReleaseSafe) }},
        }),
    });
    const install_prog = b.addInstallArtifact(prog, .{});
    const prog_step = b.step("program", "Build the wallet handler program (wasm32-wasi)");
    prog_step.dependOn(&install_prog.step);
}

fn bsvzModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.dependency("bsvz", .{ .target = target, .optimize = optimize }).module("bsvz");
}

fn libModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "bsvz", .module = bsvzModule(b, target, optimize) }},
    });
}

fn testModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "bsvz", .module = bsvzModule(b, target, optimize) }},
    });
}
