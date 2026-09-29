// wallet-zig: the wallet's state inside the skein VM (issue #29), in Zig over bsvz.
//
//   zig build test         the library and the vector corpus, native
//   zig build test-wasm    the same tests built for wasm32-wasi, run under Node's WASI
//   zig build program      the handler program (wasm32-wasi) → zig-out/bin/wallet.wasm
//   zig build component    the same program as a WASI 0.2 component (#34) → zig-out/bin/wallet.component.wasm
//
// bsvz comes from ../.build/bsvz (scripts/fetch-bsvz.sh pins and patches it).
// The index maps are the kernel's Merkle search trees: ../kernel-zig/src/mst.zig
// (with its cbor.zig and cid.zig) built as the module "mst" — shared, not copied.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The library, for other builds (programs/overlay, #36: `b.dependency("wallet", …).module("wallet")`).
    const lib = libModule(b, target, optimize);
    b.modules.put(b.graph.arena, "wallet", lib) catch @panic("OOM");

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
    const prog = programExe(b, wasi, false);
    const install_prog = b.addInstallArtifact(prog, .{});
    const prog_step = b.step("program", "Build the wallet handler program (wasm32-wasi)");
    prog_step.dependOn(&install_prog.step);

    // The same program as a WASI 0.2 component (issue #34): the skein calls
    // through the WIT (../wit/skein.wit, world `program`) and wit-bindgen's C
    // bindings (../wit/bindings/c), HTTP over standard wasi:http (#15,
    // src/wasi_http.zig), WASI through the preview1 command adapter.
    // Needs wasm-tools (-Dwasm-tools, default on PATH) and the adapter
    // (-Dwasi-adapter, else $SKEIN_WASI_ADAPTER, else
    // ~/.local/wasi-adapter-v49.0.1/wasi_snapshot_preview1.command.wasm).
    const home = b.graph.environ_map.get("HOME") orelse "/root";
    const env_adapter = b.graph.environ_map.get("SKEIN_WASI_ADAPTER");
    const adapter = b.option([]const u8, "wasi-adapter", "the preview1 command adapter (wasmtime v49.0.1)") orelse env_adapter orelse
        b.fmt("{s}/.local/wasi-adapter-v49.0.1/wasi_snapshot_preview1.command.wasm", .{home});
    const wasm_tools = b.option([]const u8, "wasm-tools", "wasm-tools (1.259.0)") orelse "wasm-tools";
    const core = programExe(b, wasi, true);
    // The core module carries the world (program_component_type.o, from wit-bindgen).
    const new = b.addSystemCommand(&.{ wasm_tools, "component", "new" });
    new.addArtifactArg(core);
    new.addArg(b.fmt("--adapt=wasi_snapshot_preview1={s}", .{adapter}));
    new.addArg("-o");
    const comp = new.addOutputFileArg("wallet.component.wasm");
    const install_comp = b.addInstallBinFile(comp, "wallet.component.wasm");
    const comp_step = b.step("component", "Build the wallet handler program as a WASI 0.2 component");
    comp_step.dependOn(&install_comp.step);
}

/// The handler program, for preview1 (the `skein` imports) or as the core of
/// the component (the WIT's C bindings compiled in; no libc: src/cabi.zig).
fn programExe(b: *std.Build, wasi: std.Build.ResolvedTarget, component: bool) *std.Build.Step.Compile {
    const opts = b.addOptions();
    opts.addOption(bool, "component", component);
    const mod = b.createModule(.{
        .root_source_file = b.path("src/program.zig"),
        .target = wasi,
        .optimize = .ReleaseSafe,
        .strip = true,
        .imports = &.{
            .{ .name = "wallet", .module = libModule(b, wasi, .ReleaseSafe) },
            .{ .name = "build_options", .module = opts.createModule() },
        },
    });
    if (component) {
        mod.addIncludePath(b.path("../wit/bindings/c"));
        mod.addIncludePath(b.path("src/c"));
        mod.addCSourceFile(.{ .file = b.path("../wit/bindings/c/program.c"), .flags = &.{"-O2"} });
        mod.addObjectFile(b.path("../wit/bindings/c/program_component_type.o"));
    }
    return b.addExecutable(.{ .name = if (component) "wallet-core" else "wallet", .root_module = mod });
}

fn bsvzModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.dependency("bsvz", .{ .target = target, .optimize = optimize }).module("bsvz");
}

fn mstModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("../kernel-zig/src/mst.zig"),
        .target = target,
        .optimize = optimize,
    });
}

fn imports(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) []const std.Build.Module.Import {
    return b.allocator.dupe(std.Build.Module.Import, &.{
        .{ .name = "bsvz", .module = bsvzModule(b, target, optimize) },
        .{ .name = "mst", .module = mstModule(b, target, optimize) },
    }) catch @panic("OOM");
}

fn libModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports(b, target, optimize),
    });
}

fn testModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports(b, target, optimize),
    });
}
