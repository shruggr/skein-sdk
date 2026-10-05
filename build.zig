// skein-sdk: what a program for a skein VM is written against (issue #71), as a
// Zig package. Zig 0.16.0.
//
// Modules (`b.dependency("skein_sdk", .{ .target = t, .optimize = o }).module(name)`):
//
//   cid        CIDs: parse, format, the codecs skein uses                      src/cid.zig
//   cbor       dag-cbor values, encode/decode, CIDs of values (imports cid)    src/cbor.zig
//   mst        Merkle search trees over dag-cbor blocks (imports cbor, cid)    src/mst.zig
//   secp       BRC-42 "anyone" keys and ECDSA verification, pure Zig           src/secp.zig
//   sk         the preview1 `skein` imports and the helpers over them          lib/sk.zig
//   brc104     BRC-103/104 framing for programs (imports cbor, sk)             lib/brc104.zig
//   dagjson    dag-json (imports cbor)                                         lib/dagjson.zig
//   message    BRC-169 messages: build, sign through the oracle, verify        lib/message.zig
//   files      files from a git tree for an http handler: paths, index,      lib/files.zig
//              301, ETag/304, content types, 404/405 (imports cbor, sk;
//              shruggr/skein#125, moved out of skein-static)
//   app        calling an app (skein docs/APPS.md §4): {fn, args} dispatch     lib/app.zig
//              by the manifest's `provides`, args checked, `writes` enforced,
//              the answer message; the `/call` route (imports cbor, sk, dagjson)
//   cabi       malloc/realloc/free/abort/strlen for wit-bindgen's C bindings   wit/zig/cabi.zig
//   skein_wit  the `skein` calls over the WIT interface, for a component       wit/zig/skein_wit.zig
//              build (the C bindings compiled in: wit/bindings/c)
//   chain      the chain library: headers and the chain tracker, merkle       chain/src/lib.zig
//              paths, BEEF, SPV, the record store and its index maps, and
//              `state`, the chain app's records (shruggr/skein#78; over bsvz)
//   wallet     the wallet library over `chain` (re-exported under the same    wallet/src/lib.zig
//              names): BRC-29, the builder, the wallet's records and index
//              maps, the overlay's state (over bsvz)
//
// `wallet` imports the same `chain` module this package exports, so a
// program may import either or both.
//
// The WIT package itself is wit/ (`dep.path("wit/…")` for a component build).
//
//   zig build test          every module's tests and the wallet's vector corpus, natively
//   zig build test-wasm     the wallet's tests built for wasm32-wasi, run under Node's WASI
//
// bsvz is a lazy URL dependency (build.zig.zon): fetched only when the wallet
// module is asked for. `-Dwallet=false` leaves the wallet out entirely (the
// skein kernel builds that way: it needs the codecs only).
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const with_wallet = b.option(bool, "wallet", "include the wallet module (fetches bsvz)") orelse true;

    const c = codecs(b, target, optimize);
    b.modules.put(b.graph.arena, "cid", c.cid) catch @panic("OOM");
    b.modules.put(b.graph.arena, "cbor", c.cbor) catch @panic("OOM");
    b.modules.put(b.graph.arena, "mst", c.mst) catch @panic("OOM");
    const secp = b.addModule("secp", .{ .root_source_file = b.path("src/secp.zig"), .target = target, .optimize = optimize });
    const sk = b.addModule("sk", .{ .root_source_file = b.path("lib/sk.zig"), .target = target, .optimize = optimize, .imports = &.{.{ .name = "cbor", .module = c.cbor }} });
    _ = b.addModule("brc104", .{ .root_source_file = b.path("lib/brc104.zig"), .target = target, .optimize = optimize, .imports = &.{ .{ .name = "cbor", .module = c.cbor }, .{ .name = "sk", .module = sk } } });
    const dagjson = b.addModule("dagjson", .{ .root_source_file = b.path("lib/dagjson.zig"), .target = target, .optimize = optimize, .imports = &.{.{ .name = "cbor", .module = c.cbor }} });
    _ = b.addModule("message", .{ .root_source_file = b.path("lib/message.zig"), .target = target, .optimize = optimize, .imports = &.{ .{ .name = "cbor", .module = c.cbor }, .{ .name = "secp", .module = secp } } });
    const files = b.addModule("files", .{ .root_source_file = b.path("lib/files.zig"), .target = target, .optimize = optimize, .imports = &.{ .{ .name = "cbor", .module = c.cbor }, .{ .name = "sk", .module = sk } } });
    const app = b.addModule("app", .{ .root_source_file = b.path("lib/app.zig"), .target = target, .optimize = optimize, .imports = &.{ .{ .name = "cbor", .module = c.cbor }, .{ .name = "sk", .module = sk }, .{ .name = "dagjson", .module = dagjson } } });

    // The component glue: no wasi-libc (wit/README.md says why).
    const cabi = b.addModule("cabi", .{ .root_source_file = b.path("wit/zig/cabi.zig"), .target = target, .optimize = optimize });
    const wit = b.addModule("skein_wit", .{ .root_source_file = b.path("wit/zig/skein_wit.zig"), .target = target, .optimize = optimize, .imports = &.{.{ .name = "cabi", .module = cabi }} });
    wit.addIncludePath(b.path("wit/bindings/c"));
    wit.addIncludePath(b.path("wit/zig/c"));
    wit.addCSourceFile(.{ .file = b.path("wit/bindings/c/program.c"), .flags = &.{"-O2"} });
    wit.addObjectFile(b.path("wit/bindings/c/program_component_type.o"));

    const test_step = b.step("test", "every module's tests and the wallet's vector corpus, natively");
    for ([_]*std.Build.Module{ c.cid, c.cbor, c.mst, secp, dagjson, files, app }) |m| {
        test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = m })).step);
    }

    if (!with_wallet) return;
    const chain = chainModule(b, "chain/src/lib.zig", target, optimize, c.mst) orelse return;
    b.modules.put(b.graph.arena, "chain", chain) catch @panic("OOM");
    const wallet = walletModule(b, "wallet/src/lib.zig", target, optimize, c.mst, chain) orelse return;
    b.modules.put(b.graph.arena, "wallet", wallet) catch @panic("OOM");

    const ctests = b.addTest(.{ .root_module = chainModule(b, "chain/test.zig", target, optimize, c.mst).? });
    test_step.dependOn(&b.addRunArtifact(ctests).step);
    const wtests = b.addTest(.{ .root_module = walletModule(b, "wallet/test.zig", target, optimize, c.mst, chain).? });
    test_step.dependOn(&b.addRunArtifact(wtests).step);

    // The same tests for wasm32-wasi, run with Node's WASI (wallet/scripts/run-wasi.mjs).
    const wasi = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .wasi });
    const wmst = codecs(b, wasi, optimize).mst;
    const wasm_tests = b.addTest(.{ .root_module = walletModule(b, "wallet/test.zig", wasi, optimize, wmst, chainModule(b, "chain/src/lib.zig", wasi, optimize, wmst).?).? });
    const run_wasm = b.addSystemCommand(&.{ "node", "--no-warnings" });
    run_wasm.addFileArg(b.path("wallet/scripts/run-wasi.mjs"));
    run_wasm.addArtifactArg(wasm_tests);
    b.step("test-wasm", "the wallet's tests built for wasm32-wasi, under Node's WASI").dependOn(&run_wasm.step);
}

const Codecs = struct { cid: *std.Build.Module, cbor: *std.Build.Module, mst: *std.Build.Module };

/// The codecs for one target: cid, cbor over it, mst over both.
fn codecs(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) Codecs {
    const cid = b.createModule(.{ .root_source_file = b.path("src/cid.zig"), .target = target, .optimize = optimize });
    const cbor = b.createModule(.{ .root_source_file = b.path("src/cbor.zig"), .target = target, .optimize = optimize, .imports = &.{.{ .name = "cid", .module = cid }} });
    const mst = b.createModule(.{ .root_source_file = b.path("src/mst.zig"), .target = target, .optimize = optimize, .imports = &.{ .{ .name = "cbor", .module = cbor }, .{ .name = "cid", .module = cid } } });
    return .{ .cid = cid, .cbor = cbor, .mst = mst };
}

/// The chain library (or its test root) over bsvz and the SDK's mst.
fn chainModule(b: *std.Build, root: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, mst: *std.Build.Module) ?*std.Build.Module {
    const bsvz = b.lazyDependency("bsvz", .{ .target = target, .optimize = optimize }) orelse return null;
    return b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "bsvz", .module = bsvz.module("bsvz") }, .{ .name = "mst", .module = mst } },
    });
}

/// The wallet library (or its test root) over bsvz, the SDK's mst and the chain library.
fn walletModule(b: *std.Build, root: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, mst: *std.Build.Module, chain: *std.Build.Module) ?*std.Build.Module {
    const bsvz = b.lazyDependency("bsvz", .{ .target = target, .optimize = optimize }) orelse return null;
    return b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "bsvz", .module = bsvz.module("bsvz") }, .{ .name = "mst", .module = mst }, .{ .name = "chain", .module = chain } },
    });
}
