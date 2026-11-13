//! The chain app's BEEF check (skein next, SPEC.md section 6: `chain.beef`, a row's `checks`
//! entry). Moved out of the skein kernel (kernel-zig/src/door.zig `kernel.beef`, at skein v0.9.1)
//! into this library, which the chain app's check function calls: the kernel keeps no BEEF code and
//! names no `chain/state`.
//!
//! `check(a, r, state, package)`: the package as CHECK hands it to the row's checks — a request
//! record {kind: "request", payload: {…, body}, signature?}, or an event record (any map) — read
//! for its BEEF: the request's body when its bytes start with a BEEF pattern (beef.zig `patterns`),
//! else each top-level field of a dag-cbor body that does; an event record's own top-level fields
//! likewise. No deeper. Each BEEF found is proven, always: skein-sdk's verifier (chain/src/spv.zig
//! `verify`) over the BEEF alone — every BUMP's root the header's at its height in the chain
//! state, every transaction no BUMP proves spending only transactions before it in the BEEF (or
//! held) with its scripts verified, a txid-only entry only for a transaction the instance HOLDS
//! (the chain state's `txs`, not `rejected`). Any error refuses the whole package (its name first),
//! as does no chain state and no BEEF at all ("nothing to validate"). Passed: the blocks to store —
//! each transaction as its `bitcoin-tx` block, each BUMP as the raw block of its bytes and the
//! merkle nodes it reveals, each pointer record (beef.zig `record`) — and the package with each
//! BEEF's bytes replaced by its envelope (beef.zig `envelope`; a dag-cbor body is handed back
//! decoded, the map with the envelopes in it). The caller (the chain app's check) puts the blocks
//! and names them in its {pass: {request, blocks}} answer; the kernel writes them at COMMIT.
//!
//! `restore` is the lossless rule's other half: the bytes an envelope stands for, put back.
const std = @import("std");
const cbor = @import("cbor");
const cidm = @import("cid");
const mst = @import("mst");
const chain = @import("chain");
pub const beef = @import("beef.zig");
const Value = cbor.Value;

/// Blocks by CID (the chain app's store, as its program reads it): null when absent.
pub const Reader = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, a: std.mem.Allocator, cid: []const u8) anyerror!?[]u8,
};

/// A block the check stores (CID, bytes).
pub const Block = struct { cid: []const u8, bytes: []const u8 };

/// What the check came to: the package to hand on (rewritten, or as received when refused), the
/// blocks to store, the pointer records it made, and — refused — why.
pub const Out = struct {
    package: Value,
    blocks: []const Block,
    pointers: []const []const u8,
    refused: ?[]const u8 = null,
};

pub const NOTHING_VALIDATED = "nothing to validate: no BEEF in the request body, a top-level field of a dag-cbor body, or the event record";

/// The chain state's headers, read only: {kind: "chain-state", maps: {headers: <MST root>, txs,
/// rejected}}, the map height (u32 big-endian) → the header (a bitcoin-block link) on its best chain.
pub const Headers = struct {
    r: Reader,
    root: ?[]const u8,
    /// The chain state's `txs` (txid → its bitcoin-tx block) and `rejected` (txid → its settlement
    /// record) maps: what the instance HOLDS, the one thing a BEEF may name by txid alone.
    txs: ?[]const u8 = null,
    rejected: ?[]const u8 = null,
    forest: mst.Forest,

    fn blockGet(ctx: *anyopaque, a: std.mem.Allocator, cid: []const u8) anyerror!?[]u8 {
        const h: *Headers = @ptrCast(@alignCast(ctx));
        return h.r.get(h.r.ctx, a, cid);
    }

    /// The headers of the chain state record `state`; null when it is none.
    pub fn open(a: std.mem.Allocator, r: Reader, state: []const u8) !?*Headers {
        const b = (try r.get(r.ctx, a, state)) orelse return null;
        const v = cbor.decode(a, b) catch return null;
        if (!std.mem.eql(u8, Value.str(v.get("kind")) orelse "", "chain-state")) return null;
        const maps = v.get("maps") orelse return null;
        const h = try a.create(Headers);
        h.* = .{ .r = r, .root = Value.cidOf(maps.get("headers")), .txs = Value.cidOf(maps.get("txs")), .rejected = Value.cidOf(maps.get("rejected")), .forest = undefined };
        h.forest = mst.Forest.init(a, .{ .ctx = h, .get = blockGet });
        return h;
    }

    /// A transaction the instance holds — the chain state holds it and it is not rejected — its raw
    /// bytes; null otherwise.
    pub fn held(h: *Headers, a: std.mem.Allocator, txid: [32]u8) !?[]const u8 {
        const v = (try h.forest.get(a, h.txs, &txid)) orelse return null;
        if ((try h.forest.get(a, h.rejected, &txid)) != null) return null;
        const c = Value.cidOf(v) orelse return null;
        return (try h.r.get(h.r.ctx, a, c)) orelse null;
    }

    /// The header at `height`: its CID and its merkle root; null when the chain state has none there.
    pub fn at(h: *Headers, a: std.mem.Allocator, height: u32) !?struct { cid: []const u8, root: [32]u8 } {
        var key: [4]u8 = undefined;
        std.mem.writeInt(u32, &key, height, .big);
        const v = (try h.forest.get(a, h.root, &key)) orelse return null;
        const c = Value.cidOf(v) orelse return null;
        const raw = (try h.r.get(h.r.ctx, a, c)) orelse return null;
        if (raw.len != 80) return null;
        return .{ .cid = c, .root = raw[36..68].* };
    }
};

const Walk = struct {
    a: std.mem.Allocator,
    headers: ?*Headers,
    found: usize = 0,
    pointers: std.ArrayList([]const u8) = .empty,
    refused: ?[]const u8 = null,
    /// What a pass stores (a refusal stores nothing).
    blocks: std.ArrayList(Block) = .empty,
    seen: std.StringHashMapUnmanaged(void) = .empty,

    fn refuse(w: *Walk, comptime f: []const u8, args: anytype) !void {
        if (w.refused == null) w.refused = try std.fmt.allocPrint(w.a, f, args);
    }

    /// One value: a BEEF's bytes → its envelope; anything else as it is.
    fn one(w: *Walk, v: Value) !Value {
        const b = Value.bytesOf(v) orelse return v;
        if (beef.recognize(b) == null) return v;
        return w.bytes(b);
    }

    /// Each top-level field of a map: a BEEF's bytes → its envelope.
    fn fields(w: *Walk, m: Value) !Value {
        const out = try w.a.alloc(cbor.Entry, m.map.len);
        for (m.map, out) |e, *o| o.* = .{ .key = e.key, .value = try w.one(e.value) };
        return .{ .map = out };
    }

    fn bytes(w: *Walk, b: []const u8) !Value {
        const a = w.a;
        w.found += 1;
        const d = beef.parse(a, b) catch {
            try w.refuse("a BEEF that does not decode (it starts with a BEEF pattern)", .{});
            return .{ .bytes = b };
        };
        const h = w.headers orelse {
            try w.refuse("no chain state (the chain app has seen no header)", .{});
            return .{ .bytes = b };
        };
        const proven = spv(a, h, b, d) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try w.refuse("{s}: {s}", .{ @errorName(e), spvWhy(e) });
                return .{ .bytes = b };
            },
        };
        // What block storage needs: each BUMP's nodes and the header it gives the root of (its `block`).
        const checked = try a.alloc(beef.Checked, d.bumps.len);
        var nodes: std.ArrayList(beef.Node) = .empty;
        for (d.bumps, checked, 0..) |p, *c, i| {
            const rev = beef.reveal(a, p) catch {
                try w.refuse("BUMP {d} (height {d}): malformed, or its nodes conflict", .{ i, p.height });
                c.* = .{ .block = null, .proves = &.{} };
                continue;
            };
            var ps: std.ArrayList(usize) = .empty;
            for (d.txs, proven, 0..) |t, ok, k| if (ok) switch (t.mark) {
                .bump => |j| if (j == i) try ps.append(a, k),
                .none => if (beef.holds(p, t.txid, true)) try ps.append(a, k),
                .txid => {},
            };
            c.* = .{ .block = null, .proves = ps.items };
            const hdr = (try h.at(a, p.height)) orelse continue;
            if (!std.mem.eql(u8, &hdr.root, &rev.root)) continue; // a BUMP proving nothing here (the verifier's "harmless")
            c.block = hdr.cid;
            try nodes.appendSlice(a, rev.nodes);
        }
        // Each block once.
        for (d.txs) |t| if (t.raw) |raw| try w.keep(try beef.txCid(a, t.txid), raw);
        for (d.bumps) |p| try w.keep(try cidm.ofRaw(a, p.bytes), p.bytes);
        for (nodes.items) |n| try w.keep(try beef.txCid(a, n.hash), try a.dupe(u8, &n.bytes));
        const blk = try cbor.block(a, try beef.record(a, d, checked));
        try w.keep(blk.cid, blk.bytes);
        try w.pointers.append(a, blk.cid);
        return beef.envelope(a, d, blk.cid);
    }

    fn keep(w: *Walk, c: []const u8, b: []const u8) !void {
        const g = try w.seen.getOrPut(w.a, c);
        if (g.found_existing) return;
        try w.blocks.append(w.a, .{ .cid = try w.a.dupe(u8, c), .bytes = try w.a.dupe(u8, b) });
    }
};

/// skein-sdk's SPV (chain/src/spv.zig `verify`) over the BEEF `b` (this file's parse `d` beside it):
/// `rootAt` the merkle root of the chain state's header at a height, `knownRaw` the transactions the
/// instance holds. Per transaction (wire order), whether a BUMP checked against the header proves it.
/// error.Disagree: chain/src/beef.zig's parse is not this one's.
fn spv(a: std.mem.Allocator, h: *Headers, b: []const u8, d: beef.Beef) ![]bool {
    const sb = chain.beef.parse(a, b) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidBeef => return error.InvalidBeef,
    };
    if (sb.entries.len != d.txs.len or sb.bumps.len != d.bumps.len) return error.Disagree;
    for (sb.entries, d.txs) |e, t| {
        if (!std.mem.eql(u8, &e.txid, &t.txid)) return error.Disagree;
        const same = switch (t.mark) {
            .none => e.format == .raw,
            .bump => |i| e.format == .raw_with_bump and e.bump == i,
            .txid => e.format == .txid_only,
        };
        if (!same) return error.Disagree;
    }
    const Ctx = struct {
        h: *Headers,
        a: std.mem.Allocator,
        fn rootAt(ptr: *anyopaque, height: u32) anyerror!?[32]u8 {
            const c: *@This() = @ptrCast(@alignCast(ptr));
            return if (try c.h.at(c.a, height)) |x| x.root else null;
        }
        fn knownRaw(ptr: *anyopaque, _: std.mem.Allocator, txid: [32]u8) anyerror!?[]const u8 {
            const c: *@This() = @ptrCast(@alignCast(ptr));
            return c.h.held(c.a, txid);
        }
    };
    var ctx = Ctx{ .h = h, .a = a };
    const r = try chain.spv.verify(a, sb, .{ .ptr = &ctx, .rootAtFn = Ctx.rootAt, .knownRawFn = Ctx.knownRaw });
    return r.proven;
}

/// What each of the verifier's errors means, for the refusal's reason (its name first).
fn spvWhy(e: anyerror) []const u8 {
    return switch (e) {
        error.InvalidBeef => "skein-sdk's BEEF parser refuses it",
        error.Disagree => "skein-sdk's two BEEF parses disagree (the transactions or their marks differ)",
        error.UnknownHeader => "a BUMP's height has no header in the chain state",
        error.RootMismatch => "a BUMP's merkle root is not the header's at its height in the chain state",
        error.NotInBump => "a transaction marked with a BUMP is not in it",
        error.MissingInput => "a transaction no BUMP proves spends an output of a transaction neither before it in the BEEF nor held here",
        error.UnknownTxidOnly => "a txid-only entry for a transaction this instance does not hold (only a held one may be named by txid alone)",
        error.ScriptFailed => "an unlocking script of a transaction no BUMP proves does not verify",
        error.NotParentsFirst => "its transactions spend in a cycle: no order puts parents first",
        else => "the BEEF's check failed",
    };
}

/// The check (above). `state`: the chain state record's CID (the chain app's head `chain/state`), or
/// null when it has none.
pub fn check(a: std.mem.Allocator, r: Reader, state: ?[]const u8, package: Value) !Out {
    var w = Walk{ .a = a, .headers = if (state) |s| try Headers.open(a, r, s) else null };
    var out: Value = package;
    if (package != .map) return .{ .package = package, .blocks = &.{}, .pointers = &.{}, .refused = "the package is not a map" };
    if (std.mem.eql(u8, Value.str(package.get("kind")) orelse "", "request")) {
        const payload = package.get("payload") orelse return .{ .package = package, .blocks = &.{}, .pointers = &.{}, .refused = "a request with no payload" };
        const body = payload.get("body") orelse .null;
        var handed: Value = body;
        if (Value.bytesOf(body)) |b| {
            if (beef.recognize(b) != null) {
                handed = try w.bytes(b);
            } else if (cbor.decode(a, b)) |dv| {
                if (dv == .map) {
                    const f = try w.fields(dv);
                    if (w.found > 0) handed = f;
                }
            } else |_| {}
        }
        if (w.found > 0) {
            var p = cbor.MapBuilder.init(a);
            for (payload.map) |e| try p.put(e.key, if (std.mem.eql(u8, e.key, "body")) handed else e.value);
            var m = cbor.MapBuilder.init(a);
            for (package.map) |e| try m.put(e.key, if (std.mem.eql(u8, e.key, "payload")) p.value() else e.value);
            out = m.value();
        }
    } else {
        const f = try w.fields(package);
        if (w.found > 0) out = f;
    }
    if (w.refused) |why| return .{ .package = package, .blocks = &.{}, .pointers = &.{}, .refused = why };
    if (w.found == 0) return .{ .package = package, .blocks = &.{}, .pointers = &.{}, .refused = NOTHING_VALIDATED };
    return .{ .package = out, .blocks = w.blocks.items, .pointers = w.pointers.items };
}

/// The bytes a package's envelopes stand for, put back (the lossless rule's other half): each
/// envelope whose pointer record is named in `pointers` replaced by the bytes it and its record
/// give (beef.zig `wire`), read through `r`.
pub fn restore(a: std.mem.Allocator, r: Reader, v: Value, pointers: []const []const u8) !Value {
    switch (v) {
        .map => |m| {
            if (beef.pointerOf(v)) |c| for (pointers) |x| if (std.mem.eql(u8, x, c)) {
                return .{ .bytes = try wireOf(a, r, v) };
            };
            const out = try a.alloc(cbor.Entry, m.len);
            for (m, out) |e, *o| o.* = .{ .key = e.key, .value = try restore(a, r, e.value, pointers) };
            return .{ .map = out };
        },
        .array => |xs| {
            const out = try a.alloc(Value, xs.len);
            for (xs, out) |x, *o| o.* = try restore(a, r, x, pointers);
            return .{ .array = out };
        },
        else => return v,
    }
}

/// The bytes an envelope stands for (beef.zig `wire`), its pointer record and blocks read through `r`.
fn wireOf(a: std.mem.Allocator, r: Reader, env: Value) ![]u8 {
    const c = beef.pointerOf(env) orelse return error.Malformed;
    const b = (try r.get(r.ctx, a, c)) orelse return error.NotFound;
    const rec = try cbor.decode(a, b);
    const G = struct {
        fn get(ctx: *anyopaque, al: std.mem.Allocator, k: []const u8) anyerror!?[]const u8 {
            const rd: *const Reader = @ptrCast(@alignCast(ctx));
            return rd.get(rd.ctx, al, k);
        }
    };
    var rc = r;
    return beef.wire(a, env, rec, .{ .ctx = &rc, .get = G.get });
}

test {
    _ = @import("check_test.zig");
    _ = @import("ingest_test.zig");
    _ = beef;
}
