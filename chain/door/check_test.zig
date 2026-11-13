//! The chain app's BEEF check (check.zig), ported from the skein kernel's door tests
//! (kernel-zig/src/door_test.zig at skein v0.9.1, kernel.beef): the BEEF proven by skein-sdk's
//! verifier against the chain state's headers, the blocks it names to store (each once), the
//! package it hands back (no BEEF bytes: the envelope, linking the pointer record), a refusal
//! (nothing to store), and the bytes put back (restore). What changed with the move: the check
//! reads the request's body (or a top-level field of a dag-cbor body) only, stores nothing itself
//! (its blocks are the caller's to name), and refuses a package with no BEEF.
const std = @import("std");
const cbor = @import("cbor");
const cidm = @import("cid");
const mst = @import("mst");
const check = @import("check.zig");
const beef = check.beef;
const Value = cbor.Value;

fn unhex(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

/// Blocks in memory: what the chain app's store holds (a Reader), and what a pass's blocks add.
const Mem = struct {
    a: std.mem.Allocator,
    m: std.StringHashMapUnmanaged([]const u8) = .empty,
    fn get(ctx: *anyopaque, a: std.mem.Allocator, c: []const u8) anyerror!?[]u8 {
        const s: *Mem = @ptrCast(@alignCast(ctx));
        const b = s.m.get(c) orelse return null;
        return try a.dupe(u8, b);
    }
    fn reader(s: *Mem) check.Reader {
        return .{ .ctx = s, .get = get };
    }
    fn putBlock(s: *Mem, c: []const u8, b: []const u8) !void {
        if (s.m.contains(c)) return;
        try s.m.put(s.a, try s.a.dupe(u8, c), try s.a.dupe(u8, b));
    }
    fn put(s: *Mem, v: Value) ![]u8 {
        const blk = try cbor.block(s.a, v);
        try s.putBlock(blk.cid, blk.bytes);
        return blk.cid;
    }
    fn has(s: *Mem, c: []const u8) bool {
        return s.m.contains(c);
    }
    fn count(s: *Mem) usize {
        return s.m.count();
    }
    /// What a pass names, stored (the kernel's COMMIT).
    fn hold(s: *Mem, out: check.Out) !void {
        for (out.blocks) |b| try s.putBlock(b.cid, b.bytes);
    }
    fn sinkPut(ctx: *anyopaque, c: []const u8, b: []const u8) anyerror!void {
        const s: *Mem = @ptrCast(@alignCast(ctx));
        try s.putBlock(c, b);
    }
};

/// A request record whose body is `body`.
fn request(a: std.mem.Allocator, body: []const u8) !Value {
    var p = cbor.MapBuilder.init(a);
    try p.put("method", cbor.string("POST"));
    try p.put("path", cbor.string("/overlay/submit"));
    try p.put("query", cbor.string(""));
    try p.put("headers", .{ .map = &.{} });
    try p.put("body", .{ .bytes = body });
    var m = cbor.MapBuilder.init(a);
    try m.put("kind", cbor.string("request"));
    try m.put("payload", p.value());
    return m.value();
}

fn bodyOf(v: Value) Value {
    return v.get("payload").?.get("body").?;
}

/// A chain state holding one header at `height` (the chain app's record shape): its CID.
fn chainState(a: std.mem.Allocator, s: *Mem, height: u32, header: []const u8) ![]u8 {
    return chainStateHolding(a, s, height, header, &.{}, &.{});
}

fn wireOf(a: std.mem.Allocator, bump: []const u8, parent: []const u8) ![]u8 {
    var o: std.ArrayList(u8) = .empty;
    try o.appendSlice(a, &.{ 1, 0, 0xbe, 0xef, 1 });
    try o.appendSlice(a, bump);
    try o.appendSlice(a, &.{1});
    try o.appendSlice(a, parent);
    try o.appendSlice(a, &.{ 1, 0 });
    return o.items;
}

fn contains(hay: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, hay, needle) != null;
}

const header170 = "0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e70";
const tx170 = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
const coinbase170 = "82501c1178fa0b222c1f3d474ec726b832013f0a532b44bb620cce8624a5feb1";

test "chain.beef: every BUMP checked against the chain state, each block named once, the pointer record linked" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Mem{ .a = a };
    const header = try unhex(a, header170);
    const tx = try unhex(a, tx170);
    const txid = beef.txidOf(tx);
    var bump: std.ArrayList(u8) = .empty;
    try bump.appendSlice(a, &.{ 0xaa, 1, 2, 0, 0 });
    try bump.appendSlice(a, try unhex(a, coinbase170));
    try bump.appendSlice(a, &.{ 1, 2 });
    try bump.appendSlice(a, &txid);
    const wire = try wireOf(a, bump.items, tx);
    const v = try request(a, wire);

    // No chain state: refused, saying so.
    const none = try check.check(a, s.reader(), null, v);
    try std.testing.expect(none.refused != null);
    try std.testing.expect(contains(none.refused.?, "chain state"));

    const st = try chainState(a, &s, 170, header);
    const got = try check.check(a, s.reader(), st, v);
    try std.testing.expectEqual(@as(?[]const u8, null), got.refused);
    try std.testing.expectEqual(@as(usize, 1), got.pointers.len);
    // The package holds the envelope where the bytes were, linking the pointer record, not the bytes.
    const body = bodyOf(got.package);
    try std.testing.expectEqualStrings("beef", Value.str(body.get("form")).?);
    try std.testing.expect(body.get("subject") == null);
    try std.testing.expectEqualSlices(u8, got.pointers[0], beef.pointerOf(body).?);
    try std.testing.expect(!contains(try cbor.encode(a, got.package), wire));
    // Nothing stored by the check itself: its blocks are named.
    try std.testing.expect(!s.has(got.pointers[0]));
    try s.hold(got);
    const rec = try cbor.decode(a, s.m.get(got.pointers[0]).?);
    try std.testing.expect(beef.isRecord(rec));
    // The transaction is its bitcoin-tx block (CID = txid); the BUMP's node is held; the header checked is linked.
    try std.testing.expectEqualSlices(u8, tx, s.m.get(try beef.txCid(a, txid)).?);
    const b0 = rec.get("bumps").?.array[0];
    try std.testing.expectEqualSlices(u8, try cidm.ofBitcoin(a, cidm.BITCOIN_BLOCK, header), Value.cidOf(b0.get("block")).?);
    try std.testing.expect(s.has(try beef.txCid(a, header[36..68].*)));
    // The bytes come back exactly.
    const back = try check.restore(a, s.reader(), got.package, got.pointers);
    try std.testing.expectEqualSlices(u8, wire, Value.bytesOf(bodyOf(back)).?);
    // Each block once in what it names.
    var seen = std.StringHashMap(void).init(a);
    for (got.blocks) |b| try std.testing.expect(!(try seen.getOrPut(b.cid)).found_existing);

    // A BUMP whose sibling is changed: its root is not the header's — RootMismatch, nothing named.
    const bad_wire = try a.dupe(u8, wire);
    bad_wire[5 + 5] ^= 0xff;
    const r = try check.check(a, s.reader(), st, try request(a, bad_wire));
    try std.testing.expect(std.mem.startsWith(u8, r.refused.?, "RootMismatch"));
    try std.testing.expectEqual(@as(usize, 0), r.blocks.len);
    try std.testing.expectEqualSlices(u8, bad_wire, Value.bytesOf(bodyOf(r.package)).?);

    // A BUMP at a height the chain state has no header for: refused.
    var hi = try a.dupe(u8, wire);
    hi[5] = 0xab;
    const r2 = try check.check(a, s.reader(), st, try request(a, hi));
    try std.testing.expect(std.mem.startsWith(u8, r2.refused.?, "UnknownHeader"));

    // A body that is no BEEF and no dag-cbor map holding one: nothing to validate, refused.
    const p = try check.check(a, s.reader(), st, try request(a, "{\"not\": \"beef\"}"));
    try std.testing.expectEqualStrings(check.NOTHING_VALIDATED, p.refused.?);
    // No deeper than a top-level field: a BEEF inside an array of the body is not looked for.
    var deep = cbor.MapBuilder.init(a);
    try deep.put("args", .{ .array = try a.dupe(Value, &.{.{ .bytes = wire }}) });
    const dp = try check.check(a, s.reader(), st, try request(a, try cbor.encode(a, deep.value())));
    try std.testing.expectEqualStrings(check.NOTHING_VALIDATED, dp.refused.?);
}

test "chain.beef: two envelopes over one BEEF in top-level fields of a dag-cbor body — one pointer record, the body handed back decoded, the bytes back" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Mem{ .a = a };
    const header = try unhex(a, header170);
    const tx = try unhex(a, tx170);
    const txid = beef.txidOf(tx);
    var v2: std.ArrayList(u8) = .empty;
    try v2.appendSlice(a, &.{ 2, 0, 0xbe, 0xef, 1, 0xaa, 1, 2, 0, 0 });
    try v2.appendSlice(a, try unhex(a, coinbase170));
    try v2.appendSlice(a, &.{ 1, 2 });
    try v2.appendSlice(a, &txid);
    try v2.appendSlice(a, &.{ 1, 1, 0 });
    try v2.appendSlice(a, tx);
    const st = try chainState(a, &s, 170, header);
    const atomic = try std.mem.concat(a, u8, &.{ &.{ 1, 1, 1, 1 }, &txid, v2.items });
    const subject = try std.mem.concat(a, u8, &.{ &.{ 0x57, 0x09, 0xbe, 0xef }, &txid, v2.items });

    var body = cbor.MapBuilder.init(a);
    try body.put("atomic", .{ .bytes = atomic });
    try body.put("subject", .{ .bytes = subject });
    try body.put("note", cbor.string("kept"));
    const got = try check.check(a, s.reader(), st, try request(a, try cbor.encode(a, body.value())));
    try std.testing.expectEqual(@as(?[]const u8, null), got.refused);
    try std.testing.expectEqual(@as(usize, 2), got.pointers.len);
    try std.testing.expectEqualSlices(u8, got.pointers[0], got.pointers[1]);
    const b = bodyOf(got.package);
    try std.testing.expect(b == .map);
    const ea = b.get("atomic").?;
    const es = b.get("subject").?;
    try std.testing.expectEqualStrings("atomic", Value.str(ea.get("form")).?);
    try std.testing.expectEqualStrings("subject", Value.str(es.get("form")).?);
    try std.testing.expectEqualStrings("kept", Value.str(b.get("note")).?);
    try std.testing.expectEqualSlices(u8, try beef.txCid(a, txid), Value.cidOf(es.get("subject")).?);
    // The log holds the package (through dag-cbor) and the blocks: the bytes come back exactly from those alone.
    try s.hold(got);
    const logged = try cbor.decode(a, try cbor.encode(a, got.package));
    const back = bodyOf(try check.restore(a, s.reader(), logged, got.pointers));
    try std.testing.expectEqualSlices(u8, atomic, Value.bytesOf(back.get("atomic")).?);
    try std.testing.expectEqualSlices(u8, subject, Value.bytesOf(back.get("subject")).?);
}

test "chain.beef: an event record's top-level fields are read the same way" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Mem{ .a = a };
    const header = try unhex(a, header170);
    const tx = try unhex(a, tx170);
    const txid = beef.txidOf(tx);
    var bump: std.ArrayList(u8) = .empty;
    try bump.appendSlice(a, &.{ 0xaa, 1, 2, 0, 0 });
    try bump.appendSlice(a, try unhex(a, coinbase170));
    try bump.appendSlice(a, &.{ 1, 2 });
    try bump.appendSlice(a, &txid);
    const st = try chainState(a, &s, 170, header);
    var ev = cbor.MapBuilder.init(a);
    try ev.put("kind", cbor.string("deploy"));
    try ev.put("beef", .{ .bytes = try wireOf(a, bump.items, tx) });
    const got = try check.check(a, s.reader(), st, ev.value());
    try std.testing.expectEqual(@as(?[]const u8, null), got.refused);
    try std.testing.expectEqualStrings("deploy", Value.str(got.package.get("kind")).?);
    try std.testing.expect(beef.pointerOf(got.package.get("beef").?) != null);
}

/// A transaction: one input (`prev`:`vout`, unlocking script `unlock`), outputs of 1000 sat each with
/// the locking scripts given, locktime 0.
fn txOf(a: std.mem.Allocator, prev: [32]u8, vout: u8, unlock: []const u8, locks: []const []const u8) ![]u8 {
    var o: std.ArrayList(u8) = .empty;
    try o.appendSlice(a, &.{ 1, 0, 0, 0, 1 });
    try o.appendSlice(a, &prev);
    try o.appendSlice(a, &.{ vout, 0, 0, 0, @intCast(unlock.len) });
    try o.appendSlice(a, unlock);
    try o.appendSlice(a, &.{ 0xff, 0xff, 0xff, 0xff, @intCast(locks.len) });
    for (locks) |l| {
        try o.appendSlice(a, &.{ 0xe8, 3, 0, 0, 0, 0, 0, 0, @intCast(l.len) });
        try o.appendSlice(a, l);
    }
    try o.appendSlice(a, &.{ 0, 0, 0, 0 });
    return o.items;
}

test "chain.beef: the BEEF proven, always (#121) — an unproven child of a proven parent passes; no parent, a txid-only parent, a failing script are refused, nothing stored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Mem{ .a = a };

    // A parent mined at height 200 (beside a sibling in a two-transaction block): output 0 OP_TRUE,
    // output 1 OP_FALSE. Its BUMP, and a header at 200 whose merkle root it gives.
    const parent = try txOf(a, [_]u8{0x11} ** 32, 0, &.{}, &.{ &.{0x51}, &.{0x00} });
    const ptxid = beef.txidOf(parent);
    const sib = [_]u8{0x22} ** 32;
    var bump: std.ArrayList(u8) = .empty;
    try bump.appendSlice(a, &.{ 0xc8, 1, 2, 0, 0 }); // height 200, depth 1, two leaves: offset 0 (a hash)
    try bump.appendSlice(a, &sib);
    try bump.appendSlice(a, &.{ 1, 2 }); // offset 1, a client txid
    try bump.appendSlice(a, &ptxid);
    const header = try a.alloc(u8, 80);
    @memset(header, 0);
    header[0] = 1;
    header[36..68].* = cidm.dblSha256(&(sib ++ ptxid));
    const st = try chainState(a, &s, 200, header);

    // The child spends output 0 (OP_TRUE: an empty unlocking script verifies); unmined.
    const child = try txOf(a, ptxid, 0, &.{}, &.{&.{0x51}});
    const v1 = try std.mem.concat(a, u8, &.{ &.{ 1, 0, 0xbe, 0xef, 1 }, bump.items, &.{2}, parent, &.{ 1, 0 }, child, &.{0} });
    const got = try check.check(a, s.reader(), st, try request(a, v1));
    try std.testing.expectEqual(@as(?[]const u8, null), got.refused);
    try s.hold(got);
    const rec = try cbor.decode(a, s.m.get(got.pointers[0]).?);
    // marks [0, null]; the BUMP proves the parent only (the verifier's proven: [true, false]).
    const marks = rec.get("marks").?.array;
    try std.testing.expectEqual(@as(?i128, 0), Value.intOf(marks[0]));
    try std.testing.expect(marks[1] == .null);
    const b0 = rec.get("bumps").?.array[0];
    const proves = b0.get("proves").?.array;
    try std.testing.expectEqual(@as(usize, 1), proves.len);
    try std.testing.expectEqual(@as(?i128, 0), Value.intOf(proves[0]));
    try std.testing.expectEqualSlices(u8, try cidm.ofBitcoin(a, cidm.BITCOIN_BLOCK, header), Value.cidOf(b0.get("block")).?);
    try std.testing.expect(s.has(try beef.txCid(a, beef.txidOf(child))));
    try std.testing.expectEqualSlices(u8, v1, Value.bytesOf(bodyOf(try check.restore(a, s.reader(), got.package, got.pointers))).?);

    const held = s.count();
    const refusedWith = struct {
        fn f(al: std.mem.Allocator, ms: *Mem, state: []const u8, bytes: []const u8, name: []const u8) !void {
            const r = try check.check(al, ms.reader(), state, try request(al, bytes));
            try std.testing.expect(r.refused != null);
            if (!std.mem.startsWith(u8, r.refused.?, name)) {
                std.debug.print("refused: {s}, expected {s}\n", .{ r.refused.?, name });
                return error.TestUnexpectedResult;
            }
            try std.testing.expectEqual(@as(usize, 0), r.blocks.len);
        }
    }.f;
    // Another child, alone: no BUMP, its parent not in the BEEF (Atomic BEEF) — MissingInput.
    const lone = try txOf(a, ptxid, 0, &.{}, &.{&.{ 0x51, 0x51 }});
    const ltxid = beef.txidOf(lone);
    try refusedWith(a, &s, st, try std.mem.concat(a, u8, &.{ &.{ 1, 1, 1, 1 }, &ltxid, &.{ 1, 0, 0xbe, 0xef, 0, 1 }, lone, &.{0} }), "MissingInput");
    // The parent as a txid-only entry (V2): UnknownTxidOnly (nothing is known beside the BEEF).
    try refusedWith(a, &s, st, try std.mem.concat(a, u8, &.{ &.{ 2, 0, 0xbe, 0xef, 0, 2, 2 }, &ptxid, &.{0}, lone }), "UnknownTxidOnly");
    // A child spending output 1 (OP_FALSE): ScriptFailed.
    const fails = try txOf(a, ptxid, 1, &.{}, &.{&.{0x51}});
    try refusedWith(a, &s, st, try std.mem.concat(a, u8, &.{ &.{ 1, 0, 0xbe, 0xef, 1 }, bump.items, &.{2}, parent, &.{ 1, 0 }, fails, &.{0} }), "ScriptFailed");
    // Nothing of the refused ones is named.
    try std.testing.expectEqual(held, s.count());
    try std.testing.expect(!s.has(try beef.txCid(a, ltxid)));
}

/// A chain state with one header at `height` and the transactions it holds (`txs`: txid → its
/// bitcoin-tx block), some of them `rejected` (txid → a settlement record) — the chain app's shape.
fn chainStateHolding(a: std.mem.Allocator, s: *Mem, height: u32, header: []const u8, txs: []const []const u8, rejected: []const []const u8) ![]u8 {
    const hc = try cidm.ofBitcoin(a, cidm.BITCOIN_BLOCK, header);
    try s.putBlock(hc, header);
    var f = mst.Forest.init(a, .{ .ctx = s, .get = Mem.get });
    var key: [4]u8 = undefined;
    std.mem.writeInt(u32, &key, height, .big);
    const hroot = try f.put(null, &key, cbor.cidv(hc));
    try f.flush(hroot, .{ .ctx = s, .put = Mem.sinkPut });
    var troot: ?[]const u8 = null;
    for (txs) |raw| {
        const txid = beef.txidOf(raw);
        const c = try beef.txCid(a, txid);
        try s.putBlock(c, raw);
        troot = try f.put(troot, &txid, cbor.cidv(c));
    }
    if (troot) |r| try f.flush(r, .{ .ctx = s, .put = Mem.sinkPut });
    var rroot: ?[]const u8 = null;
    for (rejected) |raw| {
        var rm = cbor.MapBuilder.init(a);
        try rm.put("status", cbor.string("rejected"));
        const rc = try s.put(rm.value());
        rroot = try f.put(rroot, &beef.txidOf(raw), cbor.cidv(rc));
    }
    if (rroot) |r| try f.flush(r, .{ .ctx = s, .put = Mem.sinkPut });
    var maps = cbor.MapBuilder.init(a);
    try maps.put("headers", cbor.optCid(hroot) orelse .null);
    try maps.put("txs", cbor.optCid(troot) orelse .null);
    try maps.put("rejected", cbor.optCid(rroot) orelse .null);
    var m = cbor.MapBuilder.init(a);
    try m.put("kind", cbor.string("chain-state"));
    try m.put("network", cbor.string("main"));
    try m.put("maps", maps.value());
    return s.put(m.value());
}

test "chain.beef: a BEEF may name a transaction the instance holds by txid alone (2026-11-07) — held proven or unproven passes; unknown or rejected is refused, nothing stored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = Mem{ .a = a };

    // Held: `mined` (proven when it entered), `pending` (unproven, admitted), `dropped` (rejected).
    // `stranger` is not held. Each pays OP_TRUE at output 0.
    const mined = try txOf(a, [_]u8{0x31} ** 32, 0, &.{}, &.{&.{0x51}});
    const pending = try txOf(a, beef.txidOf(mined), 0, &.{}, &.{&.{0x51}});
    const dropped = try txOf(a, [_]u8{0x32} ** 32, 0, &.{}, &.{&.{0x51}});
    const stranger = try txOf(a, [_]u8{0x33} ** 32, 0, &.{}, &.{&.{0x51}});
    const header = try a.alloc(u8, 80);
    @memset(header, 0);
    header[0] = 1;
    const st = try chainStateHolding(a, &s, 200, header, &.{ mined, pending, dropped }, &.{dropped});

    const v2With = struct {
        /// V2: the parent txid-only, then the child raw.
        fn f(al: std.mem.Allocator, parent: []const u8, child: []const u8) ![]u8 {
            return std.mem.concat(al, u8, &.{ &.{ 2, 0, 0xbe, 0xef, 0, 2, 2 }, &beef.txidOf(parent), &.{0}, child });
        }
    }.f;
    const passes = struct {
        fn f(al: std.mem.Allocator, ms: *Mem, state: []const u8, bytes: []const u8) !void {
            const r = try check.check(al, ms.reader(), state, try request(al, bytes));
            if (r.refused) |why| {
                std.debug.print("refused: {s}\n", .{why});
                return error.TestUnexpectedResult;
            }
            try std.testing.expectEqual(@as(usize, 1), r.pointers.len);
            // Lossless: the txid-only entry goes back on the wire as it came.
            var view = Mem{ .a = al };
            var it = ms.m.iterator();
            while (it.next()) |e| try view.putBlock(e.key_ptr.*, e.value_ptr.*);
            try view.hold(r);
            try std.testing.expectEqualSlices(u8, bytes, Value.bytesOf(bodyOf(try check.restore(al, view.reader(), r.package, r.pointers))).?);
        }
    }.f;
    const refusedWith = struct {
        fn f(al: std.mem.Allocator, ms: *Mem, state: []const u8, bytes: []const u8, name: []const u8) !void {
            const r = try check.check(al, ms.reader(), state, try request(al, bytes));
            try std.testing.expect(r.refused != null);
            if (!std.mem.startsWith(u8, r.refused.?, name)) {
                std.debug.print("refused: {s}, expected {s}\n", .{ r.refused.?, name });
                return error.TestUnexpectedResult;
            }
            try std.testing.expectEqual(@as(usize, 0), r.blocks.len);
        }
    }.f;

    // A child of the held, unproven transaction, the parent by txid: admitted; its record marks it "txid".
    const c1 = try txOf(a, beef.txidOf(pending), 0, &.{}, &.{&.{ 0x51, 0x51 }});
    try passes(a, &s, st, try v2With(a, pending, c1));
    {
        const r = try check.check(a, s.reader(), st, try request(a, try v2With(a, pending, c1)));
        var view = Mem{ .a = a };
        try view.hold(r);
        const rec = try cbor.decode(a, view.m.get(r.pointers[0]).?);
        const marks = rec.get("marks").?.array;
        try std.testing.expectEqualSlices(u8, "txid", Value.str(marks[0]).?);
        try std.testing.expect(marks[1] == .null);
        try std.testing.expect(view.has(try beef.txCid(a, beef.txidOf(c1))));
    }
    // A child of the held, proven transaction, the parent by txid: admitted.
    const c2 = try txOf(a, beef.txidOf(mined), 0, &.{}, &.{&.{ 0x51, 0x52 }});
    try passes(a, &s, st, try v2With(a, mined, c2));
    // A held parent not named at all (an Atomic BEEF of the child alone): its source is held, admitted.
    const c3 = try txOf(a, beef.txidOf(pending), 0, &.{}, &.{&.{ 0x51, 0x53 }});
    const c3id = beef.txidOf(c3);
    try passes(a, &s, st, try std.mem.concat(a, u8, &.{ &.{ 1, 1, 1, 1 }, &c3id, &.{ 1, 0, 0xbe, 0xef, 0, 1 }, c3, &.{0} }));

    const before = s.count();
    // A txid-only entry for a transaction not held: UnknownTxidOnly.
    const c4 = try txOf(a, beef.txidOf(stranger), 0, &.{}, &.{&.{ 0x51, 0x54 }});
    try refusedWith(a, &s, st, try v2With(a, stranger, c4), "UnknownTxidOnly");
    // For a held but rejected one: UnknownTxidOnly too.
    const c5 = try txOf(a, beef.txidOf(dropped), 0, &.{}, &.{&.{ 0x51, 0x55 }});
    try refusedWith(a, &s, st, try v2With(a, dropped, c5), "UnknownTxidOnly");
    // A raw child of a stranger with no parent: MissingInput, as before.
    const c4id = beef.txidOf(c4);
    try refusedWith(a, &s, st, try std.mem.concat(a, u8, &.{ &.{ 1, 1, 1, 1 }, &c4id, &.{ 1, 0, 0xbe, 0xef, 0, 1 }, c4, &.{0} }), "MissingInput");
    try std.testing.expectEqual(before, s.count());
    try std.testing.expect(!s.has(try beef.txCid(a, c4id)));
}
