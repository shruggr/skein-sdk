//! The chain state (shruggr/skein#78, chain/src/state.zig) over an in-memory
//! store: ingest proven and unproven BEEF, registered broadcasts and their
//! watchers, statuses, proofs (and a proof that waits for its header), a
//! rejection walking the spends, a double spend, abandonment, a reorg.
const std = @import("std");
const bsvz = @import("bsvz");
const lib = @import("src/lib.zig");

const hdr = lib.header;
const beef = lib.beef;
const State = lib.state.State;

test {
    std.testing.refAllDecls(lib);
}

fn mine(prev: [32]u8, merkle_root: [32]u8, time: u32) [80]u8 {
    var h = hdr.Header{ .version = 1, .prev_hash = prev, .merkle_root = merkle_root, .time = time, .bits = 0x207fffff, .nonce = 0 };
    while (true) : (h.nonce += 1) {
        const raw = h.serialize();
        if (hdr.powOk(&raw)) return raw;
    }
}

/// A BUMP for a block holding one transaction: its root is the txid.
fn soloPath(a: std.mem.Allocator, height: u32, txid: [32]u8) ![]const u8 {
    var path: std.ArrayList(u8) = .empty;
    try path.appendSlice(a, &.{ 0xfd, 0, 0, 0x01, 0x01, 0x00, 0x02 });
    std.mem.writeInt(u16, path.items[1..3], @intCast(height), .little);
    try path.appendSlice(a, &txid);
    return path.items;
}

fn p2pkh(pubkey: [33]u8) [25]u8 {
    var s: [25]u8 = undefined;
    s[0..3].* = .{ 0x76, 0xa9, 0x14 };
    s[3..23].* = bsvz.crypto.hash.hash160(&pubkey).bytes;
    s[23..25].* = .{ 0x88, 0xac };
    return s;
}

const priv: [32]u8 = .{0x11} ** 32;

fn pub33() ![33]u8 {
    return (try (try bsvz.primitives.ec.PrivateKey.fromBytes(priv)).publicKey()).toCompressedSec1();
}

const Tx = struct { tx: bsvz.transaction.Transaction, raw: []const u8, txid: [32]u8 };

/// The funding: one input from nowhere, `n` P2PKH outputs of 10 000 to our key.
fn funding(a: std.mem.Allocator, n: u8) !Tx {
    var raw: std.ArrayList(u8) = .empty;
    try raw.appendSlice(a, &.{ 1, 0, 0, 0, 1 });
    try raw.appendSlice(a, &([_]u8{0x72} ** 32));
    try raw.appendSlice(a, &.{ 0, 0, 0, 0, 1, 0x51, 0xff, 0xff, 0xff, 0xff, n });
    const script = p2pkh(try pub33());
    for (0..n) |_| {
        var sats: [8]u8 = undefined;
        std.mem.writeInt(u64, &sats, 10_000, .little);
        try raw.appendSlice(a, &sats);
        try raw.append(a, 25);
        try raw.appendSlice(a, &script);
    }
    try raw.appendSlice(a, &.{ 0, 0, 0, 0 });
    const tx = try bsvz.transaction.Transaction.parse(a, raw.items);
    return .{ .tx = tx, .raw = raw.items, .txid = beef.txidOf(raw.items) };
}

/// A transaction spending `src:vout` to our key again (signed P2PKH).
fn spend(a: std.mem.Allocator, src: *const bsvz.transaction.Transaction, vout: u32, sats: u64) !Tx {
    var b = bsvz.transaction.Builder.init(a);
    try b.addInputFromTx(src, vout);
    const script = p2pkh(try pub33());
    try b.addOutput(.{ .satoshis = @intCast(sats), .locking_script = bsvz.script.Script.init(try a.dupe(u8, &script)) });
    var tx = try b.build();
    const key = try bsvz.crypto.PrivateKey.fromBytes(priv);
    const prev = src.outputs[vout];
    const u = try bsvz.transaction.templates.p2pkh_spend.signAndBuildUnlockingScript(a, &tx, 0, prev.locking_script, prev.satoshis, key, bsvz.transaction.templates.p2pkh_spend.default_scope);
    @constCast(tx.inputs)[0].unlocking_script = u;
    const raw = try tx.serialize(a);
    return .{ .tx = tx, .raw = raw, .txid = beef.txidOf(raw) };
}

/// A BEEF V2 (Atomic for the last) of `proven` (each with a solo BUMP at its height) then `rest`.
fn beefOf(a: std.mem.Allocator, proven: []const struct { Tx, u32 }, rest: []const Tx) ![]const u8 {
    var entries: std.ArrayList(beef.Entry) = .empty;
    var bumps: std.ArrayList(bsvz.spv.MerklePath) = .empty;
    for (proven) |p| {
        try bumps.append(a, try bsvz.spv.MerklePath.parse(a, try soloPath(a, p[1], p[0].txid)));
        try entries.append(a, .{ .txid = p[0].txid, .format = .raw_with_bump, .bump = bumps.items.len - 1, .raw = p[0].raw, .tx = p[0].tx });
    }
    for (rest) |t| try entries.append(a, .{ .txid = t.txid, .format = .raw, .raw = t.raw, .tx = t.tx });
    return beef.serialize(a, .{ .version = beef.V2, .atomic = entries.items[entries.items.len - 1].txid, .bumps = bumps.items, .entries = entries.items });
}

const World = struct { st: State, fund: Tx, h1: [80]u8 };

/// A chain to height 1 whose block holds the funding alone; the state knowing the headers.
fn world(a: std.mem.Allocator, s: lib.store.Store, n: u8) !World {
    const fund = try funding(a, n);
    const h1 = mine(hdr.hash(&lib.chain.Network.regtest.genesis()), fund.txid, 1_700_000_600);
    var st = try State.load(a, s, null, .regtest);
    _ = try st.addHeaders(&.{&h1});
    return .{ .st = st, .fund = fund, .h1 = h1 };
}

const caller: [33]u8 = .{0x02} ++ .{0x44} ** 32;
const request: [36]u8 = .{ 0x01, 0x71, 0x12, 0x20 } ++ .{0x55} ** 32;

test "ingest: proven in is recorded proven, nothing registered" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 2);
    const got = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{}));
    try std.testing.expectEqual(lib.state.Status.proven, got.status);
    try std.testing.expectEqual(@as(usize, 0), got.registered.len);
    try std.testing.expectEqualSlices(u8, &lib.store.hashCid(.tx, w.fund.txid), got.tx);
    try std.testing.expect(!(try w.st.map("unproven").has(&w.fund.txid)));
    try std.testing.expect((try w.st.proofFor(w.fund.txid)) != null);
    const saved = try w.st.save();
    // A second load reads the same state; the same ingest again changes nothing.
    var st2 = try State.load(a, ms.store(), saved, .regtest);
    _ = try st2.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{}));
    try std.testing.expectEqualStrings(saved, try st2.save());
    try std.testing.expectError(error.NetworkMismatch, State.load(a, ms.store(), saved, .main));
}

test "ingest: unproven in is registered; accepted by the first status, proven by its proof; watchers told each" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 2);
    const child = try spend(a, &w.fund.tx, 0, 9_000);
    w.st.now = 1000;
    const got = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{child}));
    try std.testing.expectEqual(lib.state.Status.unproven, got.status);
    try std.testing.expectEqual(@as(usize, 1), got.registered.len);
    try std.testing.expectEqualSlices(u8, &child.txid, &got.registered[0]);
    try std.testing.expect(try w.st.map("unproven").has(&child.txid));
    try std.testing.expectEqualSlices(u8, &child.txid, &(try w.st.spentBy(w.fund.txid, 0)).?);
    try w.st.watch(child.txid, &caller, "chain", &request);
    const r = (try w.st.broadcastRecord(child.txid)).?;
    try std.testing.expectEqual(@as(u64, 1000), r.getUint("since").?);
    try std.testing.expectEqual(@as(usize, 1), r.getArray("watchers").?.len);
    // The Atomic BEEF to broadcast: the child over its proven parent.
    const out = try beef.parse(a, (try w.st.beefOf(child.txid)).?);
    try std.testing.expectEqual(@as(usize, 2), out.entries.len);
    try std.testing.expectEqual(beef.Format.raw_with_bump, out.entries[0].format);

    // RECEIVED: accepted (once); SEEN_ON_NETWORK: noted, no change.
    try std.testing.expectEqual(State.Outcome.accepted, try w.st.applyStatus(child.txid, "RECEIVED", null));
    try std.testing.expectEqual(State.Outcome.pending, try w.st.applyStatus(child.txid, "SEEN_ON_NETWORK", null));
    try std.testing.expectEqual(@as(usize, 1), w.st.changes.items.len);
    try std.testing.expectEqual(.accepted, w.st.changes.items[0].state);
    try std.testing.expectEqualStrings("SEEN_ON_NETWORK", (try w.st.broadcastRecord(child.txid)).?.getText("txStatus").?);
    // Its proof, before its header: kept, pending; the header: proven, the watcher told, the broadcast gone.
    const path = try soloPath(a, 2, child.txid);
    try std.testing.expectEqual(State.Outcome.pending, try w.st.applyStatus(child.txid, "MINED", path));
    try std.testing.expect(try w.st.map("parked").has(&child.txid)); // 0.21.0: parked, whatever its status
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), child.txid, 1_700_001_200)});
    try std.testing.expectEqual(lib.state.Status.proven, try w.st.status(child.txid));
    try std.testing.expect(!(try w.st.map("parked").has(&child.txid)));
    // 0.21.0: the linkage is listed; what it settles is the transaction's subscription step.
    try std.testing.expect(linkedHas(&w.st, child.txid));
    try w.st.settleProven(child.txid);
    try std.testing.expectEqual(@as(usize, 2), w.st.changes.items.len);
    try std.testing.expectEqual(.proven, w.st.changes.items[1].state);
    try std.testing.expectEqual(@as(usize, 1), w.st.changes.items[1].watchers.len);
    try std.testing.expect((try w.st.broadcastRecord(child.txid)) == null);
    try std.testing.expect(!(try w.st.map("unproven").has(&child.txid)));
    _ = try w.st.save();
}

test "beefOf: a proven transaction is served with its BUMP alone, its parents not needed" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 2);
    // The funding's input comes from a transaction nobody holds.
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{}));
    const bytes = (try w.st.beefOf(w.fund.txid)).?;
    const out = try beef.parse(a, bytes);
    try std.testing.expectEqualSlices(u8, &w.fund.txid, &out.subject().?);
    try std.testing.expectEqual(@as(usize, 1), out.entries.len);
    try std.testing.expectEqual(beef.Format.raw_with_bump, out.entries[0].format);
    try std.testing.expectEqualSlices(u8, w.fund.raw, out.entries[0].raw.?);
    try std.testing.expectEqual(@as(usize, 1), out.bumps.len);
    try std.testing.expectEqual(@as(u32, 1), out.bumps[0].block_height);
    // Against headers alone: a state holding only the chain takes it as proven.
    var ms2 = lib.store.MemStore.init(std.testing.allocator);
    defer ms2.deinit();
    var st2 = try State.load(a, ms2.store(), null, .regtest);
    _ = try st2.addHeaders(&.{&w.h1});
    const got = try st2.ingest(bytes);
    try std.testing.expectEqual(lib.state.Status.proven, got.status);
    try std.testing.expectEqual(@as(usize, 0), got.registered.len);
}

test "beefOf: an unproven child goes out over its proven parent; once proven, alone with its BUMP" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 2);
    const child = try spend(a, &w.fund.tx, 0, 9_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{child}));
    const unproven = try beef.parse(a, (try w.st.beefOf(child.txid)).?);
    try std.testing.expectEqual(@as(usize, 2), unproven.entries.len);
    try std.testing.expectEqualSlices(u8, &w.fund.txid, &unproven.entries[0].txid);
    try std.testing.expectEqual(beef.Format.raw_with_bump, unproven.entries[0].format);
    try std.testing.expectEqualSlices(u8, &child.txid, &unproven.entries[1].txid);
    try std.testing.expectEqual(beef.Format.raw, unproven.entries[1].format);
    try std.testing.expectEqual(@as(usize, 1), unproven.bumps.len);

    // Mined at 2: the child alone, with its own BUMP; the parent no longer in it.
    _ = try w.st.applyStatus(child.txid, "MINED", try soloPath(a, 2, child.txid));
    const h2 = mine(hdr.hash(&w.h1), child.txid, 1_700_001_200);
    _ = try w.st.addHeaders(&.{&h2});
    try std.testing.expectEqual(lib.state.Status.proven, try w.st.status(child.txid));
    const bytes = (try w.st.beefOf(child.txid)).?;
    const proven = try beef.parse(a, bytes);
    try std.testing.expectEqual(@as(usize, 1), proven.entries.len);
    try std.testing.expectEqualSlices(u8, &child.txid, &proven.entries[0].txid);
    try std.testing.expectEqual(beef.Format.raw_with_bump, proven.entries[0].format);
    try std.testing.expectEqual(@as(u32, 2), proven.bumps[0].block_height);
    var ms2 = lib.store.MemStore.init(std.testing.allocator);
    defer ms2.deinit();
    var st2 = try State.load(a, ms2.store(), null, .regtest);
    _ = try st2.addHeaders(&.{ &w.h1, &h2 });
    try std.testing.expectEqual(lib.state.Status.proven, (try st2.ingest(bytes)).status);
}

/// A transaction spending output 0 of each of `srcs` to our key (signed P2PKH).
fn spendAll(a: std.mem.Allocator, srcs: []const *const bsvz.transaction.Transaction, sats: u64) !Tx {
    var b = bsvz.transaction.Builder.init(a);
    for (srcs) |src| try b.addInputFromTx(src, 0);
    const script = p2pkh(try pub33());
    try b.addOutput(.{ .satoshis = @intCast(sats), .locking_script = bsvz.script.Script.init(try a.dupe(u8, &script)) });
    var tx = try b.build();
    const key = try bsvz.crypto.PrivateKey.fromBytes(priv);
    for (srcs, 0..) |src, i| {
        const prev = src.outputs[0];
        const u = try bsvz.transaction.templates.p2pkh_spend.signAndBuildUnlockingScript(a, &tx, i, prev.locking_script, prev.satoshis, key, bsvz.transaction.templates.p2pkh_spend.default_scope);
        @constCast(tx.inputs)[i].unlocking_script = u;
    }
    const raw = try tx.serialize(a);
    return .{ .tx = tx, .raw = raw, .txid = beef.txidOf(raw) };
}

/// The BUMP bytes of leaf `i` of a four-leaf block at `height` (leaves `l`).
fn path4(a: std.mem.Allocator, height: u32, l: [4][32]u8, i: usize) ![]const u8 {
    const n0 = lib.store.dblSha256(&(l[0] ++ l[1]));
    const n1 = lib.store.dblSha256(&(l[2] ++ l[3]));
    const PE = std.meta.Elem(std.meta.Elem(@FieldType(bsvz.spv.MerklePath, "path")));
    const levels = try a.alloc([]PE, 2);
    const leaf: PE = .{ .offset = i, .hash = .{ .bytes = l[i] }, .txid = true };
    const sib: PE = .{ .offset = i ^ 1, .hash = .{ .bytes = l[i ^ 1] } };
    levels[0] = try a.dupe(PE, if (i & 1 == 0) &.{ leaf, sib } else &.{ sib, leaf });
    levels[1] = try a.dupe(PE, &.{.{ .offset = (i >> 1) ^ 1, .hash = .{ .bytes = if (i < 2) n1 else n0 } }});
    const p: bsvz.spv.MerklePath = .{ .block_height = height, .path = levels };
    return p.bytes(a);
}

test "beefOf: proven parents mined in one block go out under ONE BUMP for that block, selected from the tree's nodes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 3);
    const c0 = try spend(a, &w.fund.tx, 0, 9_000);
    const c1 = try spend(a, &w.fund.tx, 1, 9_000);
    const c2 = try spend(a, &w.fund.tx, 2, 9_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ c0, c1, c2 }));
    // Block 2: c0, c1, c2 and one other transaction.
    const block: [4][32]u8 = .{ c0.txid, c1.txid, c2.txid, .{0x99} ** 32 };
    for ([_]Tx{ c0, c1, c2 }, 0..) |c, i| _ = try w.st.applyStatus(c.txid, "MINED", try path4(a, 2, block, i));
    const root = lib.store.dblSha256(&(lib.store.dblSha256(&(block[0] ++ block[1])) ++ lib.store.dblSha256(&(block[2] ++ block[3]))));
    const h2 = mine(hdr.hash(&w.h1), root, 1_700_001_200);
    _ = try w.st.addHeaders(&.{&h2});
    for ([_]Tx{ c0, c1, c2 }) |c| try std.testing.expectEqual(lib.state.Status.proven, try w.st.status(c.txid));
    // A grandchild of the funding spending c0 and c2, unmined: it goes out over both, one BUMP.
    const g = try spendAll(a, &.{ &c0.tx, &c2.tx }, 17_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ c0, c2, g }));
    const bytes = (try w.st.beefOf(g.txid)).?;
    const out = try beef.parse(a, bytes);
    try std.testing.expectEqual(@as(usize, 3), out.entries.len);
    try std.testing.expectEqual(@as(usize, 1), out.bumps.len);
    try std.testing.expectEqual(@as(u32, 2), out.bumps[0].block_height);
    for (out.entries[0..2]) |e| {
        try std.testing.expectEqual(beef.Format.raw_with_bump, e.format);
        try std.testing.expectEqual(@as(?usize, 0), e.bump);
    }
    // Both leaves (offsets 0 and 2, flagged), their siblings 1 and 3; nothing above (computable).
    try std.testing.expectEqual(@as(usize, 4), out.bumps[0].path[0].len);
    try std.testing.expectEqual(@as(usize, 0), out.bumps[0].path[1].len);
    for (out.bumps[0].path[0], 0..) |l, i| try std.testing.expectEqual(i == 0 or i == 2, l.txid orelse false);
    // Against headers alone it verifies.
    var ms2 = lib.store.MemStore.init(std.testing.allocator);
    defer ms2.deinit();
    var st2 = try State.load(a, ms2.store(), null, .regtest);
    _ = try st2.addHeaders(&.{ &w.h1, &h2 });
    _ = try st2.ingest(bytes);
    try std.testing.expectEqual(lib.state.Status.proven, try st2.status(c0.txid));
    try std.testing.expectEqual(lib.state.Status.proven, try st2.status(c2.txid));
}

test "ingest: a Subject BEEF (BRC-233) — its subject, not the last; a transaction beside it that is no ancestor; each still checked" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 2);
    const deploy = try spend(a, &w.fund.tx, 0, 9_000);
    const icon = try spend(a, &w.fund.tx, 1, 9_000);
    var b = try beef.parse(a, try beefOf(a, &.{.{ w.fund, 1 }}, &.{ deploy, icon }));
    b.atomic = deploy.txid;
    b.form = .subject;
    const bytes = try beef.serialize(a, b);
    try std.testing.expectEqualSlices(u8, &.{ 0x57, 0x09, 0xbe, 0xef }, bytes[0..4]);
    const back = try beef.parse(a, bytes);
    try std.testing.expectEqual(beef.Form.subject, back.formOf());
    try std.testing.expectEqualSlices(u8, &deploy.txid, &back.subject().?);
    const got = try w.st.ingest(bytes);
    try std.testing.expectEqualSlices(u8, &lib.store.hashCid(.tx, deploy.txid), got.tx);
    try std.testing.expectEqual(@as(usize, 2), got.registered.len);
    // A V1 inside, or a subject not in it: not a Subject BEEF.
    var v1 = b;
    v1.version = beef.V1;
    try std.testing.expectError(error.InvalidBeef, beef.serialize(a, v1));
    const in_v1 = try std.mem.concat(a, u8, &.{ bytes[0..36], try beef.serialize(a, .{ .version = beef.V1, .bumps = b.bumps, .entries = b.entries }) });
    try std.testing.expectError(error.InvalidBeef, beef.parse(a, in_v1));
    var missing = b;
    missing.atomic = .{0x99} ** 32;
    try std.testing.expectError(error.InvalidBeef, beef.parse(a, try beef.serialize(a, missing)));
    // Each transaction still passes the BRC-62 check: one whose input is neither proven nor in the bag fails.
    var ms2 = lib.store.MemStore.init(std.testing.allocator);
    defer ms2.deinit();
    var w2 = try world(a, ms2.store(), 2);
    var orphan = b;
    orphan.bumps = &.{};
    orphan.entries = b.entries[1..];
    try std.testing.expect(if (w2.st.ingest(try beef.serialize(a, orphan))) |_| false else |_| true);
}

test "ingest: out of order is sorted, then verified — a proven child before its proven parent (ts-sdk's writer), an unproven one before its parent" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 2);
    // The failing shape (2026-10-22): child proven at 2 at index 0, its parent proven at 1 at index
    // 1, the unproven subject last.
    const child = try spend(a, &w.fund.tx, 0, 9_000);
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), child.txid, 1_700_001_200)});
    const subj = try spend(a, &child.tx, 0, 8_000);
    const bumps = try a.dupe(bsvz.spv.MerklePath, &.{
        try bsvz.spv.MerklePath.parse(a, try soloPath(a, 2, child.txid)),
        try bsvz.spv.MerklePath.parse(a, try soloPath(a, 1, w.fund.txid)),
    });
    const wire = try beef.serialize(a, .{ .version = beef.V2, .atomic = subj.txid, .bumps = bumps, .entries = try a.dupe(beef.Entry, &.{
        .{ .txid = child.txid, .format = .raw_with_bump, .bump = 0, .raw = child.raw, .tx = child.tx },
        .{ .txid = w.fund.txid, .format = .raw_with_bump, .bump = 1, .raw = w.fund.raw, .tx = w.fund.tx },
        .{ .txid = subj.txid, .format = .raw, .raw = subj.raw, .tx = subj.tx },
    }) });
    const parsed = try beef.parse(a, wire);
    try std.testing.expect(!beef.parentsFirst(parsed)); // parse keeps the wire's order
    const view = try beef.sorted(a, parsed);
    try std.testing.expect(beef.parentsFirst(view));
    try std.testing.expectEqualSlices(u8, &w.fund.txid, &view.entries[0].txid);
    try std.testing.expectEqualSlices(u8, &child.txid, &view.entries[1].txid);
    try std.testing.expectEqualSlices(u8, &subj.txid, &view.entries[2].txid);
    try std.testing.expectEqual(@as(?usize, 1), view.entries[0].bump); // BUMP indices unchanged
    try std.testing.expectEqualSlices(u8, &child.txid, &parsed.entries[0].txid);
    const got = try w.st.ingest(wire);
    try std.testing.expectEqualSlices(u8, &lib.store.hashCid(.tx, subj.txid), got.tx);
    try std.testing.expectEqual(lib.state.Status.unproven, got.status);
    try std.testing.expectEqual(@as(usize, 1), got.registered.len);
    try std.testing.expectEqual(lib.state.Status.proven, try w.st.status(child.txid));
    try std.testing.expectEqual(lib.state.Status.proven, try w.st.status(w.fund.txid));

    // Unproven before unproven: tb (spending ta) ahead of ta; registered parents first.
    var ms2 = lib.store.MemStore.init(std.testing.allocator);
    defer ms2.deinit();
    var w2 = try world(a, ms2.store(), 2);
    const ta = try spend(a, &w2.fund.tx, 0, 9_000);
    const tb = try spend(a, &ta.tx, 0, 8_000);
    const fund_bump = try a.dupe(bsvz.spv.MerklePath, &.{try bsvz.spv.MerklePath.parse(a, try soloPath(a, 1, w2.fund.txid))});
    const fund_entry: beef.Entry = .{ .txid = w2.fund.txid, .format = .raw_with_bump, .bump = 0, .raw = w2.fund.raw, .tx = w2.fund.tx };
    const ta_entry: beef.Entry = .{ .txid = ta.txid, .format = .raw, .raw = ta.raw, .tx = ta.tx };
    const tb_entry: beef.Entry = .{ .txid = tb.txid, .format = .raw, .raw = tb.raw, .tx = tb.tx };
    const back = try beef.serialize(a, .{ .version = beef.V2, .atomic = tb.txid, .bumps = fund_bump, .entries = try a.dupe(beef.Entry, &.{ tb_entry, ta_entry, fund_entry }) });
    const got2 = try w2.st.ingest(back);
    try std.testing.expectEqualSlices(u8, &lib.store.hashCid(.tx, tb.txid), got2.tx);
    try std.testing.expectEqual(@as(usize, 2), got2.registered.len);
    try std.testing.expectEqualSlices(u8, &ta.txid, &got2.registered[0]);
    try std.testing.expectEqualSlices(u8, &tb.txid, &got2.registered[1]);

    // Still as strict: a parent genuinely missing fails MissingInput, sorted or not ...
    var ms3 = lib.store.MemStore.init(std.testing.allocator);
    defer ms3.deinit();
    var w3 = try world(a, ms3.store(), 2);
    const missing = try beef.serialize(a, .{ .version = beef.V2, .atomic = tb.txid, .bumps = fund_bump, .entries = try a.dupe(beef.Entry, &.{ tb_entry, fund_entry }) });
    try std.testing.expectError(error.MissingInput, w3.st.ingest(missing));
    // ... a txid-only parent not held fails UnknownTxidOnly ...
    const txid_only = try beef.serialize(a, .{ .version = beef.V2, .atomic = tb.txid, .bumps = &.{}, .entries = try a.dupe(beef.Entry, &.{ tb_entry, .{ .txid = ta.txid, .format = .txid_only } }) });
    try std.testing.expectError(error.UnknownTxidOnly, w3.st.ingest(txid_only));
    // ... and a cycle (here a transaction naming itself as its input's source) is refused.
    const self_ref = [_]beef.Entry{.{ .txid = ta.tx.inputs[0].previous_outpoint.txid.bytes, .format = .raw, .raw = ta.raw, .tx = ta.tx }};
    try std.testing.expectError(error.InvalidBeef, beef.order(a, &self_ref));
    // An order that already holds is kept as it is.
    const ok = try beef.parse(a, try beefOf(a, &.{.{ w2.fund, 1 }}, &.{ ta, tb }));
    try std.testing.expectEqual(ok.entries.ptr, (try beef.sorted(a, ok)).entries.ptr);
}

test "a rejection walks the spends; a proven competing spend is a double spend; never mined stays unproven" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 2);
    const ta = try spend(a, &w.fund.tx, 0, 9_000);
    const tb = try spend(a, &ta.tx, 0, 8_000);
    const got = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ ta, tb }));
    try std.testing.expectEqual(@as(usize, 2), got.registered.len);
    try w.st.watch(tb.txid, &caller, "chain", &request);
    const base = try w.st.save();

    // A rejected: only A at the source (0.21.0); B by its parents' subscription (`reexamine`):
    // input-rejected; the funding's output free again.
    w.st.now = 5000;
    try std.testing.expectEqual(State.Outcome.rejected, try w.st.applyStatus(ta.txid, "REJECTED", null));
    try std.testing.expectEqual(lib.state.Status.unproven, try w.st.status(tb.txid));
    try std.testing.expectEqual(@as(usize, 1), w.st.changes.items.len);
    try std.testing.expectEqual(lib.state.Reexamined.rejected, try w.st.reexamine(tb.txid));
    try std.testing.expectEqual(lib.state.Status.rejected, try w.st.status(tb.txid));
    try std.testing.expectEqual(@as(usize, 2), w.st.changes.items.len);
    try std.testing.expectEqual(@as(usize, 1), w.st.changes.items[1].watchers.len);
    try std.testing.expectEqualStrings("input-rejected", w.st.changes.items[1].detail);
    try std.testing.expect((try w.st.spentBy(w.fund.txid, 0)) == null);
    try std.testing.expect((try w.st.broadcastRecord(ta.txid)) == null and (try w.st.broadcastRecord(tb.txid)) == null);
    try std.testing.expectEqual(@as(usize, 0), try w.st.map("unproven").count());

    // Another spend of the funding's output 0, proven at 2: A and B double-spent.
    var st2 = try State.load(a, ms.store(), base, .regtest);
    const other = try spend(a, &w.fund.tx, 0, 7_000);
    _ = try st2.addHeaders(&.{&mine(hdr.hash(&w.h1), other.txid, 1_700_001_200)});
    const g2 = try st2.ingest(try beefOf(a, &.{ .{ w.fund, 1 }, .{ other, 2 } }, &.{}));
    try std.testing.expectEqual(lib.state.Status.proven, g2.status);
    try st2.settleProven(other.txid); // its subscription step
    try std.testing.expectEqual(lib.state.Status.rejected, try st2.status(ta.txid));
    try std.testing.expectEqualStrings("double-spent", (try st2.record((try st2.settlementCid(ta.txid)).?)).getText("reason").?);
    try std.testing.expectEqualSlices(u8, &other.txid, &(try st2.spentBy(w.fund.txid, 0)).?);
    // Ingesting A again now: rejected at once.
    const g3 = try st2.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ta}));
    try std.testing.expectEqual(lib.state.Status.rejected, g3.status);

    // Never mined: no clock here, it stays unproven however long it waits.
    var st3 = try State.load(a, ms.store(), base, .regtest);
    st3.now = 365 * 24 * 3_600_000;
    try std.testing.expectEqual(lib.state.Status.unproven, try st3.status(ta.txid));
}

test "added (0.19.0): every transaction newly held, parents first, once; a txid-only subject, a proof, a re-ingest add none" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 2);
    const ta = try spend(a, &w.fund.tx, 0, 9_000);
    const tb = try spend(a, &ta.tx, 0, 8_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ ta, tb }));
    try std.testing.expectEqual(@as(usize, 3), w.st.added.items.len);
    try std.testing.expectEqualSlices(u8, &w.fund.txid, &w.st.added.items[0]);
    try std.testing.expectEqualSlices(u8, &ta.txid, &w.st.added.items[1]);
    try std.testing.expectEqualSlices(u8, &tb.txid, &w.st.added.items[2]);
    const saved = try w.st.save();

    var st2 = try State.load(a, ms.store(), saved, .regtest);
    _ = try st2.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ ta, tb }));
    try std.testing.expectEqual(@as(usize, 0), st2.added.items.len);
    _ = try st2.applyStatus(ta.txid, "SEEN_ON_NETWORK", null);
    try std.testing.expectEqual(@as(usize, 0), st2.added.items.len);
}

test "a rejection's cause (0.19.0): double-spent names the proven winner, input-rejected the root; a network rejection none" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 2);
    const ta = try spend(a, &w.fund.tx, 0, 9_000);
    const tb = try spend(a, &ta.tx, 0, 8_000);
    const tc = try spend(a, &tb.tx, 0, 7_500);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ ta, tb, tc }));
    const base = try w.st.save();

    // A proven competitor of A: A double-spent by it, B and C input-rejected with A as the cause.
    var st2 = try State.load(a, ms.store(), base, .regtest);
    const other = try spend(a, &w.fund.tx, 0, 7_000);
    _ = try st2.addHeaders(&.{&mine(hdr.hash(&w.h1), other.txid, 1_700_001_200)});
    _ = try st2.ingest(try beefOf(a, &.{ .{ w.fund, 1 }, .{ other, 2 } }, &.{}));
    try st2.settleProven(other.txid); // the winner's subscription step
    try std.testing.expectEqual(lib.state.Reexamined.rejected, try st2.reexamine(tb.txid)); // B: A's fact
    try std.testing.expectEqual(lib.state.Reexamined.rejected, try st2.reexamine(tc.txid)); // C: B's fact
    const ra = (try st2.rejectionOf(ta.txid)).?;
    try std.testing.expectEqualStrings("double-spent", ra.reason);
    try std.testing.expectEqualSlices(u8, &other.txid, &ra.by.?);
    const rc = (try st2.rejectionOf(tc.txid)).?;
    try std.testing.expectEqualStrings("input-rejected", rc.reason);
    try std.testing.expectEqualSlices(u8, &ta.txid, &rc.by.?);
    try std.testing.expectEqual(@as(usize, 3), st2.changes.items.len);
    try std.testing.expectEqualSlices(u8, &ta.txid, &st2.changes.items[0].txid);
    try std.testing.expectEqualSlices(u8, &other.txid, &st2.changes.items[0].by.?);
    try std.testing.expectEqualSlices(u8, &ta.txid, &st2.changes.items[2].by.?);
    try std.testing.expect((try st2.rejectionOf(other.txid)) == null);

    // A network rejection: its reason, no cause.
    var st3 = try State.load(a, ms.store(), base, .regtest);
    _ = try st3.applyStatus(ta.txid, "REJECTED", null);
    const r3 = (try st3.rejectionOf(ta.txid)).?;
    try std.testing.expectEqualStrings("REJECTED", r3.reason);
    try std.testing.expect(r3.by == null);
    try std.testing.expect(st3.changes.items[0].by == null);
}

test "a proof is the latest fact: a rejected transaction proven later is proven, the change `proven`, its settlement record kept" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const ta = try spend(a, &w.fund.tx, 0, 9_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ta}));
    try std.testing.expectEqual(State.Outcome.rejected, try w.st.applyStatus(ta.txid, "REJECTED", null));
    try std.testing.expect((try w.st.spentBy(w.fund.txid, 0)) == null);
    const rejected = try w.st.save();

    var st2 = try State.load(a, ms.store(), rejected, .regtest);
    _ = try st2.addHeaders(&.{&mine(hdr.hash(&w.h1), ta.txid, 1_700_001_200)});
    try std.testing.expectEqual(State.Outcome.proven, try st2.applyStatus(ta.txid, "MINED", try soloPath(a, 2, ta.txid)));
    try std.testing.expectEqual(lib.state.Status.proven, try st2.status(ta.txid));
    try st2.settleProven(ta.txid); // its subscription step: its inputs' spent again
    try std.testing.expect((try st2.settlementCid(ta.txid)) != null);
    try std.testing.expectEqualSlices(u8, &ta.txid, &(try st2.spentBy(w.fund.txid, 0)).?);
    try std.testing.expect(!(try st2.map("unproven").has(&ta.txid)));
    _ = try st2.save();
}

test "a reorg turns a proven transaction back to unproven, its broadcast registered again; proven in another block, the same watchers told" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const child = try spend(a, &w.fund.tx, 0, 9_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{child}));
    try w.st.watch(child.txid, &caller, "chain", &request);
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), child.txid, 1_700_001_200)});
    try std.testing.expectEqual(State.Outcome.proven, try w.st.applyStatus(child.txid, "MINED", try soloPath(a, 2, child.txid)));
    try w.st.settleProven(child.txid); // its `chain/proof` subscription step
    try std.testing.expectEqual(@as(usize, 1), w.st.changes.items.len);
    const first = w.st.changes.items[0];
    try std.testing.expectEqual(.proven, first.state);
    try std.testing.expectEqual(@as(usize, 1), first.watchers.len);
    try std.testing.expectEqualSlices(u8, &caller, first.watchers[0].getBytes("to").?);
    try std.testing.expect((try w.st.broadcastRecord(child.txid)) == null);
    const proven = try w.st.save();

    // A heavier branch without it: unproven again, its broadcast registered again with the watcher.
    var st2 = try State.load(a, ms.store(), proven, .regtest);
    const alt1 = mine(hdr.hash(&w.h1), .{3} ** 32, 1_700_001_201);
    const alt2 = mine(hdr.hash(&alt1), .{4} ** 32, 1_700_001_202);
    try std.testing.expectEqual(@as(u32, 1), (try st2.addHeaders(&.{ &alt1, &alt2 })).replaced);
    try std.testing.expectEqual(lib.state.Status.unproven, try st2.status(child.txid));
    // 0.21.0: the block that left is listed; what was mined in it follows by its subscription step.
    try std.testing.expectEqual(@as(usize, 1), st2.blocks.items.len);
    try std.testing.expect(!st2.blocks.items[0].active);
    const moved = try st2.blockChanged(st2.blocks.items[0].hash, st2.blocks.items[0].height);
    try std.testing.expectEqual(@as(usize, 1), moved.len);
    try std.testing.expect(!moved[0].proven);
    const again = (try st2.broadcastRecord(child.txid)).?;
    try std.testing.expectEqual(@as(usize, 1), again.getArray("watchers").?.len);
    try std.testing.expect(try st2.map("unproven").has(&child.txid));
    const reverted = try st2.save();

    // Mined again at 4, in another block: proven, the same watcher told of the new proof.
    var st3 = try State.load(a, ms.store(), reverted, .regtest);
    const alt3 = mine(hdr.hash(&alt2), child.txid, 1_700_001_203);
    _ = try st3.addHeaders(&.{&alt3});
    try std.testing.expectEqual(State.Outcome.proven, try st3.applyStatus(child.txid, "MINED", try soloPath(a, 4, child.txid)));
    try std.testing.expectEqual(lib.state.Status.proven, try st3.status(child.txid));
    try st3.settleProven(child.txid);
    try std.testing.expectEqual(@as(usize, 1), st3.changes.items.len);
    const second = st3.changes.items[0];
    try std.testing.expectEqual(.proven, second.state);
    try std.testing.expectEqual(@as(usize, 1), second.watchers.len);
    try std.testing.expectEqualSlices(u8, first.watchers[0].getBytes("to").?, second.watchers[0].getBytes("to").?);
    try std.testing.expectEqualStrings(first.watchers[0].getText("box").?, second.watchers[0].getText("box").?);
    try std.testing.expectEqualSlices(u8, first.watchers[0].getCid("request").?, second.watchers[0].getCid("request").?);
    try std.testing.expectEqual(@as(u32, 4), (try st3.proofFor(child.txid)).?.block_height);
    try std.testing.expect((try st3.broadcastRecord(child.txid)) == null);
    try std.testing.expect(!(try st3.map("unproven").has(&child.txid)));
    _ = try st3.save();
}

/// The envelope the door would put for `bytes` (skein kernel-zig/src/beef.zig `envelope`), its
/// pointer record and blocks put: each transaction under its txid, each BUMP's bytes as a raw block.
fn envelopeOf(a: std.mem.Allocator, s: lib.store.Store, bytes: []const u8) !lib.cbor.Value {
    const cbor = lib.cbor;
    const b = try beef.parse(a, bytes);
    const txs = try a.alloc(cbor.Value, b.entries.len);
    const marks = try a.alloc(cbor.Value, b.entries.len);
    for (b.entries, txs, marks) |e, *t, *m| {
        const c = try a.dupe(u8, &lib.store.hashCid(.tx, e.txid));
        if (e.raw) |r| try s.putBlock(c, r);
        t.* = .{ .cid = c };
        m.* = switch (e.format) {
            .txid_only => .{ .text = "txid" },
            .raw_with_bump => .{ .uint = e.bump.? },
            .raw => .null,
        };
    }
    const bumps = try a.alloc(cbor.Value, b.bumps.len);
    for (b.bumps, bumps) |*p, *v| {
        const pb = try p.bytes(a);
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(pb, &d, .{});
        const c = try a.dupe(u8, &([_]u8{ 0x01, 0x55, 0x12, 0x20 } ++ d));
        try s.putBlock(c, pb);
        v.* = .{ .map = try a.dupe(cbor.Entry, &.{
            .{ .key = "height", .value = .{ .uint = p.block_height } },
            .{ .key = "path", .value = .{ .cid = c } },
            .{ .key = "block", .value = .null },
            .{ .key = "proves", .value = .{ .array = &.{} } },
        }) };
    }
    const rc = try s.putValue(a, .{ .map = try a.dupe(cbor.Entry, &.{
        .{ .key = "kind", .value = .{ .text = "beef" } },
        .{ .key = "version", .value = .{ .uint = if (b.version == beef.V1) 1 else 2 } },
        .{ .key = "txs", .value = .{ .array = txs } },
        .{ .key = "marks", .value = .{ .array = marks } },
        .{ .key = "bumps", .value = .{ .array = bumps } },
    }) });
    const form = b.formOf();
    var es: std.ArrayList(cbor.Entry) = .empty;
    try es.appendSlice(a, &.{
        .{ .key = "form", .value = .{ .text = @tagName(form) } },
        .{ .key = "beef", .value = .{ .cid = rc } },
    });
    if (form != .beef) try es.append(a, .{ .key = "subject", .value = .{ .cid = try a.dupe(u8, &lib.store.hashCid(.tx, b.atomic.?)) } });
    if (b.vout) |o| try es.append(a, .{ .key = "vout", .value = .{ .uint = o } });
    return .{ .map = es.items };
}

test "record: wireOf gives back the exact bytes of every form (V2 Atomic, V1, Outpoint, V2 with a txid-only entry, Subject)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();
    const fund = try funding(a, 2);
    const child = try spend(a, &fund.tx, 0, 9_000);
    const atomic = try beefOf(a, &.{.{ fund, 1 }}, &.{child});
    const parsed = try beef.parse(a, atomic);
    var v1 = parsed;
    v1.atomic = null;
    v1.version = beef.V1;
    var outpoint = parsed;
    outpoint.vout = 1;
    var txid_only = parsed;
    txid_only.atomic = null;
    const es = try a.dupe(beef.Entry, parsed.entries);
    es[0] = .{ .txid = fund.txid, .format = .txid_only };
    txid_only.entries = es;
    var subject = parsed;
    subject.form = .subject;
    for ([_][]const u8{ atomic, try beef.serialize(a, v1), try beef.serialize(a, outpoint), try beef.serialize(a, txid_only), try beef.serialize(a, subject) }) |wire| {
        const env = try envelopeOf(a, s, wire);
        try std.testing.expectEqualSlices(u8, wire, try lib.record.wireOf(a, s, env));
        const got = try lib.record.parsed(a, s, env);
        try std.testing.expectEqualSlices(u8, &child.txid, &got.subject().?);
        const e = lib.record.envelopeOf(env).?;
        try std.testing.expectEqualSlices(u8, &child.txid, &lib.record.subjectOf(e, try s.getValue(a, e.beef)).?);
    }
    const op = try beef.parse(a, try beef.serialize(a, outpoint));
    try std.testing.expectEqual(@as(?u32, 1), op.vout);
    // Atomic and Subject over one BEEF: one pointer record, the BEEF alone.
    const ea = lib.record.envelopeOf(try envelopeOf(a, s, atomic)).?;
    const es2 = lib.record.envelopeOf(try envelopeOf(a, s, try beef.serialize(a, subject))).?;
    try std.testing.expectEqualSlices(u8, ea.beef, es2.beef);
    try std.testing.expectEqual(beef.Form.subject, es2.form);
    try std.testing.expectEqualSlices(u8, atomic[36..], try lib.record.beefOf(a, s, ea.beef));
    // Not a pointer record: refused.
    try std.testing.expectError(error.NotARecord, lib.record.encode(a, s, .{ .map = &.{} }));
}

/// A regtest chain from genesis: `n` headers, the genesis first.
fn regtestChain(a: std.mem.Allocator, n: usize) ![][80]u8 {
    const out = try a.alloc([80]u8, n);
    out[0] = lib.chain.Network.regtest.genesis();
    for (out[1..], 1..) |*h, i| h.* = mine(hdr.hash(&out[i - 1]), .{@as(u8, @truncate(i))} ** 32, 1_700_000_000 + @as(u32, @intCast(i)) * 600);
    return out;
}

test "image: a header chain in an image tree loads into an empty state — the same state as adding the headers" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();
    const img = lib.image;
    // Three blocks: two full (2016 each), the last partial.
    const hs = try regtestChain(a, 2 * img.per_block + 5);
    const w = try img.write(a, s, hs);
    const found = (try img.find(a, s, &w.root)).?;
    try std.testing.expectEqual(@as(usize, 3), found.blocks.len);
    try std.testing.expectEqual(@as(u32, @intCast(hs.len - 1)), found.tip.height);

    var st = try State.load(a, s, null, .regtest);
    const got = (try img.load(&st, &w.root)).?;
    try std.testing.expectEqual(@as(u32, @intCast(hs.len)), got.headers);
    try std.testing.expectEqual(@as(u32, @intCast(hs.len - 1)), got.tip);
    const loaded = try st.save();

    // The same chain added as a run from genesis: the same state record.
    var st2 = try State.load(a, s, null, .regtest);
    const runs = try a.alloc([]const u8, hs.len - 1);
    for (hs[1..], runs) |*h, *r| r.* = h;
    _ = try st2.addHeaders(runs);
    try std.testing.expectEqualStrings(try st2.save(), loaded);

    // Read back from the saved record; the tip stream continues past the image's tip.
    var st3 = try State.load(a, s, loaded, .regtest);
    try std.testing.expectEqual(@as(?u32, @intCast(hs.len - 1)), try st3.chain().tip());
    try std.testing.expectEqualSlices(u8, &hs[2016], &(try st3.chain().at(2016)).?.raw);
    try std.testing.expectEqual(@as(?u32, 4000), try st3.chain().heightOf(hdr.hash(&hs[4000])));
    const next = mine(hdr.hash(&hs[hs.len - 1]), .{0xee} ** 32, 1_800_000_000);
    const r = try st3.addHeaders(&.{&next});
    try std.testing.expectEqual(@as(u32, 1), r.added);
    try std.testing.expectEqual(@as(u32, @intCast(hs.len)), r.tip);

    // Loaded once only: a state with headers is refused.
    try std.testing.expectError(error.NotEmpty, img.load(&st3, &w.root));
}

test "image: no chain in the tree is null; another network, a broken link, a bad target, a wrong tip refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();
    const img = lib.image;
    const hs = try regtestChain(a, 40);

    // A tree with no `chain`: nothing loaded, the state untouched.
    const empty = img.gitCid("tree 0\x00");
    try s.putBlock(&empty, "tree 0\x00");
    var st = try State.load(a, s, null, .regtest);
    try std.testing.expect((try img.load(&st, &empty)) == null);
    try std.testing.expect((try st.chain().tip()) == null);

    // A regtest chain into a mainnet state.
    const w = try img.write(a, s, hs);
    var main_st = try State.load(a, s, null, .main);
    try std.testing.expectError(error.WrongNetwork, img.load(&main_st, &w.root));

    // Two headers swapped: the link breaks.
    const swapped = try a.dupe([80]u8, hs);
    std.mem.swap([80]u8, &swapped[10], &swapped[11]);
    var st1 = try State.load(a, s, null, .regtest);
    try std.testing.expectError(error.BadLink, img.load(&st1, &(try img.write(a, s, swapped)).root));

    // The last header's bits unusable.
    const bad = try a.dupe([80]u8, hs);
    std.mem.writeInt(u32, bad[39][72..76], 0, .little);
    var st2 = try State.load(a, s, null, .regtest);
    try std.testing.expectError(error.BadTarget, img.load(&st2, &(try img.write(a, s, bad)).root));

    // A tip that is not the last header: the chain part of one tree, the tip of another.
    const short = try img.write(a, s, hs[0..39]);
    var es: std.ArrayList(u8) = .empty;
    const chain_obj = try s.get(a, &w.chain);
    const short_obj = try s.get(a, &short.chain);
    // Rebuild `chain` from w's headers tree and short's tip.
    const nul_w = std.mem.indexOfScalar(u8, chain_obj, 0).?;
    const nul_s = std.mem.indexOfScalar(u8, short_obj, 0).?;
    const body_w = chain_obj[nul_w + 1 ..];
    const body_s = short_obj[nul_s + 1 ..];
    const headers_entry_len = "40000 headers\x00".len + 20;
    try es.appendSlice(a, body_w[0..headers_entry_len]);
    try es.appendSlice(a, body_s[headers_entry_len..]);
    const mixed = try std.fmt.allocPrint(a, "tree {d}\x00{s}", .{ es.items.len, es.items });
    const mixed_cid = img.gitCid(mixed);
    try s.putBlock(&mixed_cid, mixed);
    const root_body = try std.fmt.allocPrint(a, "40000 chain\x00{s}", .{mixed_cid[4..24]});
    const root = try std.fmt.allocPrint(a, "tree {d}\x00{s}", .{ root_body.len, root_body });
    const root_cid = img.gitCid(root);
    try s.putBlock(&root_cid, root);
    var st3 = try State.load(a, s, null, .regtest);
    try std.testing.expectError(error.BadImage, img.load(&st3, &root_cid));

    // The tip text.
    const t = try img.parseTip(a, try img.tipText(a, .{ .height = 7, .hash = hdr.hash(&hs[7]) }));
    try std.testing.expectEqual(@as(u32, 7), t.height);
    try std.testing.expectEqualSlices(u8, &hdr.hash(&hs[7]), &t.hash);
    var nb: [8]u8 = undefined;
    try std.testing.expectEqualStrings("00004032", img.blockName(&nb, 4032));
}

// ------------------------------------------------------------ the host chain (shruggr/skein#156)

/// The host chain after a run of headers: its record's CID.
fn hostAdd(a: std.mem.Allocator, s: lib.store.Store, record: ?[]const u8, raws: []const []const u8) ![]const u8 {
    var h = try lib.host.Host.open(a, s, record, .regtest);
    _ = try h.add(raws);
    return (try h.save()).?;
}

test "host chain: add, save, read back; an image imported into an empty host chain is the same record as the run; a second import refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();
    const hs = try regtestChain(a, 2 * lib.image.per_block + 9);
    const runs = try a.alloc([]const u8, hs.len - 1);
    for (hs[1..], runs) |*h, *r| r.* = h;

    // Empty: no record.
    var empty = try lib.host.Host.open(a, s, null, .regtest);
    try std.testing.expect((try empty.save()) == null);

    const added = try hostAdd(a, s, null, runs);
    const r = try lib.host.read(a, s, added);
    try std.testing.expectEqual(lib.chain.Network.regtest, r.network);
    try std.testing.expectEqual(@as(u32, @intCast(hs.len - 1)), r.tip.?.height);
    try std.testing.expectEqualSlices(u8, &hdr.hash(&hs[hs.len - 1]), &r.tip.?.hash);

    // The same chain from an image tree: the same record.
    const w = try lib.image.write(a, s, hs);
    var h2 = try lib.host.Host.open(a, s, null, .regtest);
    const got = (try h2.import(&w.root)).?;
    try std.testing.expectEqual(@as(u32, @intCast(hs.len)), got.headers);
    try std.testing.expectEqualStrings(added, (try h2.save()).?);
    try std.testing.expectError(error.NotEmpty, h2.import(&w.root));

    // Another network's record refused; the tracker continues from a saved record.
    try std.testing.expectError(error.NetworkMismatch, lib.host.Host.open(a, s, added, .main));
    const next = mine(hdr.hash(&hs[hs.len - 1]), .{0xee} ** 32, 1_800_000_000);
    const grown = try hostAdd(a, s, added, &.{&next});
    try std.testing.expectEqual(@as(u32, @intCast(hs.len)), (try lib.host.read(a, s, grown)).tip.?.height);
}

test "pointAt: a state names the host chain's roots — the same state as adding the headers; a heavier branch reverts the proofs above the fork" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();

    // Block 1 holds the funding; the host chain is at 1.
    const fund = try funding(a, 1);
    const h1 = mine(hdr.hash(&lib.chain.Network.regtest.genesis()), fund.txid, 1_700_000_600);
    const host1 = try hostAdd(a, s, null, &.{&h1});

    // A new state pointed at it: fork 0 (empty), nothing replaced; its maps are the host's.
    var st = try State.load(a, s, null, .regtest);
    const p1 = try st.pointAt(host1);
    try std.testing.expectEqual(@as(u32, 1), p1.height);
    try std.testing.expectEqual(@as(u32, 0), p1.fork);
    try std.testing.expect(!p1.replaced);
    const r1 = try lib.host.read(a, s, host1);
    try std.testing.expectEqualSlices(u8, r1.headers.?, st.map("headers").root.?);
    // The same as a state that added the header itself.
    var copy = try State.load(a, s, null, .regtest);
    _ = try copy.addHeaders(&.{&h1});
    try std.testing.expectEqualStrings(try copy.save(), try st.save());

    // The child, unproven, watched; mined at 2 on the host chain; its proof applies.
    const child = try spend(a, &fund.tx, 0, 9_000);
    _ = try st.ingest(try beefOf(a, &.{.{ fund, 1 }}, &.{child}));
    try st.watch(child.txid, &caller, "chain", &request);
    const h2 = mine(hdr.hash(&h1), child.txid, 1_700_001_200);
    const host2 = try hostAdd(a, s, host1, &.{&h2});
    const p2 = try st.pointAt(host2);
    try std.testing.expectEqual(@as(u32, 2), p2.height);
    try std.testing.expectEqual(@as(u32, 1), p2.fork);
    try std.testing.expectEqual(State.Outcome.proven, try st.applyStatus(child.txid, "MINED", try soloPath(a, 2, child.txid)));
    try st.settleProven(child.txid);
    const proven = try st.save();

    // The same host record again: nothing changes.
    var again = try State.load(a, s, proven, .regtest);
    const p2b = try again.pointAt(host2);
    try std.testing.expectEqual(@as(u32, 2), p2b.fork);
    try std.testing.expectEqualStrings(proven, try again.save());

    // A heavier branch from 1 replacing 2: unproven again, its broadcast registered again with the watcher.
    const alt2 = mine(hdr.hash(&h1), .{3} ** 32, 1_700_001_201);
    const alt3 = mine(hdr.hash(&alt2), .{4} ** 32, 1_700_001_202);
    const host3 = try hostAdd(a, s, host2, &.{ &alt2, &alt3 });
    var st2 = try State.load(a, s, proven, .regtest);
    const p3 = try st2.pointAt(host3);
    try std.testing.expectEqual(@as(u32, 3), p3.height);
    try std.testing.expectEqual(@as(u32, 1), p3.fork);
    try std.testing.expect(p3.replaced);
    try std.testing.expectEqual(lib.state.Status.unproven, try st2.status(child.txid));
    try std.testing.expectEqual(@as(usize, 1), st2.blocks.items.len);
    try std.testing.expect(!st2.blocks.items[0].active);
    _ = try st2.blockChanged(st2.blocks.items[0].hash, st2.blocks.items[0].height);
    try std.testing.expectEqual(@as(usize, 1), (try st2.broadcastRecord(child.txid)).?.getArray("watchers").?.len);
    try std.testing.expect(try st2.map("unproven").has(&child.txid));
    try std.testing.expectEqual(@as(?u32, 3), try st2.chain().tip());

    // The opener (skein-sdk#1): the record's own network; null is empty on the given one.
    const saved = try st2.save();
    var ro = try lib.open(a, s, saved, .main);
    try std.testing.expectEqual(lib.chain.Network.regtest, ro.network);
    try std.testing.expectEqual(@as(?u32, 3), try ro.chain().tip());
    var none = try lib.open(a, s, null, .@"test");
    try std.testing.expectEqual(lib.chain.Network.@"test", none.network);
    try std.testing.expect((try none.chain().tip()) == null);

    // Another network's host record refused.
    var main_st = try State.load(a, s, null, .main);
    try std.testing.expectError(error.NetworkMismatch, main_st.pointAt(host3));
}

// ------------------------------------------------------------ 0.21.0: a saved path links every transaction it covers

/// A BUMP for a block of two transactions: level 0 = {0: left, 1: right}; `flag` the BRC-74 txid flag per leaf.
fn pairPath(a: std.mem.Allocator, height: u32, left: [32]u8, right: [32]u8, flag_left: bool, flag_right: bool) !bsvz.spv.MerklePath {
    return bsvz.spv.MerklePath.parse(a, try pairBytes(a, height, left, right, flag_left, flag_right));
}

fn pairBytes(a: std.mem.Allocator, height: u32, left: [32]u8, right: [32]u8, flag_left: bool, flag_right: bool) ![]const u8 {
    var path: std.ArrayList(u8) = .empty;
    try path.appendSlice(a, &.{ 0xfd, 0, 0, 0x01, 0x02, 0x00, if (flag_left) 0x02 else 0x00 });
    std.mem.writeInt(u16, path.items[1..3], @intCast(height), .little);
    try path.appendSlice(a, &left);
    try path.appendSlice(a, &.{ 0x01, if (flag_right) 0x02 else 0x00 });
    try path.appendSlice(a, &right);
    return path.items;
}

fn pairRoot(left: [32]u8, right: [32]u8) [32]u8 {
    return lib.store.dblSha256(&(left ++ right));
}

/// A BEEF V2 (Atomic for `atomic`) of `bumps` and `entries` as given.
fn beefWith(a: std.mem.Allocator, atomic: [32]u8, bumps: []const bsvz.spv.MerklePath, entries: []const beef.Entry) ![]const u8 {
    return beef.serialize(a, .{ .version = beef.V2, .atomic = atomic, .bumps = try a.dupe(bsvz.spv.MerklePath, bumps), .entries = try a.dupe(beef.Entry, entries) });
}

const Pair = struct { w: World, p: Tx, x: Tx, c: Tx, h2: [80]u8 };

/// The funding at 1; P spends it, X spends P, both mined in block 2 (P at 0, X at 1); C spends X, unmined.
fn pairWorld(a: std.mem.Allocator, s: lib.store.Store) !Pair {
    var w = try world(a, s, 1);
    const p = try spend(a, &w.fund.tx, 0, 9_000);
    const x = try spend(a, &p.tx, 0, 8_000);
    const c = try spend(a, &x.tx, 0, 7_000);
    const h2 = mine(hdr.hash(&w.h1), pairRoot(p.txid, x.txid), 1_700_001_200);
    _ = try w.st.addHeaders(&.{&h2});
    return .{ .w = w, .p = p, .x = x, .c = c, .h2 = h2 };
}

fn linkedHas(st: *State, txid: [32]u8) bool {
    for (st.linked.items) |l| if (std.mem.eql(u8, &l.txid, &txid)) return true;
    return false;
}

test "0.21.0 the live sequence: P's path saved (X's leaf unflagged); X arrives bare with an unproven child C — X proven on arrival, never registered; C's bundle carries X proven" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var z = try pairWorld(a, ms.store());
    const path2 = try pairPath(a, 2, z.p.txid, z.x.txid, true, false);

    // P with its path (and the funding proven at 1): P and X linked, both, at their own offsets.
    _ = try z.w.st.ingest(try beefWith(a, z.p.txid, &.{ try bsvz.spv.MerklePath.parse(a, try soloPath(a, 1, z.w.fund.txid)), path2 }, &.{
        .{ .txid = z.w.fund.txid, .format = .raw_with_bump, .bump = 0, .raw = z.w.fund.raw, .tx = z.w.fund.tx },
        .{ .txid = z.p.txid, .format = .raw_with_bump, .bump = 1, .raw = z.p.raw, .tx = z.p.tx },
    }));
    try std.testing.expect(linkedHas(&z.w.st, z.p.txid) and linkedHas(&z.w.st, z.x.txid));
    try std.testing.expectEqual(@as(usize, 3), z.w.st.linked.items.len); // the funding, P, X
    for (z.w.st.linked.items) |l| if (std.mem.eql(u8, &l.txid, &z.x.txid)) {
        try std.testing.expectEqual(@as(u64, 1), l.position);
        try std.testing.expectEqual(@as(u32, 2), l.height);
        try std.testing.expectEqualSlices(u8, &hdr.hash(&z.h2), &l.block);
    };
    try std.testing.expect(!(try z.w.st.holds(z.x.txid)));
    try std.testing.expectEqual(lib.state.Status.proven, try z.w.st.minedStatus(z.x.txid));
    const s1 = try z.w.st.save();

    // The same path again: nothing written, nothing linked.
    var st2 = try State.load(a, ms.store(), s1, .regtest);
    _ = try st2.addProof(z.p.txid, try pairBytes(a, 2, z.p.txid, z.x.txid, true, false));
    try std.testing.expectEqual(@as(usize, 0), st2.linked.items.len);
    try std.testing.expectEqualStrings(s1, try st2.save());

    // X bare (P txid-only: held) with its unproven child C.
    var st3 = try State.load(a, ms.store(), s1, .regtest);
    const g = try st3.ingest(try beefWith(a, z.c.txid, &.{}, &.{
        .{ .txid = z.p.txid, .format = .txid_only },
        .{ .txid = z.x.txid, .format = .raw, .raw = z.x.raw, .tx = z.x.tx },
        .{ .txid = z.c.txid, .format = .raw, .raw = z.c.raw, .tx = z.c.tx },
    }));
    try std.testing.expectEqual(lib.state.Status.proven, try st3.status(z.x.txid));
    try std.testing.expectEqual(@as(usize, 1), g.registered.len);
    try std.testing.expectEqualSlices(u8, &z.c.txid, &g.registered[0]);
    try std.testing.expect((try st3.broadcastRecord(z.x.txid)) == null);
    try std.testing.expectEqual(@as(usize, 0), st3.linked.items.len);

    // Our own outgoing bundle for C: X goes proven (raw with its BUMP, its leaf flagged), and no entry
    // is bare while a BUMP in the bundle covers its hash.
    const out = try beef.parse(a, (try st3.beefOf(z.c.txid)).?);
    var saw_x = false;
    for (out.entries) |e| {
        if (std.mem.eql(u8, &e.txid, &z.x.txid)) {
            saw_x = true;
            try std.testing.expectEqual(beef.Format.raw_with_bump, e.format);
            var flagged = false;
            for (out.bumps[e.bump.?].path[0]) |leaf| if (leaf.hash) |h| if (std.mem.eql(u8, &h.bytes, &z.x.txid)) {
                flagged = leaf.txid orelse false;
            };
            try std.testing.expect(flagged);
        }
        if (e.format == .raw) for (out.bumps) |bp| try std.testing.expect(!beef.bumpHas(bp, e.txid));
        try std.testing.expect(!std.mem.eql(u8, &e.txid, &z.p.txid)); // X proven: its parent is not needed
    }
    try std.testing.expect(saw_x);
}

test "0.21.0 a proof after the transaction: X held pending, then P's path (X unflagged) — X linked in that step; settleProven settles its broadcast" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var z = try pairWorld(a, ms.store());
    const g = try z.w.st.ingest(try beefOf(a, &.{.{ z.w.fund, 1 }}, &.{ z.p, z.x }));
    try std.testing.expectEqual(@as(usize, 2), g.registered.len);
    const s1 = try z.w.st.save();

    var st2 = try State.load(a, ms.store(), s1, .regtest);
    try std.testing.expectEqual(State.Outcome.proven, try st2.applyStatus(z.p.txid, "MINED", try pairBytes(a, 2, z.p.txid, z.x.txid, true, false)));
    try std.testing.expect(linkedHas(&st2, z.p.txid) and linkedHas(&st2, z.x.txid));
    try std.testing.expectEqual(lib.state.Status.proven, try st2.status(z.x.txid));
    // X's broadcast record waits for its own subscription step: settleProven.
    try std.testing.expect((try st2.broadcastRecord(z.x.txid)) != null);
    const n = st2.changes.items.len;
    try st2.settleProven(z.x.txid);
    try std.testing.expect((try st2.broadcastRecord(z.x.txid)) == null);
    try std.testing.expectEqual(n + 1, st2.changes.items.len);
    try std.testing.expectEqual(.proven, st2.changes.items[n].state);
    try st2.settleProven(z.x.txid); // idempotent
    try std.testing.expectEqual(n + 1, st2.changes.items.len);
    try std.testing.expect(!(try st2.map("unproven").has(&z.x.txid)));
}

test "0.21.0 held rejected, then a path covering it: proven (the latest fact), the settlement kept, its inputs' spent again" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var z = try pairWorld(a, ms.store());
    _ = try z.w.st.ingest(try beefOf(a, &.{.{ z.w.fund, 1 }}, &.{ z.p, z.x }));
    _ = try z.w.st.applyStatus(z.x.txid, "REJECTED", null);
    try std.testing.expectEqual(lib.state.Status.rejected, try z.w.st.status(z.x.txid));
    try std.testing.expect((try z.w.st.spentBy(z.p.txid, 0)) == null);
    const s1 = try z.w.st.save();

    var st2 = try State.load(a, ms.store(), s1, .regtest);
    _ = try st2.applyStatus(z.p.txid, "MINED", try pairBytes(a, 2, z.p.txid, z.x.txid, true, false));
    try std.testing.expectEqual(lib.state.Status.proven, try st2.status(z.x.txid));
    try st2.settleProven(z.x.txid);
    try std.testing.expect((try st2.rejectionOf(z.x.txid)) != null);
    try std.testing.expectEqualSlices(u8, &z.x.txid, &(try st2.spentBy(z.p.txid, 0)).?);
}

test "0.21.0 reorg: the block leaves — P and X both unproven, both reverted; proven in another block, linked again" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var z = try pairWorld(a, ms.store());
    _ = try z.w.st.ingest(try beefOf(a, &.{.{ z.w.fund, 1 }}, &.{ z.p, z.x }));
    _ = try z.w.st.applyStatus(z.p.txid, "MINED", try pairBytes(a, 2, z.p.txid, z.x.txid, true, false));
    try z.w.st.settleProven(z.x.txid);
    const s1 = try z.w.st.save();

    var st2 = try State.load(a, ms.store(), s1, .regtest);
    const alt2 = mine(hdr.hash(&z.w.h1), .{3} ** 32, 1_700_001_201);
    const alt3 = mine(hdr.hash(&alt2), .{4} ** 32, 1_700_001_202);
    _ = try st2.addHeaders(&.{ &alt2, &alt3 });
    try std.testing.expectEqual(lib.state.Status.unproven, try st2.status(z.p.txid));
    try std.testing.expectEqual(lib.state.Status.unproven, try st2.status(z.x.txid));
    try std.testing.expectEqual(@as(usize, 1), st2.blocks.items.len); // the one block both were mined in
    const moved = try st2.blockChanged(st2.blocks.items[0].hash, st2.blocks.items[0].height);
    try std.testing.expectEqual(@as(usize, 2), moved.len);
    try std.testing.expect((try st2.broadcastRecord(z.x.txid)) != null);
    const s2 = try st2.save();

    // Both mined again at 4: one path, both linked again, at the new block.
    var st3 = try State.load(a, ms.store(), s2, .regtest);
    const alt4 = mine(hdr.hash(&alt3), pairRoot(z.p.txid, z.x.txid), 1_700_001_203);
    _ = try st3.addHeaders(&.{&alt4});
    _ = try st3.applyStatus(z.p.txid, "MINED", try pairBytes(a, 4, z.p.txid, z.x.txid, true, false));
    try std.testing.expect(linkedHas(&st3, z.p.txid) and linkedHas(&st3, z.x.txid));
    try std.testing.expectEqual(lib.state.Status.proven, try st3.status(z.x.txid));
}

test "0.21.0 negatives: a path whose root is not the header's links nothing; a duplicate slot is no transaction; nothing above level 0" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var z = try pairWorld(a, ms.store());
    _ = try z.w.st.ingest(try beefOf(a, &.{.{ z.w.fund, 1 }}, &.{ z.p, z.x }));
    const s1 = try z.w.st.save();

    // Wrong root: refused, nothing linked.
    var st2 = try State.load(a, ms.store(), s1, .regtest);
    try std.testing.expectError(error.RootMismatch, st2.applyStatus(z.p.txid, "MINED", try pairBytes(a, 2, z.p.txid, .{9} ** 32, true, false)));
    try std.testing.expectEqual(@as(usize, 0), st2.linked.items.len);

    // A block of three: A, B, C; C's path names C at 2 and again at 3 (the duplicate written out),
    // and H(A,B) above. Only C is linked, at offset 2.
    var w = try world(a, ms.store(), 1);
    const ta: [32]u8 = .{0xa1} ** 32;
    const tb: [32]u8 = .{0xb2} ** 32;
    const tc = z.p.txid;
    const ab = pairRoot(ta, tb);
    const root = pairRoot(ab, pairRoot(tc, tc));
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), root, 1_700_001_300)});
    var bytes: std.ArrayList(u8) = .empty;
    try bytes.appendSlice(a, &.{ 0xfd, 2, 0, 0x02, 0x02, 0x02, 0x02 });
    try bytes.appendSlice(a, &tc);
    try bytes.appendSlice(a, &.{ 0x03, 0x00 });
    try bytes.appendSlice(a, &tc);
    try bytes.appendSlice(a, &.{ 0x01, 0x00, 0x00 });
    try bytes.appendSlice(a, &ab);
    const p3 = try bsvz.spv.MerklePath.parse(a, bytes.items);
    try w.st.putProof(tc, p3);
    try std.testing.expectEqual(@as(usize, 1), w.st.linked.items.len);
    try std.testing.expectEqualSlices(u8, &tc, &w.st.linked.items[0].txid);
    try std.testing.expectEqual(@as(u64, 2), w.st.linked.items[0].position);
    try std.testing.expectEqual(lib.state.Status.unproven, try w.st.minedStatus(ab));
}

// ------------------------------------------------------------ 0.21.0 phase 2: dependencies re-examined from the state

test "0.21.0 parents: P rejected — only P at the source; X and C (X's child) rejected input-rejected by reexamine; P proven later — X revived, then C" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var z = try pairWorld(a, ms.store());
    _ = try z.w.st.ingest(try beefOf(a, &.{.{ z.w.fund, 1 }}, &.{ z.p, z.x, z.c }));
    const s0 = try z.w.st.save();

    var st = try State.load(a, ms.store(), s0, .regtest);
    _ = try st.applyStatus(z.p.txid, "REJECTED", null);
    try std.testing.expectEqual(lib.state.Status.rejected, try st.status(z.p.txid));
    try std.testing.expectEqual(lib.state.Status.unproven, try st.status(z.x.txid)); // no walk at the source
    try std.testing.expectEqual(lib.state.Reexamined.unchanged, try st.reexamine(z.c.txid)); // its parent X is not rejected yet
    try std.testing.expectEqual(lib.state.Reexamined.rejected, try st.reexamine(z.x.txid)); // P's fact
    try std.testing.expectEqual(lib.state.Reexamined.rejected, try st.reexamine(z.c.txid)); // X's fact
    const rc = (try st.rejectionOf(z.c.txid)).?;
    try std.testing.expectEqualStrings("input-rejected", rc.reason);
    try std.testing.expectEqualSlices(u8, &z.p.txid, &rc.by.?); // the root
    try std.testing.expectEqual(lib.state.Reexamined.unchanged, try st.reexamine(z.x.txid)); // idempotent
    const s1 = try st.save();

    // P proven (block 2 holds P and X): X is linked too — proven, its input-rejected overridden; C revived.
    var st2 = try State.load(a, ms.store(), s1, .regtest);
    _ = try st2.applyStatus(z.p.txid, "MINED", try pairBytes(a, 2, z.p.txid, z.x.txid, true, false));
    try std.testing.expectEqual(lib.state.Status.proven, try st2.status(z.p.txid));
    try std.testing.expectEqual(lib.state.Status.proven, try st2.status(z.x.txid));
    try std.testing.expectEqual(lib.state.Status.rejected, try st2.status(z.c.txid));
    try std.testing.expectEqual(lib.state.Reexamined.revived, try st2.reexamine(z.c.txid)); // X's fact
    try std.testing.expectEqual(lib.state.Status.unproven, try st2.status(z.c.txid));
    try std.testing.expect((try st2.broadcastRecord(z.c.txid)) != null);
    try std.testing.expectEqual(@as(usize, 1), st2.revived.items.len);
    try std.testing.expectEqualSlices(u8, &z.c.txid, &st2.revived.items[0]);
    try std.testing.expectEqual(lib.state.Reexamined.unchanged, try st2.reexamine(z.c.txid));
}

test "0.21.0 parents: P rejected, its child X unmined — revived when P's rejection is overturned by P's own proof (P alone in its block)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const p = try spend(a, &w.fund.tx, 0, 9_000);
    const x = try spend(a, &p.tx, 0, 8_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ p, x }));
    _ = try w.st.applyStatus(p.txid, "REJECTED", null);
    _ = try w.st.reexamine(x.txid);
    try std.testing.expectEqual(lib.state.Status.rejected, try w.st.status(x.txid));
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), p.txid, 1_700_001_200)});
    _ = try w.st.applyStatus(p.txid, "MINED", try soloPath(a, 2, p.txid));
    try std.testing.expectEqual(lib.state.Reexamined.revived, try w.st.reexamine(x.txid));
    try std.testing.expectEqual(lib.state.Status.unproven, try w.st.status(x.txid));
}

test "0.21.0 a rejection is refused while a descendant is proven (a proven child proves its parents mined)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const p = try spend(a, &w.fund.tx, 0, 9_000);
    const x = try spend(a, &p.tx, 0, 8_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ p, x }));
    // X proven in a block of its own; P (its parent) has no proof here.
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), x.txid, 1_700_001_200)});
    _ = try w.st.applyStatus(x.txid, "MINED", try soloPath(a, 2, x.txid));
    try std.testing.expectEqual(lib.state.Status.proven, try w.st.status(x.txid));
    try std.testing.expectEqual(State.Outcome.pending, try w.st.applyStatus(p.txid, "REJECTED", null));
    try std.testing.expectEqual(lib.state.Status.unproven, try w.st.status(p.txid));
    try std.testing.expect((try w.st.rejectionOf(p.txid)) == null);
    try std.testing.expectEqual(@as(usize, 0), (try w.st.reject(p.txid, "REJECTED")).len);
}

test "0.21.0 a proof always overrides rejected: proven after a rejection, then reorged out — unproven, not rejected; a later rejection is rejected again" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const t = try spend(a, &w.fund.tx, 0, 9_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{t}));
    _ = try w.st.applyStatus(t.txid, "REJECTED", null);
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), t.txid, 1_700_001_200)});
    _ = try w.st.applyStatus(t.txid, "MINED", try soloPath(a, 2, t.txid));
    try std.testing.expectEqual(lib.state.Status.proven, try w.st.status(t.txid));
    try std.testing.expect(!(try w.st.map("rejected").has(&t.txid)));
    try std.testing.expectEqualStrings("REJECTED", (try w.st.rejectionOf(t.txid)).?.reason); // the record kept, read for its reason
    const alt2 = mine(hdr.hash(&w.h1), .{3} ** 32, 1_700_001_201);
    const alt3 = mine(hdr.hash(&alt2), .{4} ** 32, 1_700_001_202);
    _ = try w.st.addHeaders(&.{ &alt2, &alt3 });
    try std.testing.expectEqual(lib.state.Status.unproven, try w.st.status(t.txid));
    _ = try w.st.applyStatus(t.txid, "REJECTED", null);
    try std.testing.expectEqual(lib.state.Status.rejected, try w.st.status(t.txid));
}

test "0.21.0 a proof before its header for a rejected transaction (no broadcast record) is parked, not thrown away" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const t = try spend(a, &w.fund.tx, 0, 9_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{t}));
    _ = try w.st.applyStatus(t.txid, "REJECTED", null);
    try std.testing.expect((try w.st.broadcastRecord(t.txid)) == null);
    try std.testing.expectEqual(State.Outcome.rejected, try w.st.applyStatus(t.txid, "MINED", try soloPath(a, 2, t.txid)));
    try std.testing.expect(try w.st.map("parked").has(&t.txid));
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), t.txid, 1_700_001_200)});
    try std.testing.expectEqual(lib.state.Status.proven, try w.st.status(t.txid));
    try std.testing.expect(!(try w.st.map("parked").has(&t.txid)));
}

test "0.21.0 a path whose subject is proven already still links what it newly covers; covering nothing new, nothing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var z = try pairWorld(a, ms.store());
    _ = try z.w.st.ingest(try beefOf(a, &.{.{ z.w.fund, 1 }}, &.{z.p}));
    // P's path (X its sibling); then the same path again, flagged differently: nothing new.
    const n0 = z.w.st.linked.items.len; // the funding, linked at its ingest
    _ = try z.w.st.applyStatus(z.p.txid, "MINED", try pairBytes(a, 2, z.p.txid, z.x.txid, true, false));
    try std.testing.expectEqual(n0 + 2, z.w.st.linked.items.len);
    const s1 = try z.w.st.save();
    var st2 = try State.load(a, ms.store(), s1, .regtest);
    _ = try st2.applyStatus(z.p.txid, "MINED", try pairBytes(a, 2, z.p.txid, z.x.txid, true, true));
    try std.testing.expectEqual(@as(usize, 0), st2.linked.items.len);
    try std.testing.expectEqualStrings(s1, try st2.save());
}

test "0.21.0 a compound path for a proven subject links its other leaves (a four-leaf block, P proven by its own path, then a path naming all four)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const p = try spend(a, &w.fund.tx, 0, 9_000);
    const l: [4][32]u8 = .{ p.txid, .{0x21} ** 32, .{0x22} ** 32, .{0x23} ** 32 };
    const n0 = lib.store.dblSha256(&(l[0] ++ l[1]));
    const n1 = lib.store.dblSha256(&(l[2] ++ l[3]));
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), lib.store.dblSha256(&(n0 ++ n1)), 1_700_001_200)});
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{p}));
    const k0 = w.st.linked.items.len; // the funding
    _ = try w.st.applyStatus(p.txid, "MINED", try path4(a, 2, l, 0)); // P and its sibling 1
    try std.testing.expectEqual(k0 + 2, w.st.linked.items.len);
    const s1 = try w.st.save();
    // The same block's path for leaf 2 names 2 and 3: P is proven already; 2 and 3 are new.
    var st2 = try State.load(a, ms.store(), s1, .regtest);
    try st2.putProof(l[2], try bsvz.spv.MerklePath.parse(a, try path4(a, 2, l, 2)));
    try std.testing.expectEqual(@as(usize, 2), st2.linked.items.len);
    // Through addPath (a proof event for P carrying a compound path): still links what is new.
    var st3 = try State.load(a, ms.store(), s1, .regtest);
    const PE = std.meta.Elem(std.meta.Elem(@FieldType(bsvz.spv.MerklePath, "path")));
    const levels = try a.alloc([]PE, 2);
    levels[0] = try a.dupe(PE, &.{ .{ .offset = 0, .hash = .{ .bytes = l[0] }, .txid = true }, .{ .offset = 1, .hash = .{ .bytes = l[1] } }, .{ .offset = 2, .hash = .{ .bytes = l[2] } }, .{ .offset = 3, .hash = .{ .bytes = l[3] } } });
    levels[1] = try a.dupe(PE, &.{});
    const compound: bsvz.spv.MerklePath = .{ .block_height = 2, .path = levels };
    _ = try st3.applyStatus(p.txid, "MINED", try compound.bytes(a));
    try std.testing.expectEqual(@as(usize, 2), st3.linked.items.len);
    try std.testing.expect(linkedHas(&st3, l[2]) and linkedHas(&st3, l[3]));
}

test "0.21.0 a leaf with no sibling path is not linked; an inconsistent node refuses the path, nothing linked" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const l: [4][32]u8 = .{ .{0x31} ** 32, .{0x32} ** 32, .{0x33} ** 32, .{0x34} ** 32 };
    const n0 = lib.store.dblSha256(&(l[0] ++ l[1]));
    const n1 = lib.store.dblSha256(&(l[2] ++ l[3]));
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), lib.store.dblSha256(&(n0 ++ n1)), 1_700_001_200)});
    const PE = std.meta.Elem(std.meta.Elem(@FieldType(bsvz.spv.MerklePath, "path")));
    // Leaf 2 with its sibling 3 and n0 above; leaf 0 given alone (no sibling 1): 0 is not reached.
    var levels = try a.alloc([]PE, 2);
    levels[0] = try a.dupe(PE, &.{ .{ .offset = 0, .hash = .{ .bytes = l[0] } }, .{ .offset = 2, .hash = .{ .bytes = l[2] }, .txid = true }, .{ .offset = 3, .hash = .{ .bytes = l[3] } } });
    levels[1] = try a.dupe(PE, &.{.{ .offset = 0, .hash = .{ .bytes = n0 } }});
    try w.st.putProof(l[2], .{ .block_height = 2, .path = levels });
    try std.testing.expectEqual(@as(usize, 2), w.st.linked.items.len);
    try std.testing.expect(!linkedHas(&w.st, l[0]));
    // A node given that conflicts with the one its children make: refused, nothing linked.
    var st2 = try State.load(a, ms.store(), null, .regtest);
    _ = try st2.addHeaders(&.{ &w.h1, &mine(hdr.hash(&w.h1), lib.store.dblSha256(&(n0 ++ n1)), 1_700_001_200) });
    levels = try a.alloc([]PE, 2);
    levels[0] = try a.dupe(PE, &.{ .{ .offset = 0, .hash = .{ .bytes = l[0] }, .txid = true }, .{ .offset = 1, .hash = .{ .bytes = l[1] } }, .{ .offset = 2, .hash = .{ .bytes = l[2] } }, .{ .offset = 3, .hash = .{ .bytes = l[3] } } });
    levels[1] = try a.dupe(PE, &.{.{ .offset = 1, .hash = .{ .bytes = .{9} ** 32 } }});
    try std.testing.expectError(error.BadProof, st2.putProof(l[0], .{ .block_height = 2, .path = levels }));
    try std.testing.expectEqual(@as(usize, 0), st2.linked.items.len);
}

test "0.21.0 an unheld X linked in block A; A reorged out; X arrives — pending, registered; relinked in block B — listed again, mined" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var z = try pairWorld(a, ms.store());
    _ = try z.w.st.ingest(try beefOf(a, &.{.{ z.w.fund, 1 }}, &.{z.p}));
    _ = try z.w.st.applyStatus(z.p.txid, "MINED", try pairBytes(a, 2, z.p.txid, z.x.txid, true, false));
    try std.testing.expect(linkedHas(&z.w.st, z.x.txid));
    // A heavier branch without block 2: the block listed; X unheld is skipped by its step.
    const alt2 = mine(hdr.hash(&z.w.h1), .{3} ** 32, 1_700_001_201);
    const alt3 = mine(hdr.hash(&alt2), .{4} ** 32, 1_700_001_202);
    _ = try z.w.st.addHeaders(&.{ &alt2, &alt3 });
    try std.testing.expectEqual(@as(usize, 1), z.w.st.blocks.items.len);
    const moved = try z.w.st.blockChanged(z.w.st.blocks.items[0].hash, 2);
    try std.testing.expectEqual(@as(usize, 1), moved.len); // P only
    const s1 = try z.w.st.save();
    // X arrives: its linkage's block is off our chain — pending, registered.
    var st2 = try State.load(a, ms.store(), s1, .regtest);
    const g = try st2.ingest(try beefWith(a, z.x.txid, &.{}, &.{ .{ .txid = z.p.txid, .format = .txid_only }, .{ .txid = z.x.txid, .format = .raw, .raw = z.x.raw, .tx = z.x.tx } }));
    try std.testing.expectEqual(lib.state.Status.unproven, try st2.status(z.x.txid));
    try std.testing.expectEqual(@as(usize, 1), g.registered.len);
    // Mined again in block 4 (P and X): X linked again, at the new block.
    const alt4 = mine(hdr.hash(&alt3), pairRoot(z.p.txid, z.x.txid), 1_700_001_203);
    _ = try st2.addHeaders(&.{&alt4});
    _ = try st2.applyStatus(z.p.txid, "MINED", try pairBytes(a, 4, z.p.txid, z.x.txid, true, false));
    try std.testing.expect(linkedHas(&st2, z.x.txid));
    try std.testing.expectEqual(lib.state.Status.proven, try st2.status(z.x.txid));
}

test "0.21.0 reorg out and back: the block leaves (listed inactive), comes back (listed active) — its transaction proven again by its step" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();
    const fund = try funding(a, 1);
    const h1 = mine(hdr.hash(&lib.chain.Network.regtest.genesis()), fund.txid, 1_700_000_600);
    const child = try spend(a, &fund.tx, 0, 9_000);
    const h2 = mine(hdr.hash(&h1), child.txid, 1_700_001_200);
    const host2 = try hostAdd(a, s, null, &.{ &h1, &h2 });
    var st = try State.load(a, s, null, .regtest);
    _ = try st.pointAt(host2);
    try std.testing.expectEqual(@as(usize, 0), st.blocks.items.len); // the first pointing changes nothing linked
    _ = try st.ingest(try beefOf(a, &.{ .{ fund, 1 }, .{ child, 2 } }, &.{}));
    const s1 = try st.save();
    // Out: a heavier branch from 1.
    const alt2 = mine(hdr.hash(&h1), .{3} ** 32, 1_700_001_201);
    const alt3 = mine(hdr.hash(&alt2), .{4} ** 32, 1_700_001_202);
    const hostB = try hostAdd(a, s, null, &.{ &h1, &alt2, &alt3 });
    var st2 = try State.load(a, s, s1, .regtest);
    _ = try st2.pointAt(hostB);
    try std.testing.expectEqual(@as(usize, 1), st2.blocks.items.len);
    try std.testing.expect(!st2.blocks.items[0].active);
    const out = try st2.blockChanged(st2.blocks.items[0].hash, st2.blocks.items[0].height);
    try std.testing.expect(!out[0].proven);
    try std.testing.expect((try st2.broadcastRecord(child.txid)) != null);
    const s2 = try st2.save();
    // Back: the first branch, heavier again.
    const h3 = mine(hdr.hash(&h2), .{5} ** 32, 1_700_001_203);
    const h4 = mine(hdr.hash(&h3), .{6} ** 32, 1_700_001_204);
    const hostA = try hostAdd(a, s, null, &.{ &h1, &h2, &h3, &h4 });
    var st3 = try State.load(a, s, s2, .regtest);
    _ = try st3.pointAt(hostA);
    try std.testing.expectEqual(@as(usize, 1), st3.blocks.items.len);
    try std.testing.expect(st3.blocks.items[0].active);
    const back = try st3.blockChanged(st3.blocks.items[0].hash, st3.blocks.items[0].height);
    try std.testing.expect(back[0].proven);
    try std.testing.expectEqual(lib.state.Status.proven, try st3.status(child.txid));
    try std.testing.expect((try st3.broadcastRecord(child.txid)) == null);
}

// ------------------------------------------------------------ 0.21.0 review fixes

test "0.21.0 one height row per linkage: P, X in B2; reorg out; B4 = {P, C}; a second reorg from 2 lists B4 at height 4 — P and C both re-read; B2 not listed again" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var z = try pairWorld(a, ms.store());
    _ = try z.w.st.ingest(try beefOf(a, &.{.{ z.w.fund, 1 }}, &.{ z.p, z.x }));
    _ = try z.w.st.applyStatus(z.p.txid, "MINED", try pairBytes(a, 2, z.p.txid, z.x.txid, true, false));
    try z.w.st.settleProven(z.p.txid);
    try z.w.st.settleProven(z.x.txid);
    // First reorg: B2 out.
    const alt2 = mine(hdr.hash(&z.w.h1), .{3} ** 32, 1_700_001_201);
    const alt3 = mine(hdr.hash(&alt2), .{4} ** 32, 1_700_001_202);
    _ = try z.w.st.addHeaders(&.{ &alt2, &alt3 });
    try std.testing.expectEqual(@as(usize, 1), z.w.st.blocks.items.len);
    for (try z.w.st.blockChanged(z.w.st.blocks.items[0].hash, 2)) |_| {}
    const s1 = try z.w.st.save();
    // C (X's child) held; B4 = {P, C} at height 4 links P again (its row moves) and C.
    var st2 = try State.load(a, ms.store(), s1, .regtest);
    _ = try st2.ingest(try beefWith(a, z.c.txid, &.{}, &.{ .{ .txid = z.x.txid, .format = .txid_only }, .{ .txid = z.c.txid, .format = .raw, .raw = z.c.raw, .tx = z.c.tx } }));
    const b4 = mine(hdr.hash(&alt3), pairRoot(z.p.txid, z.c.txid), 1_700_001_203);
    _ = try st2.addHeaders(&.{&b4});
    _ = try st2.applyStatus(z.p.txid, "MINED", try pairBytes(a, 4, z.p.txid, z.c.txid, true, false));
    try std.testing.expect(!(try st2.map("proofHeights").has(&(lib.store.be32(2) ++ z.p.txid)))); // the stale row gone
    try std.testing.expect(try st2.map("proofHeights").has(&(lib.store.be32(4) ++ z.p.txid)));
    try std.testing.expectEqual(@as(?u32, 4), try st2.proofHeight(z.p.txid));
    try st2.settleProven(z.p.txid);
    try st2.settleProven(z.c.txid);
    const s2 = try st2.save();
    // Second reorg from height 2: B4 leaves — listed at ITS height 4; B2, off our chain already, not listed.
    var st3 = try State.load(a, ms.store(), s2, .regtest);
    var run: [4][80]u8 = undefined;
    var prev = hdr.hash(&z.w.h1);
    for (&run, 0..) |*r, i| {
        r.* = mine(prev, .{@as(u8, @intCast(0x50 + i))} ** 32, 1_700_002_000 + @as(u32, @intCast(i)));
        prev = hdr.hash(r);
    }
    _ = try st3.addHeaders(&.{ &run[0], &run[1], &run[2], &run[3] });
    try std.testing.expectEqual(@as(usize, 1), st3.blocks.items.len);
    try std.testing.expectEqualSlices(u8, &hdr.hash(&b4), &st3.blocks.items[0].hash);
    try std.testing.expectEqual(@as(u32, 4), st3.blocks.items[0].height);
    try std.testing.expect(!st3.blocks.items[0].active);
    const moved = try st3.blockChanged(st3.blocks.items[0].hash, st3.blocks.items[0].height);
    try std.testing.expectEqual(@as(usize, 2), moved.len); // P and C
    try std.testing.expect(try st3.map("unproven").has(&z.c.txid));
    try std.testing.expect((try st3.broadcastRecord(z.c.txid)) != null);
}

test "0.21.0 parked: a path at a future height whose root is not the block's — dropped when the header comes, later headers fine; a malformed path is refused, never parked" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const t = try spend(a, &w.fund.tx, 0, 9_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{t}));
    // A path for t at height 3 (no header yet): parked.
    try std.testing.expectEqual(State.Outcome.accepted, try w.st.applyStatus(t.txid, "MINED", try soloPath(a, 3, t.txid)));
    try std.testing.expect(try w.st.map("parked").has(&t.txid));
    // The chain reaches 3 with another block (an orphaned block's path, or a bogus root): dropped.
    const h2 = mine(hdr.hash(&w.h1), .{7} ** 32, 1_700_001_200);
    const h3 = mine(hdr.hash(&h2), .{8} ** 32, 1_700_001_201);
    _ = try w.st.addHeaders(&.{ &h2, &h3 });
    try std.testing.expect(!(try w.st.map("parked").has(&t.txid)));
    try std.testing.expectEqual(lib.state.Status.unproven, try w.st.status(t.txid));
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&h3), .{9} ** 32, 1_700_001_202)}); // not wedged
    // A malformed path (its leaf not under its root: two leaves, the subject absent): BadProof at once.
    try std.testing.expectError(error.BadProof, w.st.applyStatus(t.txid, "MINED", try (try pairPath(a, 9, .{1} ** 32, .{2} ** 32, true, false)).bytes(a)));
    try std.testing.expect(!(try w.st.map("parked").has(&t.txid)));
}

test "0.21.0 a proof landing between a reorg and its block step: T re-linked in B, its watchers kept, mined once" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const t = try spend(a, &w.fund.tx, 0, 9_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{t}));
    try w.st.watch(t.txid, &caller, "chain", &request);
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), t.txid, 1_700_001_200)});
    _ = try w.st.applyStatus(t.txid, "MINED", try soloPath(a, 2, t.txid));
    try w.st.settleProven(t.txid); // the watchers move onto the linkage
    try std.testing.expectEqual(@as(usize, 1), (try w.st.settledWatchers(t.txid)).?.len);
    const s1 = try w.st.save();
    // Reorg: block A (2) leaves; the heavier branch's block 3 holds T; T's proof in it arrives
    // before A's block step.
    var st2 = try State.load(a, ms.store(), s1, .regtest);
    const alt2 = mine(hdr.hash(&w.h1), .{3} ** 32, 1_700_001_201);
    const alt3 = mine(hdr.hash(&alt2), t.txid, 1_700_001_202);
    _ = try st2.addHeaders(&.{ &alt2, &alt3 });
    const a_block = st2.blocks.items[0];
    _ = try st2.applyStatus(t.txid, "MINED", try soloPath(a, 3, t.txid));
    try std.testing.expectEqual(lib.state.Status.proven, try st2.status(t.txid));
    try std.testing.expectEqual(@as(usize, 1), (try st2.settledWatchers(t.txid)).?.len); // kept
    // A's block step: T is no longer linked to A: nothing to re-read.
    try std.testing.expectEqual(@as(usize, 0), (try st2.blockChanged(a_block.hash, a_block.height)).len);
    try st2.settleProven(t.txid); // T's proof step
    try std.testing.expect((try st2.broadcastRecord(t.txid)) == null);
}

test "0.21.0 a parent rejected earlier whose child is proven later: the rejection is lifted (unproven, broadcast again), not made mined" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const p = try spend(a, &w.fund.tx, 0, 9_000);
    const x = try spend(a, &p.tx, 0, 8_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ p, x }));
    _ = try w.st.applyStatus(p.txid, "REJECTED", null);
    try std.testing.expectEqual(lib.state.Status.rejected, try w.st.status(p.txid));
    // X proven (alone in block 2): its parent is mined in fact; we hold no path for P.
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), x.txid, 1_700_001_200)});
    _ = try w.st.applyStatus(x.txid, "MINED", try soloPath(a, 2, x.txid));
    try std.testing.expectEqual(lib.state.Reexamined.revived, try w.st.reexamine(p.txid)); // X's fact steps P (`children`)
    try std.testing.expectEqual(lib.state.Status.unproven, try w.st.status(p.txid));
    try std.testing.expect((try w.st.broadcastRecord(p.txid)) != null);
    try std.testing.expectEqual(@as(usize, 1), w.st.revived.items.len);
    try std.testing.expect((try w.st.proofBlock(p.txid)) == null); // no linkage invented
}
