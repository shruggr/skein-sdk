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
    try std.testing.expect((try w.st.broadcastRecord(child.txid)).?.getBytes("path") != null);
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), child.txid, 1_700_001_200)});
    try std.testing.expectEqual(lib.state.Status.proven, try w.st.status(child.txid));
    try std.testing.expectEqual(@as(usize, 2), w.st.changes.items.len);
    try std.testing.expectEqual(.proven, w.st.changes.items[1].state);
    try std.testing.expectEqual(@as(usize, 1), w.st.changes.items[1].watchers.len);
    try std.testing.expect((try w.st.broadcastRecord(child.txid)) == null);
    try std.testing.expect(!(try w.st.map("unproven").has(&child.txid)));
    _ = try w.st.save();
}

test "a rejection walks the spends; a proven competing spend is a double spend; abandonment" {
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

    // A rejected: B with it (input-rejected); the funding's output free again.
    w.st.now = 5000;
    try std.testing.expectEqual(State.Outcome.rejected, try w.st.applyStatus(ta.txid, "REJECTED", null));
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
    try std.testing.expectEqual(lib.state.Status.rejected, try st2.status(ta.txid));
    try std.testing.expectEqualStrings("double-spent", (try st2.record((try st2.settlementCid(ta.txid)).?)).getText("reason").?);
    try std.testing.expectEqualSlices(u8, &other.txid, &(try st2.spentBy(w.fund.txid, 0)).?);
    // Ingesting A again now: rejected at once.
    const g3 = try st2.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{ta}));
    try std.testing.expectEqual(lib.state.Status.rejected, g3.status);

    // Never mined in time: abandoned.
    var st3 = try State.load(a, ms.store(), base, .regtest);
    st3.now = 3_600_000 - 1;
    try std.testing.expect(!(try st3.abandonIfDue(ta.txid, 3_600_000)));
    st3.now = 3_600_000;
    try std.testing.expect(try st3.abandonIfDue(ta.txid, 3_600_000));
    try std.testing.expectEqualStrings("abandoned", (try st3.record((try st3.settlementCid(ta.txid)).?)).getText("reason").?);
}

test "a reorg turns a proven transaction back to unproven: its broadcast registered again" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try world(a, ms.store(), 1);
    const child = try spend(a, &w.fund.tx, 0, 9_000);
    _ = try w.st.ingest(try beefOf(a, &.{.{ w.fund, 1 }}, &.{child}));
    _ = try w.st.addHeaders(&.{&mine(hdr.hash(&w.h1), child.txid, 1_700_001_200)});
    try std.testing.expectEqual(State.Outcome.proven, try w.st.applyStatus(child.txid, "MINED", try soloPath(a, 2, child.txid)));
    const proven = try w.st.save();
    var st2 = try State.load(a, ms.store(), proven, .regtest);
    const alt1 = mine(hdr.hash(&w.h1), .{3} ** 32, 1_700_001_201);
    const alt2 = mine(hdr.hash(&alt1), .{4} ** 32, 1_700_001_202);
    try std.testing.expectEqual(@as(u32, 1), (try st2.addHeaders(&.{ &alt1, &alt2 })).replaced);
    try std.testing.expectEqual(lib.state.Status.unproven, try st2.status(child.txid));
    try std.testing.expectEqual(@as(usize, 1), st2.reverted.items.len);
    try std.testing.expect((try st2.broadcastRecord(child.txid)) != null);
    try std.testing.expect(try st2.map("unproven").has(&child.txid));
    _ = try st2.save();
}
