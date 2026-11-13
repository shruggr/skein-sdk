//! skein next (SPEC 6): the chain app's BEEF check (`chain.beef`) and its recording in the step
//! (`State.ingestChecked`) together, over one store standing in for the instance's: a valid BEEF is
//! proved once, at the check, and recorded without proving again — the same chain state as a full
//! `ingest` of the same bytes; a BEEF missing a source is refused with nothing stored.
const std = @import("std");
const cbor = @import("cbor");
const chain = @import("chain");
const check = @import("check.zig");
const bsvz = chain.bsvz;
const hdr = chain.header;
const State = chain.state.State;

fn mine(prev: [32]u8, merkle_root: [32]u8, time: u32) [80]u8 {
    var h = hdr.Header{ .version = 1, .prev_hash = prev, .merkle_root = merkle_root, .time = time, .bits = 0x207fffff, .nonce = 0 };
    while (true) : (h.nonce += 1) {
        const raw = h.serialize();
        if (hdr.powOk(&raw)) return raw;
    }
}

fn soloPath(a: std.mem.Allocator, height: u32, txid: [32]u8) ![]const u8 {
    var path: std.ArrayList(u8) = .empty;
    try path.appendSlice(a, &.{ 0xfd, 0, 0, 0x01, 0x01, 0x00, 0x02 });
    std.mem.writeInt(u16, path.items[1..3], @intCast(height), .little);
    try path.appendSlice(a, &txid);
    return path.items;
}

const priv: [32]u8 = .{0x11} ** 32;

fn script(a: std.mem.Allocator) ![]u8 {
    const pk = (try (try bsvz.primitives.ec.PrivateKey.fromBytes(priv)).publicKey()).toCompressedSec1();
    var s: [25]u8 = undefined;
    s[0..3].* = .{ 0x76, 0xa9, 0x14 };
    s[3..23].* = bsvz.crypto.hash.hash160(&pk).bytes;
    s[23..25].* = .{ 0x88, 0xac };
    return a.dupe(u8, &s);
}

const Tx = struct { tx: bsvz.transaction.Transaction, raw: []const u8, txid: [32]u8 };

fn funding(a: std.mem.Allocator) !Tx {
    var raw: std.ArrayList(u8) = .empty;
    try raw.appendSlice(a, &.{ 1, 0, 0, 0, 1 });
    try raw.appendSlice(a, &([_]u8{0x72} ** 32));
    try raw.appendSlice(a, &.{ 0, 0, 0, 0, 1, 0x51, 0xff, 0xff, 0xff, 0xff, 1 });
    var sats: [8]u8 = undefined;
    std.mem.writeInt(u64, &sats, 10_000, .little);
    try raw.appendSlice(a, &sats);
    try raw.append(a, 25);
    try raw.appendSlice(a, try script(a));
    try raw.appendSlice(a, &.{ 0, 0, 0, 0 });
    return .{ .tx = try bsvz.transaction.Transaction.parse(a, raw.items), .raw = raw.items, .txid = chain.beef.txidOf(raw.items) };
}

fn spend(a: std.mem.Allocator, src: *const bsvz.transaction.Transaction) !Tx {
    var b = bsvz.transaction.Builder.init(a);
    try b.addInputFromTx(src, 0);
    try b.addOutput(.{ .satoshis = 9_000, .locking_script = bsvz.script.Script.init(try script(a)) });
    var tx = try b.build();
    const prev = src.outputs[0];
    const sp = bsvz.transaction.templates.p2pkh_spend;
    @constCast(tx.inputs)[0].unlocking_script = try sp.signAndBuildUnlockingScript(a, &tx, 0, prev.locking_script, prev.satoshis, try bsvz.crypto.PrivateKey.fromBytes(priv), sp.default_scope);
    const raw = try tx.serialize(a);
    return .{ .tx = tx, .raw = raw, .txid = chain.beef.txidOf(raw) };
}

/// The instance's store (chain's MemStore) as the check reads it.
fn reader(ms: *chain.store.MemStore) check.Reader {
    const G = struct {
        fn get(ctx: *anyopaque, a: std.mem.Allocator, c: []const u8) anyerror!?[]u8 {
            const m: *chain.store.MemStore = @ptrCast(@alignCast(ctx));
            const b = m.store().tryGet(a, c) orelse return null;
            return try a.dupe(u8, b);
        }
    };
    return .{ .ctx = ms, .get = G.get };
}

fn request(a: std.mem.Allocator, body: []const u8) !cbor.Value {
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

const World = struct { ms: chain.store.MemStore, state: []const u8, beef: []const u8 };

/// A regtest chain to 1 whose block holds the funding alone; the chain state knowing the header;
/// the BEEF {funding proven, child unproven}.
fn world(a: std.mem.Allocator) !World {
    var ms = chain.store.MemStore.init(std.testing.allocator);
    const f = try funding(a);
    const child = try spend(a, &f.tx);
    var st = try State.load(a, ms.store(), null, .regtest);
    _ = try st.addHeaders(&.{&mine(hdr.hash(&chain.chain.Network.regtest.genesis()), f.txid, 1_700_000_600)});
    const state = try st.save();
    const bumps = try a.dupe(bsvz.spv.MerklePath, &.{try bsvz.spv.MerklePath.parse(a, try soloPath(a, 1, f.txid))});
    const b = try chain.beef.serialize(a, .{ .version = chain.beef.V2, .atomic = child.txid, .bumps = bumps, .entries = try a.dupe(chain.beef.Entry, &.{
        .{ .txid = f.txid, .format = .raw_with_bump, .bump = 0, .raw = f.raw, .tx = f.tx },
        .{ .txid = child.txid, .format = .raw, .raw = child.raw, .tx = child.tx },
    }) });
    return .{ .ms = ms, .state = state, .beef = b };
}

test "skein next: a valid BEEF proved once at the check and recorded without proving again — the same chain state as a full ingest of the bytes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var w = try world(a);
    defer w.ms.deinit();

    const calls0 = chain.spv.calls;
    const out = try check.check(a, reader(&w.ms), w.state, try request(a, w.beef));
    try std.testing.expect(out.refused == null);
    try std.testing.expectEqual(calls0 + 1, chain.spv.calls); // the check proved it
    // COMMIT writes the blocks the check named.
    for (out.blocks) |b| try w.ms.store().putBlock(b.cid, b.bytes);
    // The step: the envelope (as the chain app reads the stored record) recorded without spv.verify.
    const env_bytes = try cbor.encode(a, out.package.get("payload").?.get("body").?);
    const env = try chain.cbor.decode(a, env_bytes);
    var st = try State.load(a, w.ms.store(), w.state, .regtest);
    st.now = 5;
    const got = try st.ingestChecked(env);
    try std.testing.expectEqual(calls0 + 1, chain.spv.calls); // not proved again
    try std.testing.expectEqual(chain.state.Status.unproven, got.status);
    try std.testing.expectEqual(@as(usize, 1), got.registered.len);
    const checked_state = try st.save();

    // The same bytes through a full ingest: verified (one more call), the same state.
    var st2 = try State.load(a, w.ms.store(), w.state, .regtest);
    st2.now = 5;
    _ = try st2.ingest(w.beef);
    try std.testing.expectEqual(calls0 + 2, chain.spv.calls);
    try std.testing.expectEqualStrings(try st2.save(), checked_state);
}

test "skein next: a BEEF whose child lacks its source is refused at the check — nothing named to store" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var w = try world(a);
    defer w.ms.deinit();
    const f = try funding(a);
    const child = try spend(a, &f.tx);
    const lone = try chain.beef.serialize(a, .{ .version = chain.beef.V2, .atomic = child.txid, .bumps = &.{}, .entries = try a.dupe(chain.beef.Entry, &.{.{ .txid = child.txid, .format = .raw, .raw = child.raw, .tx = child.tx }}) });
    const before = w.ms.count();
    const out = try check.check(a, reader(&w.ms), w.state, try request(a, lone));
    try std.testing.expect(out.refused != null);
    try std.testing.expect(std.mem.startsWith(u8, out.refused.?, "MissingInput"));
    try std.testing.expectEqual(@as(usize, 0), out.blocks.len);
    try std.testing.expectEqual(before, w.ms.count());
}
