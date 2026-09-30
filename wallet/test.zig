//! The vector corpus (vectors/*.json, made by go-sdk and cross-checked with
//! the TS toolbox) run against wallet-zig and bsvz, plus the wallet's
//! record-level behaviour. Vectors are embedded, so the wasm32-wasi build
//! needs no filesystem.
const std = @import("std");
const bsvz = @import("bsvz");
const lib = @import("src/lib.zig");

const hdr = lib.header;
const beef = lib.beef;
const J = std.json.Value;

test {
    _ = lib;
}

/// Counts of vector checks, printed at the end of the run.
var counts = struct { sign: usize = 0, tx: usize = 0, fee: usize = 0, beef: usize = 0, path: usize = 0, header: usize = 0, brc29: usize = 0, wire: usize = 0, wallet: usize = 0, chronicle: usize = 0 }{};

fn load(arena: std.mem.Allocator, comptime name: []const u8) !J {
    return std.json.parseFromSliceLeaky(J, arena, @embedFile("vectors/" ++ name), .{});
}
fn str(v: J, key: []const u8) []const u8 {
    return v.object.get(key).?.string;
}
fn int(v: J, key: []const u8) i64 {
    return v.object.get(key).?.integer;
}
fn arr(v: J, key: []const u8) []J {
    return v.object.get(key).?.array.items;
}
fn boolean(v: J, key: []const u8) bool {
    return v.object.get(key).?.bool;
}
fn unhex(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try arena.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}
fn hexOf(arena: std.mem.Allocator, b: []const u8) ![]u8 {
    const out = try arena.alloc(u8, b.len * 2);
    const chars = "0123456789abcdef";
    for (b, 0..) |x, i| {
        out[2 * i] = chars[x >> 4];
        out[2 * i + 1] = chars[x & 15];
    }
    return out;
}
fn key33(s: []const u8) ![33]u8 {
    var k: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&k, s);
    return k;
}
fn key32(s: []const u8) ![32]u8 {
    var k: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&k, s);
    return k;
}

// ---------------------------------------------------------------- transactions + fees

test "vectors: tx serialization, txid, fee (go-sdk)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = try load(a, "tx.json");
    for (arr(v, "cases")) |c| {
        const raw = try unhex(a, str(c, "hex"));
        const tx = try bsvz.transaction.Transaction.parse(a, raw);
        try std.testing.expectEqualStrings(str(c, "txid"), &hdr.toHex(beef.txidOf(raw)));
        try std.testing.expectEqualStrings(str(c, "txid"), &hdr.toHex((try tx.txid(a)).bytes));
        try std.testing.expectEqualSlices(u8, raw, try tx.serialize(a));
        try std.testing.expectEqual(@as(usize, @intCast(int(c, "size"))), tx.serializedLen());
        try std.testing.expectEqual(@as(i64, int(c, "version")), tx.version);
        try std.testing.expectEqual(@as(u32, @intCast(int(c, "lockTime"))), tx.lock_time);
        const ins = arr(c, "inputs");
        try std.testing.expectEqual(ins.len, tx.inputs.len);
        for (ins, tx.inputs) |ji, ti| {
            try std.testing.expectEqualStrings(str(ji, "sourceTxid"), &hdr.toHex(ti.previous_outpoint.txid.bytes));
            try std.testing.expectEqual(@as(u32, @intCast(int(ji, "sourceVout"))), ti.previous_outpoint.index);
            try std.testing.expectEqual(@as(u32, @intCast(int(ji, "sequence"))), ti.sequence);
            try std.testing.expectEqualStrings(str(ji, "unlockingScript"), try hexOf(a, ti.unlocking_script.bytes));
        }
        const outs = arr(c, "outputs");
        try std.testing.expectEqual(outs.len, tx.outputs.len);
        for (outs, tx.outputs) |jo, to| {
            try std.testing.expectEqual(@as(i64, int(jo, "satoshis")), to.satoshis);
            try std.testing.expectEqualStrings(str(jo, "lockingScript"), try hexOf(a, to.locking_script.bytes));
        }
        for (arr(c, "fees")) |f| {
            const model = bsvz.transaction.fee_model.SatoshisPerKilobyte{ .satoshis = @intCast(int(f, "satsPerKb")) };
            try std.testing.expectEqual(@as(u64, @intCast(int(f, "fee"))), try model.computeFee(&tx));
            counts.fee += 1;
        }
        counts.tx += 1;
    }
}

// ---------------------------------------------------------------- BEEF

fn byTxid(_: void, x: beef.Entry, y: beef.Entry) bool {
    return std.mem.lessThan(u8, &hdr.toHex(x.txid), &hdr.toHex(y.txid));
}

fn checkBeefContent(a: std.mem.Allocator, c: J, b: beef.Beef) !void {
    try std.testing.expectEqualStrings(str(c, "version"), if (b.version == beef.V1) "v1" else "v2");
    try std.testing.expectEqual(boolean(c, "atomic"), b.atomic != null);
    if (c.object.get("subjectTxid")) |s| if (b.atomic != null) try std.testing.expectEqualStrings(s.string, &hdr.toHex(b.subject().?));
    const bumps = arr(c, "bumps");
    try std.testing.expectEqual(bumps.len, b.bumps.len);
    for (bumps, b.bumps) |jb, p| {
        try std.testing.expectEqual(@as(u32, @intCast(int(jb, "blockHeight"))), p.block_height);
        try std.testing.expectEqualStrings(str(jb, "hex"), try hexOf(a, try p.bytes(a)));
    }
    const sorted = try a.dupe(beef.Entry, b.entries);
    std.sort.pdq(beef.Entry, sorted, {}, byTxid);
    const txs = arr(c, "txs");
    try std.testing.expectEqual(txs.len, sorted.len);
    for (txs, sorted) |jt, e| {
        try std.testing.expectEqualStrings(str(jt, "txid"), &hdr.toHex(e.txid));
        const f = str(jt, "format");
        try std.testing.expectEqualStrings(f, switch (e.format) {
            .raw => "raw",
            .raw_with_bump => "rawWithBump",
            .txid_only => "txidOnly",
        });
        if (jt.object.get("bumpIndex")) |bi| try std.testing.expectEqual(@as(usize, @intCast(bi.integer)), e.bump.?);
    }
}

test "vectors: BEEF parse, serialize, validity (go-sdk, @bsv/sdk)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = try load(a, "beef.json");
    for (arr(v, "cases")) |c| {
        const raw = try unhex(a, str(c, "hex"));
        const b = try beef.parse(a, raw);
        try checkBeefContent(a, c, b);
        // Serialize keeps the writer's order: byte for byte.
        try std.testing.expectEqualSlices(u8, raw, try beef.serialize(a, b));
        try std.testing.expect(beef.parentsFirst(b));
        try std.testing.expectEqual(boolean(c, "valid"), try lib.spv.structurallyValid(a, b, false));
        try std.testing.expectEqual(boolean(c, "validTxidOnly"), try lib.spv.structurallyValid(a, b, true));
        // go-sdk's reserialization (its own order) holds the same content and is parents-first.
        const re = try beef.parse(a, try unhex(a, str(c, "reserialized")));
        try checkBeefContentLoose(a, c, re);
        try std.testing.expect(beef.parentsFirst(re));
        counts.beef += 1;
    }
    for (arr(v, "damaged")) |d| {
        const b = try beef.parse(a, try unhex(a, str(d, "hex")));
        try std.testing.expectEqual(boolean(d, "valid"), try lib.spv.structurallyValid(a, b, false));
        try std.testing.expectEqual(boolean(d, "validTxidOnly"), try lib.spv.structurallyValid(a, b, true));
        counts.beef += 1;
    }
    for (arr(v, "malformed")) |m| {
        try std.testing.expectError(error.InvalidBeef, beef.parse(a, try unhex(a, str(m, "hex"))));
        counts.beef += 1;
    }
}

/// Same content as the vector, ignoring the atomic prefix (go-sdk reserializes the inner BEEF).
fn checkBeefContentLoose(a: std.mem.Allocator, c: J, b: beef.Beef) !void {
    const sorted = try a.dupe(beef.Entry, b.entries);
    std.sort.pdq(beef.Entry, sorted, {}, byTxid);
    const txs = arr(c, "txs");
    try std.testing.expectEqual(txs.len, sorted.len);
    for (txs, sorted) |jt, e| try std.testing.expectEqualStrings(str(jt, "txid"), &hdr.toHex(e.txid));
    try std.testing.expectEqual(arr(c, "bumps").len, b.bumps.len);
}

// ---------------------------------------------------------------- merkle paths

test "vectors: BRC-74 merkle paths and roots against mainnet headers (go-sdk)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = try load(a, "merkle_path.json");
    for (arr(v, "cases")) |c| {
        const p = try bsvz.spv.MerklePath.parse(a, try unhex(a, str(c, "hex")));
        try std.testing.expectEqual(@as(u32, @intCast(int(c, "blockHeight"))), p.block_height);
        try std.testing.expectEqualStrings(str(c, "reserialized"), try hexOf(a, try p.bytes(a)));
        for (arr(c, "leaves")) |l| {
            const root = beef.rootFor(a, p, try hdr.fromHex(str(l, "txid"))) orelse return error.NoRoot;
            try std.testing.expectEqualStrings(str(l, "root"), &hdr.toHex(root));
            counts.path += 1;
        }
    }
    for (arr(v, "headerChecks")) |c| {
        const p = try bsvz.spv.MerklePath.parse(a, try unhex(a, str(c, "bumpHex")));
        const raw = try unhex(a, str(c, "headerHex"));
        const h = try hdr.Header.parse(raw);
        const root = beef.rootFor(a, p, try hdr.fromHex(str(c, "txid"))).?;
        try std.testing.expectEqual(boolean(c, "rootMatches"), std.mem.eql(u8, &root, &h.merkle_root) and p.block_height == @as(u32, @intCast(int(c, "height"))));
        counts.path += 1;
    }
}

// ---------------------------------------------------------------- the merkle tree as IPLD nodes (#29)

/// The merkle nodes a MemStore holds (64-byte bitcoin-tx blocks, #42), as sorted hex CIDs.
fn merkleBlocks(a: std.mem.Allocator, ms: *lib.store.MemStore) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = ms.blocks.iterator();
    while (it.next()) |e| if (e.key_ptr.len == 37 and e.key_ptr.*[1] == 0xb1 and e.value_ptr.len == 64) try out.append(a, try hexOf(a, e.key_ptr.*));
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    return out.items;
}

test "merkle nodes: every vector path's nodes stored; each leaf's BUMP rebuilt from them gives the root" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = try load(a, "merkle_path.json");
    for (arr(v, "cases")) |c| {
        var ms = lib.store.MemStore.init(std.testing.allocator);
        defer ms.deinit();
        const p = try bsvz.spv.MerklePath.parse(a, try unhex(a, str(c, "hex")));
        const rev = try lib.merkle.reveal(a, p);
        try lib.merkle.putNodes(ms.store(), rev.nodes);
        for (arr(c, "leaves")) |l| {
            const txid = try hdr.fromHex(str(l, "txid"));
            try std.testing.expectEqualStrings(str(l, "root"), &hdr.toHex(rev.root));
            const pos = lib.merkle.positionIn(p, txid) orelse return error.NotInPath;
            const rebuilt = (try lib.merkle.pathFor(a, ms.store(), rev.root, p.block_height, txid, pos)) orelse return error.NotRebuilt;
            try std.testing.expectEqual(p.block_height, rebuilt.block_height);
            try std.testing.expectEqualSlices(u8, &rev.root, &(beef.rootFor(a, rebuilt, txid) orelse return error.NoRoot));
            counts.path += 1;
        }
    }
}

/// A block of `n` transactions (synthetic txids): every level of its merkle tree, leaves first.
fn fullTree(a: std.mem.Allocator, leaves: []const [32]u8) ![]const []const [32]u8 {
    var levels: std.ArrayList([]const [32]u8) = .empty;
    try levels.append(a, leaves);
    while (levels.items[levels.items.len - 1].len > 1) {
        const cur = levels.items[levels.items.len - 1];
        const up = try a.alloc([32]u8, (cur.len + 1) / 2);
        for (up, 0..) |*u, i| {
            const l = cur[2 * i];
            const r = if (2 * i + 1 < cur.len) cur[2 * i + 1] else l;
            u.* = lib.store.dblSha256(&(l ++ r));
        }
        try levels.append(a, up);
    }
    return levels.items;
}

/// The minimal BUMP for leaf `i` of a tree (sorted by offset; a missing right sibling is a duplicate).
fn bumpFor(a: std.mem.Allocator, tree: []const []const [32]u8, height: u32, i: u64) !bsvz.spv.MerklePath {
    const PE = std.meta.Elem(std.meta.Elem(@FieldType(bsvz.spv.MerklePath, "path")));
    const h = tree.len - 1;
    const levels = try a.alloc([]PE, h);
    for (levels, 0..) |*lv, k| {
        const so = (i >> @intCast(k)) ^ 1;
        const sib: PE = if (so < tree[k].len) .{ .offset = so, .hash = .{ .bytes = tree[k][@intCast(so)] } } else .{ .offset = so, .duplicate = true };
        if (k == 0) {
            const leaf: PE = .{ .offset = i, .hash = .{ .bytes = tree[0][@intCast(i)] }, .txid = true };
            lv.* = try a.dupe(PE, if (i & 1 == 0) &.{ leaf, sib } else &.{ sib, leaf });
        } else lv.* = try a.dupe(PE, &.{sib});
    }
    return .{ .block_height = height, .path = levels };
}

test "merkle nodes: three transactions of one regtest block, proven by separate BUMPs, in any order: one node set; each BUMP rebuilt" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // Seven transactions (the odd level ends duplicate their last node): prove 1, 4 and 6.
    var leaves: [7][32]u8 = undefined;
    for (&leaves, 0..) |*l, i| l.* = lib.store.dblSha256(&.{ 'l', @as(u8, @intCast(i)) });
    const tree = try fullTree(a, &leaves);
    const root = tree[tree.len - 1][0];
    const chain = try regtestChain(a, 1002, &.{.{ 1002, root }});
    const picks = [_]u64{ 1, 4, 6 };
    var bumps: [3]bsvz.spv.MerklePath = undefined;
    for (&bumps, picks) |*b, i| b.* = try bumpFor(a, tree, 1002, i);
    const orders = [_][3]usize{ .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 }, .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 } };
    var first_nodes: ?[]const []const u8 = null;
    var first_state: ?[]const u8 = null;
    for (orders) |ord| {
        var ms = lib.store.MemStore.init(std.testing.allocator);
        defer ms.deinit();
        var w = try lib.wallet.Wallet.load(a, ms.store(), null, .regtest);
        _ = try w.addHeaders(try slices(a, chain));
        for (ord) |k| try w.putProof(leaves[@intCast(picks[k])], bumps[k]);
        const state = try w.save();
        const nodes = try merkleBlocks(a, &ms);
        if (first_nodes) |f| {
            try std.testing.expectEqual(f.len, nodes.len);
            for (f, nodes) |x, y| try std.testing.expectEqualStrings(x, y);
            try std.testing.expectEqualStrings(first_state.?, state);
        } else {
            first_nodes = nodes;
            first_state = state;
        }
        // Each BUMP rebuilt from the nodes: byte for byte the minimal one, and it proves the header's root.
        for (picks, bumps) |i, b| {
            const got = (try w.proofFor(leaves[@intCast(i)])).?;
            try std.testing.expectEqualStrings(try hexOf(a, try b.bytes(a)), try hexOf(a, try got.bytes(a)));
            try std.testing.expectEqualSlices(u8, &root, &beef.rootFor(a, got, leaves[@intCast(i)]).?);
        }
        try std.testing.expect((try w.proofFor(leaves[0])) == null); // never proven here
        // The proof record holds the leaf's position (#42, decided 2026-09-30): the descent from the
        // root turns by its bits, one node read per level (the tree's depth, 3), no search — and the
        // siblings read are the BUMP, byte for byte.
        for (picks, bumps) |i, b| {
            const rec = (try w.proofRecord(leaves[@intCast(i)])).?;
            try std.testing.expectEqual(lib.merkle.Position{ .depth = 3, .offset = i }, rec.pos);
            var cs = CountingStore{ .inner = ms.store() };
            const got = (try lib.merkle.pathFor(a, cs.store(), root, 1002, leaves[@intCast(i)], rec.pos)).?;
            try std.testing.expectEqual(tree.len - 1, cs.reads);
            try std.testing.expectEqualStrings(try hexOf(a, try b.bytes(a)), try hexOf(a, try got.bytes(a)));
            // Another position is not this transaction's: the descent ends elsewhere (or at a node not held).
            try std.testing.expect((try lib.merkle.pathFor(a, ms.store(), root, 1002, leaves[@intCast(i)], .{ .depth = 3, .offset = i ^ 2 })) == null);
        }
    }
    // Only the paths to the three: the root, the level below it, and the nodes above the three leaves.
    // Levels 7 → 4 → 2 → 1: the leaf pairs of 1, 4, 6 (three nodes), both nodes above them, the root.
    try std.testing.expectEqual(@as(usize, 1 + 2 + 3), first_nodes.?.len);

    // Refusals: a path whose sibling is wrong proves another root; a path that gives a node
    // at a position with another hash than its children make is a conflicting node.
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    var w = try lib.wallet.Wallet.load(a, ms.store(), null, .regtest);
    _ = try w.addHeaders(try slices(a, chain));
    var bad = try bumps[0].clone(a);
    bad.path[1][0].hash.?.bytes[0] ^= 1;
    try std.testing.expectError(error.RootMismatch, w.putProof(leaves[1], bad));
    try std.testing.expectEqual(@as(usize, 0), (try merkleBlocks(a, &ms)).len);
    // Leaves 0 and 1 given, and their parent given too, wrongly: the same position, another hash.
    var conflict = try bumps[0].clone(a);
    const PE = std.meta.Elem(std.meta.Elem(@FieldType(bsvz.spv.MerklePath, "path")));
    conflict.path[1] = try a.dupe(PE, &.{ .{ .offset = 0, .hash = .{ .bytes = .{9} ** 32 } }, conflict.path[1][0] });
    try std.testing.expectError(error.ConflictingNode, lib.merkle.reveal(a, conflict));
    counts.path += 3;
}

// ---------------------------------------------------------------- headers

test "vectors: headers — fields, hash, target, work, PoW, links (go-sdk, go-chaintracks, TS toolbox)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = try load(a, "headers.json");
    const checkOne = struct {
        fn f(al: std.mem.Allocator, c: J) !void {
            const raw = try unhex(al, str(c, "hex"));
            const h = try hdr.Header.parse(raw);
            try std.testing.expectEqualSlices(u8, raw, &h.serialize());
            try std.testing.expectEqualStrings(str(c, "hash"), &hdr.toHex(hdr.hash(raw[0..80])));
            try std.testing.expectEqualStrings(str(c, "prevHash"), &hdr.toHex(h.prev_hash));
            try std.testing.expectEqualStrings(str(c, "merkleRoot"), &hdr.toHex(h.merkle_root));
            try std.testing.expectEqual(@as(i64, int(c, "version")), h.version);
            try std.testing.expectEqual(@as(u32, @intCast(int(c, "time"))), h.time);
            try std.testing.expectEqual(@as(u32, @intCast(int(c, "bits"))), h.bits);
            try std.testing.expectEqual(@as(u32, @intCast(int(c, "nonce"))), h.nonce);
            const t = hdr.target(h.bits).?;
            try std.testing.expectEqualStrings(str(c, "target"), &hdr.u256Hex(t));
            try std.testing.expectEqualStrings(str(c, "work"), &hdr.u256Hex(hdr.work(t)));
            try std.testing.expectEqual(boolean(c, "powOk"), hdr.powOk(raw[0..80]));
        }
    }.f;
    const headers = arr(v, "headers");
    for (headers) |c| {
        try checkOne(a, c);
        counts.header += 1;
    }
    for (arr(v, "bits")) |c| {
        const bits: u32 = @intCast(int(c, "bits"));
        if (boolean(c, "valid")) {
            try std.testing.expectEqualStrings(str(c, "target"), &hdr.u256Hex(hdr.target(bits).?));
            try std.testing.expectEqualStrings(str(c, "work"), &hdr.u256Hex(hdr.work(hdr.target(bits).?)));
        } else try std.testing.expect(hdr.target(bits) == null);
        counts.header += 1;
    }

    // The run far from genesis: its work, and its links.
    const run_start: u32 = @intCast(int(v, "runStart"));
    const run_len: u32 = @intCast(int(v, "runLen"));
    var run: std.ArrayList([]const u8) = .empty;
    var run_work: u256 = 0;
    for (headers) |c| {
        const h: u32 = @intCast(int(c, "height"));
        if (h < run_start or h >= run_start + run_len) continue;
        const raw = try unhex(a, str(c, "hex"));
        if (run.items.len > 0) try std.testing.expect(std.mem.eql(u8, &(try hdr.Header.parse(raw)).prev_hash, &hdr.hash(run.items[run.items.len - 1][0..80])));
        try run.append(a, raw);
        run_work += hdr.work(hdr.target((try hdr.Header.parse(raw)).bits).?);
    }
    try std.testing.expectEqualStrings(str(v, "runWork"), &hdr.u256Hex(run_work));

    // The chain from the anchor: mainnet's genesis header is the chain's constant, and the
    // first real headers extend it (with or without the genesis at the batch's head).
    const glen: u32 = @intCast(int(v, "genesisRunLen"));
    var grun: std.ArrayList([]const u8) = .empty;
    var gwork: u256 = 0;
    for (headers) |c| {
        const h: u32 = @intCast(int(c, "height"));
        if (h >= glen) continue;
        const raw = try unhex(a, str(c, "hex"));
        try grun.append(a, raw);
        gwork += hdr.work(hdr.target((try hdr.Header.parse(raw)).bits).?);
    }
    try std.testing.expectEqualStrings(str(v, "genesisRunWork"), &hdr.u256Hex(gwork));
    const main_genesis = lib.chain.Network.main.genesis();
    try std.testing.expectEqualSlices(u8, grun.items[0], &main_genesis);
    for ([_]bool{ false, true }) |with_genesis| {
        var ms = lib.store.MemStore.init(std.testing.allocator);
        defer ms.deinit();
        const maps = try lib.store.Maps.create(a, ms.store());
        var headers_ix = maps.map(null);
        var heights_ix = maps.map(null);
        const ch = lib.chain.Chain{ .arena = a, .store = ms.store(), .headers = &headers_ix, .heights = &heights_ix, .network = .main };
        const res = try ch.add(if (with_genesis) grun.items else grun.items[1..]);
        try std.testing.expectEqual(glen - 1, res.added);
        try std.testing.expectEqual(@as(u32, if (with_genesis) 1 else 0), res.known);
        try std.testing.expectEqual(glen - 1, res.tip);
        // The header's block is its hash: a bitcoin-block CID.
        const at5 = (try ch.at(5)).?;
        try std.testing.expectEqualSlices(u8, grun.items[5], &at5.raw);
        const c5 = (try headers_ix.link(&lib.store.be32(5))).?;
        try std.testing.expectEqual(@as(u32, 5), (try ch.heightOf(at5.hash)).?);
        try std.testing.expectEqualSlices(u8, &at5.hash, &lib.store.bitcoinHash(c5).?);
        // Again: all known. The run far away does not connect. Testnet's anchor is another chain.
        try std.testing.expectEqual(glen - 1, (try ch.add(grun.items[1..])).known);
        try std.testing.expectError(error.Unconnected, ch.add(run.items));
        var ix2 = maps.map(null);
        var ix3 = maps.map(null);
        const tch = lib.chain.Chain{ .arena = a, .store = ms.store(), .headers = &ix2, .heights = &ix3, .network = .@"test" };
        try std.testing.expectError(error.Unconnected, tch.add(grun.items[1..]));
        counts.header += 1;
    }
    // Tampered copies of run[1]: each fails its check.
    for (arr(v, "tampered")) |t| {
        const c = t.object.get("case").?;
        try checkOne(a, c);
        const raw = try unhex(a, str(c, "hex"));
        const h = try hdr.Header.parse(raw);
        const links = std.mem.eql(u8, &h.prev_hash, &hdr.hash(run.items[0][0..80]));
        try std.testing.expectEqual(boolean(t, "prevHashLinks"), links);
        if (!boolean(c, "powOk")) try std.testing.expectError(error.BadPow, lib.chain.checkHeader(raw[0..80]));
        counts.header += 1;
    }
    counts.header += 1;
}

// ---------------------------------------------------------------- BRC-29

test "vectors: BRC-29 payee derivation and recognition (go-sdk KeyDeriver, @bsv/sdk)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = try load(a, "brc29.json");
    for (arr(v, "cases")) |c| {
        const sender = try key32(str(c, "senderPrivateKey"));
        const recipient = try key32(str(c, "recipientPrivateKey"));
        const key_id = try lib.brc29.keyId(a, str(c, "derivationPrefix"), str(c, "derivationSuffix"));
        try std.testing.expectEqualStrings(str(c, "keyID"), key_id);
        const sender_pub = try lib.brc29.identityKey(sender);
        const recipient_pub = try lib.brc29.identityKey(recipient);
        try std.testing.expectEqualStrings(str(c, "senderIdentityKey"), &std.fmt.bytesToHex(sender_pub, .lower));
        try std.testing.expectEqualStrings(str(c, "recipientIdentityKey"), &std.fmt.bytesToHex(recipient_pub, .lower));
        const payee = try lib.brc29.payeeKey(a, recipient, sender_pub, key_id);
        const payer = try lib.brc29.payerKey(a, sender, recipient_pub, key_id);
        try std.testing.expectEqualStrings(str(c, "payeeDerivedKey"), &std.fmt.bytesToHex(payee, .lower));
        try std.testing.expectEqualStrings(str(c, "payerDerivedKey"), &std.fmt.bytesToHex(payer, .lower));
        try std.testing.expectEqualStrings(str(c, "lockingScript"), &std.fmt.bytesToHex(lib.brc29.p2pkh(payee), .lower));
        counts.brc29 += 1;
    }
    for (arr(v, "recognize")) |r| {
        const tx = try bsvz.transaction.Transaction.parse(a, try unhex(a, str(r, "txHex")));
        const recipient = try key32(str(r, "recipientPrivateKey"));
        for (arr(r, "remittances")) |m| {
            const key_id = try lib.brc29.keyId(a, str(m, "derivationPrefix"), str(m, "derivationSuffix"));
            const k = try lib.brc29.payeeKey(a, recipient, try key33(str(m, "senderIdentityKey")), key_id);
            const vout: usize = @intCast(int(m, "vout"));
            try std.testing.expectEqual(boolean(m, "matches"), lib.brc29.pays(tx.outputs[vout].locking_script.bytes, k));
            counts.brc29 += 1;
        }
    }
}

// ---------------------------------------------------------------- wire

test "vectors: BRC-100 getPublicKey wire frames (go-sdk serializer)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = try load(a, "wire.json");
    for (arr(v, "requests")) |q| {
        const proto = arr(q, "protocolID");
        const fs = q.object.get("forSelf").?;
        const for_self: ?bool = if (fs == .null) null else fs.bool;
        const frame = try lib.wire.getPublicKeyFrame(a, @intCast(proto[0].integer), proto[1].string, str(q, "keyID"), try key33(str(q, "counterparty")), for_self);
        try std.testing.expectEqualStrings(str(q, "frame"), try hexOf(a, frame));
        counts.wire += 1;
    }
    for (arr(v, "results")) |r| {
        const frame = try unhex(a, str(r, "frame"));
        if (boolean(r, "error")) {
            try std.testing.expectError(error.WalletError, lib.wire.publicKeyResult(frame));
            try std.testing.expectEqualStrings("denied", lib.wire.errorMessage(frame).?);
        } else try std.testing.expectEqualStrings(str(r, "publicKey"), &std.fmt.bytesToHex(try lib.wire.publicKeyResult(frame), .lower));
        counts.wire += 1;
    }
}

// #56: the `anyone` counterparty (BRC-100 wire code 12), removed by #37's
// cleanup (c6a923c) and restored — amm-poc's validator key derivation and
// liveness attestation need it. There is no go-sdk vector for it (go-sdk's
// vectors never exercised `anyone`), so the expected bytes here are the
// pre-c6a923c encoding worked out by hand from keyParams (unchanged except
// for the counterparty byte) and cross-checked against amm-poc-zig016's own
// copy of the frame (programs/amm-topic/src/frames.zig, counterparty_anyone
// = 12, the same field order).
test "wire: the anyone counterparty (BRC-100 code 12) encodes byte-identically to the pre-#37 encoding; round-trips through the mock oracle" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // getPublicKey(level 1, protocol "amm live", keyID "1", counterparty anyone, forSelf true):
    // 08 00 (call, empty originator) 00 (identityKey: false)
    // 01 08 "amm live" (level, protocol) 01 "1" (keyID) 0c (anyone) 00 ff (privileged, reason)
    // 01 (forSelf) 00 (seekPermission).
    const gp = try lib.wire.getPublicKeyFrameFor(a, 1, "amm live", "1", .anyone, true);
    try std.testing.expectEqualStrings("0800000108616d6d206c69766501310c00ff0100", try hexOf(a, gp));

    // createSignature over a 32-byte hash with the same key: 0f 00, the same
    // keyParams, 02 (hashToDirectlySign) + the hash, 00 (seekPermission).
    var digest: [32]u8 = undefined;
    for (&digest, 0..) |*b, i| b.* = @intCast(i);
    const cs = try lib.wire.createSignatureFrame(a, 1, "amm live", "1", .anyone, digest);
    try std.testing.expectEqualStrings("0f000108616d6d206c69766501310c00ff02000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00", try hexOf(a, cs));

    // Round-trips through the mock oracle used by the wire tests (VectorOracle,
    // below): registered by the exact anyone-counterparty frame bytes, answered
    // with real result frames from vectors/wire.json and vectors/signing.json,
    // and parsed back through wire.zig's own result readers.
    var vo = VectorOracle{};
    try vo.frames.put(a, try hexOf(a, gp), "00034da006f958beba78ec54443df4a3f52237253f7ae8cbdb17dccf3feaa57f3126");
    try vo.frames.put(a, try hexOf(a, cs), "003045022100a505e27dcc4eaf5d750cc3cab726ab9447b5dd2cff49a6a5aa14ce72e79abaa8022077ff248815ec49d20017a1f580b3f51119ec031a254761bd98a26e98b4a64b00");

    const gp_res = try VectorOracle.call(&vo, a, gp);
    try std.testing.expectEqualStrings("034da006f958beba78ec54443df4a3f52237253f7ae8cbdb17dccf3feaa57f3126", &std.fmt.bytesToHex(try lib.wire.publicKeyResult(gp_res), .lower));

    const cs_res = try VectorOracle.call(&vo, a, cs);
    try std.testing.expectEqualStrings("3045022100a505e27dcc4eaf5d750cc3cab726ab9447b5dd2cff49a6a5aa14ce72e79abaa8022077ff248815ec49d20017a1f580b3f51119ec031a254761bd98a26e98b4a64b00", try hexOf(a, try lib.wire.signatureResult(cs_res)));
    try std.testing.expectEqual(@as(usize, 2), vo.calls);
    counts.wire += 4;
}

// #59: identityKeyFrame, removed by #37's cleanup (c6a923c) along with the
// sealing frames it was added for, and restored — a program (the front door's
// BRC-103 handshake, the AMM validator's pool state, its liveness heartbeat)
// asks the oracle for the instance's identity key with BRC-100's getPublicKey
// (identityKey: true), byte-identical to the pre-c6a923c encoding and
// cross-checked against amm-poc-zig016's own copy of the frame
// (programs/amm-topic/src/frames.zig, identityKeyFrame).
test "wire: identityKeyFrame (BRC-100 getPublicKey, identityKey: true) encodes byte-identically to the pre-#37 encoding; round-trips through the mock oracle" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // getPublicKey: 08 00 (call, empty originator) 01 (identityKey: true)
    // 00 (level 0) ff (privilegedReason: none, no protocol/keyID/counterparty)
    // 00 (seekPermission).
    const gp = try lib.wire.identityKeyFrame(a);
    try std.testing.expectEqualStrings("08000100ff00", try hexOf(a, gp));

    // Round-trips through the mock oracle used by the wire tests (VectorOracle,
    // above): registered by the exact identityKeyFrame bytes, answered with a
    // real getPublicKey result frame from vectors/wire.json, and parsed back
    // through wire.zig's own result reader.
    var vo = VectorOracle{};
    try vo.frames.put(a, try hexOf(a, gp), "000310c283aac7b35b4ae6fab201d36e8322c3408331149982e16013a5bcb917081c");

    const gp_res = try VectorOracle.call(&vo, a, gp);
    try std.testing.expectEqualStrings("0310c283aac7b35b4ae6fab201d36e8322c3408331149982e16013a5bcb917081c", &std.fmt.bytesToHex(try lib.wire.publicKeyResult(gp_res), .lower));
    try std.testing.expectEqual(@as(usize, 1), vo.calls);
    counts.wire += 2;
}

// ---------------------------------------------------------------- signing through the oracle

/// The oracle as go-sdk's ProtoWallet answered it: every request frame must be one
/// the vector recorded, and gets the recorded result frame.
const VectorOracle = struct {
    frames: std.StringHashMapUnmanaged([]const u8) = .empty,
    calls: usize = 0,
    fn call(ctx: *anyopaque, arena: std.mem.Allocator, frame: []const u8) anyerror![]const u8 {
        const self: *VectorOracle = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        const res = self.frames.get(try hexOf(arena, frame)) orelse {
            std.debug.print("unexpected oracle frame {s}\n", .{try hexOf(arena, frame)});
            return error.UnexpectedFrame;
        };
        return unhex(arena, res);
    }
};

fn keyOf(k: J) !lib.builder.Key {
    const c = str(k, "counterparty");
    return .{ .key_id = str(k, "keyID"), .counterparty = if (std.mem.eql(u8, c, "self")) .self else .{ .other = try key33(c) } };
}

test "vectors: spends signed through the oracle — frames, sighash, fee, change, tx (go-sdk ProtoWallet)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = try load(a, "signing.json");
    const root = try key32(str(v, "rootKey"));
    try std.testing.expectEqualStrings(str(v, "identityKey"), &std.fmt.bytesToHex(try lib.brc29.identityKey(root), .lower));
    for (arr(v, "cases")) |c| {
        var vo = VectorOracle{};
        var inputs: std.ArrayList(lib.builder.Input) = .empty;
        for (arr(c, "inputs")) |in| {
            try vo.frames.put(a, str(in, "getPublicKeyFrame"), str(in, "getPublicKeyResult"));
            try vo.frames.put(a, str(in, "createSignatureFrame"), str(in, "createSignatureResult"));
            const src = try bsvz.transaction.Transaction.parse(a, try unhex(a, str(in, "sourceTx")));
            const vout: u32 = @intCast(int(in, "vout"));
            try std.testing.expectEqualStrings(str(in, "lockingScript"), try hexOf(a, src.outputs[vout].locking_script.bytes));
            try inputs.append(a, .{
                .source_txid = try hdr.fromHex(str(in, "sourceTxid")),
                .vout = vout,
                .satoshis = @intCast(int(in, "satoshis")),
                .locking_script = src.outputs[vout].locking_script.bytes,
                .key = try keyOf(in),
            });
        }
        const ch = c.object.get("change").?;
        try vo.frames.put(a, str(ch, "getPublicKeyFrame"), str(ch, "getPublicKeyResult"));
        var outputs: std.ArrayList(lib.builder.Output) = .empty;
        for (arr(c, "outputs")) |o| try outputs.append(a, .{ .satoshis = @intCast(int(o, "satoshis")), .locking_script = try unhex(a, str(o, "lockingScript")) });
        const rate: u64 = @intCast(int(c, "satsPerKb"));

        var ws = lib.builder.WireSigner{ .ctx = &vo, .call = VectorOracle.call };
        const built = try lib.builder.build(a, ws.signer(), inputs.items, outputs.items, try keyOf(ch), rate, true);
        try std.testing.expectEqual(@as(u64, @intCast(int(c, "fee"))), built.fee);
        const cs = ch.object.get("satoshis").?;
        if (cs == .null) try std.testing.expect(built.change == null) else try std.testing.expectEqual(@as(u64, @intCast(cs.integer)), built.change.?.satoshis);
        try std.testing.expectEqualStrings(str(c, "tx"), try hexOf(a, built.raw));
        try std.testing.expectEqualStrings(str(c, "txid"), &hdr.toHex(built.txid));
        try std.testing.expectEqual(1 + 2 * inputs.items.len, vo.calls);
        // The preimage and sighash, and each input's script, checked here too.
        for (arr(c, "inputs"), inputs.items, 0..) |jin, in, i| {
            const pre = try bsvz.transaction.sighash.formatPreimage(a, &built.tx, i, bsvz.script.Script.init(in.locking_script), @intCast(in.satoshis), lib.builder.sighash_all_forkid);
            try std.testing.expectEqualStrings(str(jin, "preimage"), try hexOf(a, pre));
            const d = try bsvz.transaction.sighash.digest(a, &built.tx, i, bsvz.script.Script.init(in.locking_script), @intCast(in.satoshis), lib.builder.sighash_all_forkid);
            try std.testing.expectEqualStrings(str(jin, "sighash"), try hexOf(a, &d.bytes));
            try std.testing.expectEqualStrings(str(jin, "unlockingScript"), try hexOf(a, built.tx.inputs[i].unlocking_script.bytes));
            try std.testing.expect(try bsvz.script.interpreter.verifyPrevout(.{
                .allocator = a,
                .tx = &built.tx,
                .input_index = i,
                .previous_output = .{ .satoshis = @intCast(in.satoshis), .locking_script = bsvz.script.Script.init(in.locking_script) },
                .unlocking_script = built.tx.inputs[i].unlocking_script,
            }));
            counts.sign += 1;
        }
        // The same spend with the root key in hand (bsvz's BRC-42): the same keys, a valid tx.
        var ks = lib.builder.KeySigner{ .root = root };
        const again = try lib.builder.build(a, ks.signer(), inputs.items, outputs.items, try keyOf(ch), rate, true);
        try std.testing.expectEqual(built.fee, again.fee);
        for (inputs.items, 0..) |in, i| try std.testing.expect(try bsvz.script.interpreter.verifyPrevout(.{
            .allocator = a,
            .tx = &again.tx,
            .input_index = i,
            .previous_output = .{ .satoshis = @intCast(in.satoshis), .locking_script = bsvz.script.Script.init(in.locking_script) },
            .unlocking_script = again.tx.inputs[i].unlocking_script,
        }));
        for (built.tx.outputs, again.tx.outputs) |x, y| try std.testing.expectEqualSlices(u8, x.locking_script.bytes, y.locking_script.bytes);
        counts.sign += 1;
    }
    // Not enough: refused before any signature.
    var ks = lib.builder.KeySigner{ .root = root };
    const c0 = arr(v, "cases")[0];
    const in0 = arr(c0, "inputs")[0];
    const src0 = try bsvz.transaction.Transaction.parse(a, try unhex(a, str(in0, "sourceTx")));
    try std.testing.expectError(error.InsufficientFunds, lib.builder.build(a, ks.signer(), &.{.{ .source_txid = try hdr.fromHex(str(in0, "sourceTxid")), .vout = 1, .satoshis = 30000, .locking_script = src0.outputs[1].locking_script.bytes, .key = try keyOf(in0) }}, &.{.{ .satoshis = 30000, .locking_script = &.{0x51} }}, .{ .key_id = "x", .counterparty = .self }, 1, true));
}

// ---------------------------------------------------------------- Chronicle script rules (#53)

test "vectors: Rúnar AMM pool spends execute OP_2MUL — verified under Chronicle rules (the default), refused before them" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try load(a, "chronicle.json");
    const txs = v.object.get("txs").?;
    for (arr(v, "spends")) |s| {
        const tx = try bsvz.transaction.Transaction.parse(a, try unhex(a, str(txs, str(s, "name"))));
        const src = try bsvz.transaction.Transaction.parse(a, try unhex(a, str(txs, str(s, "source"))));
        const i: usize = @intCast(int(s, "input"));
        const vout: u32 = @intCast(int(s, "vout"));
        try std.testing.expectEqualSlices(u8, &(try src.txid(a)).bytes, &tx.inputs[i].previous_outpoint.txid.bytes);
        try std.testing.expectEqual(vout, tx.inputs[i].previous_outpoint.index);
        const ctx = bsvz.script.interpreter.PrevoutSpendContext{
            .allocator = a,
            .tx = &tx,
            .input_index = i,
            .previous_output = src.outputs[vout],
            .unlocking_script = tx.inputs[i].unlocking_script,
        };
        // ExecutionFlags{}: current mainnet rules, Chronicle on (the flags the wallet and the overlay verify with).
        try std.testing.expect(try bsvz.script.interpreter.verifyPrevout(ctx));
        // Before Chronicle OP_2MUL is a disabled opcode.
        var pre = ctx;
        pre.flags = bsvz.script.interpreter.ExecutionFlags.postGenesisBsv();
        try std.testing.expectError(error.UnknownOpcode, bsvz.script.interpreter.verifyPrevout(pre));
        var legacy = ctx;
        legacy.flags = bsvz.script.interpreter.ExecutionFlags.legacyReference();
        try std.testing.expect(!(bsvz.script.interpreter.verifyPrevout(legacy) catch false));
        counts.chronicle += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), counts.chronicle);
}

// ---------------------------------------------------------------- the wallet over records

/// A regtest chain from its genesis up to `tip`, the header at each height in
/// `roots` carrying that merkle root (the rest a filler). Heights 1..tip.
fn regtestChain(a: std.mem.Allocator, tip: u32, roots: []const struct { u32, [32]u8 }) ![][80]u8 {
    const out = try a.alloc([80]u8, tip);
    var prev = hdr.hash(&lib.chain.Network.regtest.genesis());
    for (out, 1..) |*h, height| {
        var root: [32]u8 = .{0x5a} ** 32;
        std.mem.writeInt(u32, root[0..4], @intCast(height), .little);
        for (roots) |r| if (r[0] == height) {
            root = r[1];
        };
        h.* = mine(prev, root, 1_700_000_000 + @as(u32, @intCast(height)) * 600);
        prev = hdr.hash(h);
    }
    return out;
}

fn slices(a: std.mem.Allocator, hs: []const [80]u8) ![]const []const u8 {
    const out = try a.alloc([]const u8, hs.len);
    for (hs, out) |*h, *o| o.* = h;
    return out;
}

/// Mine a header at regtest difficulty (0x207fffff): a nonce search of a few tries.
fn mine(prev: [32]u8, merkle_root: [32]u8, time: u32) [80]u8 {
    var h = hdr.Header{ .version = 1, .prev_hash = prev, .merkle_root = merkle_root, .time = time, .bits = 0x207fffff, .nonce = 0 };
    while (true) : (h.nonce += 1) {
        const raw = h.serialize();
        if (hdr.powOk(&raw)) return raw;
    }
}

/// A test oracle: BRC-29 payee keys from a private key, as the real oracle derives them.
const KeyOracle = struct {
    priv: [32]u8,
    calls: usize = 0,
    fn derive(ptr: *anyopaque, arena: std.mem.Allocator, key_id: []const u8, sender: [33]u8) anyerror![33]u8 {
        const self: *KeyOracle = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        return lib.brc29.payeeKey(arena, self.priv, sender, key_id);
    }
    fn oracle(self: *KeyOracle) lib.wallet.Oracle {
        return .{ .ptr = self, .derivePayeeFn = derive };
    }
};

test "wallet: headers, a BRC-29 payment internalized from Atomic BEEF, spendable outputs, computed status, reorg" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();

    // The funding: universal-test-vectors' 1-in-1-out (a parent with a BUMP at height 1000, and its child
    // paying the vector's "recipient"). The recipient is our payer here.
    const utv = std.json.parseFromSliceLeaky(J, a, @embedFile("vectors/beef.json"), .{}) catch unreachable;
    var fund_hex: []const u8 = undefined;
    for (arr(utv, "cases")) |c| if (std.mem.eql(u8, str(c, "name"), "utv-1-in-1-out-atomic")) {
        fund_hex = str(c, "hex");
    };
    const fund = try beef.parse(a, try unhex(a, fund_hex));
    const payer_priv = try key32("fdd506efec13e05cdff57ef13e24a60009aba0e8f2162e2cff2886460175cad8"); // generated/bsv-tx/1-in-1-out.json recipient
    const payer_pub = try lib.brc29.identityKey(payer_priv);
    const bump = fund.bumps[0];
    var proven_txid: [32]u8 = undefined;
    for (fund.entries) |e| if (e.format == .raw_with_bump) {
        proven_txid = e.txid;
    };
    const root = beef.rootFor(a, bump, proven_txid).?;

    // Our chain: regtest from its genesis, 1000 carrying that root, up to 1001.
    var w = try lib.wallet.Wallet.load(a, s, null, .regtest);
    const chain = try regtestChain(a, bump.block_height + 1, &.{.{ bump.block_height, root }});
    const h1001 = chain[chain.len - 1];
    const added = try w.addHeaders(try slices(a, chain));
    try std.testing.expectEqual(@as(u32, 1001), added.added);
    try std.testing.expectError(error.Unconnected, w.addHeaders(&.{&mine(.{1} ** 32, .{2} ** 32, 5)}));

    // The payment: the payer spends the funding output to a BRC-29 key derived for us.
    const our_priv = try key32("6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8");
    const our_pub = try lib.brc29.identityKey(our_priv);
    const key_id = try lib.brc29.keyId(a, "cHJlZml4", "c3VmZml4");
    const pay_to = try lib.brc29.payerKey(a, payer_priv, our_pub, key_id);
    const fund_tx = fund.find(fund.atomic.?).?.tx.?;
    var builder = bsvz.transaction.Builder.init(a);
    try builder.addInputFromTx(&fund_tx, 0);
    const script = lib.brc29.p2pkh(pay_to);
    try builder.addOutput(.{ .satoshis = fund_tx.outputs[0].satoshis - 100, .locking_script = bsvz.script.Script.init(&script) });
    try builder.sign(try bsvz.crypto.PrivateKey.fromBytes(payer_priv));
    const pay_tx = try builder.build();
    const pay_raw = try pay_tx.serialize(a);
    const pay_txid = beef.txidOf(pay_raw);
    var entries: std.ArrayList(beef.Entry) = .empty;
    try entries.appendSlice(a, fund.entries);
    try entries.append(a, .{ .txid = pay_txid, .format = .raw, .raw = pay_raw, .tx = pay_tx });
    const pay_beef = try beef.serialize(a, .{ .version = beef.V2, .atomic = pay_txid, .bumps = fund.bumps, .entries = entries.items });

    var oracle = KeyOracle{ .priv = our_priv };
    const remit = lib.wallet.PaymentRemittance{ .derivation_prefix = "cHJlZml4", .derivation_suffix = "c3VmZml4", .sender_identity_key = payer_pub };
    // A wrong suffix is not ours.
    try std.testing.expectError(error.NotOurPayment, w.internalize(.{
        .tx = pay_beef,
        .outputs = &.{.{ .output_index = 0, .payment = .{ .derivation_prefix = "cHJlZml4", .derivation_suffix = "eA==", .sender_identity_key = payer_pub } }},
        .description = "wrong",
    }, oracle.oracle()));
    const r = try w.internalize(.{ .tx = pay_beef, .outputs = &.{.{ .output_index = 0, .payment = remit }}, .description = "funding from the payer" }, oracle.oracle());
    try std.testing.expectEqual(lib.wallet.Status.unproven, r.status);
    try std.testing.expect(std.mem.eql(u8, &r.txid, &pay_txid));

    // A tampered signature fails SPV (script verification of the unproven payment).
    const bad_raw = try a.dupe(u8, pay_raw);
    bad_raw[50] ^= 1;
    const bad_tx = try bsvz.transaction.Transaction.parse(a, bad_raw);
    entries.items[entries.items.len - 1] = .{ .txid = beef.txidOf(bad_raw), .format = .raw, .raw = bad_raw, .tx = bad_tx };
    const bad_beef = try beef.serialize(a, .{ .version = beef.V2, .atomic = beef.txidOf(bad_raw), .bumps = fund.bumps, .entries = entries.items });
    try std.testing.expectError(error.ScriptFailed, w.internalize(.{ .tx = bad_beef, .outputs = &.{.{ .output_index = 0, .payment = remit }}, .description = "bad" }, oracle.oracle()));

    const state1 = try w.save();
    // A fresh load from the state record sees the same wallet.
    try std.testing.expectError(error.NetworkMismatch, lib.wallet.Wallet.load(a, s, state1, .main));
    var w2 = try lib.wallet.Wallet.load(a, s, state1, .regtest);
    const list = try w2.listOutputs("default", false);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expect(std.mem.eql(u8, &list[0].txid, &pay_txid));
    try std.testing.expectEqual(@as(u64, @intCast(fund_tx.outputs[0].satoshis - 100)), list[0].satoshis);
    try std.testing.expect(list[0].spendable);
    try std.testing.expectEqual(lib.wallet.Status.unproven, list[0].status);
    // The funding transactions are known (records), but only the payment is our action.
    try std.testing.expectEqual(@as(usize, 1), try w2.mapCount("actions"));
    try std.testing.expectEqual(@as(usize, 3), try w2.mapCount("txs"));
    // A transaction's block is its txid: a bitcoin-tx CID.
    try std.testing.expectEqualSlices(u8, &pay_txid, &lib.store.bitcoinHash((try w2.map("txs").link(&pay_txid)).?).?);
    try std.testing.expect(try w2.map("unproven").has(&pay_txid));

    // The payment is mined at 1002: a single-transaction block, root = txid.
    const h1002 = mine(hdr.hash(&h1001), pay_txid, 1_700_001_800);
    _ = try w2.addHeaders(&.{&h1002});
    // A BUMP for a one-transaction block: height 1002, one level, the txid as its only leaf.
    var path: std.ArrayList(u8) = .empty;
    try path.appendSlice(a, &.{ 0xfd, 0xea, 0x03, 0x01, 0x01, 0x00, 0x02 });
    try path.appendSlice(a, &pay_txid);
    try std.testing.expectEqual(lib.wallet.Status.proven, try w2.addProof(pay_txid, path.items));
    try std.testing.expectEqual(lib.wallet.Status.proven, try w2.status(pay_txid));
    const state2 = try w2.save();

    // A reorg: a heavier branch from 1001 without our block. Status is computed, so it drops back.
    var w3 = try lib.wallet.Wallet.load(a, s, state2, .regtest);
    const alt1 = mine(hdr.hash(&h1001), .{3} ** 32, 1_700_001_801);
    const alt2 = mine(hdr.hash(&alt1), .{4} ** 32, 1_700_001_802);
    const re = try w3.addHeaders(&.{ &alt1, &alt2 });
    try std.testing.expectEqual(@as(u32, 1), re.replaced);
    try std.testing.expectEqual(@as(u32, 1003), re.tip);
    try std.testing.expectEqual(lib.wallet.Status.unproven, try w3.status(pay_txid));
    // A lighter branch does not replace ours.
    const lone = mine(hdr.hash(&h1001), .{5} ** 32, 1_700_001_900);
    try std.testing.expectEqual(@as(u32, 1), (try w3.addHeaders(&.{&lone})).ignored);
    _ = try w3.save();

    // Idempotence: internalizing the same payment again changes nothing.
    var w4 = try lib.wallet.Wallet.load(a, s, state1, .regtest);
    _ = try w4.internalize(.{ .tx = pay_beef, .outputs = &.{.{ .output_index = 0, .payment = remit }}, .description = "again" }, oracle.oracle());
    try std.testing.expectEqualStrings(state1, try w4.save());

    // Spending: createAction pays someone from the payment, change to a fresh key of ours, signed by the oracle.
    var signer = lib.builder.KeySigner{ .root = our_priv };
    const payee_script = lib.brc29.p2pkh(try lib.brc29.identityKey(.{0x33} ** 32));
    var w5 = try lib.wallet.Wallet.load(a, s, state1, .regtest);
    const paid: u64 = @intCast(fund_tx.outputs[0].satoshis - 100);
    try std.testing.expectError(error.InsufficientFunds, w5.createAction(.{ .description = "too much", .outputs = &.{.{ .satoshis = paid, .locking_script = &payee_script }} }, signer.signer(), "cA==", "cw==", 100));
    const c1 = try w5.createAction(.{ .description = "pay", .labels = &.{"out"}, .outputs = &.{
        .{ .satoshis = 300, .locking_script = &payee_script },
        .{ .satoshis = 1, .locking_script = &.{ 0x00, 0x6a, 0x01, 0x42 }, .basket = "tokens", .tags = &.{"t"} },
    } }, signer.signer(), "Y2hhbmdl", "MQ==", 100);
    try std.testing.expect(c1.reference == null);
    const b1 = try beef.parse(a, c1.beef);
    try std.testing.expectEqualSlices(u8, &c1.txid, &b1.atomic.?);
    // The BEEF carries the unproven payment, its unproven parent and their proven ancestor: it SPV-checks against our chain.
    try std.testing.expectEqual(@as(usize, 4), b1.entries.len);
    try std.testing.expectEqual(@as(usize, 1), b1.bumps.len);
    const spent_tx = b1.find(c1.txid).?.tx.?;
    try std.testing.expectEqualSlices(u8, &pay_txid, &spent_tx.inputs[0].previous_outpoint.txid.bytes);
    try std.testing.expect(try bsvz.script.interpreter.verifyPrevout(.{ .allocator = a, .tx = &spent_tx, .input_index = 0, .previous_output = pay_tx.outputs[0], .unlocking_script = spent_tx.inputs[0].unlocking_script }));
    const change_sats = paid - 301 - (try lib.builder.estimateFee(a, 1, &.{ .{ .satoshis = 300, .locking_script = &payee_script }, .{ .satoshis = 1, .locking_script = &.{ 0x00, 0x6a, 0x01, 0x42 } } }, 25, 100));
    const state5 = try w5.save();
    var w6 = try lib.wallet.Wallet.load(a, s, state5, .regtest);
    const def = try w6.listOutputs("default", true);
    try std.testing.expectEqual(@as(usize, 2), def.len);
    try std.testing.expect(std.mem.eql(u8, &def[0].txid, &c1.txid) and def[0].spendable and def[0].satoshis == change_sats);
    try std.testing.expect(std.mem.eql(u8, &def[1].txid, &pay_txid) and !def[1].spendable);
    try std.testing.expectEqual(@as(usize, 1), (try w6.listOutputs("tokens", false)).len);
    try std.testing.expectEqual(@as(usize, 2), try w6.mapCount("actions"));
    // The change (counterparty self) funds the next spend, unconfirmed: its BEEF goes back to the proven grandparent.
    const c2 = try w6.createAction(.{ .description = "again", .outputs = &.{.{ .satoshis = 100, .locking_script = &payee_script }} }, signer.signer(), "Y2hhbmdl", "Mg==", 100);
    const b2 = try beef.parse(a, c2.beef);
    try std.testing.expectEqual(@as(usize, 5), b2.entries.len);
    var ctx2 = struct {
        w: *lib.wallet.Wallet,
        fn rootAt(ptr: *anyopaque, height: u32) anyerror!?[32]u8 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.w.chain().rootAt(height);
        }
        fn none(_: *anyopaque, _: std.mem.Allocator, _: [32]u8) anyerror!?[]const u8 {
            return null;
        }
    }{ .w = &w6 };
    _ = try lib.spv.verify(a, b2, .{ .ptr = &ctx2, .rootAtFn = @TypeOf(ctx2).rootAt, .knownRawFn = @TypeOf(ctx2).none });

    // signAndProcess false: a draft, signable; signAction signs the same transaction.
    var w7 = try lib.wallet.Wallet.load(a, s, state1, .regtest);
    const d = try w7.createAction(.{ .description = "pay", .labels = &.{"out"}, .sign_and_process = false, .outputs = &.{
        .{ .satoshis = 300, .locking_script = &payee_script },
        .{ .satoshis = 1, .locking_script = &.{ 0x00, 0x6a, 0x01, 0x42 }, .basket = "tokens", .tags = &.{"t"} },
    } }, signer.signer(), "Y2hhbmdl", "MQ==", 100);
    try std.testing.expect(d.reference != null);
    try std.testing.expectEqual(@as(usize, 1), try w7.mapCount("actions")); // nothing recorded yet
    const signed = try w7.signAction(d.reference.?, signer.signer());
    try std.testing.expectEqualSlices(u8, &c1.txid, &signed.txid);
    try std.testing.expectEqualStrings(state5, try w7.save());
    try std.testing.expectError(error.InputSpent, w7.signAction(d.reference.?, signer.signer()));
    counts.wallet += 1;
}

test "wallet: basket insertion, spent outputs, BEEF refusals" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const utv = try load(a, "beef.json");
    var fund_hex: []const u8 = undefined;
    var two_hex: []const u8 = undefined;
    for (arr(utv, "cases")) |c| {
        if (std.mem.eql(u8, str(c, "name"), "utv-1-in-1-out-atomic")) fund_hex = str(c, "hex");
        if (std.mem.eql(u8, str(c, "name"), "utv-1-in-1-out-v2")) two_hex = str(c, "hex");
    }
    const fund = try beef.parse(a, try unhex(a, fund_hex));
    var w = try lib.wallet.Wallet.load(a, ms.store(), null, .regtest);
    var oracle = KeyOracle{ .priv = .{1} ** 32 };
    // No headers: the BUMP's height is unknown.
    try std.testing.expectError(error.UnknownHeader, w.internalize(.{ .tx = try unhex(a, fund_hex), .outputs = &.{.{ .output_index = 0, .insertion = .{ .basket = "tokens" } }}, .description = "x" }, oracle.oracle()));
    // Not atomic.
    try std.testing.expectError(error.NotAtomicBeef, w.internalize(.{ .tx = try unhex(a, two_hex), .outputs = &.{.{ .output_index = 0, .insertion = .{ .basket = "tokens" } }}, .description = "x" }, oracle.oracle()));

    var proven_txid: [32]u8 = undefined;
    for (fund.entries) |e| if (e.format == .raw_with_bump) {
        proven_txid = e.txid;
    };
    _ = try w.addHeaders(try slices(a, try regtestChain(a, fund.bumps[0].block_height, &.{.{ fund.bumps[0].block_height, beef.rootFor(a, fund.bumps[0], proven_txid).? }})));
    // A wrong-root header at the BUMP's height would have failed; with the right one it passes.
    try std.testing.expectError(error.BadBasket, w.internalize(.{ .tx = try unhex(a, fund_hex), .outputs = &.{.{ .output_index = 0, .insertion = .{ .basket = "default" } }}, .description = "x" }, oracle.oracle()));
    try std.testing.expectError(error.BadOutputIndex, w.internalize(.{ .tx = try unhex(a, fund_hex), .outputs = &.{.{ .output_index = 5, .insertion = .{ .basket = "tokens" } }}, .description = "x" }, oracle.oracle()));
    const r = try w.internalize(.{ .tx = try unhex(a, fund_hex), .outputs = &.{.{ .output_index = 0, .insertion = .{ .basket = "tokens", .tags = &.{"t1"} } }}, .description = "tokens in" }, oracle.oracle());
    try std.testing.expectEqual(lib.wallet.Status.unproven, r.status);
    try std.testing.expectEqual(@as(usize, 0), oracle.calls);
    _ = try w.save();
    try std.testing.expectEqual(@as(usize, 1), (try w.listOutputs("tokens", false)).len);
    try std.testing.expectEqual(@as(usize, 0), (try w.listOutputs("default", false)).len);

    // The proven parent's output is also inserted, then the child (ours) spends it: the parent's output is spent.
    const parent_atomic = try beef.serialize(a, .{ .version = beef.V2, .atomic = proven_txid, .bumps = fund.bumps, .entries = fund.entries[0..1] });
    const rp = try w.internalize(.{ .tx = parent_atomic, .outputs = &.{.{ .output_index = 0, .insertion = .{ .basket = "coins" } }}, .description = "parent" }, oracle.oracle());
    try std.testing.expectEqual(lib.wallet.Status.proven, rp.status);
    _ = try w.save();
    const coins = try w.listOutputs("coins", true);
    try std.testing.expectEqual(@as(usize, 1), coins.len);
    try std.testing.expect(!coins[0].spendable);
    try std.testing.expectEqual(@as(usize, 0), (try w.listOutputs("coins", false)).len);
    counts.wallet += 1;
}

// ---------------------------------------------------------------- settlement (#37)

/// A wallet on regtest (1001 headers) holding one unproven BRC-29 payment to
/// us, spendable: the state record, the payment and the keys.
const Paid = struct {
    state: []const u8,
    pay_txid: [32]u8,
    pay_sats: u64,
    h1001: [80]u8,
    our_priv: [32]u8,
};

fn setupPaid(a: std.mem.Allocator, s: lib.store.Store) !Paid {
    const utv = std.json.parseFromSliceLeaky(J, a, @embedFile("vectors/beef.json"), .{}) catch unreachable;
    var fund_hex: []const u8 = undefined;
    for (arr(utv, "cases")) |c| if (std.mem.eql(u8, str(c, "name"), "utv-1-in-1-out-atomic")) {
        fund_hex = str(c, "hex");
    };
    const fund = try beef.parse(a, try unhex(a, fund_hex));
    const payer_priv = try key32("fdd506efec13e05cdff57ef13e24a60009aba0e8f2162e2cff2886460175cad8");
    const payer_pub = try lib.brc29.identityKey(payer_priv);
    const bump = fund.bumps[0];
    var proven_txid: [32]u8 = undefined;
    for (fund.entries) |e| if (e.format == .raw_with_bump) {
        proven_txid = e.txid;
    };
    var w = try lib.wallet.Wallet.load(a, s, null, .regtest);
    const chain = try regtestChain(a, bump.block_height + 1, &.{.{ bump.block_height, beef.rootFor(a, bump, proven_txid).? }});
    _ = try w.addHeaders(try slices(a, chain));
    const our_priv = try key32("6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8");
    const key_id = try lib.brc29.keyId(a, "cHJlZml4", "c3VmZml4");
    const pay_to = try lib.brc29.payerKey(a, payer_priv, try lib.brc29.identityKey(our_priv), key_id);
    const fund_tx = fund.find(fund.atomic.?).?.tx.?;
    var b = bsvz.transaction.Builder.init(a);
    try b.addInputFromTx(&fund_tx, 0);
    const script = lib.brc29.p2pkh(pay_to);
    try b.addOutput(.{ .satoshis = fund_tx.outputs[0].satoshis - 100, .locking_script = bsvz.script.Script.init(try a.dupe(u8, &script)) });
    try b.sign(try bsvz.crypto.PrivateKey.fromBytes(payer_priv));
    const pay_tx = try b.build();
    const pay_raw = try pay_tx.serialize(a);
    const pay_txid = beef.txidOf(pay_raw);
    var entries: std.ArrayList(beef.Entry) = .empty;
    try entries.appendSlice(a, fund.entries);
    try entries.append(a, .{ .txid = pay_txid, .format = .raw, .raw = pay_raw, .tx = pay_tx });
    const pay_beef = try beef.serialize(a, .{ .version = beef.V2, .atomic = pay_txid, .bumps = fund.bumps, .entries = entries.items });
    var oracle = KeyOracle{ .priv = our_priv };
    _ = try w.internalize(.{ .tx = pay_beef, .outputs = &.{.{ .output_index = 0, .payment = .{ .derivation_prefix = "cHJlZml4", .derivation_suffix = "c3VmZml4", .sender_identity_key = payer_pub } }}, .description = "funding" }, oracle.oracle());
    return .{ .state = try w.save(), .pay_txid = pay_txid, .pay_sats = @intCast(fund_tx.outputs[0].satoshis - 100), .h1001 = chain[chain.len - 1], .our_priv = our_priv };
}

/// A BUMP for a block holding one transaction: its root is the txid.
fn soloPath(a: std.mem.Allocator, height: u32, txid: [32]u8) ![]const u8 {
    var path: std.ArrayList(u8) = .empty;
    try path.appendSlice(a, &.{ 0xfd, 0, 0, 0x01, 0x01, 0x00, 0x02 }); // height (a 3-byte varint), 1 level, 1 leaf, offset 0, txid flag
    std.mem.writeInt(u16, path.items[1..3], @intCast(height), .little);
    try path.appendSlice(a, &txid);
    return path.items;
}

test "settlement: unproven → proven; reorg → unproven (reverted) → re-proven" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();
    const p = try setupPaid(a, s);

    var w = try lib.wallet.Wallet.load(a, s, p.state, .regtest);
    try std.testing.expectEqual(lib.wallet.Status.unproven, try w.status(p.pay_txid));
    try std.testing.expect(try w.map("unproven").has(&p.pay_txid));
    // Mined alone at 1002: proven.
    const h1002 = mine(hdr.hash(&p.h1001), p.pay_txid, 1_700_001_800);
    _ = try w.addHeaders(&.{&h1002});
    try std.testing.expectEqual(lib.wallet.Status.proven, try w.addProof(p.pay_txid, try soloPath(a, 1002, p.pay_txid)));
    const proven_state = try w.save();
    try std.testing.expect(!(try w.map("unproven").has(&p.pay_txid))); // proven: it leaves the settlement index

    // A heavier branch from 1001 without that block: the proof no longer holds.
    var w2 = try lib.wallet.Wallet.load(a, s, proven_state, .regtest);
    const alt1 = mine(hdr.hash(&p.h1001), .{3} ** 32, 1_700_001_801);
    const alt2 = mine(hdr.hash(&alt1), .{4} ** 32, 1_700_001_802);
    try std.testing.expectEqual(@as(u32, 1), (try w2.addHeaders(&.{ &alt1, &alt2 })).replaced);
    try std.testing.expectEqual(lib.wallet.Status.unproven, try w2.status(p.pay_txid));
    try std.testing.expectEqual(@as(usize, 1), w2.reverted.items.len);
    try std.testing.expectEqualSlices(u8, &p.pay_txid, &w2.reverted.items[0]);
    _ = try w2.save();
    try std.testing.expect(try w2.map("unproven").has(&p.pay_txid)); // reverted: back in it
    // The old proof is no longer accepted against the new chain; the new block's is.
    try std.testing.expectError(error.RootMismatch, w2.addProof(p.pay_txid, try soloPath(a, 1002, p.pay_txid)));
    const alt3 = mine(hdr.hash(&alt2), p.pay_txid, 1_700_001_803);
    _ = try w2.addHeaders(&.{&alt3});
    try std.testing.expectEqual(lib.wallet.Status.proven, try w2.addProof(p.pay_txid, try soloPath(a, 1004, p.pay_txid)));
    // A proven transaction is never rejected.
    try std.testing.expectEqual(@as(usize, 0), (try w2.reject(p.pay_txid, "REJECTED")).len);
    try std.testing.expectEqual(lib.wallet.Status.proven, try w2.status(p.pay_txid));
    _ = try w2.save();
    counts.wallet += 1;
}

test "settlement: a rejection bubbles through spends and drafts; inputs freed; mentions do not propagate" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();
    const p = try setupPaid(a, s);
    var signer = lib.builder.KeySigner{ .root = p.our_priv };
    const payee = lib.brc29.p2pkh(try lib.brc29.identityKey(.{0x33} ** 32));

    // A spends the (unproven) payment; B spends A's change; a draft D would spend B's change.
    var w = try lib.wallet.Wallet.load(a, s, p.state, .regtest);
    const ca = try w.createAction(.{ .description = "A", .outputs = &.{
        .{ .satoshis = 300, .locking_script = &payee },
        .{ .satoshis = 1, .locking_script = &.{ 0x00, 0x6a, 0x01, 0x42 }, .basket = "tokens" },
    } }, signer.signer(), "YQ==", "MQ==", 100);
    _ = try w.save();
    const cb = try w.createAction(.{ .description = "B", .outputs = &.{.{ .satoshis = 200, .locking_script = &payee }} }, signer.signer(), "Yg==", "MQ==", 100);
    _ = try w.save();
    const d = try w.createAction(.{ .description = "D", .sign_and_process = false, .outputs = &.{.{ .satoshis = 100, .locking_script = &payee }} }, signer.signer(), "ZA==", "MQ==", 100);
    const before = try w.save();
    // The relations as written: B spends A (a `spends` edge, #42: B kept, its input
    // an edge into A's CID with locator = A's change vout); A's action and outputs derive from A; D from B.
    const spenders_a = try w.spendersOfTx(ca.txid);
    try std.testing.expectEqual(@as(usize, 1), spenders_a.len);
    try std.testing.expectEqualSlices(u8, &cb.txid, &spenders_a[0]);
    const e = try s.edges(a, &lib.store.hashCid(.tx, ca.txid), "spends");
    try std.testing.expectEqual(@as(usize, 1), e.len);
    try std.testing.expectEqualSlices(u8, &lib.store.hashCid(.tx, cb.txid), e[0].from);
    for (try w.dependentsOf(ca.txid)) |dep| try std.testing.expect(dep.rel != .spends); // no longer a dependents entry
    try std.testing.expectEqual(@as(usize, 1), (try w.listOutputs("default", false)).len); // B's change only
    try std.testing.expectEqual(@as(usize, 1), (try w.listOutputs("tokens", false)).len);
    // Something that merely mentions A (another transaction, and a record naming it).
    const mentioner: [32]u8 = .{0x77} ** 32;
    try w.relate(ca.txid, .tx, &mentioner, .mentions);
    try w.relate(ca.txid, .record, &cbor_cid(0x42), .mentions);

    // ARC rejects A (e.g. a double spend it saw): A and B are rejected, D too, outputs gone, the payment spendable again.
    w.now = 5000;
    try std.testing.expectEqual(lib.wallet.Wallet.Outcome.rejected, try w.applyStatus(ca.txid, "DOUBLE_SPEND_ATTEMPTED", null));
    try std.testing.expectEqual(lib.wallet.Status.rejected, try w.status(ca.txid));
    try std.testing.expectEqual(lib.wallet.Status.rejected, try w.status(cb.txid));
    try std.testing.expect(try w.status(mentioner) != .rejected);
    try std.testing.expectEqual(lib.wallet.Status.unproven, try w.status(p.pay_txid));
    const sa = (try w.settlement(ca.txid)).?;
    try std.testing.expectEqualStrings("DOUBLE_SPEND_ATTEMPTED", sa.getText("reason").?);
    const sb = (try w.settlement(cb.txid)).?;
    try std.testing.expectEqualStrings("input-rejected", sb.getText("reason").?);
    try std.testing.expectEqualStrings(&hdr.toHex(ca.txid), sb.getText("cause").?);
    try std.testing.expectEqual(@as(u64, 5000), sb.getUint("at").?);
    const after = try w.save();
    const def = try w.listOutputs("default", true);
    try std.testing.expectEqual(@as(usize, 1), def.len);
    try std.testing.expectEqualSlices(u8, &p.pay_txid, &def[0].txid);
    try std.testing.expect(def[0].spendable);
    try std.testing.expectEqual(@as(usize, 0), (try w.listOutputs("tokens", true)).len);
    try std.testing.expect(!(try w.map("unproven").has(&ca.txid)) and try w.map("rejected").has(&ca.txid));
    try std.testing.expect(!(try w.map("unproven").has(&cb.txid)) and try w.map("rejected").has(&cb.txid));
    try std.testing.expectError(error.DraftRejected, w.signAction(d.reference.?, signer.signer()));
    // The payment funds a new spend.
    const again = try w.createAction(.{ .description = "again", .outputs = &.{.{ .satoshis = 300, .locking_script = &payee }} }, signer.signer(), "Yw==", "MQ==", 100);
    try std.testing.expectEqualSlices(u8, &p.pay_txid, &(try beef.parse(a, again.beef)).find(again.txid).?.tx.?.inputs[0].previous_outpoint.txid.bytes);

    // Deterministic: the same rejection from the same state gives the same state record.
    var w2 = try lib.wallet.Wallet.load(a, s, before, .regtest);
    try w2.relate(ca.txid, .tx, &mentioner, .mentions);
    try w2.relate(ca.txid, .record, &cbor_cid(0x42), .mentions);
    w2.now = 5000;
    const rej = try w2.reject(ca.txid, "DOUBLE_SPEND_ATTEMPTED");
    try std.testing.expectEqual(@as(usize, 2), rej.len);
    try std.testing.expectEqualStrings(after, try w2.save());
    counts.wallet += 1;
}

test "settlement: a competing spend proven rejects ours; never mined in time is abandoned" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();
    const p = try setupPaid(a, s);
    var signer = lib.builder.KeySigner{ .root = p.our_priv };
    const payee = lib.brc29.p2pkh(try lib.brc29.identityKey(.{0x33} ** 32));

    var w = try lib.wallet.Wallet.load(a, s, p.state, .regtest);
    const ca = try w.createAction(.{ .description = "A", .outputs = &.{.{ .satoshis = 300, .locking_script = &payee }} }, signer.signer(), "YQ==", "MQ==", 100);
    const cb = try w.createAction(.{ .description = "B", .outputs = &.{.{ .satoshis = 200, .locking_script = &payee }} }, signer.signer(), "Yg==", "MQ==", 100);
    const base = try w.save();

    // Another spend of the payment's output (the same key signed it elsewhere) is mined at 1002.
    var wc = try lib.wallet.Wallet.load(a, s, base, .regtest);
    const out0 = (try wc.listOutputs("default", true));
    var pay_out: lib.wallet.OutputView = undefined;
    for (out0) |o| if (std.mem.eql(u8, &o.txid, &p.pay_txid)) {
        pay_out = o;
    };
    const key = (try wc.keyOf(pay_out.record)).?;
    const other = try lib.builder.build(a, signer.signer(), &.{.{ .source_txid = p.pay_txid, .vout = 0, .satoshis = pay_out.satoshis, .locking_script = pay_out.locking_script, .key = key }}, &.{.{ .satoshis = pay_out.satoshis / 2, .locking_script = &payee }}, .{ .key_id = "x y", .counterparty = .self }, 100, true);
    _ = try wc.putTx(other.txid, other.raw);
    _ = try wc.addHeaders(&.{&mine(hdr.hash(&p.h1001), other.txid, 1_700_001_800)});
    try std.testing.expectEqual(lib.wallet.Status.proven, try wc.addProof(other.txid, try soloPath(a, 1002, other.txid)));
    try std.testing.expectEqual(lib.wallet.Status.rejected, try wc.status(ca.txid));
    try std.testing.expectEqual(lib.wallet.Status.rejected, try wc.status(cb.txid));
    try std.testing.expectEqualStrings("double-spent", (try wc.settlement(ca.txid)).?.getText("reason").?);
    _ = try wc.save();
    // The payment's output is spent by the proven transaction: nothing of ours is spendable.
    try std.testing.expectEqual(@as(usize, 0), (try wc.listOutputs("default", false)).len);

    // Never mined: B broadcast at 1000, still unproven at the deadline, is abandoned (A stands).
    var wa = try lib.wallet.Wallet.load(a, s, base, .regtest);
    wa.now = 1000;
    try wa.noteBroadcast(cb.txid, "https://arc.test", "SEEN_ON_NETWORK");
    wa.now = 1000 + 3_600_000 - 1;
    try std.testing.expect(!(try wa.abandonIfDue(cb.txid, 3_600_000)));
    try wa.noteBroadcast(cb.txid, "https://arc.test", "SEEN_IN_ORPHAN_MEMPOOL"); // keeps its `since`
    wa.now = 1000 + 3_600_000;
    try std.testing.expect(try wa.abandonIfDue(cb.txid, 3_600_000));
    try std.testing.expectEqual(lib.wallet.Status.rejected, try wa.status(cb.txid));
    try std.testing.expectEqual(lib.wallet.Status.unproven, try wa.status(ca.txid));
    try std.testing.expectEqualStrings("abandoned", (try wa.settlement(cb.txid)).?.getText("reason").?);
    try std.testing.expect((try wa.awaitingRecord(cb.txid)) == null);
    _ = try wa.save();
    // A's change is spendable again; A's own input stays spent.
    const def = try wa.listOutputs("default", false);
    try std.testing.expectEqual(@as(usize, 1), def.len);
    try std.testing.expectEqualSlices(u8, &ca.txid, &def[0].txid);
    counts.wallet += 1;
}

// ---------------------------------------------------------------- overlay (#36)

/// A demo token: <"tm_demo"> OP_DROP, then P2PKH to `pkh`.
fn tokenScript(pkh: [20]u8) [34]u8 {
    return .{ 0x07, 't', 'm', '_', 'd', 'e', 'm', 'o', 0x75, 0x76, 0xa9, 0x14 } ++ pkh ++ .{ 0x88, 0xac };
}

/// A transaction spending `ins` (each from its source transaction, signed
/// with `priv` as P2PKH-style: <sig> <pubkey>), paying `outs`.
fn spend(a: std.mem.Allocator, ins: []const struct { *const bsvz.transaction.Transaction, u32 }, outs: []const struct { u64, []const u8 }, priv: [32]u8) !struct { tx: bsvz.transaction.Transaction, raw: []const u8, txid: [32]u8 } {
    var b = bsvz.transaction.Builder.init(a);
    for (ins) |i| try b.addInputFromTx(i[0], i[1]);
    for (outs) |o| try b.addOutput(.{ .satoshis = @intCast(o[0]), .locking_script = bsvz.script.Script.init(try a.dupe(u8, o[1])) });
    var tx = try b.build();
    const key = try bsvz.crypto.PrivateKey.fromBytes(priv);
    const unlocks = try a.alloc(bsvz.script.Script, ins.len);
    for (ins, unlocks, 0..) |i, *u, k| {
        const prev = i[0].outputs[i[1]];
        u.* = try bsvz.transaction.templates.p2pkh_spend.signAndBuildUnlockingScript(a, &tx, k, prev.locking_script, prev.satoshis, key, bsvz.transaction.templates.p2pkh_spend.default_scope);
    }
    for (@constCast(tx.inputs), unlocks) |*in, u| in.unlocking_script = u;
    const raw = try tx.serialize(a);
    return .{ .tx = tx, .raw = raw, .txid = beef.txidOf(raw) };
}

/// A submission as the overlay takes it (#50): the BEEF decoded into
/// records, SPV over them, and (`hold`) the records held as the admitting
/// step holds them.
fn submitted(a: std.mem.Allocator, w: *lib.wallet.Wallet, bytes: []const u8, hold: bool) !lib.overlay.Subject {
    const d = try lib.overlay.decode(a, w.store, bytes);
    const sub = try lib.overlay.verifyDecoded(w, d);
    if (hold) {
        const raws = try a.alloc([]const u8, d.txs.len);
        for (d.txs, raws) |t, *r| r.* = t.raw;
        const nodes = try a.alloc([]const u8, d.nodes.len);
        for (d.nodes, nodes) |n, *o| o.* = try a.dupe(u8, &n.bytes);
        try lib.overlay.holdDecoded(w, raws, nodes, d.proven);
    }
    return sub;
}

/// The maintained `byTopic` is exactly `admitted` joined to the spends edge (`spent`), key for key (#36, #41).
fn joinHolds(a: std.mem.Allocator, w: *lib.wallet.Wallet) !void {
    var want: std.ArrayList([]const u8) = .empty;
    for (try w.map("admitted").prefixed("")) |kv| {
        const tl = 1 + @as(usize, kv.key[0]);
        const state: u8 = if (try w.map("spent").has(kv.key[tl..])) 1 else 0;
        try want.append(a, try std.mem.concat(a, u8, &.{ kv.key[0..tl], &.{state}, kv.key[tl..] }));
    }
    std.mem.sort([]const u8, want.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    const have = try w.map("byTopic").prefixed("");
    try std.testing.expectEqual(want.items.len, have.len);
    for (want.items, have) |x, y| try std.testing.expectEqualSlices(u8, x, y.key);
}

test "overlay: submit and admit, spend with retained coins, lookups with valid BEEF, a rejected spend restores" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const s = ms.store();
    const ov = lib.overlay;

    // A mined funding transaction (a mainnet vector), our regtest chain carrying its block's root.
    const utv = std.json.parseFromSliceLeaky(J, a, @embedFile("vectors/beef.json"), .{}) catch unreachable;
    var fund_hex: []const u8 = undefined;
    for (arr(utv, "cases")) |c| if (std.mem.eql(u8, str(c, "name"), "utv-1-in-1-out-atomic")) {
        fund_hex = str(c, "hex");
    };
    const fund = try beef.parse(a, try unhex(a, fund_hex));
    const bump = fund.bumps[0];
    var proven_txid: [32]u8 = undefined;
    for (fund.entries) |e| if (e.format == .raw_with_bump) {
        proven_txid = e.txid;
    };
    const priv = try key32("fdd506efec13e05cdff57ef13e24a60009aba0e8f2162e2cff2886460175cad8");
    const pub_key = try lib.brc29.identityKey(priv);
    const pkh = bsvz.crypto.hash.hash160(&pub_key).bytes;
    const token = tokenScript(pkh);
    var w = try lib.wallet.Wallet.load(a, s, null, .regtest);
    _ = try w.addHeaders(try slices(a, try regtestChain(a, bump.block_height + 1, &.{.{ bump.block_height, beef.rootFor(a, bump, proven_txid).? }})));
    const empty = try w.save();

    // T1 spends the funding output into a token (output 0) and change (output 1).
    const fund_tx = fund.find(fund.atomic.?).?.tx.?;
    const sats: u64 = @intCast(fund_tx.outputs[0].satoshis);
    const tok_sats = sats / 2;
    const t1 = try spend(a, &.{.{ &fund_tx, 0 }}, &.{ .{ tok_sats, &token }, .{ sats - tok_sats - 20, &lib.brc29.p2pkh(pub_key) } }, priv);
    var e1: std.ArrayList(beef.Entry) = .empty;
    try e1.appendSlice(a, fund.entries);
    try e1.append(a, .{ .txid = t1.txid, .format = .raw, .raw = t1.raw, .tx = t1.tx });
    const t1_beef = try beef.serialize(a, .{ .version = beef.V2, .bumps = fund.bumps, .entries = e1.items }); // plain BEEF: the subject is the last

    w = try lib.wallet.Wallet.load(a, s, empty, .regtest);
    w.now = 1000;
    const sub1 = try submitted(a, &w, t1_beef, true);
    try std.testing.expectEqualSlices(u8, &t1.txid, &sub1.txid);
    try std.testing.expectEqual(@as(usize, 0), (try ov.previousCoins(&w, "tm_demo", sub1.tx)).len);
    // Out-of-range or duplicate instructions are refused.
    try std.testing.expectError(error.BadInstructions, ov.apply(&w, sub1, "tm_demo", &.{}, .{ .outputs_to_admit = &.{7} }));
    try std.testing.expectError(error.BadInstructions, ov.apply(&w, sub1, "tm_demo", &.{}, .{ .coins_to_retain = &.{0} }));
    const a1 = try ov.apply(&w, sub1, "tm_demo", &.{}, .{ .outputs_to_admit = &.{0} });
    try std.testing.expectEqualSlices(u32, &.{0}, a1.outputs_to_admit);
    try std.testing.expectEqual(@as(usize, 2), a1.records.len); // the admittance and the judgement
    // A topic that takes nothing records nothing.
    const other = try ov.apply(&w, sub1, "tm_other", &.{}, .{});
    try std.testing.expect(!other.dupe and other.records.len == 0);
    const s1 = try w.save();
    try joinHolds(a, &w);
    try std.testing.expect(try ov.isApplied(&w, "tm_demo", t1.txid));
    try std.testing.expect(!(try ov.isApplied(&w, "tm_other", t1.txid)));
    const adm = (try w.record(a1.records[0]));
    try std.testing.expectEqualStrings("admitted", adm.getText("kind").?);
    try std.testing.expectEqual(tok_sats, adm.getUint("satoshis").?);
    try std.testing.expectEqualStrings("admits", adm.getArray("refs").?[0].getText("rel").?);
    // The `admits` relation in the wallet's dependents.
    var rel_ok = false;
    for (try w.dependentsOf(t1.txid)) |d| rel_ok = rel_ok or (d.tag == .admitted and d.rel == .admits);
    try std.testing.expect(rel_ok);

    // In the topic; the BEEF a lookup answer carries verifies against our chain.
    {
        const live = try ov.inTopic(&w, "tm_demo", false);
        try std.testing.expectEqual(@as(usize, 1), live.len);
        try std.testing.expectEqualSlices(u8, &t1.txid, &live[0].txid);
        const ans = try beef.parse(a, try ov.beefFor(&w, t1.txid));
        try std.testing.expectEqualSlices(u8, &t1.txid, &ans.atomic.?);
        var fresh = try lib.wallet.Wallet.load(a, s, empty, .regtest); // verified by a node holding only the headers
        var ctx = lib.wallet.Wallet.SpvCtx{ .w = &fresh };
        const res = try lib.spv.verify(a, ans, .{ .ptr = &ctx, .rootAtFn = lib.wallet.Wallet.SpvCtx.rootAt, .knownRawFn = lib.wallet.Wallet.SpvCtx.knownRaw });
        try std.testing.expect(res.proven[0]);
    }

    // T2 spends the token into a new token: the topic retains the old one for history.
    const t2 = try spend(a, &.{.{ &t1.tx, 0 }}, &.{.{ tok_sats - 10, &token }}, priv);
    const e2 = try a.dupe(beef.Entry, &.{.{ .txid = t2.txid, .format = .raw, .raw = t2.raw, .tx = t2.tx }});
    const t2_beef = try beef.serialize(a, .{ .version = beef.V2, .atomic = t2.txid, .bumps = &.{}, .entries = e2 });
    w = try lib.wallet.Wallet.load(a, s, s1, .regtest);
    w.now = 2000;
    const sub2 = try submitted(a, &w, t2_beef, true); // its input's source is held
    const prev2 = try ov.previousCoins(&w, "tm_demo", sub2.tx);
    try std.testing.expectEqualSlices(u32, &.{0}, prev2);
    const a2 = try ov.apply(&w, sub2, "tm_demo", prev2, .{ .outputs_to_admit = &.{0}, .coins_to_retain = &.{0} });
    try std.testing.expectEqualSlices(u32, &.{0}, a2.coins_to_retain);
    try std.testing.expectEqual(@as(usize, 0), a2.coins_removed.len);
    try std.testing.expect((try ov.apply(&w, sub2, "tm_demo", prev2, .{})).dupe);
    const s2 = try w.save();
    try joinHolds(a, &w);
    {
        const live = try ov.inTopic(&w, "tm_demo", false);
        try std.testing.expectEqual(@as(usize, 1), live.len);
        try std.testing.expectEqualSlices(u8, &t2.txid, &live[0].txid);
        const all = try ov.inTopic(&w, "tm_demo", true);
        try std.testing.expectEqual(@as(usize, 2), all.len);
        // Spent within the topic = admitted ⋈ the spends edge; retained = T2's judgement (`applied`).
        const sp = (try ov.spender(&w, "tm_demo", t1.txid, 0)).?;
        try std.testing.expectEqualSlices(u8, &t2.txid, &sp.txid);
        try std.testing.expect(sp.retained and sp.judged);
        try std.testing.expect((try ov.spender(&w, "tm_demo", t2.txid, 0)) == null);
        // The answer for T2 carries its unmined ancestry down to the proven funding.
        const ans = try beef.parse(a, try ov.beefFor(&w, t2.txid));
        try std.testing.expectEqual(fund.entries.len + 2, ans.entries.len);
    }

    // T2 is rejected (a status entry: ARC saw a double spend): its admittance
    // and judgement vanish, and T1's token is live in the topic again.
    w = try lib.wallet.Wallet.load(a, s, s2, .regtest);
    w.now = 3000;
    try std.testing.expectEqual(lib.wallet.Wallet.Outcome.rejected, try w.applyStatus(t2.txid, "DOUBLE_SPEND_ATTEMPTED", null));
    // The judgement it removed, for the topic's lookup services (#50: `rejected`).
    try std.testing.expectEqual(@as(usize, 1), w.unapplied.items.len);
    try std.testing.expectEqualStrings("tm_demo", w.unapplied.items[0].topic);
    try std.testing.expectEqualSlices(u8, &t2.txid, &w.unapplied.items[0].txid);
    const s3 = try w.save();
    try joinHolds(a, &w);
    {
        const live = try ov.inTopic(&w, "tm_demo", true);
        try std.testing.expectEqual(@as(usize, 1), live.len);
        try std.testing.expectEqualSlices(u8, &t1.txid, &live[0].txid);
        try std.testing.expect(!live[0].spent);
        try std.testing.expect(!(try ov.isApplied(&w, "tm_demo", t2.txid)));
        // Resubmitting a rejected transaction is refused.
        try std.testing.expectError(error.TransactionRejected, submitted(a, &w, t2_beef, false));
    }
    // Deterministic: the same rejection from the same state gives the same state record.
    var w3 = try lib.wallet.Wallet.load(a, s, s2, .regtest);
    w3.now = 3000;
    _ = try w3.reject(t2.txid, "DOUBLE_SPEND_ATTEMPTED");
    try std.testing.expectEqualStrings(s3, try w3.save());

    // T1 rejected instead: bubbles to T2 (it spends T1), every admittance vanishes.
    var w4 = try lib.wallet.Wallet.load(a, s, s2, .regtest);
    w4.now = 3000;
    try std.testing.expectEqual(@as(usize, 2), (try w4.reject(t1.txid, "REJECTED")).len);
    // Both judgements removed, in the walk's order.
    try std.testing.expectEqual(@as(usize, 2), w4.unapplied.items.len);
    try std.testing.expectEqualSlices(u8, &t1.txid, &w4.unapplied.items[0].txid);
    try std.testing.expectEqualSlices(u8, &t2.txid, &w4.unapplied.items[1].txid);
    _ = try w4.save();
    try joinHolds(a, &w4);
    try std.testing.expectEqual(@as(usize, 0), (try ov.inTopic(&w4, "tm_demo", true)).len);
    try std.testing.expectEqual(@as(usize, 0), try w4.map("admitted").count());
    counts.wallet += 1;
}

// ---------------------------------------------------------------- index cost (#41)

/// A store that counts what is written through it (every put / putblock
/// call) and what is read (every get).
const CountingStore = struct {
    inner: lib.store.Store,
    puts: usize = 0,
    reads: usize = 0,
    fn store(self: *CountingStore) lib.store.Store {
        return .{ .ptr = self, .getFn = get, .putFn = put, .putBlockFn = putBlock, .keepFn = keep, .edgesFn = edges };
    }
    fn get(ptr: *anyopaque, arena: std.mem.Allocator, cid: []const u8) anyerror![]const u8 {
        const self: *CountingStore = @ptrCast(@alignCast(ptr));
        self.reads += 1;
        return self.inner.get(arena, cid);
    }
    // Keeping writes no block (the kernel's edges are its index, not the wallet's).
    fn keep(ptr: *anyopaque, cid: []const u8) anyerror!void {
        const self: *CountingStore = @ptrCast(@alignCast(ptr));
        return self.inner.keep(cid);
    }
    fn edges(ptr: *anyopaque, arena: std.mem.Allocator, to: []const u8, rel: ?[]const u8) anyerror![]const lib.store.Edge {
        const self: *CountingStore = @ptrCast(@alignCast(ptr));
        return self.inner.edges(arena, to, rel);
    }
    fn put(ptr: *anyopaque, arena: std.mem.Allocator, bytes: []const u8) anyerror![]const u8 {
        const self: *CountingStore = @ptrCast(@alignCast(ptr));
        self.puts += 1;
        return self.inner.put(arena, bytes);
    }
    fn putBlock(ptr: *anyopaque, cid: []const u8, bytes: []const u8) anyerror!void {
        const self: *CountingStore = @ptrCast(@alignCast(ptr));
        self.puts += 1;
        return self.inner.putBlock(cid, bytes);
    }
};

/// A raw transaction: one input (`prev`), `n` outputs of `script` (unsigned: putTx does not verify).
fn rawTx(a: std.mem.Allocator, prev: [32]u8, prev_vout: u32, n: u32, script: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, &.{ 1, 0, 0, 0, 1 });
    try out.appendSlice(a, &prev);
    try out.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u32, prev_vout)));
    try out.appendSlice(a, &.{ 0, 0xff, 0xff, 0xff, 0xff });
    if (n < 0xfd) try out.append(a, @intCast(n)) else {
        try out.append(a, 0xfd);
        try out.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u16, @intCast(n))));
    }
    for (0..n) |i| {
        try out.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, 1000 + i)));
        try out.append(a, @intCast(script.len));
        try out.appendSlice(a, script);
    }
    try out.appendSlice(a, &.{ 0, 0, 0, 0 });
    return out.items;
}

fn insertOutput(a: std.mem.Allocator, w: *lib.wallet.Wallet, txid: [32]u8, tx_cid: []const u8, vout: u32) !void {
    try w.putOutput(txid, vout, .{ .map = try a.dupe(lib.cbor.Entry, &.{
        .{ .key = "kind", .value = .{ .text = "output" } },
        .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &hdr.toHex(txid)) } },
        .{ .key = "vout", .value = .{ .uint = vout } },
        .{ .key = "tx", .value = .{ .cid = tx_cid } },
        .{ .key = "basket", .value = .{ .text = "tokens" } },
        .{ .key = "protocol", .value = .{ .text = "basket insertion" } },
    }) });
}

/// Blocks written (put / putblock calls) to add one transaction of ours — the
/// transaction, its action, one output record, the index nodes and the state
/// record — to a wallet holding `n` outputs.
fn costOfOneTx(n: u32) !usize {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = lib.store.MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const script = lib.brc29.p2pkh(try lib.brc29.identityKey(.{0x33} ** 32));
    var w = try lib.wallet.Wallet.load(a, ms.store(), null, .regtest);
    const big = try rawTx(a, .{0x11} ** 32, 0, n, &script);
    const big_txid = beef.txidOf(big);
    const big_cid = try w.putTx(big_txid, big);
    try w.putAction(big_txid, big_cid, "many", &.{}, null);
    for (0..n) |i| try insertOutput(a, &w, big_txid, big_cid, @intCast(i));
    const state = try w.save();

    var cs = CountingStore{ .inner = ms.store() };
    var w2 = try lib.wallet.Wallet.load(a, cs.store(), state, .regtest);
    const one = try rawTx(a, big_txid, n / 2, 1, &script);
    const one_txid = beef.txidOf(one);
    const one_cid = try w2.putTx(one_txid, one);
    try w2.putAction(one_txid, one_cid, "one", &.{}, null);
    try insertOutput(a, &w2, one_txid, one_cid, 0);
    _ = try w2.save();
    // The spent output moved in byBasket.
    try std.testing.expectEqual(@as(usize, n), (try w2.listOutputs("tokens", false)).len);
    return cs.puts;
}

test "index cost: blocks written per transaction, independent of store size (#41)" {
    // 10k outputs natively; fewer under wasm32-wasi (building the store there
    // runs the test runner's allocator out of pages, not the wallet).
    const n: u32 = if (@import("builtin").cpu.arch == .wasm32) 2_000 else 10_000;
    const small = try costOfOneTx(100);
    const large = try costOfOneTx(n);
    std.debug.print("\nindex cost: one tx writes {d} blocks at 100 outputs, {d} at {d} outputs\n", .{ small, large, n });
    // Bounded, and independent of the store's size (the MST's depth grows by
    // one level per ×32 keys: a few nodes at most between the two).
    try std.testing.expect(large < 40);
    try std.testing.expect(large <= small + 8);
}

fn cbor_cid(b: u8) [36]u8 {
    return lib.cbor.cidOf(&.{b});
}

test "zz: vector counts" {
    std.debug.print("\nvectors passed: tx {d} (fees {d}), beef {d}, merkle {d}, headers {d}, brc29 {d}, wire {d}, signing {d}, chronicle {d}; wallet scenarios {d}\n", .{ counts.tx, counts.fee, counts.beef, counts.path, counts.header, counts.brc29, counts.wire, counts.sign, counts.chronicle, counts.wallet });
}
