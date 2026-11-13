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
var counts = struct { sign: usize = 0, tx: usize = 0, fee: usize = 0, beef: usize = 0, path: usize = 0, header: usize = 0, brc29: usize = 0, wire: usize = 0, chronicle: usize = 0 }{};

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
        var w = try lib.chainstate.State.load(a, ms.store(), null, .regtest);
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
        // Never proven here (skein next: the chain state's putProof links every leaf a path covers,
        // siblings too — 0, 5 — so the uncovered leaf 2 stands for "not proven").
        try std.testing.expect((try w.proofFor(leaves[2])) == null);
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
    var w = try lib.chainstate.State.load(a, ms.store(), null, .regtest);
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

const sighash_all_forkid: u32 = 0x41;

fn counterpartyOf(k: J) !lib.wire.Counterparty {
    const c = str(k, "counterparty");
    return if (std.mem.eql(u8, c, "self")) .self else .{ .other = try key33(c) };
}

// skein next (SPEC 6, plan B24): the transaction builder (wallet/src/builder.zig) is deleted with the
// combined wallet; the go-sdk ProtoWallet vectors are kept, checked over the transaction each case
// recorded instead of one built here — the request frames (BRC-100 getPublicKey / createSignature,
// lib.wire), each input's preimage and sighash (BIP143 ALL|FORKID), the signature result read back
// into the P2PKH unlock, each script verified, the fee the inputs less the outputs. What only the
// builder did (fee estimation from the rate, change, coin selection, the KeySigner equivalence,
// InsufficientFunds, UnlockingScriptTooLong) went with it.
test "vectors: spends signed through the oracle — frames, sighash, unlock, fee, tx (go-sdk ProtoWallet)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = try load(a, "signing.json");
    const root = try key32(str(v, "rootKey"));
    try std.testing.expectEqualStrings(str(v, "identityKey"), &std.fmt.bytesToHex(try lib.brc29.identityKey(root), .lower));
    for (arr(v, "cases")) |c| {
        const raw = try unhex(a, str(c, "tx"));
        const tx = try bsvz.transaction.Transaction.parse(a, raw);
        try std.testing.expectEqualStrings(str(c, "txid"), &hdr.toHex(beef.txidOf(raw)));
        try std.testing.expectEqual(arr(c, "inputs").len, tx.inputs.len);
        var in_sats: u64 = 0;
        for (arr(c, "inputs"), 0..) |in, i| {
            const src = try bsvz.transaction.Transaction.parse(a, try unhex(a, str(in, "sourceTx")));
            const vout: u32 = @intCast(int(in, "vout"));
            const lock = src.outputs[vout].locking_script.bytes;
            const sats: u64 = @intCast(int(in, "satoshis"));
            in_sats += sats;
            try std.testing.expectEqualStrings(str(in, "lockingScript"), try hexOf(a, lock));
            try std.testing.expectEqualSlices(u8, &(try hdr.fromHex(str(in, "sourceTxid"))), &tx.inputs[i].previous_outpoint.txid.bytes);
            try std.testing.expectEqual(vout, tx.inputs[i].previous_outpoint.index);
            const pre = try bsvz.transaction.sighash.formatPreimage(a, &tx, i, bsvz.script.Script.init(lock), @intCast(sats), sighash_all_forkid);
            try std.testing.expectEqualStrings(str(in, "preimage"), try hexOf(a, pre));
            const d = try bsvz.transaction.sighash.digest(a, &tx, i, bsvz.script.Script.init(lock), @intCast(sats), sighash_all_forkid);
            try std.testing.expectEqualStrings(str(in, "sighash"), try hexOf(a, &d.bytes));
            try std.testing.expectEqualStrings(str(in, "unlockingScript"), try hexOf(a, tx.inputs[i].unlocking_script.bytes));
            var unlock: std.ArrayList(u8) = .empty;
            if (in.object.get("caller")) |cu| {
                // #93: a caller's input, its own createSignature (its own protocol and keyID) over its sighash.
                const frame = try lib.wire.createSignatureFrame(a, @intCast(int(cu, "securityLevel")), str(cu, "protocol"), str(cu, "keyID"), .self, d.bytes);
                try std.testing.expectEqualStrings(str(cu, "createSignatureFrame"), try hexOf(a, frame));
                const der = try lib.wire.signatureResult(try unhex(a, str(cu, "createSignatureResult")));
                try unlock.append(a, @intCast(der.len + 1)); // <DER ‖ ALL|FORKID>: go-sdk's PushDrop unlock
                try unlock.appendSlice(a, der);
                try unlock.append(a, @intCast(sighash_all_forkid));
            } else {
                const cp = try counterpartyOf(in);
                const pk_frame = try lib.wire.getPublicKeyFrameFor(a, lib.brc29.security_level, lib.brc29.protocol_name, str(in, "keyID"), cp, true);
                try std.testing.expectEqualStrings(str(in, "getPublicKeyFrame"), try hexOf(a, pk_frame));
                const pk = try lib.wire.publicKeyResult(try unhex(a, str(in, "getPublicKeyResult")));
                try std.testing.expectEqualStrings(str(in, "publicKey"), &std.fmt.bytesToHex(pk, .lower));
                const frame = try lib.wire.createSignatureFrame(a, lib.brc29.security_level, lib.brc29.protocol_name, str(in, "keyID"), cp, d.bytes);
                try std.testing.expectEqualStrings(str(in, "createSignatureFrame"), try hexOf(a, frame));
                const der = try lib.wire.signatureResult(try unhex(a, str(in, "createSignatureResult")));
                try unlock.append(a, @intCast(der.len + 1)); // <DER ‖ ALL|FORKID> <public key>
                try unlock.appendSlice(a, der);
                try unlock.append(a, @intCast(sighash_all_forkid));
                try unlock.append(a, 33);
                try unlock.appendSlice(a, &pk);
            }
            try std.testing.expectEqualSlices(u8, unlock.items, tx.inputs[i].unlocking_script.bytes);
            try std.testing.expect(try bsvz.script.interpreter.verifyPrevout(.{
                .allocator = a,
                .tx = &tx,
                .input_index = i,
                .previous_output = .{ .satoshis = @intCast(sats), .locking_script = bsvz.script.Script.init(lock) },
                .unlocking_script = tx.inputs[i].unlocking_script,
            }));
            counts.sign += 1;
        }
        // The outputs as given, then the change (when any) to the change key's P2PKH.
        const outs = arr(c, "outputs");
        var out_sats: u64 = 0;
        for (outs, 0..) |o, k| {
            try std.testing.expectEqual(@as(i64, int(o, "satoshis")), @as(i64, @intCast(tx.outputs[k].satoshis)));
            try std.testing.expectEqualStrings(str(o, "lockingScript"), try hexOf(a, tx.outputs[k].locking_script.bytes));
        }
        for (tx.outputs) |o| out_sats += @intCast(o.satoshis);
        const ch = c.object.get("change").?;
        const cpk_frame = try lib.wire.getPublicKeyFrameFor(a, lib.brc29.security_level, lib.brc29.protocol_name, str(ch, "keyID"), try counterpartyOf(ch), true);
        try std.testing.expectEqualStrings(str(ch, "getPublicKeyFrame"), try hexOf(a, cpk_frame));
        const cs = ch.object.get("satoshis").?;
        if (cs == .null) try std.testing.expectEqual(outs.len, tx.outputs.len) else {
            try std.testing.expectEqual(outs.len + 1, tx.outputs.len);
            try std.testing.expectEqual(@as(i64, cs.integer), @as(i64, @intCast(tx.outputs[outs.len].satoshis)));
            try std.testing.expectEqualStrings(str(ch, "lockingScript"), try hexOf(a, tx.outputs[outs.len].locking_script.bytes));
        }
        try std.testing.expectEqual(@as(u64, @intCast(int(c, "fee"))), in_sats - out_sats);
    }
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

// ---------------------------------------------------------------- regtest headers

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

// ---------------------------------------------------------------- a counting store

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

test "zz: vector counts" {
    std.debug.print("\nvectors passed: tx {d} (fees {d}), beef {d}, merkle {d}, headers {d}, brc29 {d}, wire {d}, signing {d}, chronicle {d}\n", .{ counts.tx, counts.fee, counts.beef, counts.path, counts.header, counts.brc29, counts.wire, counts.sign, counts.chronicle });
}

// ---------------------------------------------------------------- one BUMP per block, selected (no merges)

/// Every node of a full tree into the store (64-byte bitcoin-tx blocks).
fn putTree(s: lib.store.Store, tree: []const []const [32]u8) !void {
    for (tree[0 .. tree.len - 1], 0..) |cur, k| {
        var i: usize = 0;
        while (i < cur.len) : (i += 2) {
            const l = cur[i];
            const r = if (i + 1 < cur.len) cur[i + 1] else l;
            try lib.merkle.putNodes(s, &.{.{ .hash = tree[k + 1][i / 2], .bytes = l ++ r }});
        }
    }
}

/// The BUMP the accumulators made before: the one-leaf paths, `combine`d in `order`, txids flagged.
fn combined(a: std.mem.Allocator, s: lib.store.Store, root: [32]u8, height: u32, leaves: []const lib.merkle.Leaf, order: []const usize) ![]const u8 {
    var acc: ?bsvz.spv.MerklePath = null;
    for (order) |k| {
        const p = (try lib.merkle.pathFor(a, s, root, height, leaves[k].txid, leaves[k].pos)).?;
        if (acc) |*q| try q.combine(&p, a) else acc = p;
    }
    for (acc.?.path[0]) |*l| if (l.hash) |h| for (leaves) |x| if (std.mem.eql(u8, &h.bytes, &x.txid)) {
        l.txid = true;
    };
    return acc.?.bytes(a);
}

/// Every order of `0..k` (Heap's algorithm), each handed to `f`.
fn eachOrder(a: std.mem.Allocator, k: usize, ctx: anytype, comptime f: fn (@TypeOf(ctx), []const usize) anyerror!void) !void {
    const order = try a.alloc(usize, k);
    for (order, 0..) |*o, i| o.* = i;
    const c = try a.alloc(usize, k);
    @memset(c, 0);
    try f(ctx, order);
    var i: usize = 1;
    while (i < k) {
        if (c[i] < i) {
            if (i % 2 == 0) std.mem.swap(usize, &order[0], &order[i]) else std.mem.swap(usize, &order[c[i]], &order[i]);
            try f(ctx, order);
            c[i] += 1;
            i = 1;
        } else {
            c[i] = 0;
            i += 1;
        }
    }
}

const Orders = struct {
    a: std.mem.Allocator,
    s: lib.store.Store,
    root: [32]u8,
    leaves: []const lib.merkle.Leaf,
    first: ?[]const u8 = null,
    same: bool = true,
    ours: ?[]const u8 = null,
    matched: bool = false,
    fn one(self: *Orders, order: []const usize) !void {
        const got = try combined(self.a, self.s, self.root, 1, self.leaves, order);
        if (self.ours) |x| if (std.mem.eql(u8, x, got)) {
            self.matched = true;
        };
        if (self.first) |f| {
            if (!std.mem.eql(u8, f, got)) self.same = false;
        } else self.first = got;
    }
};

/// A block of `size` synthetic transactions, its whole tree in a MemStore.
const Block = struct {
    ms: lib.store.MemStore,
    leaves: [][32]u8,
    tree: []const []const [32]u8,
    fn init(a: std.mem.Allocator, size: usize) !Block {
        var b: Block = .{ .ms = lib.store.MemStore.init(std.testing.allocator), .leaves = try a.alloc([32]u8, size), .tree = undefined };
        for (b.leaves, 0..) |*l, i| l.* = lib.store.dblSha256(std.mem.asBytes(&i));
        b.tree = try fullTree(a, b.leaves);
        try putTree(b.ms.store(), b.tree);
        return b;
    }
    fn root(b: *const Block) [32]u8 {
        return b.tree[b.tree.len - 1][0];
    }
    fn leaf(b: *const Block, i: usize) lib.merkle.Leaf {
        return .{ .txid = b.leaves[i], .pos = .{ .depth = @intCast(b.tree.len - 1), .offset = i } };
    }
};

test "pathsFor: one BUMP for several transactions of a block, selected in one descent — byte for byte the one combine makes of their one-leaf paths, in every order" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // Named cases: an odd block whose last leaf's sibling is the duplicate, leaf pairs, a whole small
    // block, one leaf (= pathFor), a leaf named twice, a one-transaction block.
    const Case = struct { size: usize, picks: []const usize };
    const cases = [_]Case{
        .{ .size = 7, .picks = &.{ 1, 4, 6 } },
        .{ .size = 7, .picks = &.{6} },
        .{ .size = 7, .picks = &.{ 6, 2, 3 } },
        .{ .size = 13, .picks = &.{ 0, 5, 12 } },
        .{ .size = 13, .picks = &.{ 12, 12, 1 } },
        .{ .size = 2, .picks = &.{ 0, 1 } },
        .{ .size = 4, .picks = &.{ 0, 1, 2, 3 } },
        .{ .size = 1, .picks = &.{0} },
        .{ .size = 1, .picks = &.{ 0, 0 } },
        .{ .size = 100, .picks = &.{ 0, 99, 37 } },
    };
    for (cases) |c| {
        var b = try Block.init(a, c.size);
        defer b.ms.deinit();
        var picks: std.ArrayList(lib.merkle.Leaf) = .empty;
        for (c.picks) |i| try picks.append(a, b.leaf(i));
        const got = (try lib.merkle.pathsFor(a, b.ms.store(), b.root(), 1, picks.items)).?;
        var o = Orders{ .a = a, .s = b.ms.store(), .root = b.root(), .leaves = picks.items };
        // Where combine's bytes depend on the order (1, 4, 6 of seven: the level-1 sibling of 1's
        // pair comes back when 1's path is merged last), ours are those of one of the orders;
        // elsewhere those of every order.
        o.ours = try got.bytes(a);
        try eachOrder(a, picks.items.len, &o, Orders.one);
        if (o.same) try std.testing.expectEqualStrings(try hexOf(a, o.first.?), try hexOf(a, o.ours.?)) else try std.testing.expect(o.matched);
        for (picks.items) |l| try std.testing.expectEqualSlices(u8, &b.root(), &beef.rootFor(a, got, l.txid).?);
        if (c.picks.len == 1) try std.testing.expectEqualStrings(
            try hexOf(a, try (try lib.merkle.pathFor(a, b.ms.store(), b.root(), 1, picks.items[0].txid, picks.items[0].pos)).?.bytes(a)),
            try hexOf(a, try got.bytes(a)),
        );
    }

    // Random leaf sets: every leaf proves the root; wherever combine gives the same bytes in every
    // order, ours are those bytes. (combine's result depends on the order for some sets: an upper
    // sibling it left out as computable can come back with a later path. Ours does not.)
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    var same_orders: usize = 0;
    for ([_]usize{ 2, 3, 7, 13, 64, 100, 257 }) |size| {
        var b = try Block.init(a, size);
        defer b.ms.deinit();
        for (0..40) |_| {
            const k = 1 + rnd.uintLessThan(usize, @min(size, 5));
            var picks: std.ArrayList(lib.merkle.Leaf) = .empty;
            for (0..k) |_| try picks.append(a, b.leaf(rnd.uintLessThan(usize, size)));
            const got = (try lib.merkle.pathsFor(a, b.ms.store(), b.root(), 1, picks.items)).?;
            for (picks.items) |l| try std.testing.expectEqualSlices(u8, &b.root(), &beef.rootFor(a, got, l.txid).?);
            const back = try bsvz.spv.MerklePath.parse(a, try got.bytes(a));
            try std.testing.expectEqualSlices(u8, try got.bytes(a), try back.bytes(a));
            var o = Orders{ .a = a, .s = b.ms.store(), .root = b.root(), .leaves = picks.items };
            try eachOrder(a, k, &o, Orders.one);
            if (o.same) {
                same_orders += 1;
                try std.testing.expectEqualSlices(u8, o.first.?, try got.bytes(a));
            }
        }
    }
    try std.testing.expect(same_orders > 200); // 237 of 280 with this seed

    // One read per node on the way, however many leaves pass under it: 1, 4, 6 of seven read the
    // root, both nodes below it and the three leaf pairs' nodes.
    {
        var b = try Block.init(a, 7);
        defer b.ms.deinit();
        var cs = CountingStore{ .inner = b.ms.store() };
        _ = (try lib.merkle.pathsFor(a, cs.store(), b.root(), 1, &.{ b.leaf(1), b.leaf(4), b.leaf(6) })).?;
        try std.testing.expectEqual(@as(usize, 6), cs.reads);
        // Null: a leaf at another txid's position, the duplicate right as a leaf, a node not held,
        // leaves of different depths.
        var wrong = b.leaf(1);
        wrong.pos.offset = 2;
        try std.testing.expect((try lib.merkle.pathsFor(a, b.ms.store(), b.root(), 1, &.{ b.leaf(4), wrong })) == null);
        var dup = b.leaf(6);
        dup.pos.offset = 7;
        try std.testing.expect((try lib.merkle.pathsFor(a, b.ms.store(), b.root(), 1, &.{dup})) == null);
        var deep = b.leaf(4);
        deep.pos.depth = 4;
        try std.testing.expect((try lib.merkle.pathsFor(a, b.ms.store(), b.root(), 1, &.{ b.leaf(1), deep })) == null);
        var empty = lib.store.MemStore.init(std.testing.allocator);
        defer empty.deinit();
        try std.testing.expect((try lib.merkle.pathsFor(a, empty.store(), b.root(), 1, &.{ b.leaf(1), b.leaf(4) })) == null);
    }
}

test "pathsFor: K leaves of one block — the one descent against the one-leaf paths combined (time, store reads)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var b = try Block.init(a, 4096);
    defer b.ms.deinit();
    const io = std.testing.io;
    for ([_]usize{ 1, 10, 50 }) |k| {
        var picks: std.ArrayList(lib.merkle.Leaf) = .empty;
        for (0..k) |i| try picks.append(a, b.leaf(@intCast((@as(u64, i) * 2654435761) % 4096)));
        const order = try a.alloc(usize, k);
        for (order, 0..) |*o, i| o.* = i;
        var old = CountingStore{ .inner = b.ms.store() };
        const t0 = std.Io.Timestamp.now(io, .awake);
        _ = try combined(a, old.store(), b.root(), 1, picks.items, order);
        const t1 = std.Io.Timestamp.now(io, .awake);
        var new = CountingStore{ .inner = b.ms.store() };
        _ = (try lib.merkle.pathsFor(a, new.store(), b.root(), 1, picks.items)).?;
        const t2 = std.Io.Timestamp.now(io, .awake);
        std.debug.print("pathsFor bench K={d}: combine {d} us, {d} reads; pathsFor {d} us, {d} reads\n", .{ k, @divTrunc(t0.durationTo(t1).nanoseconds, 1000), old.reads, @divTrunc(t1.durationTo(t2).nanoseconds, 1000), new.reads });
        try std.testing.expect(new.reads <= old.reads);
    }
}
