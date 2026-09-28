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
var counts = struct { sign: usize = 0, tx: usize = 0, fee: usize = 0, beef: usize = 0, path: usize = 0, header: usize = 0, brc29: usize = 0, wire: usize = 0, wallet: usize = 0 }{};

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
    try std.testing.expect(try w2.map("byStatus").has(&(.{1} ++ pay_txid)));

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

test "zz: vector counts" {
    std.debug.print("\nvectors passed: tx {d} (fees {d}), beef {d}, merkle {d}, headers {d}, brc29 {d}, wire {d}, signing {d}; wallet scenarios {d}\n", .{ counts.tx, counts.fee, counts.beef, counts.path, counts.header, counts.brc29, counts.wire, counts.sign, counts.wallet });
}
