//! An overlay's state (issue #36): what topics admitted, over the same records
//! and the same settlement as the wallet. An overlay is the transaction graph
//! the wallet holds, judged and indexed differently: a submitted transaction
//! (BRC-22) is SPV-checked against the chain the wallet tracks and held like
//! any other (`txs`, `proofs`, kept: a `spends` edge per input, #42);
//! what a topic's program decided is recorded here as index maps in the
//! wallet's own state record (wallet.zig `map_names`), so one instance can be
//! a wallet and an overlay at once and a transaction's settlement (#37) is one
//! thing for both.
//!
//! The maps (keys bytes, ordered bytewise; `tp` = len ‖ topic):
//!   admitted       tp ‖ txid ‖ vout → admittance record {kind: "admitted", topic, txid, vout, script, satoshis, admittedAt, tx, refs}
//!   applied        tp ‖ txid → applied record {kind: "applied", topic, txid, outputsToAdmit, coinsToRetain, coinsRemoved, at, tx, refs}
//!   byTopic        tp ‖ 0 (unspent) | 1 (spent) ‖ outpoint → null         derived
//!
//! Indexes for answering queries are not here: each lookup service keeps its
//! own, under its own head, through the hooks the engine calls (#50: `Caller`,
//! `hookAdmitted`, `hookRejected`; programs/overlay/src/lookup.zig).
//!
//! Spent within a topic (#36 notes) is not a table of its own: it is
//! `admitted` joined to the spends edge — the wallet's `spent[outpoint]`, the
//! first spender we hold that is not rejected (topic-independent). Whether
//! the topic retained that coin is its judgement of the spending transaction:
//! the `applied` record for (topic, spender), its `coinsToRetain` (`spender`).
//!
//! The derived maps are maintained where a fact changes (#41): an admittance
//! (`apply`), an admittance that vanishes (Wallet.reject → `unadmit`), and an
//! admitted outpoint turning spent or unspent (Wallet.refreshSpent → `spentChanged`).
//!
//! Relations (the wallet's `dependents`, #37): an admitted output and an
//! applied record stand on their transaction with rel `admits` (tags `m`,
//! `p`): a rejected transaction's admittances vanish (Wallet.reject), and
//! since `spent` counts only spenders that are not rejected, a rejected spend
//! gives the admitted outputs it consumed back to the topic.
//! The records also carry `refs: [{to: <tx CID>, rel: "admits"}]`, so the
//! step that keeps them gives the kernel the same edges (docs/VM.md "Edges").
const std = @import("std");
const bsvz = @import("bsvz");
const cbor = @import("cbor.zig");
const hdr = @import("header.zig");
const beef_mod = @import("beef.zig");
const merkle = @import("merkle.zig");
const store_mod = @import("store.zig");
const wallet_mod = @import("wallet.zig");

const Wallet = wallet_mod.Wallet;
const Value = cbor.Value;
const Transaction = bsvz.transaction.Transaction;

/// A topic's decision on one transaction (BRC-22 AdmittanceInstructions):
/// output indices to admit, and input indices whose admitted predecessors
/// stay queryable for history.
pub const Instructions = struct {
    outputs_to_admit: []const u32 = &.{},
    coins_to_retain: []const u32 = &.{},
};

/// What a topic's judgement came to (the STEAK's entry for it).
pub const Applied = struct {
    outputs_to_admit: []const u32 = &.{},
    coins_to_retain: []const u32 = &.{},
    /// The previous coins not retained (BRC-22 `coinsRemoved`).
    coins_removed: []const u32 = &.{},
    /// Judged before: nothing recorded again.
    dupe: bool = false,
    /// The records this judgement wrote (admittances, then the applied record): the step keeps them.
    records: []const []const u8 = &.{},
};

/// A transaction being judged: its txid, its CID (bitcoin-tx), and the
/// transaction as its block decodes.
pub const Subject = struct {
    txid: [32]u8,
    cid: []const u8,
    tx: Transaction,
};

/// A transaction a submission carried, as decoded: its txid and block bytes.
pub const DecodedTx = struct { txid: [32]u8, raw: []const u8 };
/// A BUMP's block, as the submission's merkle nodes reach it: its height and root.
pub const Bump = struct { height: u32, root: [32]u8 };
/// A transaction a BUMP proves (flagged as a txid in it), at that BUMP's height.
pub const Proven = struct { txid: [32]u8, height: u32 };

/// A submitted BEEF decoded into records (#50): each transaction a
/// `bitcoin-tx` block, each BUMP the merkle nodes it reveals (64-byte
/// `bitcoin-tx` blocks, merkle.zig). The blocks are put when decoded — in a
/// front-door call they land in the call's in-memory overlay, and nothing
/// persists unless the submission is admitted. What is here besides the
/// blocks is what the BEEF said about them: the order, the subject, which
/// BUMP proves which transaction, which entries named a txid only.
pub const Decoded = struct {
    subject: [32]u8,
    /// Every transaction with its bytes, in BEEF order (parents first).
    txs: []const DecodedTx,
    /// The merkle nodes the BUMPs reveal, each once.
    nodes: []const merkle.Node,
    /// The BUMPs that prove something here (a txid-flagged leaf, or one of ours).
    bumps: []const Bump,
    proven: []const Proven,
    /// Entries that named a txid only (they must be held).
    txid_only: []const [32]u8,
};

pub fn topicPrefix(a: std.mem.Allocator, topic: []const u8) ![]u8 {
    if (topic.len == 0) return error.BadTopic;
    return store_mod.nameKey(a, topic, &.{});
}

fn cat(a: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    return std.mem.concat(a, u8, parts);
}

// ---------------------------------------------------------------- submit (BRC-22)

/// Whether the BUMP flags this txid as a transaction (not just a sibling hash).
fn flagged(p: merkle.MerklePath, txid: [32]u8) bool {
    if (p.path.len == 0) return false;
    for (p.path[0]) |leaf| if (leaf.hash) |h| if (std.mem.eql(u8, &h.bytes, &txid)) return leaf.txid orelse false;
    return false;
}

/// Decode a submitted BEEF (V1, V2 or Atomic: the subject is the Atomic
/// BEEF's, else the last transaction) into records, parsing it once (#50):
/// each transaction put as its `bitcoin-tx` block, each BUMP as the merkle
/// nodes it reveals (hash-checked by the store). Nothing is kept here: in a
/// front-door call the blocks live in the call's overlay; the step that
/// admits the submission holds them (`holdDecoded`). Structure is checked
/// (parents first, a BUMP that names a transaction holds it, BUMPs that
/// agree with themselves); the chain and the scripts are `verifyDecoded`'s.
pub fn decode(a: std.mem.Allocator, s: store_mod.Store, bytes: []const u8) !Decoded {
    const b = beef_mod.parse(a, bytes) catch return error.InvalidBeef;
    const subject = b.subject() orelse return error.InvalidBeef;
    const entry = b.find(subject) orelse return error.InvalidBeef;
    if (entry.raw == null) return error.InvalidBeef; // a txid-only subject
    if (!beef_mod.parentsFirst(b)) return error.NotParentsFirst;

    // The BUMPs that prove something here: their nodes, and the root they reach.
    var bumps: std.ArrayList(Bump) = .empty;
    var nodes: std.ArrayList(merkle.Node) = .empty;
    const bump_of = try a.alloc(?usize, b.bumps.len); // BEEF bump index → `bumps` index
    for (b.bumps, bump_of) |p, *bi| {
        bi.* = null;
        if (p.path.len == 0) return error.RootMismatch;
        var relevant = false;
        for (p.path[0]) |leaf| {
            const h = leaf.hash orelse continue;
            relevant = relevant or (leaf.txid orelse false) or b.find(h.bytes) != null;
        }
        if (!relevant) continue; // a BUMP proving nothing here is harmless
        const rev = merkle.reveal(a, p) catch return error.RootMismatch;
        outer: for (rev.nodes) |n| {
            for (nodes.items) |m| if (std.mem.eql(u8, &m.hash, &n.hash)) continue :outer;
            try nodes.append(a, n);
        }
        bi.* = bumps.items.len;
        try bumps.append(a, .{ .height = p.block_height, .root = rev.root });
    }
    for (nodes.items) |n| try s.putBlock(&merkle.nodeCid(n.hash), &n.bytes);

    var txs: std.ArrayList(DecodedTx) = .empty;
    var proven: std.ArrayList(Proven) = .empty;
    var txid_only: std.ArrayList([32]u8) = .empty;
    for (b.entries) |e| {
        switch (e.format) {
            .txid_only => {
                try txid_only.append(a, e.txid);
                continue;
            },
            .raw_with_bump => {
                const i = e.bump.?;
                if (!beef_mod.bumpHas(b.bumps[i], e.txid)) return error.NotInBump;
                try proven.append(a, .{ .txid = e.txid, .height = bumps.items[bump_of[i].?].height });
            },
            .raw => for (b.bumps, bump_of) |p, bi| {
                const i = bi orelse continue;
                if (!flagged(p, e.txid)) continue;
                try proven.append(a, .{ .txid = e.txid, .height = bumps.items[i].height });
                break;
            },
        }
        const raw = e.raw.?;
        try s.putBlock(&store_mod.hashCid(.tx, e.txid), raw);
        try txs.append(a, .{ .txid = e.txid, .raw = raw });
    }
    return .{ .subject = subject, .txs = txs.items, .nodes = nodes.items, .bumps = bumps.items, .proven = proven.items, .txid_only = txid_only.items };
}

/// A transaction's block, read (`get`: in a call, through its overlay) and decoded.
pub fn subjectOf(w: *Wallet, txid: [32]u8) !Subject {
    const c = try w.arena.dupe(u8, &store_mod.hashCid(.tx, txid));
    const raw = w.store.get(w.arena, c) catch return error.MissingInput;
    return .{ .txid = txid, .cid = c, .tx = Transaction.parse(w.arena, raw) catch return error.InvalidBeef };
}

fn provenAt(d: Decoded, txid: [32]u8) ?u32 {
    for (d.proven) |p| if (std.mem.eql(u8, &p.txid, &txid)) return p.height;
    return null;
}

fn rootAtHeight(d: Decoded, height: u32) ?[32]u8 {
    for (d.bumps) |b| if (b.height == height) return b.root;
    return null;
}

/// SPV over the decoded records (#50), against our chain, as `internalize`
/// does over a BEEF: every BUMP's root is our header's at its height (an
/// unknown height is refused) and each proven transaction is reached from it
/// through the merkle nodes; every other transaction's inputs come from a
/// transaction decoded before it or held, read through `get`, with their
/// scripts verified; a txid-only entry names a transaction we hold. A
/// subject already rejected, or spending an output a proven transaction
/// spends, is refused. → the subject.
pub fn verifyDecoded(w: *Wallet, d: Decoded) !Subject {
    const a = w.arena;
    for (d.bumps) |b| {
        const want = (try w.chain().rootAt(b.height)) orelse return error.UnknownHeader;
        if (!std.mem.eql(u8, &want, &b.root)) return error.RootMismatch;
    }
    for (d.proven) |p| {
        const root = rootAtHeight(d, p.height) orelse return error.NotInBump;
        if ((try merkle.pathFor(a, w.store, root, p.height, p.txid)) == null) return error.NotInBump;
    }
    for (d.txid_only) |t| if ((try w.txRaw(t)) == null) return error.UnknownTxidOnly;
    for (d.txs, 0..) |t, i| {
        if (provenAt(d, t.txid) != null) continue;
        const sub = try subjectOf(w, t.txid);
        for (sub.tx.inputs, 0..) |in, k| {
            const src_txid = in.previous_outpoint.txid.bytes;
            const earlier = for (d.txs[0..i]) |x| {
                if (std.mem.eql(u8, &x.txid, &src_txid)) break true;
            } else false;
            if (!earlier and (try w.txRaw(src_txid)) == null) return error.MissingInput;
            const src = try subjectOf(w, src_txid);
            if (in.previous_outpoint.index >= src.tx.outputs.len) return error.MissingInput;
            const ok = bsvz.script.interpreter.verifyPrevout(.{
                .allocator = a,
                .tx = &sub.tx,
                .input_index = k,
                .previous_output = src.tx.outputs[in.previous_outpoint.index],
                .unlocking_script = in.unlocking_script,
            }) catch false;
            if (!ok) return error.ScriptFailed;
        }
    }
    const subject = try subjectOf(w, d.subject);
    if (try w.map("rejected").has(&d.subject)) return error.TransactionRejected;
    for (subject.tx.inputs) |in| {
        const op = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
        for (try w.spendersOf(op)) |other| {
            if (std.mem.eql(u8, &other, &d.subject)) continue;
            if ((try w.status(other)) == .proven) return error.DoubleSpend;
        }
    }
    return subject;
}

/// Whether the topic judged this transaction already (a dupe: BRC-22 answers it with nothing new).
pub fn isApplied(w: *Wallet, topic: []const u8, txid: [32]u8) !bool {
    return w.map("applied").has(try cat(w.arena, &.{ try topicPrefix(w.arena, topic), &txid }));
}

/// The input indices of `tx` that spend an output live in the topic
/// (admitted, its transaction not rejected, not spent by another transaction
/// we hold that is not rejected): BRC-22's `previousCoins`.
pub fn previousCoins(w: *Wallet, topic: []const u8, tx: Transaction) ![]u32 {
    const a = w.arena;
    const tp = try topicPrefix(a, topic);
    const self_txid = (try tx.txid(a)).bytes;
    var out: std.ArrayList(u32) = .empty;
    for (tx.inputs, 0..) |in, i| {
        const op = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
        if (!(try w.map("admitted").has(try cat(a, &.{ tp, &op })))) continue;
        if (try spentByOther(w, op, self_txid)) continue;
        try out.append(a, @intCast(i));
    }
    return out.items;
}

/// Whether a transaction we hold other than `tx`, not rejected, spends `op`.
fn spentByOther(w: *Wallet, op: [36]u8, tx: [32]u8) !bool {
    for (try w.spendersOf(op)) |sp| {
        if (std.mem.eql(u8, &sp, &tx)) continue;
        if (!(try w.map("rejected").has(&sp))) return true;
    }
    return false;
}

/// Who spent an admitted output, as the topic sees it: the spends edge (the
/// wallet's `spent`, the first spender not rejected) joined to the topic's
/// judgement of that spender (`applied`: whether it retained the coin).
/// Null while it is unspent (or not admitted).
pub fn spender(w: *Wallet, topic: []const u8, txid: [32]u8, vout: u32) !?struct { txid: [32]u8, retained: bool, judged: bool } {
    const a = w.arena;
    const tp = try topicPrefix(a, topic);
    const op = store_mod.outpointKey(txid, vout);
    if (!(try w.map("admitted").has(try cat(a, &.{ tp, &op })))) return null;
    const v = (try w.map("spent").get(&op)) orelse return null;
    if (v != .bytes or v.bytes.len != 32) return error.BadIndex;
    const sp: [32]u8 = v.bytes[0..32].*;
    const rc = (try w.map("applied").link(try cat(a, &.{ tp, &sp }))) orelse return .{ .txid = sp, .retained = false, .judged = false };
    const raw = (try w.txRaw(sp)) orelse return error.BadRecord;
    const tx = try Transaction.parse(a, raw);
    var retained = false;
    for ((try w.record(rc)).getArray("coinsToRetain") orelse &.{}) |c| {
        if (c != .uint or c.uint >= tx.inputs.len) continue;
        const in = tx.inputs[@intCast(c.uint)];
        retained = retained or std.mem.eql(u8, &store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index), &op);
    }
    return .{ .txid = sp, .retained = retained, .judged = true };
}

/// Hold a submission's decoded records (#50), in the step that admits it,
/// like any other transactions we hold: each transaction's block kept
/// (`spends` edges, #42) and in `txs`; the merkle nodes kept (no edges:
/// a proof reads down from the root); each proven transaction's proof recorded (`proofs`, from the
/// header its nodes reach). `txs` are block bytes, `nodes` 64-byte merkle
/// nodes: the records the submit entry carries, not a BEEF.
pub fn holdDecoded(w: *Wallet, txs: []const []const u8, nodes: []const []const u8, proven: []const Proven) !void {
    for (txs) |raw| _ = try w.putTx(store_mod.dblSha256(raw), raw);
    for (nodes) |n| {
        if (n.len != 64) return error.BadNode;
        const c = merkle.nodeCid(store_mod.dblSha256(n));
        try w.store.putBlock(&c, n);
        try w.store.keep(&c);
    }
    for (proven) |p| {
        if (try w.map("proofs").has(&p.txid)) continue;
        try w.putProofAt(p.txid, p.height);
    }
}

fn contains(xs: []const u32, x: u32) bool {
    for (xs) |y| if (y == x) return true;
    return false;
}

fn uints(a: std.mem.Allocator, xs: []const u32) ![]Value {
    const out = try a.alloc(Value, xs.len);
    for (xs, out) |x, *o| o.* = .{ .uint = x };
    return out;
}

fn admitsRef(a: std.mem.Allocator, tx_cid: []const u8) !Value {
    const refs = try a.alloc(Value, 1);
    refs[0] = .{ .map = try a.dupe(cbor.Entry, &.{
        .{ .key = "to", .value = .{ .cid = tx_cid } },
        .{ .key = "rel", .value = .{ .text = "admits" } },
    }) };
    return .{ .array = refs };
}

/// Check a topic's instructions against the transaction: output indices in
/// range and distinct, retained coins among the previous coins.
pub fn check(tx: Transaction, previous: []const u32, ins: Instructions) !void {
    for (ins.outputs_to_admit, 0..) |o, i| {
        if (o >= tx.outputs.len) return error.BadInstructions;
        if (contains(ins.outputs_to_admit[0..i], o)) return error.BadInstructions;
    }
    for (ins.coins_to_retain, 0..) |c, i| {
        if (!contains(previous, c)) return error.BadInstructions;
        if (contains(ins.coins_to_retain[0..i], c)) return error.BadInstructions;
    }
}

/// Whether a topic's instructions take anything: an output admitted, or a
/// previous coin consumed (retained or removed). One that takes nothing
/// records nothing.
pub fn takes(previous: []const u32, ins: Instructions) bool {
    return ins.outputs_to_admit.len > 0 or previous.len > 0;
}

/// Record a topic's judgement of a held submission (BRC-22 step 4; the
/// step holds the decoded records first, `holdDecoded`): each admitted
/// output as an admittance record in `admitted`, the judgement (which
/// previous coins it retains, which it removes) in `applied` — both with rel
/// `admits` on the transaction. The previous coins are spent by the
/// transaction's own `spends` edges (held). `previous` is `previousCoins`
/// for this topic, taken before any judgement of this step. A transaction
/// the topic judged before is a dupe: nothing is written.
pub fn apply(w: *Wallet, sub: Subject, topic: []const u8, previous: []const u32, ins: Instructions) !Applied {
    const a = w.arena;
    if (try isApplied(w, topic, sub.txid)) return .{ .dupe = true };
    try check(sub.tx, previous, ins);
    var removed: std.ArrayList(u32) = .empty;
    for (previous) |p| if (!contains(ins.coins_to_retain, p)) try removed.append(a, p);
    if (!takes(previous, ins)) return .{};

    const tx_cid = sub.cid;
    const tp = try topicPrefix(a, topic);
    const txid_hex = try a.dupe(u8, &hdr.toHex(sub.txid));
    var records: std.ArrayList([]const u8) = .empty;
    const sorted = try a.dupe(u32, ins.outputs_to_admit);
    std.mem.sort(u32, sorted, {}, std.sort.asc(u32));
    for (sorted) |vout| {
        const out = sub.tx.outputs[vout];
        const rec = try w.store.putValue(a, .{ .map = try a.dupe(cbor.Entry, &.{
            .{ .key = "kind", .value = .{ .text = "admitted" } },
            .{ .key = "topic", .value = .{ .text = topic } },
            .{ .key = "txid", .value = .{ .text = txid_hex } },
            .{ .key = "vout", .value = .{ .uint = vout } },
            .{ .key = "script", .value = .{ .bytes = out.locking_script.bytes } },
            .{ .key = "satoshis", .value = .{ .uint = @intCast(out.satoshis) } },
            .{ .key = "admittedAt", .value = .{ .uint = @intCast(@max(w.now, 0)) } },
            .{ .key = "tx", .value = .{ .cid = tx_cid } },
            .{ .key = "refs", .value = try admitsRef(a, tx_cid) },
        }) });
        const key = try cat(a, &.{ tp, &store_mod.outpointKey(sub.txid, vout) });
        try w.map("admitted").putLink(key, rec);
        try w.relate(sub.txid, .admitted, key, .admits);
        try records.append(a, rec);
    }
    for (sorted) |vout| try refreshAdmitted(w, try cat(a, &.{ tp, &store_mod.outpointKey(sub.txid, vout) }));
    const retained = try a.dupe(u32, ins.coins_to_retain);
    std.mem.sort(u32, retained, {}, std.sort.asc(u32));
    const applied = try w.store.putValue(a, .{ .map = try a.dupe(cbor.Entry, &.{
        .{ .key = "kind", .value = .{ .text = "applied" } },
        .{ .key = "topic", .value = .{ .text = topic } },
        .{ .key = "txid", .value = .{ .text = txid_hex } },
        .{ .key = "outputsToAdmit", .value = .{ .array = try uints(a, sorted) } },
        .{ .key = "coinsToRetain", .value = .{ .array = try uints(a, retained) } },
        .{ .key = "coinsRemoved", .value = .{ .array = try uints(a, removed.items) } },
        .{ .key = "at", .value = .{ .uint = @intCast(@max(w.now, 0)) } },
        .{ .key = "tx", .value = .{ .cid = tx_cid } },
        .{ .key = "refs", .value = try admitsRef(a, tx_cid) },
    }) });
    const akey = try cat(a, &.{ tp, &sub.txid });
    try w.map("applied").putLink(akey, applied);
    try w.relate(sub.txid, .applied, akey, .admits);
    try records.append(a, applied);
    return .{ .outputs_to_admit = sorted, .coins_to_retain = retained, .coins_removed = removed.items, .records = records.items };
}

// ---------------------------------------------------------------- derived, maintained (#41)

/// An admitted output's `byTopic` key (key = tp ‖ outpoint), under whether
/// the outpoint is spent (the wallet's `spent`: a spender we hold that is not
/// rejected).
pub fn refreshAdmitted(w: *Wallet, key: []const u8) !void {
    const a = w.arena;
    if (!(try w.map("admitted").has(key))) return;
    const tl = 1 + @as(usize, key[0]);
    if (key.len != tl + 36) return error.BadIndex;
    const state: u8 = if (try w.map("spent").has(key[tl..])) 1 else 0;
    _ = try w.map("byTopic").remove(try cat(a, &.{ key[0..tl], &.{1 - state}, key[tl..] }));
    try w.map("byTopic").add(try cat(a, &.{ key[0..tl], &.{state}, key[tl..] }));
}

/// An admittance vanishes (its transaction was rejected): the record and every derived key of it.
pub fn unadmit(w: *Wallet, key: []const u8) !void {
    const a = w.arena;
    if (!(try w.map("admitted").has(key))) return;
    const tl = 1 + @as(usize, key[0]);
    if (key.len != tl + 36) return error.BadIndex;
    for ([_]u8{ 0, 1 }) |state| {
        _ = try w.map("byTopic").remove(try cat(a, &.{ key[0..tl], &.{state}, key[tl..] }));
    }
    _ = try w.map("admitted").remove(key);
}

/// An outpoint turned spent or unspent (Wallet.refreshSpent): its keys in
/// every topic that admitted it move. The topics are found through the
/// wallet's `dependents` of its transaction (tag `m`: the `admitted` keys).
pub fn spentChanged(w: *Wallet, op: [36]u8) !void {
    const prefix = op[0..32].* ++ [_]u8{@intFromEnum(wallet_mod.Tag.admitted)};
    for (try w.map("dependents").prefixed(&prefix)) |kv| {
        const id = kv.key[33..];
        if (id.len < 37 or !std.mem.eql(u8, id[id.len - 36 ..], &op)) continue;
        try refreshAdmitted(w, id);
    }
}

// ---------------------------------------------------------------- programs: topics and lookup services (#50)

/// An in-VM call (#40) as the overlay makes it: `program`'s function `func`
/// on `arg` → its answer. The VM's `call` import in a program; a dispatch
/// table in the native tests.
pub const Caller = struct {
    ctx: *anyopaque,
    callFn: *const fn (ctx: *anyopaque, a: std.mem.Allocator, program: []const u8, func: []const u8, arg: Value) anyerror!Value,

    pub fn call(self: Caller, a: std.mem.Allocator, program: []const u8, func: []const u8, arg: Value) !Value {
        return self.callFn(self.ctx, a, program, func, arg);
    }
};

/// A genesis config map (defaults.<key>: a JSON object in a string).
pub fn configObject(a: std.mem.Allocator, in: Value, key: []const u8) !std.json.ObjectMap {
    const text = if (in.get("defaults")) |d| d.getText(key) orelse "{}" else "{}";
    const j = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch return error.BadConfig;
    if (j != .object) return error.BadConfig;
    return j.object;
}

/// A program record by its genesis name (the step's or call's `programs`).
pub fn programNamed(in: Value, name: []const u8) !?[]const u8 {
    const progs = in.get("programs") orelse return error.BadConfig;
    return progs.getCid(name) orelse {
        std.log.err("config names program {s}, not in the genesis programs", .{name});
        return error.BadConfig;
    };
}

/// A configured name's program: the value is the `bin/` program name, or
/// (defaults.overlayLookups) an object `{program, topics?}`.
pub fn configuredProgram(in: Value, map: std.json.ObjectMap, name: []const u8) !?[]const u8 {
    const v = map.get(name) orelse return null;
    const prog = switch (v) {
        .string => |s| s,
        .object => |o| if (o.get("program")) |p| (if (p == .string) p.string else return error.BadConfig) else return error.BadConfig,
        else => return error.BadConfig,
    };
    return programNamed(in, prog);
}

/// A lookup service that listens to a topic.
pub const Listener = struct { service: []const u8, program: []const u8 };

/// The lookup services listening to `topic` (defaults.overlayLookups, #50):
/// `{"ls_x": {"program": "<bin/ name>", "topics": ["tm_x", …]}}`; the short
/// form `{"ls_x": "<bin/ name>"}` listens to every topic the instance serves
/// (defaults.overlayTopics). In the config's order.
pub fn listeners(a: std.mem.Allocator, in: Value, topic: []const u8) ![]Listener {
    const lookups = try configObject(a, in, "overlayLookups");
    const topics = try configObject(a, in, "overlayTopics");
    var out: std.ArrayList(Listener) = .empty;
    var it = lookups.iterator();
    while (it.next()) |e| {
        const listens = switch (e.value_ptr.*) {
            .string => topics.contains(topic),
            .object => |o| blk: {
                const ts = o.get("topics") orelse break :blk topics.contains(topic);
                if (ts != .array) return error.BadConfig;
                for (ts.array.items) |t| {
                    if (t != .string) return error.BadConfig;
                    if (std.mem.eql(u8, t.string, topic)) break :blk true;
                }
                break :blk false;
            },
            else => return error.BadConfig,
        };
        if (!listens) continue;
        try out.append(a, .{ .service = e.key_ptr.*, .program = (try configuredProgram(in, lookups, e.key_ptr.*)).? });
    }
    return out.items;
}

fn hookArg(a: std.mem.Allocator, service: []const u8, topic: []const u8, rest: []const cbor.Entry) !Value {
    var es: std.ArrayList(cbor.Entry) = .empty;
    try es.appendSlice(a, &.{
        .{ .key = "kind", .value = .{ .text = "lookup-hook" } },
        .{ .key = "service", .value = .{ .text = service } },
        .{ .key = "topic", .value = .{ .text = topic } },
    });
    try es.appendSlice(a, rest);
    return .{ .map = es.items };
}

/// A topic admitted a transaction (in the step that recorded it): each of
/// its lookup services' `admitted(topic, tx, outputsToAdmit, coinsRetained)`,
/// then `spent(topic, outpoint, spendingTx)` for each previous coin it consumed.
pub fn hookAdmitted(a: std.mem.Allocator, caller: Caller, in: Value, topic: []const u8, sub: Subject, previous: []const u32, applied: Applied) !void {
    for (try listeners(a, in, topic)) |l| {
        _ = try caller.call(a, l.program, "admitted", try hookArg(a, l.service, topic, &.{
            .{ .key = "tx", .value = .{ .cid = sub.cid } },
            .{ .key = "outputsToAdmit", .value = .{ .array = try uints(a, applied.outputs_to_admit) } },
            .{ .key = "coinsRetained", .value = .{ .array = try uints(a, applied.coins_to_retain) } },
        }));
        for (previous) |p| {
            const in_ = sub.tx.inputs[p];
            _ = try caller.call(a, l.program, "spent", try hookArg(a, l.service, topic, &.{
                .{ .key = "outpoint", .value = .{ .map = try a.dupe(cbor.Entry, &.{
                    .{ .key = "tx", .value = .{ .cid = try a.dupe(u8, &store_mod.hashCid(.tx, in_.previous_outpoint.txid.bytes)) } },
                    .{ .key = "vout", .value = .{ .uint = in_.previous_outpoint.index } },
                }) } },
                .{ .key = "spendingTx", .value = .{ .cid = sub.cid } },
            }));
        }
    }
}

/// The topics' judgements a rejection removed (Wallet.reject → `unapplied`,
/// in the walk's order): each topic's lookup services' `rejected(topic, tx)`.
pub fn hookRejected(a: std.mem.Allocator, caller: Caller, in: Value, gone: []const wallet_mod.Unapplied) !void {
    for (gone) |g| {
        const cid = try a.dupe(u8, &store_mod.hashCid(.tx, g.txid));
        for (try listeners(a, in, g.topic)) |l| {
            _ = try caller.call(a, l.program, "rejected", try hookArg(a, l.service, g.topic, &.{.{ .key = "tx", .value = .{ .cid = cid } }}));
        }
    }
}

// ---------------------------------------------------------------- lookup (BRC-24)

/// An admitted output as a lookup sees it.
pub const Admitted = struct {
    topic: []const u8,
    txid: [32]u8,
    vout: u32,
    spent: bool,
    record: Value,
};

fn admittedAt(w: *Wallet, tp: []const u8, op: []const u8, spent: bool) !Admitted {
    const key = try cat(w.arena, &.{ tp, op });
    const c = (try w.map("admitted").link(key)) orelse return error.BadIndex;
    const o = try store_mod.outpointOf(op);
    return .{ .topic = tp[1..], .txid = o.txid, .vout = o.vout, .spent = spent, .record = try w.record(c) };
}

/// The outputs admitted into a topic: the unspent ones (and the spent ones
/// too with `include_spent`), in outpoint order.
pub fn inTopic(w: *Wallet, topic: []const u8, include_spent: bool) ![]Admitted {
    const a = w.arena;
    const tp = try topicPrefix(a, topic);
    var out: std.ArrayList(Admitted) = .empty;
    for ([_]u8{ 0, 1 }) |state| {
        if (state == 1 and !include_spent) continue;
        for (try w.map("byTopic").prefixed(try cat(a, &.{ tp, &.{state} }))) |kv| try out.append(a, try admittedAt(w, tp, kv.key[tp.len + 1 ..], state == 1));
    }
    return out.items;
}

/// The Atomic BEEF a lookup answer carries for an admitted output's
/// transaction: its ancestry back to proven transactions, from the records
/// held (Wallet.beefOf).
pub fn beefFor(w: *Wallet, txid: [32]u8) ![]const u8 {
    return (try w.beefOf(txid)) orelse error.UnknownTransaction;
}
