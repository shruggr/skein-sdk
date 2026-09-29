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
//!   byScript       sha256(script) ‖ tp ‖ 0 | 1 ‖ outpoint → null          derived
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
const spv = @import("spv.zig");
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

/// A submitted transaction, verified: its BEEF, the subject, and which
/// entries a BUMP proved.
pub const Submission = struct {
    beef: beef_mod.Beef,
    txid: [32]u8,
    tx: Transaction,
    proven: []const bool,
};

pub fn topicPrefix(a: std.mem.Allocator, topic: []const u8) ![]u8 {
    if (topic.len == 0) return error.BadTopic;
    return store_mod.nameKey(a, topic, &.{});
}

fn cat(a: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    return std.mem.concat(a, u8, parts);
}

fn scriptHash(script: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(script, &h, .{});
    return h;
}

// ---------------------------------------------------------------- submit (BRC-22)

/// Parse a submitted BEEF (V1, V2 or Atomic: the subject is the Atomic
/// BEEF's, else the last transaction) and verify it against our chain as
/// `internalize` does: every BUMP's root is our header's at its height (an
/// unknown height is refused), every unproven transaction's inputs come
/// earlier or are held, with their scripts verified. A subject already
/// rejected, or spending an output a proven transaction spends, is refused.
pub fn verify(w: *Wallet, bytes: []const u8) !Submission {
    const a = w.arena;
    const b = beef_mod.parse(a, bytes) catch return error.InvalidBeef;
    const subject = b.subject() orelse return error.InvalidBeef;
    const entry = b.find(subject) orelse return error.InvalidBeef;
    const tx = entry.tx orelse return error.InvalidBeef; // a txid-only subject
    var ctx = Wallet.SpvCtx{ .w = w };
    const checked = try spv.verify(a, b, .{ .ptr = &ctx, .rootAtFn = Wallet.SpvCtx.rootAt, .knownRawFn = Wallet.SpvCtx.knownRaw });
    if (try w.map("rejected").has(&subject)) return error.TransactionRejected;
    for (tx.inputs) |in| {
        const op = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
        for (try w.spendersOf(op)) |other| {
            if (std.mem.eql(u8, &other, &subject)) continue;
            if ((try w.status(other)) == .proven) return error.DoubleSpend;
        }
    }
    return .{ .beef = b, .txid = subject, .tx = tx, .proven = checked.proven };
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

/// Hold the submission's transactions (and the proofs its BUMPs carry) like
/// any other we hold: blocks (kept: `spends` edges, #42), `txs`. → the
/// subject's CID.
pub fn hold(w: *Wallet, sub: Submission) ![]const u8 {
    var subject_cid: []const u8 = "";
    for (sub.beef.entries, sub.proven) |e, proven| {
        const raw = e.raw orelse continue;
        const c = try w.putTx(e.txid, raw);
        if (std.mem.eql(u8, &e.txid, &sub.txid)) subject_cid = c;
        if (!proven or (try w.map("proofs").has(&e.txid))) continue;
        for (sub.beef.bumps) |p| if (beef_mod.bumpHas(p, e.txid)) {
            try w.putProof(e.txid, p);
            break;
        };
    }
    return subject_cid;
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

/// Record a topic's judgement of a verified submission (BRC-22 step 4): the
/// transactions held (when the topic took anything: an output or a previous
/// coin), each admitted output as an admittance record in `admitted`, the
/// judgement (which previous coins it retains, which it removes) in
/// `applied` — both with rel `admits` on the transaction. The previous coins
/// are spent by the transaction's own `spends` edges (held here). `previous` is
/// `previousCoins` for this topic, taken before any judgement of this step.
/// A transaction the topic judged before is a dupe: nothing is written.
pub fn apply(w: *Wallet, sub: Submission, topic: []const u8, previous: []const u32, ins: Instructions) !Applied {
    const a = w.arena;
    if (try isApplied(w, topic, sub.txid)) return .{ .dupe = true };
    try check(sub.tx, previous, ins);
    var removed: std.ArrayList(u32) = .empty;
    for (previous) |p| if (!contains(ins.coins_to_retain, p)) try removed.append(a, p);
    if (ins.outputs_to_admit.len == 0 and previous.len == 0) return .{};

    const tx_cid = try hold(w, sub);
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

/// An admitted output's `byTopic` / `byScript` keys (key = tp ‖ outpoint),
/// under whether the outpoint is spent (the wallet's `spent`: a spender we
/// hold that is not rejected).
pub fn refreshAdmitted(w: *Wallet, key: []const u8) !void {
    const a = w.arena;
    const rc = (try w.map("admitted").link(key)) orelse return;
    const tl = 1 + @as(usize, key[0]);
    if (key.len != tl + 36) return error.BadIndex;
    const state: u8 = if (try w.map("spent").has(key[tl..])) 1 else 0;
    const sh = scriptHash((try w.record(rc)).getBytes("script") orelse return error.BadRecord);
    _ = try w.map("byTopic").remove(try cat(a, &.{ key[0..tl], &.{1 - state}, key[tl..] }));
    try w.map("byTopic").add(try cat(a, &.{ key[0..tl], &.{state}, key[tl..] }));
    _ = try w.map("byScript").remove(try cat(a, &.{ &sh, key[0..tl], &.{1 - state}, key[tl..] }));
    try w.map("byScript").add(try cat(a, &.{ &sh, key[0..tl], &.{state}, key[tl..] }));
}

/// An admittance vanishes (its transaction was rejected): the record and every derived key of it.
pub fn unadmit(w: *Wallet, key: []const u8) !void {
    const a = w.arena;
    const rc = (try w.map("admitted").link(key)) orelse return;
    const tl = 1 + @as(usize, key[0]);
    if (key.len != tl + 36) return error.BadIndex;
    const sh = scriptHash((try w.record(rc)).getBytes("script") orelse return error.BadRecord);
    for ([_]u8{ 0, 1 }) |state| {
        _ = try w.map("byTopic").remove(try cat(a, &.{ key[0..tl], &.{state}, key[tl..] }));
        _ = try w.map("byScript").remove(try cat(a, &.{ &sh, key[0..tl], &.{state}, key[tl..] }));
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

/// The admitted outputs whose locking script hashes (sha256) to `hash`, in
/// one topic or in any: unspent only unless `include_spent`.
pub fn byScriptHash(w: *Wallet, hash: [32]u8, topic: ?[]const u8, include_spent: bool) ![]Admitted {
    const a = w.arena;
    const prefix = if (topic) |t| try cat(a, &.{ &hash, try topicPrefix(a, t) }) else try a.dupe(u8, &hash);
    var out: std.ArrayList(Admitted) = .empty;
    for (try w.map("byScript").prefixed(prefix)) |kv| {
        const rest = kv.key[32..];
        const tl = 1 + @as(usize, rest[0]);
        if (rest.len != tl + 1 + 36) return error.BadIndex;
        const spent = rest[tl] == 1;
        if (spent and !include_spent) continue;
        try out.append(a, try admittedAt(w, rest[0..tl], rest[tl + 1 ..], spent));
    }
    return out.items;
}

/// The Atomic BEEF a lookup answer carries for an admitted output's
/// transaction: its ancestry back to proven transactions, from the records
/// held (Wallet.beefOf).
pub fn beefFor(w: *Wallet, txid: [32]u8) ![]const u8 {
    return (try w.beefOf(txid)) orelse error.UnknownTransaction;
}
