//! An overlay's state (issue #36): what topics admitted, over the same records
//! and the same settlement as the wallet. An overlay is the transaction graph
//! the wallet holds, judged and indexed differently: a submitted transaction
//! (BRC-22) is SPV-checked against the chain the wallet tracks and held like
//! any other (`txs`, `proofs`, `spenders`, a `spends` relation per input);
//! what a topic's program decided is recorded here as index maps in the
//! wallet's own state record (wallet.zig `map_names`), so one instance can be
//! a wallet and an overlay at once and a transaction's settlement (#37) is one
//! thing for both.
//!
//! The maps (keys bytes, ordered bytewise; `tp` = len ‖ topic):
//!   admitted       tp ‖ txid ‖ vout → admittance record {kind: "admitted", topic, txid, vout, script, satoshis, admittedAt, tx, refs}
//!   consumed       tp ‖ outpoint ‖ spending txid → retained (bool): a later judged tx spent an admitted output
//!   applied        tp ‖ txid → applied record {kind: "applied", topic, txid, outputsToAdmit, coinsToRetain, coinsRemoved, at, tx, refs}
//!   spentAdmitted  tp ‖ outpoint → spender (32) ‖ retained (1)          derived
//!   byTopic        tp ‖ 0 (unspent) | 1 (spent) ‖ outpoint → null         derived
//!   byScript       sha256(script) ‖ tp ‖ 0 | 1 ‖ outpoint → null          derived
//!
//! The derived maps are maintained where a fact changes (#41): an admittance
//! or a consumed coin (`apply`), an admittance that vanishes and a judgement
//! that vanishes (Wallet.reject → `unadmit`, `unjudged`).
//!
//! Relations (the wallet's `dependents`, #37): an admitted output and an
//! applied record stand on their transaction with rel `admits` (tags `m`,
//! `p`): a rejected transaction's admittances vanish (Wallet.reject), and
//! since `spentAdmitted` counts only spenders that are not rejected, a
//! rejected spend gives the admitted outputs it consumed back to the topic.
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
        for (try w.map("spenders").prefixed(&op)) |kv| {
            const other: [32]u8 = kv.key[36..68].*;
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
/// (admitted, its transaction not rejected, not spent by another judged
/// transaction): BRC-22's `previousCoins`.
pub fn previousCoins(w: *Wallet, topic: []const u8, tx: Transaction) ![]u32 {
    const a = w.arena;
    const tp = try topicPrefix(a, topic);
    var out: std.ArrayList(u32) = .empty;
    for (tx.inputs, 0..) |in, i| {
        const op = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
        const key = try cat(a, &.{ tp, &op });
        if (!(try w.map("admitted").has(key))) continue;
        if (try w.map("spentAdmitted").has(key)) continue;
        try out.append(a, @intCast(i));
    }
    return out.items;
}

/// Hold the submission's transactions (and the proofs its BUMPs carry) like
/// any other we hold: blocks, `txs`, `spenders`, `spends` relations. → the
/// subject's CID.
pub fn hold(w: *Wallet, sub: Submission) ![]const u8 {
    const a = w.arena;
    var subject_cid: []const u8 = "";
    for (sub.beef.entries, sub.proven) |e, proven| {
        const raw = e.raw orelse continue;
        const c = try w.putTx(e.txid, raw);
        if (std.mem.eql(u8, &e.txid, &sub.txid)) subject_cid = c;
        if (!proven or (try w.map("proofs").has(&e.txid))) continue;
        for (sub.beef.bumps) |p| if (beef_mod.bumpHas(p, e.txid)) {
            try w.putProof(e.txid, p.block_height, try p.bytes(a));
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
/// coin), each admitted output as an admittance record in `admitted`, each
/// previous coin consumed (retained or removed) in `consumed`, the judgement
/// in `applied` — all with rel `admits` on the transaction. `previous` is
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
    for (previous) |p| {
        const in = sub.tx.inputs[p];
        const op = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
        try w.map("consumed").put(try cat(a, &.{ tp, &op, &sub.txid }), .{ .bool = contains(ins.coins_to_retain, p) });
        try refreshAdmitted(w, try cat(a, &.{ tp, &op }));
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

/// An admitted output's derived keys (key = tp ‖ outpoint): `spentAdmitted`
/// (the first spender, lowest txid, of the ones this topic judged that is not
/// rejected), and its `byTopic` / `byScript` keys under that state.
pub fn refreshAdmitted(w: *Wallet, key: []const u8) !void {
    const a = w.arena;
    const rc = (try w.map("admitted").link(key)) orelse {
        _ = try w.map("spentAdmitted").remove(key);
        return;
    };
    var first: ?store_mod.MValue = null;
    for (try w.map("consumed").prefixed(key)) |kv| {
        if (kv.key.len != key.len + 32) return error.BadIndex;
        const spender: [32]u8 = kv.key[key.len..][0..32].*;
        if (try w.map("rejected").has(&spender)) continue;
        const retained: u8 = if (kv.value == .bool and kv.value.bool) 1 else 0;
        first = .{ .bytes = try cat(a, &.{ &spender, &.{retained} }) };
        break;
    }
    if (first) |v| try w.map("spentAdmitted").put(key, v) else _ = try w.map("spentAdmitted").remove(key);
    const state: u8 = if (first != null) 1 else 0;
    const tl = 1 + @as(usize, key[0]);
    if (key.len != tl + 36) return error.BadIndex;
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
    _ = try w.map("spentAdmitted").remove(key);
    _ = try w.map("admitted").remove(key);
}

/// Judgements that vanished (their transactions rejected; `applied` keys tp ‖
/// txid): the admitted outputs each consumed in its topic are live again
/// unless another judged spender stands.
pub fn unjudged(w: *Wallet, keys: []const []const u8) !void {
    const a = w.arena;
    for (keys) |k| {
        if (k.len < 33) return error.BadIndex;
        const tp = k[0 .. k.len - 32];
        const raw = (try w.txRaw(k[k.len - 32 ..][0..32].*)) orelse continue;
        const tx = try Transaction.parse(a, raw);
        for (tx.inputs) |in| try refreshAdmitted(w, try cat(a, &.{ tp, &store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index) }));
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
