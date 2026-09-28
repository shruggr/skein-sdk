//! Wallet state as records (issue #29): headers and transactions are
//! bitcoin-block / bitcoin-tx blocks, merkle proofs, actions and outputs are
//! dag-cbor records; lookups go through index maps — the kernel's Merkle
//! search trees (#30), one per lookup, their roots in the state record.
//! Status and spendability are computed from the records, never stored as
//! fields. The derived maps (`spent`, `byBasket`, `byStatus`, `bySettlement`) are rebuilt
//! from the primary ones on every save, so they are a pure function of the
//! records and the best chain: anyone can recompute and compare (the trees
//! are canonical: same contents, same root).
//!
//! One `Wallet` lives for one step: load from the state record, apply
//! operations, save (new map nodes, a new state record).
//!
//! Settlement (#37): every transaction we hold is `proven` (a merkle proof
//! against our best chain), `unproven`, or `rejected` (a `settlement` record
//! says so: ARC rejected it, a competing spend was proven, it was never
//! mined in time, or something it depends on was rejected). The relations
//! between records are kept as they are written, in `dependents`, each with
//! its kind: `spends`, `derives-from`, `admits` (#36) propagate a
//! rejection; `mentions` does not. A rejection walks them and recomputes
//! what was derived (the outputs vanish, drafts and dependent transactions
//! are rejected in turn, the inputs they consumed are spendable again).
const std = @import("std");
const bsvz = @import("bsvz");
const cbor = @import("cbor.zig");
const hdr = @import("header.zig");
const beef_mod = @import("beef.zig");
const spv = @import("spv.zig");
const brc29 = @import("brc29.zig");
const chain_mod = @import("chain.zig");
const store_mod = @import("store.zig");
const builder = @import("builder.zig");
const overlay = @import("overlay.zig");

const Store = store_mod.Store;
const Map = store_mod.Map;
const Value = cbor.Value;

pub const Network = chain_mod.Network;

/// The signing oracle, as far as internalize needs it: derive our BRC-29
/// payee key (getPublicKey, forSelf, counterparty = the sender).
pub const Oracle = struct {
    ptr: *anyopaque,
    derivePayeeFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, key_id: []const u8, sender: [33]u8) anyerror![33]u8,
};

/// The maps, by name, in the state record's order.
///   headers   height (u32 BE) → header (bitcoin-block)       the best chain
///   heights   block hash → height                           the best chain, backwards
///   txs       txid → transaction (bitcoin-tx)               every transaction we hold
///   proofs    txid → proof record                           proof by txid
///   actions   txid → action record                          our transactions
///   outputs   txid ‖ vout (u32 BE) → output record           output by outpoint
///   awaiting  txid → broadcast record                       transactions awaiting a status callback
///   spent     txid ‖ vout → spending txid (bytes)            derived: inputs of our actions
///   byBasket  len ‖ basket ‖ 0|1 ‖ outpoint → null          derived: 0 spendable, 1 spent
///   byStatus  0|1|2 ‖ txid → null                           derived: our actions, 0 proven, 1 unproven, 2 rejected
///   spenders  txid ‖ vout ‖ spending txid → null             every input of every transaction we hold
///   dependents  txid ‖ tag ‖ id → rel (text)                what depends on a transaction, and how (Rel, Tag)
///   rejected  txid → settlement record                      transactions that will never be mined
///   proofHeights  height (u32 BE) ‖ txid → null             proofs by block height (what a reorg reverts)
///   drafts    draft CID → null | settlement record          signable drafts (rejected with an input)
///   watchers  identity key (33 bytes) → null                who is sent settlement changes (the `settlement` box)
///   bySettlement  0|1|2 ‖ txid → null                       derived: every transaction we hold, by status
/// The overlay's (#36, overlay.zig), in the same state record: one chain and
/// one settlement for a wallet and an overlay in one instance.
///   admitted  len ‖ topic ‖ outpoint → admittance record      outputs admitted into a topic
///   consumed  len ‖ topic ‖ outpoint ‖ spending txid → retained (bool)   admitted outputs a later admitted tx spends
///   applied   len ‖ topic ‖ txid → applied record             transactions a topic judged (dupes)
///   spentAdmitted  len ‖ topic ‖ outpoint → spender ‖ retained   derived: consumed by a tx that is not rejected
///   byTopic   len ‖ topic ‖ 0|1 ‖ outpoint → null             derived: 0 unspent, 1 spent
///   byScript  sha256(script) ‖ len ‖ topic ‖ 0|1 ‖ outpoint → null   derived: by locking script hash
pub const map_names = [_][]const u8{ "headers", "heights", "txs", "proofs", "actions", "outputs", "awaiting", "spent", "byBasket", "byStatus", "spenders", "dependents", "rejected", "proofHeights", "drafts", "watchers", "bySettlement", "admitted", "consumed", "applied", "spentAdmitted", "byTopic", "byScript" };

pub const Status = enum { proven, unproven, rejected };

/// The kind of a relation from a record to the transaction it names: whether
/// the record stands or falls with it. `spends` (an input of a transaction
/// we hold consumes one of its outputs), `admits` (an overlay admitted one of
/// its outputs, #36: reserved), `derives-from` (a record built on it: our
/// action, an output record, a draft) propagate a rejection; `mentions` (a
/// record that merely names it) does not.
pub const Rel = enum {
    spends,
    admits,
    @"derives-from",
    mentions,

    pub fn parse(t: []const u8) ?Rel {
        return std.meta.stringToEnum(Rel, t);
    }
    pub fn propagates(r: Rel) bool {
        return r != .mentions;
    }
};

/// What a dependent is, in a `dependents` key: a transaction (id = its
/// txid), our action (txid), an output record (outpoint), a draft (its CID),
/// an overlay's admitted output (its `admitted` key) or judgement (its
/// `applied` key, #36), or any other record (its CID).
pub const Tag = enum(u8) { tx = 't', action = 'a', output = 'o', draft = 'd', record = 'r', admitted = 'm', applied = 'p' };

/// One settlement change in a step (what the `settlement` box is sent).
pub const Change = struct { txid: [32]u8, status: Status, reason: []const u8, cause: ?[32]u8 = null };

pub const PaymentRemittance = struct { derivation_prefix: []const u8, derivation_suffix: []const u8, sender_identity_key: [33]u8 };
pub const InsertionRemittance = struct { basket: []const u8, custom_instructions: ?[]const u8 = null, tags: []const []const u8 = &.{} };

pub const InternalizeOutput = struct {
    output_index: u32,
    payment: ?PaymentRemittance = null,
    insertion: ?InsertionRemittance = null,
};

/// BRC-100 internalizeAction's arguments.
pub const InternalizeArgs = struct {
    tx: []const u8, // Atomic BEEF
    outputs: []const InternalizeOutput,
    description: []const u8,
    labels: []const []const u8 = &.{},
};

pub const InternalizeResult = struct { txid: [32]u8, status: Status, outputs: u32 };

pub const OutputView = struct {
    txid: [32]u8,
    vout: u32,
    satoshis: u64,
    locking_script: []const u8,
    basket: []const u8,
    spendable: bool,
    status: Status,
    /// The output record (derivation, remittance fields).
    record: Value,
};

pub fn textArray(arena: std.mem.Allocator, xs: []const []const u8) ![]Value {
    const out = try arena.alloc(Value, xs.len);
    for (xs, out) |x, *o| o.* = .{ .text = x };
    return out;
}

pub fn textsOf(arena: std.mem.Allocator, items: []const Value) ![]const []const u8 {
    const out = try arena.alloc([]const u8, items.len);
    for (items, out) |it, *o| o.* = if (it == .text) it.text else return error.BadRecord;
    return out;
}

fn encodeOutputs(a: std.mem.Allocator, outputs: []const Wallet.CreateOutput) ![]Value {
    const out = try a.alloc(Value, outputs.len);
    for (outputs, out) |o, *v| {
        var fields: std.ArrayList(cbor.Entry) = .empty;
        try fields.appendSlice(a, &.{
            .{ .key = "satoshis", .value = .{ .uint = o.satoshis } },
            .{ .key = "lockingScript", .value = .{ .bytes = o.locking_script } },
            .{ .key = "outputDescription", .value = .{ .text = o.description } },
            .{ .key = "tags", .value = .{ .array = try textArray(a, o.tags) } },
        });
        if (o.basket) |b| try fields.append(a, .{ .key = "basket", .value = .{ .text = b } });
        if (o.custom_instructions) |ci| try fields.append(a, .{ .key = "customInstructions", .value = .{ .text = ci } });
        v.* = .{ .map = fields.items };
    }
    return out;
}

/// BRC-100 createAction outputs (as the program's bodies and drafts carry them).
pub fn decodeOutputs(a: std.mem.Allocator, items: []const Value) ![]Wallet.CreateOutput {
    const out = try a.alloc(Wallet.CreateOutput, items.len);
    for (items, out) |it, *o| o.* = .{
        .satoshis = it.getUint("satoshis") orelse return error.BadOutput,
        .locking_script = it.getBytes("lockingScript") orelse return error.BadOutput,
        .description = it.getText("outputDescription") orelse "",
        .basket = it.getText("basket"),
        .tags = try textsOf(a, it.getArray("tags") orelse &.{}),
        .custom_instructions = it.getText("customInstructions"),
    };
    return out;
}

pub const Wallet = struct {
    arena: std.mem.Allocator,
    store: Store,
    network: Network,
    maps: *store_mod.Maps,
    m: [map_names.len]Map,
    /// The step's time (ms): settlement records and broadcasts are stamped with it.
    now: i64 = 0,
    /// Settlement changes this step made (in order), for the `settlement` box.
    changes: std.ArrayList(Change) = .empty,
    /// Transactions of ours a reorg this step turned back to unproven: to be asked about again.
    reverted: std.ArrayList([32]u8) = .empty,

    /// The wallet the state record names (null: a new one) on `network`; a
    /// state made for another network is refused.
    pub fn load(arena: std.mem.Allocator, s: Store, state: ?[]const u8, network: Network) !Wallet {
        const maps = try store_mod.Maps.create(arena, s);
        var w = Wallet{ .arena = arena, .store = s, .network = network, .maps = maps, .m = undefined };
        var roots: ?Value = null;
        if (state) |c| {
            const v = try s.getValue(arena, c);
            if (!std.mem.eql(u8, v.getText("kind") orelse "", "wallet-state")) return error.BadState;
            if (!std.mem.eql(u8, v.getText("network") orelse "", @tagName(network))) return error.NetworkMismatch;
            roots = v.get("maps") orelse return error.BadState;
        }
        for (map_names, 0..) |n, i| w.m[i] = maps.map(if (roots) |r| r.getCid(n) else null);
        return w;
    }

    pub fn map(self: *Wallet, comptime name: []const u8) *Map {
        inline for (map_names, 0..) |n, i| if (comptime std.mem.eql(u8, n, name)) return &self.m[i];
        @compileError("no map " ++ name);
    }

    pub fn chain(self: *Wallet) chain_mod.Chain {
        return .{ .arena = self.arena, .store = self.store, .headers = self.map("headers"), .heights = self.map("heights"), .network = self.network };
    }

    /// Rebuild the derived maps, put every new node, and a state record; → its CID.
    pub fn save(self: *Wallet) ![]const u8 {
        try self.rebuildDerived();
        const es = try self.arena.alloc(cbor.Entry, map_names.len);
        for (map_names, &self.m, es) |n, *mp, *e| {
            try mp.flush();
            e.* = .{ .key = n, .value = if (mp.root) |r| .{ .cid = r } else .null };
        }
        return self.store.putValue(self.arena, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "wallet-state" } },
            .{ .key = "network", .value = .{ .text = @tagName(self.network) } },
            .{ .key = "maps", .value = .{ .map = es } },
        } });
    }

    // ------------------------------------------------------------ records

    /// A transaction we hold: a bitcoin-tx block, its CID the txid.
    pub fn txRaw(self: *Wallet, txid: [32]u8) !?[]const u8 {
        const c = (try self.map("txs").link(&txid)) orelse return null;
        return try self.store.get(self.arena, c);
    }

    /// A transaction, held: its block, and each input as a `spends` relation
    /// to the transaction it consumes (held or not) and in `spenders`.
    pub fn putTx(self: *Wallet, txid: [32]u8, raw: []const u8) ![]const u8 {
        if (try self.map("txs").link(&txid)) |c| return c;
        const cid = try self.store.putBitcoin(self.arena, .tx, raw);
        try self.map("txs").putLink(&txid, cid);
        const tx = try bsvz.transaction.Transaction.parse(self.arena, raw);
        for (tx.inputs) |in| {
            const src = in.previous_outpoint.txid.bytes;
            try self.map("spenders").add(&(store_mod.outpointKey(src, in.previous_outpoint.index) ++ txid));
            try self.relate(src, .tx, &txid, .spends);
        }
        return cid;
    }

    /// A relation from a dependent record to the transaction it names (`dependents`).
    pub fn relate(self: *Wallet, to: [32]u8, tag: Tag, id: []const u8, rel: Rel) !void {
        const key = try std.mem.concat(self.arena, u8, &.{ &to, &.{@intFromEnum(tag)}, id });
        try self.map("dependents").put(key, .{ .string = @tagName(rel) });
    }

    /// What depends on a transaction: each dependent's tag, id and relation.
    pub const Dependent = struct { tag: Tag, id: []const u8, rel: ?Rel };
    pub fn dependentsOf(self: *Wallet, txid: [32]u8) ![]Dependent {
        const kvs = try self.map("dependents").prefixed(&txid);
        const out = try self.arena.alloc(Dependent, kvs.len);
        for (kvs, out) |kv, *d| {
            if (kv.key.len < 33) return error.BadIndex;
            d.* = .{
                .tag = std.meta.intToEnum(Tag, kv.key[32]) catch return error.BadIndex,
                .id = kv.key[33..],
                .rel = if (kv.value == .string) Rel.parse(kv.value.string) else null,
            };
        }
        return out;
    }

    pub fn putProof(self: *Wallet, txid: [32]u8, height: u32, path: []const u8) !void {
        const key = hdr.toHex(txid);
        const cid = try self.store.putValue(self.arena, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "proof" } },
            .{ .key = "txid", .value = .{ .text = &key } },
            .{ .key = "height", .value = .{ .uint = height } },
            .{ .key = "path", .value = .{ .bytes = path } },
        } });
        try self.map("proofs").putLink(&txid, cid);
        try self.map("proofHeights").add(&(store_mod.be32(height) ++ txid));
    }

    /// The proof we hold for a txid (its BRC-74 bytes), or null.
    pub fn proofPath(self: *Wallet, txid: [32]u8) !?[]const u8 {
        const c = (try self.map("proofs").link(&txid)) orelse return null;
        const rec = try self.store.getValue(self.arena, c);
        return rec.getBytes("path") orelse error.BadRecord;
    }

    pub fn record(self: *Wallet, cid: []const u8) !Value {
        return self.store.getValue(self.arena, cid);
    }

    // ------------------------------------------------------------ status (computed)

    /// rejected: a settlement record says the transaction will never be
    /// mined (it stays so). proven: we hold a merkle proof for the txid whose
    /// root is our best-chain header's at its height. Anything else is
    /// unproven — a reorg that drops the block turns it back, with nothing to update.
    pub fn status(self: *Wallet, txid: [32]u8) !Status {
        if (try self.map("rejected").has(&txid)) return .rejected;
        return self.minedStatus(txid);
    }

    /// The settlement record of a rejected transaction, or null.
    pub fn settlement(self: *Wallet, txid: [32]u8) !?Value {
        const c = (try self.map("rejected").link(&txid)) orelse return null;
        return try self.record(c);
    }

    pub fn minedStatus(self: *Wallet, txid: [32]u8) !Status {
        const path = (try self.proofPath(txid)) orelse return .unproven;
        const p = bsvz.spv.MerklePath.parse(self.arena, path) catch return .unproven;
        const root = beef_mod.rootFor(self.arena, p, txid) orelse return .unproven;
        const want = (try self.chain().rootAt(p.block_height)) orelse return .unproven;
        return if (std.mem.eql(u8, &root, &want)) .proven else .unproven;
    }

    fn rebuildDerived(self: *Wallet) !void {
        const a = self.arena;
        // spent: every outpoint a transaction we hold consumes → the spending
        // txid, unless that transaction is rejected (its inputs are free again).
        var spent = self.maps.map(null);
        for (try self.map("spenders").prefixed("")) |kv| {
            if (kv.key.len != 68) return error.BadIndex;
            const spender: [32]u8 = kv.key[36..68].*;
            if (try self.map("rejected").has(&spender)) continue;
            if (try spent.has(kv.key[0..36])) continue; // the first (lowest txid) names it
            try spent.put(kv.key[0..36], .{ .bytes = try a.dupe(u8, &spender) });
        }
        const actions = try self.map("actions").prefixed("");
        // byBasket: basket ‖ 0 (spendable) | 1 (spent) ‖ outpoint.
        var by_basket = self.maps.map(null);
        for (try self.map("outputs").prefixed("")) |kv| {
            const rec = try self.record(kv.value.cid);
            const basket = rec.getText("basket") orelse return error.BadRecord;
            const state: u8 = if (try spent.has(kv.key)) 1 else 0;
            try by_basket.add(try store_mod.nameKey(a, basket, &.{ &.{state}, kv.key }));
        }
        // byStatus: 0 (proven) | 1 (unproven) | 2 (rejected) ‖ txid, our actions.
        var by_status = self.maps.map(null);
        for (actions) |kv| {
            const st: u8 = @intFromEnum(try self.status(kv.key[0..32].*));
            try by_status.add(try std.mem.concat(a, u8, &.{ &.{st}, kv.key }));
        }
        // bySettlement: the same over every transaction we hold.
        var by_settlement = self.maps.map(null);
        for (try self.map("txs").prefixed("")) |kv| {
            const st: u8 = @intFromEnum(try self.status(kv.key[0..32].*));
            try by_settlement.add(try std.mem.concat(a, u8, &.{ &.{st}, kv.key }));
        }
        self.map("spent").root = spent.root;
        self.map("byBasket").root = by_basket.root;
        self.map("byStatus").root = by_status.root;
        self.map("bySettlement").root = by_settlement.root;
        try overlay.rebuildDerived(self);
    }

    // ------------------------------------------------------------ settlement

    /// Reject a transaction and bubble: record a settlement record for it,
    /// then walk what depends on it through `dependents`, following only the
    /// relations that propagate — a transaction that spends it is rejected in
    /// turn (transitively, breadth first in key order: deterministic), an
    /// output record of it vanishes, a draft built on it is rejected; a
    /// `mentions` is left alone. What is derived from the remaining records
    /// (spent, spendable, by status) is recomputed at `save`: the inputs a
    /// rejected transaction consumed are spendable again unless another
    /// transaction we hold spends them. A proven transaction is never
    /// rejected (its proof is on our best chain), nor walked through. → the
    /// transactions rejected, the given one first.
    pub fn reject(self: *Wallet, root: [32]u8, reason: []const u8) ![][32]u8 {
        const a = self.arena;
        var queue: std.ArrayList([32]u8) = .empty;
        try queue.append(a, root);
        var out: std.ArrayList([32]u8) = .empty;
        var i: usize = 0;
        while (i < queue.items.len) : (i += 1) {
            const t = queue.items[i];
            if (try self.map("rejected").has(&t)) continue;
            if ((try self.minedStatus(t)) == .proven) continue;
            const by = i > 0;
            var fields: std.ArrayList(cbor.Entry) = .empty;
            try fields.appendSlice(a, &.{
                .{ .key = "kind", .value = .{ .text = "settlement" } },
                .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &hdr.toHex(t)) } },
                .{ .key = "status", .value = .{ .text = "rejected" } },
                .{ .key = "reason", .value = .{ .text = if (by) "input-rejected" else reason } },
                .{ .key = "at", .value = .{ .uint = @intCast(@max(self.now, 0)) } },
            });
            if (by) try fields.append(a, .{ .key = "cause", .value = .{ .text = try a.dupe(u8, &hdr.toHex(root)) } });
            const rec = try self.store.putValue(a, .{ .map = fields.items });
            try self.map("rejected").putLink(&t, rec);
            _ = try self.map("awaiting").remove(&t);
            try out.append(a, t);
            if (try self.map("actions").has(&t)) try self.changes.append(a, .{ .txid = t, .status = .rejected, .reason = if (by) "input-rejected" else reason, .cause = if (by) root else null });
            for (try self.dependentsOf(t)) |d| {
                const rel = d.rel orelse continue;
                if (!rel.propagates()) continue;
                switch (d.tag) {
                    .tx => if (d.id.len == 32) try queue.append(a, d.id[0..32].*),
                    .output => _ = try self.map("outputs").remove(d.id),
                    .draft => try self.map("drafts").putLink(d.id, rec),
                    // An overlay's admittance and judgement vanish with it (#36); what it consumed is freed at save.
                    .admitted => _ = try self.map("admitted").remove(d.id),
                    .applied => _ = try self.map("applied").remove(d.id),
                    .action, .record => {}, // an action's status is computed; a record is only reported
                }
            }
        }
        return out.items;
    }

    /// A transaction just proven: every other transaction we hold that spends
    /// one of the same outputs is a double spend, and rejected (with what
    /// depends on it).
    fn rejectConflicting(self: *Wallet, txid: [32]u8) !void {
        const raw = (try self.txRaw(txid)) orelse return;
        const tx = try bsvz.transaction.Transaction.parse(self.arena, raw);
        for (tx.inputs) |in| {
            const op = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
            for (try self.map("spenders").prefixed(&op)) |kv| {
                const other: [32]u8 = kv.key[36..68].*;
                if (std.mem.eql(u8, &other, &txid)) continue;
                _ = try self.reject(other, "double-spent");
            }
        }
    }

    /// A transaction that spends an output a proven transaction of ours
    /// already spends is dead on arrival: rejected.
    pub fn rejectIfConflicted(self: *Wallet, txid: [32]u8) !bool {
        const raw = (try self.txRaw(txid)) orelse return false;
        const tx = try bsvz.transaction.Transaction.parse(self.arena, raw);
        for (tx.inputs) |in| {
            const op = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
            for (try self.map("spenders").prefixed(&op)) |kv| {
                const other: [32]u8 = kv.key[36..68].*;
                if (std.mem.eql(u8, &other, &txid)) continue;
                if ((try self.status(other)) == .proven) {
                    _ = try self.reject(txid, "double-spent");
                    return true;
                }
            }
        }
        return false;
    }

    /// After a reorg replaced our chain from `start`: the proofs at those
    /// heights no longer hold, so those transactions are unproven again
    /// (computed; nothing to rewrite). Ours are noted in `reverted`, to be
    /// asked about again as after a fresh broadcast.
    fn revertFrom(self: *Wallet, start: u32) !void {
        for (try self.map("proofHeights").from(&store_mod.be32(start))) |kv| {
            if (kv.key.len != 36) return error.BadIndex;
            const txid: [32]u8 = kv.key[4..36].*;
            const c = (try self.map("proofs").link(&txid)) orelse continue;
            const rec = try self.record(c);
            if (rec.getUint("height") != std.mem.readInt(u32, kv.key[0..4], .big)) continue; // a later proof replaced it
            if ((try self.status(txid)) != .unproven) continue;
            if (!(try self.map("actions").has(&txid))) continue;
            var dup = false;
            for (self.reverted.items) |r| dup = dup or std.mem.eql(u8, &r, &txid);
            if (dup) continue;
            try self.reverted.append(self.arena, txid);
            try self.changes.append(self.arena, .{ .txid = txid, .status = .unproven, .reason = "reorg" });
        }
    }

    // ------------------------------------------------------------ watchers (the `settlement` box)

    pub fn watch(self: *Wallet, identity: [33]u8, on: bool) !void {
        if (on) try self.map("watchers").add(&identity) else _ = try self.map("watchers").remove(&identity);
    }

    pub fn watchers(self: *Wallet) ![][33]u8 {
        const kvs = try self.map("watchers").prefixed("");
        const out = try self.arena.alloc([33]u8, kvs.len);
        for (kvs, out) |kv, *o| {
            if (kv.key.len != 33) return error.BadIndex;
            o.* = kv.key[0..33].*;
        }
        return out;
    }

    // ------------------------------------------------------------ operations

    /// A run of headers. When a heavier branch replaces ours, the proofs
    /// against the replaced headers stop holding: those transactions are
    /// unproven again (`reverted`, for ours).
    pub fn addHeaders(self: *Wallet, raws: []const []const u8) !chain_mod.Chain.AddResult {
        const res = try self.chain().add(raws);
        if (res.replaced > 0) try self.revertFrom(res.tip + 1 - res.added);
        return res;
    }

    /// A merkle proof for a transaction we hold (a `proof` entry, or ARC's
    /// answer). A proof makes every competing spend of the same outputs a
    /// double spend: rejected. A rejected transaction keeps its rejection
    /// (the proof is kept, the status stays `rejected`).
    pub fn addProof(self: *Wallet, txid: [32]u8, path: []const u8) !Status {
        if ((try self.txRaw(txid)) == null) return error.UnknownTransaction;
        const p = bsvz.spv.MerklePath.parse(self.arena, path) catch return error.BadProof;
        const root = beef_mod.rootFor(self.arena, p, txid) orelse return error.BadProof;
        const want = (try self.chain().rootAt(p.block_height)) orelse return error.UnknownHeader;
        if (!std.mem.eql(u8, &root, &want)) return error.RootMismatch;
        const before = try self.status(txid);
        try self.putProof(txid, p.block_height, path);
        if (before == .rejected) return .rejected;
        if (before != .proven and try self.map("actions").has(&txid)) try self.changes.append(self.arena, .{ .txid = txid, .status = .proven, .reason = "mined" });
        try self.rejectConflicting(txid);
        return .proven;
    }

    pub const SpvCtx = struct {
        w: *Wallet,
        pub fn rootAt(ptr: *anyopaque, height: u32) anyerror!?[32]u8 {
            const self: *SpvCtx = @ptrCast(@alignCast(ptr));
            return self.w.chain().rootAt(height);
        }
        pub fn knownRaw(ptr: *anyopaque, arena: std.mem.Allocator, txid: [32]u8) anyerror!?[]const u8 {
            _ = arena;
            const self: *SpvCtx = @ptrCast(@alignCast(ptr));
            return self.w.txRaw(txid);
        }
    };

    /// BRC-100 internalizeAction, payee side: SPV-check the Atomic BEEF
    /// against our chain, check each claimed output is ours (a BRC-29
    /// payment the oracle's key recognises, or a basket insertion), then
    /// record the transactions, proofs, the action and the outputs.
    pub fn internalize(self: *Wallet, args: InternalizeArgs, oracle: Oracle) !InternalizeResult {
        const a = self.arena;
        const b = beef_mod.parse(a, args.tx) catch return error.InvalidBeef;
        const subject = b.atomic orelse return error.NotAtomicBeef;
        const entry = b.find(subject).?;
        const tx = entry.tx orelse return error.InvalidBeef; // txid-only subject
        var ctx = SpvCtx{ .w = self };
        const checked = try spv.verify(a, b, .{ .ptr = &ctx, .rootAtFn = SpvCtx.rootAt, .knownRawFn = SpvCtx.knownRaw });
        if (args.outputs.len == 0) return error.NoOutputs;

        // Which outputs are ours, and how.
        const recs = try a.alloc(cbor.Value, args.outputs.len);
        for (args.outputs, recs, 0..) |o, *rec, i| {
            for (args.outputs[0..i]) |prev| if (prev.output_index == o.output_index) return error.DuplicateOutput;
            if (o.output_index >= tx.outputs.len) return error.BadOutputIndex;
            const script = tx.outputs[o.output_index].locking_script.bytes;
            var fields: std.ArrayList(cbor.Entry) = .empty;
            try fields.appendSlice(a, &.{
                .{ .key = "kind", .value = .{ .text = "output" } },
                .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &hdr.toHex(subject)) } },
                .{ .key = "vout", .value = .{ .uint = o.output_index } },
            });
            if (o.payment) |p| {
                if (o.insertion != null) return error.BadOutputSpec;
                const key_id = try brc29.keyId(a, p.derivation_prefix, p.derivation_suffix);
                const key = try oracle.derivePayeeFn(oracle.ptr, a, key_id, p.sender_identity_key);
                if (!brc29.pays(script, key)) return error.NotOurPayment;
                try fields.appendSlice(a, &.{
                    .{ .key = "basket", .value = .{ .text = "default" } },
                    .{ .key = "protocol", .value = .{ .text = "wallet payment" } },
                    .{ .key = "derivationPrefix", .value = .{ .text = p.derivation_prefix } },
                    .{ .key = "derivationSuffix", .value = .{ .text = p.derivation_suffix } },
                    .{ .key = "senderIdentityKey", .value = .{ .text = try a.dupe(u8, &std.fmt.bytesToHex(p.sender_identity_key, .lower)) } },
                });
            } else if (o.insertion) |ins| {
                // BRC-100: "default" is the wallet's own basket, filled only by payments.
                if (ins.basket.len == 0 or std.mem.eql(u8, ins.basket, "default")) return error.BadBasket;
                try fields.appendSlice(a, &.{
                    .{ .key = "basket", .value = .{ .text = ins.basket } },
                    .{ .key = "protocol", .value = .{ .text = "basket insertion" } },
                    .{ .key = "tags", .value = .{ .array = try textArray(a, ins.tags) } },
                });
                if (ins.custom_instructions) |ci| try fields.append(a, .{ .key = "customInstructions", .value = .{ .text = ci } });
            } else return error.BadOutputSpec;
            rec.* = .{ .map = fields.items };
        }

        if (try self.map("rejected").has(&subject)) return error.TransactionRejected;
        // Record: every transaction the BEEF carries, every proof it carries, then the action and its outputs.
        var tx_cid: []const u8 = undefined;
        for (b.entries, checked.proven) |e, proven| {
            const raw = e.raw orelse continue;
            const c = try self.putTx(e.txid, raw);
            if (std.mem.eql(u8, &e.txid, &subject)) tx_cid = c;
            if (proven) {
                for (b.bumps) |p| if (beef_mod.bumpHas(p, e.txid)) {
                    try self.putProof(e.txid, p.block_height, try p.bytes(a));
                    break;
                };
            }
        }
        try self.putAction(subject, tx_cid, args.description, args.labels, null);
        for (recs) |*rec| {
            var fields = try a.dupe(cbor.Entry, rec.map);
            fields = try a.realloc(fields, fields.len + 1);
            fields[fields.len - 1] = .{ .key = "tx", .value = .{ .cid = tx_cid } };
            const vout: u32 = @intCast(rec.getUint("vout").?);
            try self.putOutput(subject, vout, .{ .map = fields });
        }
        // A spend of an output a proven transaction already spends is never mined.
        _ = try self.rejectIfConflicted(subject);
        return .{ .txid = subject, .status = try self.status(subject), .outputs = @intCast(args.outputs.len) };
    }

    /// An output record of ours, derived from its transaction (a `derives-from` relation).
    fn putOutput(self: *Wallet, txid: [32]u8, vout: u32, rec: Value) !void {
        const op = store_mod.outpointKey(txid, vout);
        try self.map("outputs").putLink(&op, try self.store.putValue(self.arena, rec));
        try self.relate(txid, .output, &op, .@"derives-from");
    }

    /// An action (a transaction of ours), unless we already hold one for the txid.
    pub fn putAction(self: *Wallet, txid: [32]u8, tx_cid: []const u8, description: []const u8, labels: []const []const u8, extra: ?[]const cbor.Entry) !void {
        if (try self.map("actions").has(&txid)) return;
        const a = self.arena;
        var fields: std.ArrayList(cbor.Entry) = .empty;
        try fields.appendSlice(a, &.{
            .{ .key = "kind", .value = .{ .text = "action" } },
            .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &hdr.toHex(txid)) } },
            .{ .key = "tx", .value = .{ .cid = tx_cid } },
            .{ .key = "description", .value = .{ .text = description } },
            .{ .key = "labels", .value = .{ .array = try textArray(a, labels) } },
        });
        if (extra) |x| try fields.appendSlice(a, x);
        try self.map("actions").putLink(&txid, try self.store.putValue(a, .{ .map = fields.items }));
        try self.relate(txid, .action, &txid, .@"derives-from");
    }

    /// Outputs in a basket, spendable ones only unless `include_spent`.
    /// Satoshis and script come from the transaction, not the output record.
    pub fn listOutputs(self: *Wallet, basket: []const u8, include_spent: bool) ![]OutputView {
        const a = self.arena;
        try self.rebuildDerived();
        var out: std.ArrayList(OutputView) = .empty;
        for ([_]u8{ 0, 1 }) |state| {
            if (!include_spent and state == 1) continue;
            const prefix = try store_mod.nameKey(a, basket, &.{&.{state}});
            for (try self.map("byBasket").prefixed(prefix)) |kv| {
                const op = try store_mod.outpointOf(kv.key[prefix.len..]);
                const raw = (try self.txRaw(op.txid)) orelse return error.BadRecord;
                const tx = try bsvz.transaction.Transaction.parse(a, raw);
                if (op.vout >= tx.outputs.len) return error.BadRecord;
                const rc = (try self.map("outputs").link(&store_mod.outpointKey(op.txid, op.vout))) orelse return error.BadRecord;
                try out.append(a, .{
                    .txid = op.txid,
                    .vout = op.vout,
                    .satoshis = @intCast(tx.outputs[op.vout].satoshis),
                    .locking_script = tx.outputs[op.vout].locking_script.bytes,
                    .basket = basket,
                    .spendable = state == 0,
                    .status = try self.status(op.txid),
                    .record = try self.record(rc),
                });
            }
        }
        return out.toOwnedSlice(a);
    }

    // ------------------------------------------------------------ building (createAction / signAction)

    /// The BRC-29 key an output of ours is locked to: a payment's (counterparty
    /// the sender) or our change's (counterparty self); null for anything else.
    pub fn keyOf(self: *Wallet, rec: Value) !?builder.Key {
        const protocol = rec.getText("protocol") orelse return null;
        const key_id = try brc29.keyId(self.arena, rec.getText("derivationPrefix") orelse return null, rec.getText("derivationSuffix") orelse return null);
        if (std.mem.eql(u8, protocol, "wallet change")) return .{ .key_id = key_id, .counterparty = .self };
        if (!std.mem.eql(u8, protocol, "wallet payment")) return null;
        const hex = rec.getText("senderIdentityKey") orelse return error.BadRecord;
        var k: [33]u8 = undefined;
        if (hex.len != 66) return error.BadRecord;
        _ = std.fmt.hexToBytes(&k, hex) catch return error.BadRecord;
        return .{ .key_id = key_id, .counterparty = .{ .other = k } };
    }

    /// Our spendable outputs we hold keys for (the `default` basket), largest first.
    fn spendableInputs(self: *Wallet) ![]builder.Input {
        var out: std.ArrayList(builder.Input) = .empty;
        for (try self.listOutputs("default", false)) |o| {
            const key = (try self.keyOf(o.record)) orelse continue;
            try out.append(self.arena, .{ .source_txid = o.txid, .vout = o.vout, .satoshis = o.satoshis, .locking_script = o.locking_script, .key = key });
        }
        std.mem.sort(builder.Input, out.items, {}, struct {
            fn lt(_: void, x: builder.Input, y: builder.Input) bool {
                if (x.satoshis != y.satoshis) return x.satoshis > y.satoshis;
                const kx = store_mod.outpointKey(x.source_txid, x.vout);
                const ky = store_mod.outpointKey(y.source_txid, y.vout);
                return std.mem.order(u8, &kx, &ky) == .lt;
            }
        }.lt);
        return out.items;
    }

    /// Inputs for these outputs: the largest spendable first, until they cover the outputs and the fee.
    pub fn selectInputs(self: *Wallet, outputs: []const builder.Output, sats_per_kb: u64) ![]builder.Input {
        const all = try self.spendableInputs();
        var need: u64 = 0;
        for (outputs) |o| need += o.satoshis;
        var have: u64 = 0;
        for (all, 1..) |in, n| {
            have += in.satoshis;
            if (have >= need + try builder.estimateFee(self.arena, n, outputs, 25, sats_per_kb)) return all[0..n];
        }
        return error.InsufficientFunds;
    }

    pub const CreateOutput = struct {
        satoshis: u64,
        locking_script: []const u8,
        description: []const u8 = "",
        basket: ?[]const u8 = null,
        tags: []const []const u8 = &.{},
        custom_instructions: ?[]const u8 = null,
    };

    /// BRC-100 createAction's arguments, as far as the wallet takes them:
    /// outputs (inputs are chosen from our own spendable outputs), labels,
    /// options.signAndProcess / options.noSend.
    pub const CreateArgs = struct {
        description: []const u8,
        outputs: []const CreateOutput,
        labels: []const []const u8 = &.{},
        sign_and_process: bool = true,
        no_send: bool = false,
    };

    pub const Created = struct {
        txid: [32]u8,
        /// Atomic BEEF: the signed transaction and its ancestry, or the signable draft's.
        beef: []const u8,
        /// A signable draft: the draft record's CID (signAction's `reference`).
        reference: ?[]const u8 = null,
        no_send: bool = false,
    };

    /// BRC-100 createAction: choose inputs, build with change to a fresh key of
    /// ours (derivation prefix and suffix given: the program draws them from
    /// the thread's random), sign through the oracle and record it — or, with
    /// signAndProcess false, keep a draft and return it signable.
    pub fn createAction(self: *Wallet, args: CreateArgs, signer: builder.Signer, change_prefix: []const u8, change_suffix: []const u8, sats_per_kb: u64) !Created {
        const a = self.arena;
        if (args.outputs.len == 0) return error.NoOutputs;
        const outs = try a.alloc(builder.Output, args.outputs.len);
        for (args.outputs, outs) |o, *x| {
            if (o.locking_script.len == 0) return error.BadOutput;
            if (o.basket) |b| if (b.len == 0 or std.mem.eql(u8, b, "default")) return error.BadBasket;
            x.* = .{ .satoshis = o.satoshis, .locking_script = o.locking_script };
        }
        const inputs = try self.selectInputs(outs, sats_per_kb);
        const change_key = builder.Key{ .key_id = try brc29.keyId(a, change_prefix, change_suffix), .counterparty = .self };
        const built = try builder.build(a, signer, inputs, outs, change_key, sats_per_kb, args.sign_and_process);
        if (args.sign_and_process) return self.recordSigned(built, args, change_prefix, change_suffix);

        // A draft: what signAction needs to build the same transaction again, signed.
        const ops = try a.alloc(Value, inputs.len);
        for (inputs, ops) |in, *o| o.* = .{ .bytes = try a.dupe(u8, &store_mod.outpointKey(in.source_txid, in.vout)) };
        const draft = try self.store.putValue(a, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "draft" } },
            .{ .key = "description", .value = .{ .text = args.description } },
            .{ .key = "labels", .value = .{ .array = try textArray(a, args.labels) } },
            .{ .key = "outputs", .value = .{ .array = try encodeOutputs(a, args.outputs) } },
            .{ .key = "inputs", .value = .{ .array = ops } },
            .{ .key = "derivationPrefix", .value = .{ .text = change_prefix } },
            .{ .key = "derivationSuffix", .value = .{ .text = change_suffix } },
            .{ .key = "satsPerKb", .value = .{ .uint = sats_per_kb } },
            .{ .key = "noSend", .value = .{ .boolean = args.no_send } },
        } });
        // The draft stands on its inputs' transactions (`derives-from`): rejected with any of them.
        try self.map("drafts").add(draft);
        for (inputs) |in| try self.relate(in.source_txid, .draft, draft, .@"derives-from");
        return .{ .txid = built.txid, .beef = try self.atomicBeef(built.txid, built.raw, built.tx), .reference = draft, .no_send = args.no_send };
    }

    /// BRC-100 signAction for a draft of ours: the same inputs (still
    /// spendable), outputs and change key, now signed through the oracle, and recorded.
    pub fn signAction(self: *Wallet, reference: []const u8, signer: builder.Signer) !Created {
        const a = self.arena;
        const d = self.record(reference) catch return error.UnknownReference;
        if (!std.mem.eql(u8, d.getText("kind") orelse "", "draft")) return error.UnknownReference;
        if (try self.map("drafts").get(reference)) |v| if (v == .cid) return error.DraftRejected;
        const outputs = try decodeOutputs(a, d.getArray("outputs") orelse return error.BadRecord);
        try self.rebuildDerived();
        const ops = d.getArray("inputs") orelse return error.BadRecord;
        const inputs = try a.alloc(builder.Input, ops.len);
        for (ops, inputs) |o, *in| {
            if (o != .bytes) return error.BadRecord;
            const op = try store_mod.outpointOf(o.bytes);
            if (try self.map("spent").has(o.bytes)) return error.InputSpent;
            const rc = (try self.map("outputs").link(o.bytes)) orelse return error.BadRecord;
            const raw = (try self.txRaw(op.txid)) orelse return error.BadRecord;
            const src = try bsvz.transaction.Transaction.parse(a, raw);
            in.* = .{
                .source_txid = op.txid,
                .vout = op.vout,
                .satoshis = @intCast(src.outputs[op.vout].satoshis),
                .locking_script = src.outputs[op.vout].locking_script.bytes,
                .key = (try self.keyOf(try self.record(rc))) orelse return error.BadRecord,
            };
        }
        const outs = try a.alloc(builder.Output, outputs.len);
        for (outputs, outs) |o, *x| x.* = .{ .satoshis = o.satoshis, .locking_script = o.locking_script };
        const prefix = d.getText("derivationPrefix") orelse return error.BadRecord;
        const suffix = d.getText("derivationSuffix") orelse return error.BadRecord;
        const change_key = builder.Key{ .key_id = try brc29.keyId(a, prefix, suffix), .counterparty = .self };
        const built = try builder.build(a, signer, inputs, outs, change_key, d.getUint("satsPerKb") orelse return error.BadRecord, true);
        const args = CreateArgs{
            .description = d.getText("description") orelse "",
            .outputs = outputs,
            .labels = try textsOf(a, d.getArray("labels") orelse &.{}),
            .no_send = d.getBool("noSend") orelse false,
        };
        // Signed, the draft is done: the action stands in its place (its own relations).
        _ = try self.map("drafts").remove(reference);
        for (inputs) |in| _ = try self.map("dependents").remove(try std.mem.concat(a, u8, &.{ &in.source_txid, &.{@intFromEnum(Tag.draft)}, reference }));
        return self.recordSigned(built, args, prefix, suffix);
    }

    /// Record a signed transaction of ours: the transaction, the action, our
    /// change output and every output the caller put in a basket.
    fn recordSigned(self: *Wallet, built: builder.Built, args: CreateArgs, change_prefix: []const u8, change_suffix: []const u8) !Created {
        const a = self.arena;
        const tx_cid = try self.putTx(built.txid, built.raw);
        try self.putAction(built.txid, tx_cid, args.description, args.labels, &.{.{ .key = "noSend", .value = .{ .boolean = args.no_send } }});
        const txid_hex = try a.dupe(u8, &hdr.toHex(built.txid));
        if (built.change) |c| {
            try self.putOutput(built.txid, c.vout, .{ .map = try a.dupe(cbor.Entry, &.{
                .{ .key = "kind", .value = .{ .text = "output" } },
                .{ .key = "txid", .value = .{ .text = txid_hex } },
                .{ .key = "vout", .value = .{ .uint = c.vout } },
                .{ .key = "tx", .value = .{ .cid = tx_cid } },
                .{ .key = "basket", .value = .{ .text = "default" } },
                .{ .key = "protocol", .value = .{ .text = "wallet change" } },
                .{ .key = "derivationPrefix", .value = .{ .text = change_prefix } },
                .{ .key = "derivationSuffix", .value = .{ .text = change_suffix } },
            }) });
        }
        for (args.outputs, 0..) |o, i| {
            const basket = o.basket orelse continue;
            var fields: std.ArrayList(cbor.Entry) = .empty;
            try fields.appendSlice(a, &.{
                .{ .key = "kind", .value = .{ .text = "output" } },
                .{ .key = "txid", .value = .{ .text = txid_hex } },
                .{ .key = "vout", .value = .{ .uint = i } },
                .{ .key = "tx", .value = .{ .cid = tx_cid } },
                .{ .key = "basket", .value = .{ .text = basket } },
                .{ .key = "protocol", .value = .{ .text = "basket insertion" } },
                .{ .key = "tags", .value = .{ .array = try textArray(a, o.tags) } },
            });
            if (o.custom_instructions) |ci| try fields.append(a, .{ .key = "customInstructions", .value = .{ .text = ci } });
            try self.putOutput(built.txid, @intCast(i), .{ .map = fields.items });
        }
        return .{ .txid = built.txid, .beef = try self.atomicBeef(built.txid, built.raw, built.tx), .no_send = args.no_send };
    }

    /// The Atomic BEEF (BRC-95 over BRC-96) of a transaction: its ancestry
    /// back to proven transactions (with their BUMPs, merged per block),
    /// parents first, then the transaction itself.
    pub fn atomicBeef(self: *Wallet, txid: [32]u8, raw: []const u8, tx: bsvz.transaction.Transaction) ![]const u8 {
        var acc = BeefAcc{ .w = self };
        for (tx.inputs) |in| try acc.visit(in.previous_outpoint.txid.bytes);
        try acc.entries.append(self.arena, .{ .txid = txid, .format = .raw, .raw = raw, .tx = tx });
        return beef_mod.serialize(self.arena, .{ .version = beef_mod.V2, .atomic = txid, .bumps = acc.bumps.items, .entries = acc.entries.items });
    }

    /// The Atomic BEEF of a transaction we hold, or null.
    pub fn beefOf(self: *Wallet, txid: [32]u8) !?[]const u8 {
        const raw = (try self.txRaw(txid)) orelse return null;
        return try self.atomicBeef(txid, raw, try bsvz.transaction.Transaction.parse(self.arena, raw));
    }

    const BeefAcc = struct {
        w: *Wallet,
        entries: std.ArrayList(beef_mod.Entry) = .empty,
        bumps: std.ArrayList(bsvz.spv.MerklePath) = .empty,

        fn visit(acc: *BeefAcc, txid: [32]u8) anyerror!void {
            const a = acc.w.arena;
            for (acc.entries.items) |e| if (std.mem.eql(u8, &e.txid, &txid)) return;
            const raw = (try acc.w.txRaw(txid)) orelse return error.MissingAncestor;
            const tx = try bsvz.transaction.Transaction.parse(a, raw);
            if ((try acc.w.status(txid)) == .proven) {
                const p = try bsvz.spv.MerklePath.parse(a, (try acc.w.proofPath(txid)).?);
                const idx = for (acc.bumps.items, 0..) |*b, i| {
                    if (b.block_height != p.block_height) continue;
                    b.combine(&p, a) catch continue;
                    break i;
                } else blk: {
                    try acc.bumps.append(a, p);
                    break :blk acc.bumps.items.len - 1;
                };
                try acc.entries.append(a, .{ .txid = txid, .format = .raw_with_bump, .bump = idx, .raw = raw, .tx = tx });
                return;
            }
            for (tx.inputs) |in| try acc.visit(in.previous_outpoint.txid.bytes);
            try acc.entries.append(a, .{ .txid = txid, .format = .raw, .raw = raw, .tx = tx });
        }
    };

    // ------------------------------------------------------------ broadcast and its callback

    pub const Outcome = enum { proven, pending, rejected };

    /// ARC's txStatus, as the wallet reads it: rejected, or not (yet).
    pub fn isRejection(tx_status: []const u8) bool {
        for ([_][]const u8{ "REJECTED", "DOUBLE_SPEND_ATTEMPTED", "INVALID", "MALFORMED" }) |s| if (std.mem.eql(u8, s, tx_status)) return true;
        return false;
    }

    /// A transaction of ours now awaits its status: the `awaiting` map names
    /// the broadcast record (the ARC it went to, the last status heard, and
    /// `since`: when it was first broadcast, the abandonment clock).
    pub fn noteBroadcast(self: *Wallet, txid: [32]u8, arc: []const u8, tx_status: []const u8) !void {
        const a = self.arena;
        const since: u64 = if (try self.awaitingRecord(txid)) |r| r.getUint("since") orelse @intCast(@max(self.now, 0)) else @intCast(@max(self.now, 0));
        const cid = try self.store.putValue(a, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "broadcast" } },
            .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &hdr.toHex(txid)) } },
            .{ .key = "subject", .value = .{ .cid = try a.dupe(u8, &store_mod.bitcoinCid(.tx, (try self.txRaw(txid)) orelse return error.UnknownTransaction)) } },
            .{ .key = "arc", .value = .{ .text = arc } },
            .{ .key = "txStatus", .value = .{ .text = tx_status } },
            .{ .key = "since", .value = .{ .uint = since } },
        } });
        try self.map("awaiting").putLink(&txid, cid);
    }

    pub fn awaitingRecord(self: *Wallet, txid: [32]u8) !?Value {
        const c = (try self.map("awaiting").link(&txid)) orelse return null;
        return try self.record(c);
    }

    /// Every transaction awaiting a status.
    pub fn awaitingTxids(self: *Wallet) ![][32]u8 {
        const kvs = try self.map("awaiting").prefixed("");
        const out = try self.arena.alloc([32]u8, kvs.len);
        for (kvs, out) |kv, *o| o.* = kv.key[0..32].*;
        return out;
    }

    /// Never mined in time: a transaction awaiting its status for at least
    /// `abandon_ms` since it was broadcast is rejected ("abandoned"), with
    /// what depends on it. → whether it was.
    pub fn abandonIfDue(self: *Wallet, txid: [32]u8, abandon_ms: i64) !bool {
        if (abandon_ms <= 0) return false;
        const r = (try self.awaitingRecord(txid)) orelse return false;
        const since: i64 = @intCast(r.getUint("since") orelse return false);
        if (self.now - since < abandon_ms) return false;
        if ((try self.status(txid)) != .unproven) return false;
        _ = try self.reject(txid, "abandoned");
        return true;
    }

    /// What a status says about one of our transactions (ARC's answer, or a
    /// `status` / `proof` entry): a merkle path is a proof, checked against our
    /// chain (a header not yet held leaves it pending); a rejection rejects it
    /// and bubbles (`reject`): what spends it and was built on it is rejected
    /// too, its outputs vanish, its inputs are spendable again. Proven or
    /// rejected, it no longer awaits.
    pub fn applyStatus(self: *Wallet, txid: [32]u8, tx_status: []const u8, merkle_path: ?[]const u8) !Outcome {
        var outcome: Outcome = .pending;
        if (merkle_path) |p| {
            if (self.addProof(txid, p)) |st| {
                outcome = if (st == .rejected) .rejected else .proven;
            } else |e| switch (e) {
                error.UnknownHeader => {},
                else => return e,
            }
        } else if (isRejection(tx_status)) {
            _ = try self.reject(txid, tx_status);
        }
        if (outcome == .pending) outcome = switch (try self.status(txid)) {
            .proven => .proven,
            .rejected => .rejected,
            .unproven => .pending,
        };
        if (outcome != .pending) {
            _ = try self.map("awaiting").remove(&txid);
        } else if (try self.awaitingRecord(txid)) |r| {
            if (!std.mem.eql(u8, r.getText("txStatus") orelse "", tx_status) and tx_status.len > 0) try self.noteBroadcast(txid, r.getText("arc") orelse "", tx_status);
        }
        return outcome;
    }

    pub fn mapCount(self: *Wallet, comptime name: []const u8) !usize {
        return self.map(name).count();
    }
};
