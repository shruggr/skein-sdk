//! Wallet state as records (issue #29): headers and transactions are
//! bitcoin-block / bitcoin-tx blocks, merkle proofs, actions and outputs are
//! dag-cbor records; lookups go through index maps — the kernel's Merkle
//! search trees (#30), one per lookup, their roots in the state record.
//! Status and spendability are computed from the records, never stored as
//! fields. The derived maps (`spent`, `byBasket`, `byStatus`) are rebuilt
//! from the primary ones on every save, so they are a pure function of the
//! records and the best chain: anyone can recompute and compare (the trees
//! are canonical: same contents, same root).
//!
//! One `Wallet` lives for one step: load from the state record, apply
//! operations, save (new map nodes, a new state record).
const std = @import("std");
const bsvz = @import("bsvz");
const cbor = @import("cbor.zig");
const hdr = @import("header.zig");
const beef_mod = @import("beef.zig");
const spv = @import("spv.zig");
const brc29 = @import("brc29.zig");
const chain_mod = @import("chain.zig");
const store_mod = @import("store.zig");

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
///   byStatus  0|1 ‖ txid → null                             derived: our actions, 0 proven, 1 unproven
pub const map_names = [_][]const u8{ "headers", "heights", "txs", "proofs", "actions", "outputs", "awaiting", "spent", "byBasket", "byStatus" };

pub const Status = enum { proven, unproven };

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

pub const Wallet = struct {
    arena: std.mem.Allocator,
    store: Store,
    network: Network,
    maps: *store_mod.Maps,
    m: [map_names.len]Map,

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

    pub fn putTx(self: *Wallet, txid: [32]u8, raw: []const u8) ![]const u8 {
        if (try self.map("txs").link(&txid)) |c| return c;
        const cid = try self.store.putBitcoin(self.arena, .tx, raw);
        try self.map("txs").putLink(&txid, cid);
        return cid;
    }

    fn putProof(self: *Wallet, txid: [32]u8, height: u32, path: []const u8) !void {
        const key = hdr.toHex(txid);
        const cid = try self.store.putValue(self.arena, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "proof" } },
            .{ .key = "txid", .value = .{ .text = &key } },
            .{ .key = "height", .value = .{ .uint = height } },
            .{ .key = "path", .value = .{ .bytes = path } },
        } });
        try self.map("proofs").putLink(&txid, cid);
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

    /// proven: we hold a merkle proof for the txid whose root is our
    /// best-chain header's at its height. Anything else is unproven.
    pub fn status(self: *Wallet, txid: [32]u8) !Status {
        const path = (try self.proofPath(txid)) orelse return .unproven;
        const p = bsvz.spv.MerklePath.parse(self.arena, path) catch return .unproven;
        const root = beef_mod.rootFor(self.arena, p, txid) orelse return .unproven;
        const want = (try self.chain().rootAt(p.block_height)) orelse return .unproven;
        return if (std.mem.eql(u8, &root, &want)) .proven else .unproven;
    }

    fn rebuildDerived(self: *Wallet) !void {
        const a = self.arena;
        // spent: every outpoint one of our actions consumes → the spending txid.
        var spent = self.maps.map(null);
        const actions = try self.map("actions").prefixed("");
        for (actions) |kv| {
            const txid: [32]u8 = kv.key[0..32].*;
            const raw = (try self.txRaw(txid)) orelse return error.BadRecord;
            const tx = try bsvz.transaction.Transaction.parse(a, raw);
            for (tx.inputs) |in| {
                const k = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
                try spent.put(&k, .{ .bytes = try a.dupe(u8, &txid) });
            }
        }
        // byBasket: basket ‖ 0 (spendable) | 1 (spent) ‖ outpoint.
        var by_basket = self.maps.map(null);
        for (try self.map("outputs").prefixed("")) |kv| {
            const rec = try self.record(kv.value.cid);
            const basket = rec.getText("basket") orelse return error.BadRecord;
            const state: u8 = if (try spent.has(kv.key)) 1 else 0;
            try by_basket.add(try store_mod.nameKey(a, basket, &.{ &.{state}, kv.key }));
        }
        // byStatus: 0 (proven) | 1 (unproven) ‖ txid.
        var by_status = self.maps.map(null);
        for (actions) |kv| {
            const st: u8 = if ((try self.status(kv.key[0..32].*)) == .proven) 0 else 1;
            try by_status.add(try std.mem.concat(a, u8, &.{ &.{st}, kv.key }));
        }
        self.map("spent").root = spent.root;
        self.map("byBasket").root = by_basket.root;
        self.map("byStatus").root = by_status.root;
    }

    // ------------------------------------------------------------ operations

    pub fn addHeaders(self: *Wallet, raws: []const []const u8) !chain_mod.Chain.AddResult {
        return self.chain().add(raws);
    }

    /// A merkle proof for a transaction we hold (a `proof` entry, or ARC's answer).
    pub fn addProof(self: *Wallet, txid: [32]u8, path: []const u8) !Status {
        if ((try self.txRaw(txid)) == null) return error.UnknownTransaction;
        const p = bsvz.spv.MerklePath.parse(self.arena, path) catch return error.BadProof;
        const root = beef_mod.rootFor(self.arena, p, txid) orelse return error.BadProof;
        const want = (try self.chain().rootAt(p.block_height)) orelse return error.UnknownHeader;
        if (!std.mem.eql(u8, &root, &want)) return error.RootMismatch;
        try self.putProof(txid, p.block_height, path);
        return .proven;
    }

    const SpvCtx = struct {
        w: *Wallet,
        fn rootAt(ptr: *anyopaque, height: u32) anyerror!?[32]u8 {
            const self: *SpvCtx = @ptrCast(@alignCast(ptr));
            return self.w.chain().rootAt(height);
        }
        fn knownRaw(ptr: *anyopaque, arena: std.mem.Allocator, txid: [32]u8) anyerror!?[]const u8 {
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
            const c = try self.store.putValue(a, .{ .map = fields });
            const vout: u32 = @intCast(rec.getUint("vout").?);
            try self.map("outputs").putLink(&store_mod.outpointKey(subject, vout), c);
        }
        return .{ .txid = subject, .status = try self.status(subject), .outputs = @intCast(args.outputs.len) };
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

    pub fn mapCount(self: *Wallet, comptime name: []const u8) !usize {
        return self.map(name).count();
    }
};
