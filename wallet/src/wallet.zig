//! Wallet state as records (issue #29): headers, transactions, merkle proofs,
//! actions and outputs are records; lookups go through index maps; status
//! and spendability are computed from them, never stored as fields. The
//! derived index maps (`spent`, `byBasket`, `byStatus`) are rebuilt from the
//! primary ones on every save, so they are a pure function of the records
//! and the best chain: anyone can recompute and compare.
//!
//! One `Wallet` lives for one step: load from the state record, apply
//! operations, save (new index records, a new state record).
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
const Index = store_mod.Index;
const Value = cbor.Value;

/// The signing oracle, as far as the wallet needs it now: derive our BRC-29
/// payee key (getPublicKey, forSelf, counterparty = the sender).
pub const Oracle = struct {
    ptr: *anyopaque,
    derivePayeeFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, key_id: []const u8, sender: [33]u8) anyerror![33]u8,
};

pub const index_names = [_][]const u8{ "headers", "txs", "proofs", "actions", "outputs", "spent", "byBasket", "byStatus" };

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
};

pub fn outpointKey(arena: std.mem.Allocator, txid: [32]u8, vout: u32) ![]u8 {
    return std.fmt.allocPrint(arena, "{s}.{d}", .{ hdr.toHex(txid), vout });
}

fn textArray(arena: std.mem.Allocator, xs: []const []const u8) ![]Value {
    const out = try arena.alloc(Value, xs.len);
    for (xs, out) |x, *o| o.* = .{ .text = x };
    return out;
}

pub const Network = chain_mod.Network;

pub const Wallet = struct {
    arena: std.mem.Allocator,
    store: Store,
    network: Network,
    ix: [index_names.len]Index,
    cids: [index_names.len]?[]const u8,

    /// The wallet the state record names (null: a new one) on `network`; a
    /// state made for another network is refused.
    pub fn load(arena: std.mem.Allocator, s: Store, state: ?[]const u8, network: Network) !Wallet {
        var w = Wallet{ .arena = arena, .store = s, .network = network, .ix = undefined, .cids = .{null} ** index_names.len };
        var st: ?Value = null;
        if (state) |c| {
            const v = try s.getValue(arena, c);
            if (!std.mem.eql(u8, v.getText("kind") orelse "", "wallet-state")) return error.BadState;
            if (!std.mem.eql(u8, v.getText("network") orelse "", @tagName(network))) return error.NetworkMismatch;
            st = v.get("indexes") orelse return error.BadState;
        }
        for (index_names, 0..) |n, i| {
            w.cids[i] = if (st) |v| v.getCid(n) else null;
            w.ix[i] = try Index.load(arena, s, n, w.cids[i]);
        }
        return w;
    }

    fn index(self: *Wallet, comptime name: []const u8) *Index {
        inline for (index_names, 0..) |n, i| if (comptime std.mem.eql(u8, n, name)) return &self.ix[i];
        @compileError("no index " ++ name);
    }

    pub fn chain(self: *Wallet) chain_mod.Chain {
        return .{ .arena = self.arena, .store = self.store, .headers = self.index("headers"), .network = self.network };
    }

    /// Rebuild the derived indexes, write every changed index and a state record; → its CID.
    pub fn save(self: *Wallet) ![]const u8 {
        try self.rebuildDerived();
        const es = try self.arena.alloc(cbor.Entry, index_names.len);
        for (index_names, 0..) |n, i| {
            if (self.ix[i].dirty or self.cids[i] == null) {
                self.cids[i] = try self.ix[i].save(self.arena, self.store);
                self.ix[i].dirty = false;
            }
            es[i] = .{ .key = n, .value = .{ .cid = self.cids[i].? } };
        }
        return self.store.putValue(self.arena, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "wallet-state" } },
            .{ .key = "network", .value = .{ .text = @tagName(self.network) } },
            .{ .key = "indexes", .value = .{ .map = es } },
        } });
    }

    // ------------------------------------------------------------ records

    /// A transaction we hold: a bitcoin-tx block, its CID the txid.
    fn txRaw(self: *Wallet, txid: [32]u8) !?[]const u8 {
        const v = self.index("txs").get(&hdr.toHex(txid)) orelse return null;
        if (v != .cid) return error.BadRecord;
        return try self.store.get(self.arena, v.cid);
    }

    fn putTx(self: *Wallet, txid: [32]u8, raw: []const u8) ![]const u8 {
        const key = hdr.toHex(txid);
        if (self.index("txs").get(&key)) |v| if (v == .cid) return v.cid;
        const cid = try self.store.putBitcoin(self.arena, .tx, raw);
        try self.index("txs").put(self.arena, &key, .{ .cid = cid });
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
        if (self.index("proofs").get(&key)) |old| if (old == .cid and std.mem.eql(u8, old.cid, cid)) return;
        try self.index("proofs").put(self.arena, &key, .{ .cid = cid });
    }

    // ------------------------------------------------------------ status (computed)

    /// proven: we hold a merkle proof for the txid whose root is our
    /// best-chain header's at its height. Anything else is unproven.
    pub fn status(self: *Wallet, txid: [32]u8) !Status {
        const v = self.index("proofs").get(&hdr.toHex(txid)) orelse return .unproven;
        if (v != .cid) return error.BadRecord;
        const rec = try self.store.getValue(self.arena, v.cid);
        const path = rec.getBytes("path") orelse return error.BadRecord;
        const p = bsvz.spv.MerklePath.parse(self.arena, path) catch return .unproven;
        const root = beef_mod.rootFor(self.arena, p, txid) orelse return .unproven;
        const want = (try self.chain().rootAt(p.block_height)) orelse return .unproven;
        return if (std.mem.eql(u8, &root, &want)) .proven else .unproven;
    }

    fn rebuildDerived(self: *Wallet) !void {
        const a = self.arena;
        // spent: every outpoint one of our actions consumes → the spending txid.
        var spent = Index{ .name = "spent" };
        for (self.index("actions").sortedKeys()) |txid_hex| {
            const txid = try hdr.fromHex(txid_hex);
            const raw = (try self.txRaw(txid)) orelse return error.BadRecord;
            const tx = try bsvz.transaction.Transaction.parse(a, raw);
            for (tx.inputs) |in| {
                const k = try outpointKey(a, in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
                try spent.put(a, k, .{ .text = txid_hex });
            }
        }
        // byBasket: "<basket>/spendable" | "<basket>/spent" → outpoints.
        var lists = std.StringArrayHashMapUnmanaged(std.ArrayList(Value)).empty;
        for (self.index("outputs").sortedKeys()) |op| {
            const v = self.index("outputs").get(op).?;
            const rec = try self.store.getValue(a, v.cid);
            const basket = rec.getText("basket") orelse return error.BadRecord;
            const k = try std.fmt.allocPrint(a, "{s}/{s}", .{ basket, if (spent.get(op) != null) "spent" else "spendable" });
            const gop = try lists.getOrPut(a, k);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(a, .{ .text = op });
        }
        var by_basket = Index{ .name = "byBasket" };
        for (lists.keys(), lists.values()) |k, l| try by_basket.put(a, k, .{ .array = l.items });
        // byStatus: proven | unproven → our actions' txids.
        var proven: std.ArrayList(Value) = .empty;
        var unproven: std.ArrayList(Value) = .empty;
        for (self.index("actions").sortedKeys()) |txid_hex| {
            const st = try self.status(try hdr.fromHex(txid_hex));
            try (if (st == .proven) &proven else &unproven).append(a, .{ .text = txid_hex });
        }
        var by_status = Index{ .name = "byStatus" };
        if (proven.items.len > 0) try by_status.put(a, "proven", .{ .array = proven.items });
        if (unproven.items.len > 0) try by_status.put(a, "unproven", .{ .array = unproven.items });

        self.replaceDerived("spent", spent);
        self.replaceDerived("byBasket", by_basket);
        self.replaceDerived("byStatus", by_status);
    }

    fn replaceDerived(self: *Wallet, comptime name: []const u8, fresh: Index) void {
        const ix = self.index(name);
        ix.* = fresh;
        ix.dirty = true; // re-put; an unchanged map gets the same CID
    }

    // ------------------------------------------------------------ operations

    pub fn addHeaders(self: *Wallet, raws: []const []const u8) !chain_mod.Chain.AddResult {
        return self.chain().add(raws);
    }

    /// A merkle proof for a transaction we hold (a ChainTracks/Arcade answer).
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
        const txid_hex = hdr.toHex(subject);
        const action = try self.store.putValue(a, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "action" } },
            .{ .key = "txid", .value = .{ .text = &txid_hex } },
            .{ .key = "tx", .value = .{ .cid = tx_cid } },
            .{ .key = "description", .value = .{ .text = args.description } },
            .{ .key = "labels", .value = .{ .array = try textArray(a, args.labels) } },
        } });
        if (self.index("actions").get(&txid_hex) == null) try self.index("actions").put(a, &txid_hex, .{ .cid = action });
        for (recs) |*rec| {
            var fields = try a.dupe(cbor.Entry, rec.map);
            fields = try a.realloc(fields, fields.len + 1);
            fields[fields.len - 1] = .{ .key = "tx", .value = .{ .cid = tx_cid } };
            const c = try self.store.putValue(a, .{ .map = fields });
            const vout: u32 = @intCast(rec.getUint("vout").?);
            try self.index("outputs").put(a, try outpointKey(a, subject, vout), .{ .cid = c });
        }
        return .{ .txid = subject, .status = try self.status(subject), .outputs = @intCast(args.outputs.len) };
    }

    /// Outputs in a basket, spendable ones only unless `include_spent`.
    /// Satoshis and script come from the transaction, not the output record.
    pub fn listOutputs(self: *Wallet, basket: []const u8, include_spent: bool) ![]OutputView {
        const a = self.arena;
        try self.rebuildDerived();
        var out: std.ArrayList(OutputView) = .empty;
        for ([_][]const u8{ "spendable", "spent" }) |state| {
            if (!include_spent and std.mem.eql(u8, state, "spent")) continue;
            const k = try std.fmt.allocPrint(a, "{s}/{s}", .{ basket, state });
            const list = self.index("byBasket").get(k) orelse continue;
            for (list.array) |op| {
                const dot = std.mem.lastIndexOfScalar(u8, op.text, '.') orelse return error.BadRecord;
                const txid = try hdr.fromHex(op.text[0..dot]);
                const vout = try std.fmt.parseInt(u32, op.text[dot + 1 ..], 10);
                const raw = (try self.txRaw(txid)) orelse return error.BadRecord;
                const tx = try bsvz.transaction.Transaction.parse(a, raw);
                if (vout >= tx.outputs.len) return error.BadRecord;
                try out.append(a, .{
                    .txid = txid,
                    .vout = vout,
                    .satoshis = @intCast(tx.outputs[vout].satoshis),
                    .locking_script = tx.outputs[vout].locking_script.bytes,
                    .basket = basket,
                    .spendable = std.mem.eql(u8, state, "spendable"),
                    .status = try self.status(txid),
                });
            }
        }
        return out.toOwnedSlice(a);
    }

    pub fn indexCount(self: *Wallet, comptime name: []const u8) usize {
        return self.index(name).count();
    }
    pub fn indexGet(self: *Wallet, comptime name: []const u8, key: []const u8) ?Value {
        return self.index(name).get(key);
    }
};
