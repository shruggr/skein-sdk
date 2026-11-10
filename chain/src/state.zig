//! The chain state (shruggr/skein#78): one instance's view of the chain,
//! global to the instance, written by one app — the chain module
//! (shruggr/skein-chain) — and read by everyone else by CID. Headers and the
//! best chain, every transaction ingested, its proof, its spends, its
//! settlement, and the broadcast each unproven one has registered.
//!
//! One `State` lives for one step: load from the state record (the root of
//! the chain app's head `<app>/state`), apply operations, save (new map
//! nodes, a new state record). The record:
//!
//!   {kind: "chain-state", network: "main" | "test" | "regtest", maps: {<name>: <MST root> | null}}
//!
//! The maps (keys bytes, ordered bytewise; the kernel's Merkle search trees):
//!
//!   headers       height (u32 BE) → header (bitcoin-block)            the best chain (chain.zig)
//!   heights       block hash → height                                 the best chain, backwards
//!   txs           txid → transaction (bitcoin-tx)                     every transaction ingested (kept: its
//!                                                                     inputs are the kernel's `spends` edges)
//!   proofs        txid → {block, depth, position, broadcast?}         its block's header (a bitcoin-block link)
//!                                                                     and its leaf (merkle.zig `Position`);
//!                                                                     the broadcast record it settled (a link)
//!   proofHeights  height (u32 BE) ‖ txid → null                       proofs by height: what a reorg reverts
//!   rejected      txid → settlement record                            will never be mined (reason, at, cause?)
//!   unproven      txid → null                                         derived: held, neither proven nor rejected
//!   spent         txid ‖ vout (u32 BE) → spending txid (bytes)        derived: the first held spender not rejected
//!   broadcasts    txid → broadcast record                             the broadcast each unproven transaction
//!                                                                     has registered (below)
//!
//! **Every unproven transaction at rest has a registered broadcast**: a
//! transaction is in `unproven` only while `broadcasts` holds a record for
//! it. The record:
//!
//!   {kind: "broadcast", txid (hex), subject: <tx CID>, since: ms, txStatus: text,
//!    accepted?: true, path?: bytes (a BUMP whose header is not held yet),
//!    watchers: [{to: bytes(33), box, request: <message CID>}]}
//!
//! `watchers` are the callers to answer on each state change of the
//! transaction (accepted, proven, rejected); `accepted` is set by the first
//! status that is not a rejection. Proven or rejected, the record goes: the
//! transaction no longer awaits anything. Proven, its `proofs` entry links
//! the record it settled, for the watchers: a reorg that turns it back to unproven registers its
//! broadcast again (`reverted`) with the same watchers, and the next proof
//! — the same transaction in another block — tells them again.
//!
//! Status is computed from the records, never stored: proven (its proof's block
//! is on our best chain — also after a rejection: the latest fact wins, the
//! settlement record stays), rejected (a settlement record), else unproven.
//! A rejection walks what spends the transaction (the `spends` edges into it,
//! held transactions only) and rejects that too ("input-rejected"). A proof
//! rejects every other held transaction spending one of the same outputs
//! ("double-spent").
//!
//! Every state change of a transaction with a registered broadcast is listed
//! in `changes`, with the watchers to answer — the program answers them.
//! 0.19.0 (David 2026-11-09): every transaction newly held in a step is listed
//! in `added` (in the order recorded), so the chain app gives each one its
//! status at intake; a rejection names its cause (`by`): the winner of a
//! double spend, the cascade's root for "input-rejected" — on the settlement
//! record (`cause`) and on the change.
const std = @import("std");
const bsvz = @import("bsvz");
const cbor = @import("cbor.zig");
const hdr = @import("header.zig");
const beef_mod = @import("beef.zig");
const spv = @import("spv.zig");
const chain_mod = @import("chain.zig");
const store_mod = @import("store.zig");
const merkle = @import("merkle.zig");
const host_mod = @import("host.zig");

const Store = store_mod.Store;
const Map = store_mod.Map;
const Value = cbor.Value;

pub const Network = chain_mod.Network;

pub const map_names = [_][]const u8{ "headers", "heights", "txs", "proofs", "proofHeights", "rejected", "unproven", "spent", "broadcasts" };

pub const Status = enum { proven, unproven, rejected };

/// A state change of a transaction with a registered broadcast: what its watchers are told.
pub const Change = struct {
    txid: [32]u8,
    state: enum { accepted, proven, rejected },
    /// The watchers registered when it changed (`{to, box, request}`).
    watchers: []const Value,
    /// The status that accepted it, or the rejection's reason.
    detail: []const u8 = "",
    /// A rejection's cause (0.19.0): the proven transaction that spends the same output
    /// ("double-spent"), or the rejected transaction it spends from ("input-rejected": the
    /// cascade's root). Null for a rejection by the network.
    by: ?[32]u8 = null,
};

/// The status texts (Arcade's txStatus) that reject a transaction.
pub fn isRejection(tx_status: []const u8) bool {
    for ([_][]const u8{ "REJECTED", "DOUBLE_SPEND_ATTEMPTED", "INVALID", "MALFORMED" }) |s| if (std.mem.eql(u8, s, tx_status)) return true;
    return false;
}

/// What an ingest came to.
pub const Ingested = struct {
    txid: [32]u8,
    /// The transaction's CID (bitcoin-tx: its txid).
    tx: []const u8,
    status: Status,
    /// Transactions this ingest recorded unproven and registered a broadcast for, parents first:
    /// the caller broadcasts each and awaits it.
    registered: []const [32]u8,
};

pub const State = struct {
    arena: std.mem.Allocator,
    store: Store,
    network: Network,
    maps: *store_mod.Maps,
    m: [map_names.len]Map,
    /// The step's time (ms): settlement records and broadcasts are stamped with it.
    now: i64 = 0,
    /// Transactions a reorg this step turned back to unproven (their broadcasts registered again):
    /// the caller broadcasts each again and awaits it.
    reverted: std.ArrayList([32]u8) = .empty,
    /// State changes this step of transactions with a registered broadcast.
    changes: std.ArrayList(Change) = .empty,
    /// Transactions this step newly held (`putTx` recorded them), in the order recorded (an ingest:
    /// parents first). 0.19.0: each gets its status at intake.
    added: std.ArrayList([32]u8) = .empty,

    /// The state the record names (null: a new one) on `network`; a state made for another network is refused.
    pub fn load(arena: std.mem.Allocator, s: Store, state: ?[]const u8, network: Network) !State {
        const maps = try store_mod.Maps.create(arena, s);
        var st = State{ .arena = arena, .store = s, .network = network, .maps = maps, .m = undefined };
        var roots: ?Value = null;
        if (state) |c| {
            const v = try s.getValue(arena, c);
            if (!std.mem.eql(u8, v.getText("kind") orelse "", "chain-state")) return error.BadState;
            if (!std.mem.eql(u8, v.getText("network") orelse "", @tagName(network))) return error.NetworkMismatch;
            roots = v.get("maps") orelse return error.BadState;
        }
        for (map_names, 0..) |n, i| st.m[i] = maps.map(if (roots) |r| r.getCid(n) else null);
        return st;
    }

    pub fn map(self: *State, comptime name: []const u8) *Map {
        inline for (map_names, 0..) |n, i| if (comptime std.mem.eql(u8, n, name)) return &self.m[i];
        @compileError("no map " ++ name);
    }

    pub fn chain(self: *State) chain_mod.Chain {
        return .{ .arena = self.arena, .store = self.store, .headers = self.map("headers"), .heights = self.map("heights"), .network = self.network };
    }

    /// Put every new map node and a state record naming the maps' roots; → its CID.
    pub fn save(self: *State) ![]const u8 {
        const es = try self.arena.alloc(cbor.Entry, map_names.len);
        for (map_names, &self.m, es) |n, *mp, *e| {
            try mp.flush();
            e.* = .{ .key = n, .value = if (mp.root) |r| .{ .cid = r } else .null };
        }
        return self.store.putValue(self.arena, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "chain-state" } },
            .{ .key = "network", .value = .{ .text = @tagName(self.network) } },
            .{ .key = "maps", .value = .{ .map = es } },
        } });
    }

    pub fn record(self: *State, cid: []const u8) !Value {
        return self.store.getValue(self.arena, cid);
    }

    // ------------------------------------------------------------ transactions

    /// A transaction we hold: a bitcoin-tx block, its CID the txid.
    pub fn txRaw(self: *State, txid: [32]u8) !?[]const u8 {
        const c = (try self.map("txs").link(&txid)) orelse return null;
        return try self.store.get(self.arena, c);
    }

    pub fn holds(self: *State, txid: [32]u8) !bool {
        return self.map("txs").has(&txid);
    }

    /// A transaction, held: its block, kept (each input a `spends` edge, #42), and what that changes in `spent`.
    pub fn putTx(self: *State, txid: [32]u8, raw: []const u8) ![]const u8 {
        if (try self.map("txs").link(&txid)) |c| return c;
        const cid = try self.store.putBitcoin(self.arena, .tx, raw);
        try self.map("txs").putLink(&txid, cid);
        try self.added.append(self.arena, txid);
        const tx = try bsvz.transaction.Transaction.parse(self.arena, raw);
        for (tx.inputs) |in| try self.refreshSpent(store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index));
        try self.resettle(txid);
        return cid;
    }

    /// `spent[op]`: the first (lowest txid) held spender of `op` that is not rejected, or none.
    fn refreshSpent(self: *State, op: [36]u8) !void {
        var first: ?[32]u8 = null;
        for (try self.spendersOf(op)) |sp| {
            if ((try self.status(sp)) == .rejected) continue;
            first = sp;
            break;
        }
        if (first) |f| {
            try self.map("spent").put(&op, .{ .bytes = try self.arena.dupe(u8, &f) });
        } else _ = try self.map("spent").remove(&op);
    }

    /// `unproven`: held, neither proven on our best chain nor rejected.
    fn resettle(self: *State, txid: [32]u8) !void {
        if ((try self.holds(txid)) and (try self.status(txid)) == .unproven) {
            try self.map("unproven").add(&txid);
        } else _ = try self.map("unproven").remove(&txid);
    }

    /// The held transactions that spend `op`, lowest txid first (the kernel's `spends` edges).
    pub fn spendersOf(self: *State, op: [36]u8) ![][32]u8 {
        var held: std.ArrayList([32]u8) = .empty;
        for (try self.store.spendersOf(self.arena, op[0..32].*, std.mem.readInt(u32, op[32..36], .big))) |sp| {
            if (try self.holds(sp)) try held.append(self.arena, sp);
        }
        return held.items;
    }

    /// The held transactions that spend any output of `txid`, lowest txid first.
    pub fn spendersOfTx(self: *State, txid: [32]u8) ![][32]u8 {
        var out: std.ArrayList([32]u8) = .empty;
        for (try self.store.edges(self.arena, &store_mod.hashCid(.tx, txid), "spends")) |e| {
            const h = store_mod.bitcoinHash(e.from) orelse continue;
            if (out.items.len > 0 and std.mem.eql(u8, &out.items[out.items.len - 1], &h)) continue;
            if (!(try self.holds(h))) continue;
            try out.append(self.arena, h);
        }
        return out.items;
    }

    /// The spending txid `spent` names for an outpoint, or null.
    pub fn spentBy(self: *State, txid: [32]u8, vout: u32) !?[32]u8 {
        const v = (try self.map("spent").get(&store_mod.outpointKey(txid, vout))) orelse return null;
        if (v != .bytes or v.bytes.len != 32) return error.BadIndex;
        return v.bytes[0..32].*;
    }

    // ------------------------------------------------------------ status

    /// A transaction's status is its latest fact (0.18.0, David 2026-11-09): a proof on our best chain
    /// makes it proven, also when it was rejected before (its settlement record stays: the reason is
    /// read from state); else rejected (a settlement record); else unproven.
    pub fn status(self: *State, txid: [32]u8) !Status {
        if ((try self.minedStatus(txid)) == .proven) return .proven;
        if (try self.map("rejected").has(&txid)) return .rejected;
        return .unproven;
    }

    pub fn minedStatus(self: *State, txid: [32]u8) !Status {
        const block = (try self.proofBlock(txid)) orelse return .unproven;
        return if ((try self.chain().heightOf(block)) != null) .proven else .unproven;
    }

    /// The settlement record's CID of a rejected transaction, or null.
    pub fn settlementCid(self: *State, txid: [32]u8) !?[]const u8 {
        return self.map("rejected").link(&txid);
    }

    /// A rejected transaction's reason and cause (0.19.0), from its settlement record; null when it
    /// has none. `by`: the winner of a double spend, or the root of an "input-rejected" cascade.
    pub fn rejectionOf(self: *State, txid: [32]u8) !?struct { reason: []const u8, by: ?[32]u8 } {
        const c = (try self.settlementCid(txid)) orelse return null;
        const r = try self.record(c);
        const by: ?[32]u8 = if (r.getText("cause")) |h| (hdr.fromHex(h) catch return error.BadRecord) else null;
        return .{ .reason = r.getText("reason") orelse "", .by = by };
    }

    // ------------------------------------------------------------ proofs

    const ProofEntry = std.meta.Elem(@FieldType(store_mod.MValue, "map"));

    /// A merkle path proving `txid`: its root must be our best-chain header's at its height. The nodes
    /// it reveals are put as 64-byte bitcoin-tx blocks; `proofs` names the header and the leaf.
    pub fn putProof(self: *State, txid: [32]u8, p: merkle.MerklePath) !void {
        const got = beef_mod.rootFor(self.arena, p, txid) orelse return error.BadProof;
        const at = (try self.chain().at(p.block_height)) orelse return error.UnknownHeader;
        const want = (try hdr.Header.parse(&at.raw)).merkle_root;
        if (!std.mem.eql(u8, &got, &want)) return error.RootMismatch;
        const rev = try merkle.reveal(self.arena, p);
        if (!std.mem.eql(u8, &rev.root, &want)) return error.RootMismatch;
        try merkle.putNodes(self.store, rev.nodes);
        const pos = merkle.positionIn(p, txid) orelse return error.BadProof;
        const block = try self.arena.dupe(u8, &store_mod.hashCid(.block, at.hash));
        const es = try self.arena.dupe(ProofEntry, &.{
            .{ .key = "block", .value = .{ .cid = block } },
            .{ .key = "depth", .value = .{ .int = pos.depth } },
            .{ .key = "position", .value = .{ .int = pos.offset } },
        });
        try self.map("proofs").put(&txid, .{ .map = es });
        try self.map("proofHeights").add(&(store_mod.be32(p.block_height) ++ txid));
        try self.resettle(txid);
    }

    /// The proof record for a txid: its block's header CID and the leaf's position; null when none.
    pub fn proofRecord(self: *State, txid: [32]u8) !?struct { block: []const u8, pos: merkle.Position } {
        const v = (try self.map("proofs").get(&txid)) orelse return null;
        const block = if (v.get("block")) |b| (if (b == .cid) b.cid else return error.BadIndex) else return error.BadIndex;
        const depth = if (v.get("depth")) |d| (if (d == .int and d.int >= 0 and d.int <= 64) d.int else return error.BadIndex) else return error.BadIndex;
        const offset = if (v.get("position")) |o| (if (o == .int and o.int >= 0 and o.int <= std.math.maxInt(u64)) o.int else return error.BadIndex) else return error.BadIndex;
        return .{ .block = block, .pos = .{ .depth = @intCast(depth), .offset = @intCast(offset) } };
    }

    pub fn proofBlock(self: *State, txid: [32]u8) !?[32]u8 {
        const r = (try self.proofRecord(txid)) orelse return null;
        return store_mod.bitcoinHash(r.block) orelse error.BadIndex;
    }

    /// The BUMP for a txid, rebuilt from the tree's nodes, when its proof's block is on our best chain.
    pub fn proofFor(self: *State, txid: [32]u8) !?merkle.MerklePath {
        const r = (try self.proofRecord(txid)) orelse return null;
        const hash = store_mod.bitcoinHash(r.block) orelse return error.BadIndex;
        const height = (try self.chain().heightOf(hash)) orelse return null;
        const raw = try self.store.get(self.arena, r.block);
        if (raw.len != hdr.size) return error.BadRecord;
        const root = (try hdr.Header.parse(raw[0..hdr.size])).merkle_root;
        return merkle.pathFor(self.arena, self.store, root, height, txid, r.pos);
    }

    /// The BUMPs of several proven transactions, one per block: gather them (`add`, which gives the
    /// index of the transaction's block, blocks numbered in the order first named), then `build`
    /// selects each block's BUMP from the tree's nodes in one descent (`merkle.pathsFor`), no merges.
    pub fn bumps(self: *State) Bumps {
        return .{ .st = self };
    }

    pub const Bumps = struct {
        st: *State,
        blocks: std.ArrayList(Block) = .empty,

        const Block = struct { hash: [32]u8, height: u32, root: [32]u8, leaves: std.ArrayList(merkle.Leaf) = .empty };

        /// A proven transaction's block's index; error.MissingProof when its proof's block is not on our best chain.
        pub fn add(self: *Bumps, txid: [32]u8) !usize {
            const a = self.st.arena;
            const r = (try self.st.proofRecord(txid)) orelse return error.MissingProof;
            const hash = store_mod.bitcoinHash(r.block) orelse return error.BadIndex;
            for (self.blocks.items, 0..) |*b, i| if (std.mem.eql(u8, &b.hash, &hash)) {
                try b.leaves.append(a, .{ .txid = txid, .pos = r.pos });
                return i;
            };
            const height = (try self.st.chain().heightOf(hash)) orelse return error.MissingProof;
            const raw = try self.st.store.get(a, r.block);
            if (raw.len != hdr.size) return error.BadRecord;
            var b: Block = .{ .hash = hash, .height = height, .root = (try hdr.Header.parse(raw[0..hdr.size])).merkle_root };
            try b.leaves.append(a, .{ .txid = txid, .pos = r.pos });
            try self.blocks.append(a, b);
            return self.blocks.items.len - 1;
        }

        /// One BUMP per block, in index order.
        pub fn build(self: *Bumps) ![]merkle.MerklePath {
            const a = self.st.arena;
            const out = try a.alloc(merkle.MerklePath, self.blocks.items.len);
            for (self.blocks.items, out) |b, *p| p.* = (try merkle.pathsFor(a, self.st.store, b.root, b.height, b.leaves.items)) orelse return error.MissingProof;
            return out;
        }
    };

    /// A merkle path (BRC-74) for a transaction we hold: proven, also when it was rejected first (its
    /// settlement record stays; the proof is the latest fact, and it is a change: `mined`). Every other
    /// held transaction spending one of the same outputs is rejected ("double-spent").
    /// error.UnknownHeader when the header at its height is not held yet.
    pub fn addProof(self: *State, txid: [32]u8, path: []const u8) !Status {
        if (!(try self.holds(txid))) return error.UnknownTransaction;
        const p = bsvz.spv.MerklePath.parse(self.arena, path) catch return error.BadProof;
        return self.addPath(txid, p);
    }

    fn addPath(self: *State, txid: [32]u8, p: merkle.MerklePath) !Status {
        const before = try self.status(txid);
        if (before == .proven) return .proven;
        try self.putProof(txid, p);
        try self.rejectConflicting(txid);
        if (before == .rejected) {
            // Its inputs' `spent` again (a rejected spender was left out), and the change itself: no
            // broadcast record is left to settle (the rejection removed it), no watchers.
            const raw = (try self.txRaw(txid)) orelse return error.UnknownTransaction;
            const tx = try bsvz.transaction.Transaction.parse(self.arena, raw);
            for (tx.inputs) |in| try self.refreshSpent(store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index));
            try self.changes.append(self.arena, .{ .txid = txid, .state = .proven, .watchers = &.{}, .detail = "" });
        }
        try self.settled(txid, .proven, "");
        return .proven;
    }

    // ------------------------------------------------------------ headers

    /// A run of headers, parents first. A heavier branch that replaces ours reverts the proofs against
    /// the replaced headers: those transactions are unproven again and register their broadcasts again
    /// (`reverted`). Proofs that waited for a header (a broadcast's `path`) are tried again.
    pub fn addHeaders(self: *State, raws: []const []const u8) !chain_mod.Chain.AddResult {
        const res = try self.chain().add(raws);
        if (res.added > 0) {
            const start = res.tip + 1 - res.added;
            for (try self.map("proofHeights").from(&store_mod.be32(start))) |kv| {
                if (kv.key.len != 36) return error.BadIndex;
                const txid: [32]u8 = kv.key[4..36].*;
                try self.resettle(txid);
                if (res.replaced > 0 and (try self.status(txid)) == .unproven and (try self.broadcastRecord(txid)) == null) {
                    try self.writeBroadcast(txid, null, .{ .tx_status = "", .watchers = try self.settledWatchers(txid) });
                    if (!contains(self.reverted.items, txid)) try self.reverted.append(self.arena, txid);
                }
            }
            try self.retryPendingProofs();
        }
        return res;
    }

    pub const Pointed = struct {
        /// The host chain's tip height (0 for a chain with only the anchor).
        height: u32,
        /// The highest height where this state's best chain and the host's agree.
        fork: u32,
        /// Whether headers of this state's chain above the fork are not the host's (a reorg).
        replaced: bool,
    };

    /// The host chain (shruggr/skein#156): this state's `headers` and `heights` become the host
    /// chain record's (`host_cid`, skein-sdk `chain.host`) — pointed at, not copied. The fork is the
    /// highest height of this state's best chain whose header the host's best chain holds at the
    /// same height (walked back from this state's tip; an empty state forks at 0). Headers of ours
    /// above it that the host's chain replaced revert the proofs against them, as `addHeaders` does
    /// for a heavier branch: those transactions are unproven again and register their broadcasts
    /// again (`reverted`); proofs that waited for a header are tried again. A record of another
    /// network is refused (`error.NetworkMismatch`).
    pub fn pointAt(self: *State, host_cid: []const u8) !Pointed {
        const r = try host_mod.read(self.arena, self.store, host_cid);
        if (r.network != self.network) return error.NetworkMismatch;
        var hh = self.maps.map(r.headers);
        var hs = self.maps.map(r.heights);
        const theirs = chain_mod.Chain{ .arena = self.arena, .store = self.store, .headers = &hh, .heights = &hs, .network = self.network };
        const host_tip = (try theirs.tip()) orelse 0;
        const ours = self.chain();
        const our_tip = try ours.tip();
        var fork: u32 = 0;
        if (our_tip) |t| {
            var h = t;
            while (true) {
                const at = (try ours.at(h)) orelse return error.BadRecord;
                if ((try theirs.heightOf(at.hash))) |x| if (x == h) {
                    fork = h;
                    break;
                };
                if (h == 0) break;
                h -= 1;
            }
        }
        const replaced = if (our_tip) |t| t > fork else false;
        const same = !replaced and our_tip != null and our_tip.? == host_tip and
            optEq(self.map("headers").root, r.headers) and optEq(self.map("heights").root, r.heights);
        if (same) return .{ .height = host_tip, .fork = fork, .replaced = false };
        const headers = self.map("headers");
        const heights = self.map("heights");
        headers.root = r.headers;
        heights.root = r.heights;
        headers.dirty = true;
        heights.dirty = true;
        for (try self.map("proofHeights").from(&store_mod.be32(fork + 1))) |kv| {
            if (kv.key.len != 36) return error.BadIndex;
            const txid: [32]u8 = kv.key[4..36].*;
            try self.resettle(txid);
            if (replaced and (try self.status(txid)) == .unproven and (try self.broadcastRecord(txid)) == null) {
                try self.writeBroadcast(txid, null, .{ .tx_status = "", .watchers = try self.settledWatchers(txid) });
                if (!contains(self.reverted.items, txid)) try self.reverted.append(self.arena, txid);
            }
        }
        try self.retryPendingProofs();
        return .{ .height = host_tip, .fork = fork, .replaced = replaced };
    }

    fn retryPendingProofs(self: *State) !void {
        for (try self.map("broadcasts").prefixed("")) |kv| {
            if (kv.key.len != 32) return error.BadIndex;
            const txid: [32]u8 = kv.key[0..32].*;
            const r = try self.record(if (kv.value == .cid) kv.value.cid else return error.BadIndex);
            const path = r.getBytes("path") orelse continue;
            _ = self.addProof(txid, path) catch |e| switch (e) {
                error.UnknownHeader => continue,
                else => return e,
            };
        }
    }

    // ------------------------------------------------------------ rejection

    /// Reject a transaction and what spends it (held, transitively, breadth first; spenders in txid
    /// order): a settlement record each, `unproven` and `spent` kept up to date. A proven transaction
    /// is never rejected. → the transactions rejected, the given one first.
    pub fn reject(self: *State, root: [32]u8, reason: []const u8) ![][32]u8 {
        return self.rejectBy(root, reason, null);
    }

    /// `reject` with the root's cause (0.19.0): `by` the proven transaction that spends the same
    /// output ("double-spent"), recorded as the root's `cause`; what spends it is "input-rejected"
    /// with the root as its cause, as before.
    pub fn rejectBy(self: *State, root: [32]u8, reason: []const u8, root_by: ?[32]u8) ![][32]u8 {
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
            const cause: ?[32]u8 = if (by) root else root_by;
            if (cause) |cz| try fields.append(a, .{ .key = "cause", .value = .{ .text = try a.dupe(u8, &hdr.toHex(cz)) } });
            const rec = try self.store.putValue(a, .{ .map = fields.items });
            try self.map("rejected").putLink(&t, rec);
            try self.resettle(t);
            try self.settledBy(t, .rejected, if (by) "input-rejected" else reason, cause);
            try out.append(a, t);
            for (try self.spendersOfTx(t)) |s| try queue.append(a, s);
        }
        for (out.items) |t| {
            const raw = (try self.txRaw(t)) orelse continue;
            const tx = try bsvz.transaction.Transaction.parse(a, raw);
            for (tx.inputs) |in| try self.refreshSpent(store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index));
        }
        return out.items;
    }

    /// A transaction just proven: every other held transaction spending one of the same outputs is a double spend.
    fn rejectConflicting(self: *State, txid: [32]u8) !void {
        const raw = (try self.txRaw(txid)) orelse return;
        const tx = try bsvz.transaction.Transaction.parse(self.arena, raw);
        for (tx.inputs) |in| {
            const op = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
            for (try self.spendersOf(op)) |other| {
                if (std.mem.eql(u8, &other, &txid)) continue;
                _ = try self.rejectBy(other, "double-spent", txid);
            }
        }
    }

    /// A transaction spending an output a proven held transaction already spends: rejected at once.
    pub fn rejectIfConflicted(self: *State, txid: [32]u8) !bool {
        const raw = (try self.txRaw(txid)) orelse return false;
        const tx = try bsvz.transaction.Transaction.parse(self.arena, raw);
        for (tx.inputs) |in| {
            const op = store_mod.outpointKey(in.previous_outpoint.txid.bytes, in.previous_outpoint.index);
            for (try self.spendersOf(op)) |other| {
                if (std.mem.eql(u8, &other, &txid)) continue;
                if ((try self.status(other)) == .proven) {
                    _ = try self.rejectBy(txid, "double-spent", other);
                    return true;
                }
            }
        }
        return false;
    }

    // ------------------------------------------------------------ broadcasts

    pub fn broadcastCid(self: *State, txid: [32]u8) !?[]const u8 {
        return self.map("broadcasts").link(&txid);
    }

    pub fn broadcastRecord(self: *State, txid: [32]u8) !?Value {
        const c = (try self.broadcastCid(txid)) orelse return null;
        return try self.record(c);
    }

    /// Every transaction with a registered broadcast.
    pub fn broadcastTxids(self: *State) ![][32]u8 {
        const kvs = try self.map("broadcasts").prefixed("");
        const out = try self.arena.alloc([32]u8, kvs.len);
        for (kvs, out) |kv, *o| o.* = kv.key[0..32].*;
        return out;
    }

    /// Register the broadcast of an unproven transaction we hold (since now, no watchers).
    pub fn register(self: *State, txid: [32]u8, tx_status: []const u8) !void {
        try self.writeBroadcast(txid, null, .{ .tx_status = tx_status });
    }

    const Fields = struct { tx_status: ?[]const u8 = null, accepted: ?bool = null, path: ?[]const u8 = null, add_watcher: ?Value = null, watchers: ?[]const Value = null };

    /// The broadcast record of `txid` with some fields changed (`prior`: the record as it stands;
    /// `watchers`: the list to start from instead of the prior record's).
    fn writeBroadcast(self: *State, txid: [32]u8, prior: ?Value, f: Fields) !void {
        const a = self.arena;
        const raw = (try self.txRaw(txid)) orelse return error.UnknownTransaction;
        var watchers: std.ArrayList(Value) = .empty;
        if (f.watchers) |ws| {
            try watchers.appendSlice(a, ws);
        } else if (prior) |p| if (p.getArray("watchers")) |ws| try watchers.appendSlice(a, ws);
        if (f.add_watcher) |w| try watchers.append(a, w);
        var fields: std.ArrayList(cbor.Entry) = .empty;
        try fields.appendSlice(a, &.{
            .{ .key = "kind", .value = .{ .text = "broadcast" } },
            .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &hdr.toHex(txid)) } },
            .{ .key = "subject", .value = .{ .cid = try a.dupe(u8, &store_mod.bitcoinCid(.tx, raw)) } },
            .{ .key = "since", .value = .{ .uint = if (prior) |p| p.getUint("since") orelse @intCast(@max(self.now, 0)) else @intCast(@max(self.now, 0)) } },
            .{ .key = "txStatus", .value = .{ .text = f.tx_status orelse if (prior) |p| p.getText("txStatus") orelse "" else "" } },
            .{ .key = "watchers", .value = .{ .array = watchers.items } },
        });
        if (f.accepted orelse if (prior) |p| p.getBool("accepted") orelse false else false) try fields.append(a, .{ .key = "accepted", .value = .{ .boolean = true } });
        if (f.path orelse if (prior) |p| p.getBytes("path") else null) |path| try fields.append(a, .{ .key = "path", .value = .{ .bytes = path } });
        try self.map("broadcasts").putLink(&txid, try self.store.putValue(a, .{ .map = fields.items }));
    }

    /// A caller to answer on each state change of `txid` (its broadcast must be registered).
    pub fn watch(self: *State, txid: [32]u8, to: []const u8, box: []const u8, request: []const u8) !void {
        const prior = (try self.broadcastRecord(txid)) orelse return error.NotRegistered;
        const w: Value = .{ .map = try self.arena.dupe(cbor.Entry, &.{
            .{ .key = "to", .value = .{ .bytes = to } },
            .{ .key = "box", .value = .{ .text = box } },
            .{ .key = "request", .value = .{ .cid = request } },
        }) };
        try self.writeBroadcast(txid, prior, .{ .add_watcher = w });
    }

    /// Proven or rejected: the watchers are told (`changes`) and the broadcast record goes. Proven, the
    /// watchers move onto the `proofs` entry: a reorg registers the broadcast again with them.
    fn settled(self: *State, txid: [32]u8, to: @FieldType(Change, "state"), detail: []const u8) !void {
        return self.settledBy(txid, to, detail, null);
    }

    fn settledBy(self: *State, txid: [32]u8, to: @FieldType(Change, "state"), detail: []const u8, by: ?[32]u8) !void {
        const r = (try self.broadcastRecord(txid)) orelse return;
        try self.changes.append(self.arena, .{ .txid = txid, .state = to, .watchers = r.getArray("watchers") orelse &.{}, .detail = detail, .by = by });
        if (to == .proven) {
            const c = (try self.broadcastCid(txid)).?;
            const v = (try self.map("proofs").get(&txid)) orelse return error.BadIndex;
            if (v != .map) return error.BadIndex;
            var es: std.ArrayList(ProofEntry) = .empty;
            for (v.map) |e| if (!std.mem.eql(u8, e.key, "broadcast")) try es.append(self.arena, e);
            try es.append(self.arena, .{ .key = "broadcast", .value = .{ .cid = c } });
            try self.map("proofs").put(&txid, .{ .map = es.items });
        }
        _ = try self.map("broadcasts").remove(&txid);
    }

    /// The watchers of the broadcast record a proven transaction's proof settled (none: none).
    fn settledWatchers(self: *State, txid: [32]u8) !?[]const Value {
        const v = (try self.map("proofs").get(&txid)) orelse return null;
        const b = v.get("broadcast") orelse return null;
        if (b != .cid) return error.BadIndex;
        return (try self.record(b.cid)).getArray("watchers");
    }

    pub const Outcome = enum { pending, accepted, proven, rejected };

    /// A status for a transaction we hold (a status provider's message, or a proof event as `MINED`
    /// with its path): a path proves it (a header not held yet keeps the path for later), a rejection
    /// rejects it (and what spends it), any other status — the first — accepts it.
    pub fn applyStatus(self: *State, txid: [32]u8, tx_status: []const u8, merkle_path: ?[]const u8) !Outcome {
        if (!(try self.holds(txid))) return error.UnknownTransaction;
        if (merkle_path) |p| {
            if (self.addProof(txid, p)) |_| {
                return .proven;
            } else |e| switch (e) {
                error.UnknownHeader => if (try self.broadcastRecord(txid)) |r| try self.writeBroadcast(txid, r, .{ .path = p }),
                else => return e,
            }
        } else if (isRejection(tx_status)) {
            _ = try self.reject(txid, tx_status);
        }
        switch (try self.status(txid)) {
            .proven => return .proven,
            .rejected => return .rejected,
            .unproven => {},
        }
        const r = (try self.broadcastRecord(txid)) orelse return .pending;
        if (r.getBool("accepted") orelse false) {
            if (tx_status.len > 0 and !std.mem.eql(u8, r.getText("txStatus") orelse "", tx_status)) try self.writeBroadcast(txid, r, .{ .tx_status = tx_status });
            return .pending;
        }
        if (tx_status.len == 0 or isRejection(tx_status)) return .pending;
        try self.writeBroadcast(txid, r, .{ .tx_status = tx_status, .accepted = true });
        try self.changes.append(self.arena, .{ .txid = txid, .state = .accepted, .watchers = r.getArray("watchers") orelse &.{}, .detail = tx_status });
        return .accepted;
    }

    // ------------------------------------------------------------ ingest

    pub const SpvCtx = struct {
        st: *State,
        pub fn rootAt(ptr: *anyopaque, height: u32) anyerror!?[32]u8 {
            const self: *SpvCtx = @ptrCast(@alignCast(ptr));
            return self.st.chain().rootAt(height);
        }
        pub fn knownRaw(ptr: *anyopaque, arena: std.mem.Allocator, txid: [32]u8) anyerror!?[]const u8 {
            _ = arena;
            const self: *SpvCtx = @ptrCast(@alignCast(ptr));
            return self.st.txRaw(txid);
        }
    };

    /// Ingest a BEEF (V1, V2, Atomic, Outpoint or Subject — BRC-233, its other transactions any; its
    /// subject the envelope's txid, else the last transaction): SPV
    /// against our chain (every BUMP's root our header's at its height; every unproven transaction's
    /// inputs held or earlier in the BEEF once sorted parents-first — a writer's order is sorted, not
    /// refused — their scripts verified), then every transaction it carries
    /// recorded, every proof it carries put, and each one left unproven registered for broadcast
    /// (`registered`). A transaction spending what a proven one already spends is rejected at once.
    pub fn ingest(self: *State, bytes: []const u8) !Ingested {
        const a = self.arena;
        const parsed = beef_mod.parse(a, bytes) catch return error.InvalidBeef;
        const subject = parsed.subject() orelse return error.InvalidBeef;
        const entry = parsed.find(subject) orelse return error.InvalidBeef;
        if (entry.raw == null) {
            // A txid-only subject: only a transaction we already hold.
            if (!(try self.holds(subject))) return error.UnknownTxidOnly;
        }
        // Parents first (a writer's order sorted, not refused): recorded and registered in it.
        const b = beef_mod.sorted(a, parsed) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidBeef => return error.NotParentsFirst,
        };
        var ctx = SpvCtx{ .st = self };
        const checked = try spv.verify(a, b, .{ .ptr = &ctx, .rootAtFn = SpvCtx.rootAt, .knownRawFn = SpvCtx.knownRaw });
        var registered: std.ArrayList([32]u8) = .empty;
        for (b.entries, checked.proven) |e, proven| {
            const raw = e.raw orelse continue;
            _ = try self.putTx(e.txid, raw);
            if (proven) {
                for (b.bumps) |p| if (beef_mod.bumpHas(p, e.txid)) {
                    _ = try self.addPath(e.txid, p);
                    break;
                };
            }
        }
        for (b.entries) |e| {
            if (e.raw == null) continue;
            if ((try self.status(e.txid)) != .unproven) continue;
            if (try self.rejectIfConflicted(e.txid)) continue;
            if ((try self.broadcastRecord(e.txid)) != null) continue;
            try self.register(e.txid, "");
            try registered.append(a, e.txid);
        }
        return .{
            .txid = subject,
            .tx = try a.dupe(u8, &store_mod.hashCid(.tx, subject)),
            .status = try self.status(subject),
            .registered = registered.items,
        };
    }

    // ------------------------------------------------------------ BEEF out

    /// The Atomic BEEF (BRC-95 over BRC-96) of a transaction we hold. Proven: the transaction with
    /// its BUMP and nothing above it. Unproven: its parents, each the same way, back to proven
    /// transactions (their BUMPs, merged per block), parents first, then the transaction.
    pub fn beefOf(self: *State, txid: [32]u8) !?[]const u8 {
        if ((try self.txRaw(txid)) == null) return null;
        var acc = BeefAcc{ .st = self, .bumps = self.bumps() };
        try acc.visit(txid);
        const paths = try acc.bumps.build();
        flagLeaves(acc.entries.items, paths);
        return try beef_mod.serialize(self.arena, .{ .version = beef_mod.V2, .atomic = txid, .bumps = paths, .entries = acc.entries.items });
    }

    /// The ancestry walk: proven transactions noted by block (their BUMPs built after, one per block),
    /// unproven ones over their parents, parents first.
    const BeefAcc = struct {
        st: *State,
        entries: std.ArrayList(beef_mod.Entry) = .empty,
        bumps: Bumps,

        fn visit(acc: *BeefAcc, txid: [32]u8) anyerror!void {
            const a = acc.st.arena;
            for (acc.entries.items) |e| if (std.mem.eql(u8, &e.txid, &txid)) return;
            const raw = (try acc.st.txRaw(txid)) orelse return error.MissingAncestor;
            const tx = try bsvz.transaction.Transaction.parse(a, raw);
            if ((try acc.st.status(txid)) == .proven) {
                const idx = try acc.bumps.add(txid);
                try acc.entries.append(a, .{ .txid = txid, .format = .raw_with_bump, .bump = idx, .raw = raw, .tx = tx });
                return;
            }
            for (tx.inputs) |in| try acc.visit(in.previous_outpoint.txid.bytes);
            try acc.entries.append(a, .{ .txid = txid, .format = .raw, .raw = raw, .tx = tx });
        }
    };
};

/// Flag each proven entry's leaf in its BUMP as a transaction (BRC-74 txid).
pub fn flagLeaves(entries: []const beef_mod.Entry, paths: []merkle.MerklePath) void {
    for (entries) |e| {
        const bi = e.bump orelse continue;
        for (paths[bi].path[0]) |*l| if (l.hash) |h| if (std.mem.eql(u8, &h.bytes, &e.txid)) {
            l.txid = true;
        };
    }
}

fn optEq(x: ?[]const u8, y: ?[]const u8) bool {
    if (x == null or y == null) return x == null and y == null;
    return std.mem.eql(u8, x.?, y.?);
}

/// The chain state the `chain/state` record `state` names, for reading (shruggr/skein-sdk#1: the
/// one opener every reader uses): its network is the record's own; null (no chain state yet) is an
/// empty state on `network`. Nothing is written through it unless the caller saves.
pub fn open(arena: std.mem.Allocator, s: Store, state: ?[]const u8, network: Network) !State {
    var net = network;
    if (state) |c| net = Network.parse((try s.getValue(arena, c)).getText("network") orelse "") orelse return error.BadChainState;
    return State.load(arena, s, state, net);
}

fn contains(xs: []const [32]u8, t: [32]u8) bool {
    for (xs) |x| if (std.mem.eql(u8, &x, &t)) return true;
    return false;
}
