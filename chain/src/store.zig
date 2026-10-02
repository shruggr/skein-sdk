//! The record store as the wallet sees it: get a block's bytes by CID, put
//! dag-cbor bytes and get their CID, put a block under a CID made here
//! (bitcoin-tx / bitcoin-block: the txid / block hash; index nodes). In the
//! VM this is the `skein` get/put/putblock imports (program.zig); in tests,
//! MemStore.
//!
//! The index maps are the kernel's Merkle search trees (kernel-zig/src/mst.zig,
//! issue #30, shared through build.zig): one persistent ordered map per
//! lookup, its root CID named in the wallet's state record. A step's changes
//! write new nodes along one path per change; `flush` puts the ones a root
//! reaches. Keys are bytes, ordered bytewise; values are the kernel codec's
//! IPLD values (links, bytes, numbers, null).
const std = @import("std");
const cbor = @import("cbor.zig");
const bsvz = @import("bsvz");
pub const mst = @import("mst");

pub const MValue = mst.Value;

/// One edge into a record, as the kernel's `edges` import answers it (#42):
/// from whom (a chain's origin, or a kept bitcoin block's own CID), at which
/// step (`seq`; 0 for a bitcoin block), the link's rel and locator (a vout, a
/// child's side, a record's text locator, or null).
pub const Edge = struct { from: []const u8, seq: i64, rel: []const u8, locator: cbor.Value };

/// The dag-cbor answer of the `edges` import: [{from, seq, rel, locator}] → edges.
pub fn decodeEdges(arena: std.mem.Allocator, bytes: []const u8) ![]const Edge {
    const v = try cbor.decode(arena, bytes);
    if (v != .array) return error.BadEdges;
    const out = try arena.alloc(Edge, v.array.len);
    for (v.array, out) |x, *e| e.* = .{
        .from = x.getCid("from") orelse return error.BadEdges,
        .seq = if (x.get("seq")) |s| (if (s == .uint) @intCast(s.uint) else return error.BadEdges) else return error.BadEdges,
        .rel = x.getText("rel") orelse return error.BadEdges,
        .locator = x.get("locator") orelse .null,
    };
    return out;
}

/// The edges a kept bitcoin block contributes (kernel-zig/src/bitcoin.zig
/// `edgesOf`, #42) — for MemStore, which stands in for the kernel's index in
/// native tests: a transaction's inputs `spends` (locator = vout; a coinbase
/// input links nothing). None for a header or a merkle node (#42 decided
/// 2026-09-30: nothing asks the reverse questions), nor for a block that is
/// not bitcoin or does not parse.
pub const Link = struct { to: [37]u8, rel: []const u8, locator: cbor.Value };
pub fn bitcoinEdges(arena: std.mem.Allocator, cid: []const u8, bytes: []const u8) ![]Link {
    var out: std.ArrayList(Link) = .empty;
    if (bitcoinHash(cid) == null or cid[1] == @intFromEnum(Codec.block) or bytes.len == 64) return out.items;
    const tx = bsvz.transaction.Transaction.parse(arena, bytes) catch return out.items;
    for (tx.inputs) |in| {
        const prev = in.previous_outpoint;
        if (prev.index == 0xffffffff and std.mem.allEqual(u8, &prev.txid.bytes, 0)) continue;
        try out.append(arena, .{ .to = hashCid(.tx, prev.txid.bytes), .rel = "spends", .locator = .{ .uint = prev.index } });
    }
    return out.items;
}

pub const Store = struct {
    ptr: *anyopaque,
    getFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, cid: []const u8) anyerror![]const u8,
    putFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, bytes: []const u8) anyerror![]const u8,
    putBlockFn: *const fn (ptr: *anyopaque, cid: []const u8, bytes: []const u8) anyerror!void,
    /// Keep a block in the step (the kernel's `keep`): a kept bitcoin block's
    /// links become edges in the kernel's index (#42). Null: keeping is a no-op.
    keepFn: ?*const fn (ptr: *anyopaque, cid: []const u8) anyerror!void = null,
    /// The kernel's edges into `to` (#42, its `edges` import): who points at
    /// it, with `rel` only if given, in key order (from, seq, ord).
    edgesFn: ?*const fn (ptr: *anyopaque, arena: std.mem.Allocator, to: []const u8, rel: ?[]const u8) anyerror![]const Edge = null,

    pub fn keep(self: Store, cid: []const u8) !void {
        if (self.keepFn) |f| try f(self.ptr, cid);
    }
    pub fn edges(self: Store, arena: std.mem.Allocator, to: []const u8, rel: ?[]const u8) ![]const Edge {
        const f = self.edgesFn orelse return error.NoEdges;
        return f(self.ptr, arena, to, rel);
    }
    /// The transactions that spend `txid:vout` (edges `spends` from kept
    /// transactions, locator = vout), in txid order: every input of every
    /// transaction held (kept), whatever its settlement.
    pub fn spendersOf(self: Store, arena: std.mem.Allocator, txid: [32]u8, vout: u32) ![][32]u8 {
        var out: std.ArrayList([32]u8) = .empty;
        for (try self.edges(arena, &hashCid(.tx, txid), "spends")) |e| {
            if (e.locator != .uint or e.locator.uint != vout) continue;
            const h = bitcoinHash(e.from) orelse continue;
            if (e.from[1] != @intFromEnum(Codec.tx)) continue;
            try out.append(arena, h);
        }
        return out.items;
    }

    pub fn get(self: Store, arena: std.mem.Allocator, cid: []const u8) ![]const u8 {
        return self.getFn(self.ptr, arena, cid);
    }
    pub fn put(self: Store, arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
        return self.putFn(self.ptr, arena, bytes);
    }
    pub fn putBlock(self: Store, cid: []const u8, bytes: []const u8) !void {
        return self.putBlockFn(self.ptr, cid, bytes);
    }
    /// A transaction or a merkle node (bitcoin-tx) or an 80-byte header
    /// (bitcoin-block), under its own CID, and kept: every bitcoin block a
    /// wallet holds is kept, so its links are in the kernel's edges (#42).
    pub fn putBitcoin(self: Store, arena: std.mem.Allocator, codec: Codec, bytes: []const u8) ![]const u8 {
        const c = try arena.dupe(u8, &bitcoinCid(codec, bytes));
        try self.putBlock(c, bytes);
        try self.keep(c);
        return c;
    }
    /// A block's bytes, or null when the store does not hold it (a sparse tree's missing child).
    pub fn tryGet(self: Store, arena: std.mem.Allocator, cid: []const u8) ?[]const u8 {
        return self.getFn(self.ptr, arena, cid) catch null;
    }
    pub fn getValue(self: Store, arena: std.mem.Allocator, cid: []const u8) !cbor.Value {
        return cbor.decode(arena, try self.get(arena, cid));
    }
    pub fn putValue(self: Store, arena: std.mem.Allocator, v: cbor.Value) ![]const u8 {
        return self.put(arena, try cbor.encode(arena, v));
    }
};

/// bitcoin-block (an 80-byte header), bitcoin-tx (a transaction, or a 64-byte
/// merkle node: IPLD's convention, #42; kernel-zig/src/bitcoin.zig).
pub const Codec = enum(u8) { block = 0xb0, tx = 0xb1 };

/// CIDv1, bitcoin-tx (0xb1) or bitcoin-block (0xb0),
/// dbl-sha2-256 (0x56): the digest is the txid / block hash / merkle hash in
/// internal byte order.
pub fn bitcoinCid(codec: Codec, bytes: []const u8) [37]u8 {
    return hashCid(codec, dblSha256(bytes));
}

/// The bitcoin CID naming a hash (a txid, a block hash, a merkle node's hash).
pub fn hashCid(codec: Codec, hash: [32]u8) [37]u8 {
    return .{ 0x01, @intFromEnum(codec), 0x01, 0x56, 0x20 } ++ hash;
}

/// The txid / block hash / merkle hash a bitcoin CID names, or null for any other CID.
pub fn bitcoinHash(cid: []const u8) ?[32]u8 {
    if (cid.len != 37 or cid[0] != 1 or (cid[1] != 0xb0 and cid[1] != 0xb1) or cid[2] != 1 or cid[3] != 0x56 or cid[4] != 0x20) return null;
    return cid[5..37].*;
}

pub fn dblSha256(bytes: []const u8) [32]u8 {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &a, .{});
    std.crypto.hash.sha2.Sha256.hash(&a, &b, .{});
    return b;
}

/// An in-memory store for tests: CIDv1 dag-cbor sha2-256, as the runtime names records.
pub const MemStore = struct {
    gpa: std.mem.Allocator,
    blocks: std.StringHashMapUnmanaged([]u8) = .empty,
    /// The bitcoin blocks kept, and their links as edges (the kernel's index,
    /// index.zig, as a native test sees it: from the block, seq 0).
    kept: std.StringHashMapUnmanaged(void) = .empty,
    edge_rows: std.ArrayListUnmanaged(MemEdge) = .empty,

    const MemEdge = struct { to: [37]u8, from: [37]u8, ord: u32, rel: []const u8, locator: cbor.Value };

    pub fn init(gpa: std.mem.Allocator) MemStore {
        return .{ .gpa = gpa };
    }
    pub fn deinit(self: *MemStore) void {
        var it = self.blocks.iterator();
        while (it.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            self.gpa.free(e.value_ptr.*);
        }
        self.blocks.deinit(self.gpa);
        var kt = self.kept.keyIterator();
        while (kt.next()) |k| self.gpa.free(k.*);
        self.kept.deinit(self.gpa);
        self.edge_rows.deinit(self.gpa);
    }
    pub fn store(self: *MemStore) Store {
        return .{ .ptr = self, .getFn = getImpl, .putFn = putImpl, .putBlockFn = putBlockImpl, .keepFn = keepImpl, .edgesFn = edgesImpl };
    }
    fn keepImpl(ptr: *anyopaque, cid: []const u8) anyerror!void {
        const self: *MemStore = @ptrCast(@alignCast(ptr));
        if (!self.blocks.contains(cid)) return error.NotFound;
        if (bitcoinHash(cid) == null or self.kept.contains(cid)) return;
        try self.kept.put(self.gpa, try self.gpa.dupe(u8, cid), {});
        var tmp = std.heap.ArenaAllocator.init(self.gpa);
        defer tmp.deinit();
        for (try bitcoinEdges(tmp.allocator(), cid, self.blocks.get(cid).?), 0..) |l, i| {
            // rel is a literal; a locator is a uint or null: nothing borrowed from tmp.
            try self.edge_rows.append(self.gpa, .{ .to = l.to, .from = cid[0..37].*, .ord = @intCast(i), .rel = l.rel, .locator = l.locator });
        }
    }
    fn edgesImpl(ptr: *anyopaque, arena: std.mem.Allocator, to: []const u8, rel: ?[]const u8) anyerror![]const Edge {
        const self: *MemStore = @ptrCast(@alignCast(ptr));
        var rows: std.ArrayList(MemEdge) = .empty;
        for (self.edge_rows.items) |r| {
            if (!std.mem.eql(u8, &r.to, to)) continue;
            if (rel) |want| if (!std.mem.eql(u8, want, r.rel)) continue;
            try rows.append(arena, r);
        }
        std.mem.sort(MemEdge, rows.items, {}, struct {
            fn lt(_: void, x: MemEdge, y: MemEdge) bool {
                return switch (std.mem.order(u8, &x.from, &y.from)) {
                    .lt => true,
                    .gt => false,
                    .eq => x.ord < y.ord,
                };
            }
        }.lt);
        const out = try arena.alloc(Edge, rows.items.len);
        for (rows.items, out) |r, *e| e.* = .{ .from = try arena.dupe(u8, &r.from), .seq = 0, .rel = r.rel, .locator = r.locator };
        return out;
    }
    fn getImpl(ptr: *anyopaque, arena: std.mem.Allocator, cid: []const u8) anyerror![]const u8 {
        const self: *MemStore = @ptrCast(@alignCast(ptr));
        const b = self.blocks.get(cid) orelse return error.NotFound;
        return arena.dupe(u8, b);
    }
    fn putImpl(ptr: *anyopaque, arena: std.mem.Allocator, bytes: []const u8) anyerror![]const u8 {
        const self: *MemStore = @ptrCast(@alignCast(ptr));
        // As the runtime does: decode and re-encode canonically, then hash.
        var tmp = std.heap.ArenaAllocator.init(self.gpa);
        defer tmp.deinit();
        const canon = try cbor.encode(tmp.allocator(), try cbor.decode(tmp.allocator(), bytes));
        const cid = cbor.cidOf(canon);
        try self.hold(&cid, canon);
        return arena.dupe(u8, &cid);
    }
    /// As the kernel's putblock: the bytes must hash to the CID (bitcoin-tx,
    /// bitcoin-block, or dag-cbor sha2-256 — index nodes).
    fn putBlockImpl(ptr: *anyopaque, cid: []const u8, bytes: []const u8) anyerror!void {
        const self: *MemStore = @ptrCast(@alignCast(ptr));
        if (bitcoinHash(cid)) |h| {
            if (cid[1] == 0xb0 and bytes.len != 80) return error.HashMismatch;
            if (!std.mem.eql(u8, &h, &dblSha256(bytes))) return error.HashMismatch;
        } else if (cid.len == 36 and std.mem.eql(u8, cid[0..4], &.{ 0x01, 0x71, 0x12, 0x20 })) {
            if (!std.mem.eql(u8, cid, &cbor.cidOf(bytes))) return error.HashMismatch;
        } else return error.UnsupportedCid;
        try self.hold(cid, bytes);
    }
    fn hold(self: *MemStore, cid: []const u8, bytes: []const u8) !void {
        if (self.blocks.contains(cid)) return;
        const k = try self.gpa.dupe(u8, cid);
        errdefer self.gpa.free(k);
        try self.blocks.put(self.gpa, k, try self.gpa.dupe(u8, bytes));
    }
    pub fn count(self: *const MemStore) usize {
        return self.blocks.count();
    }
};

// ---------------------------------------------------------------- index maps

/// The node store a wallet's maps share for one step (an MST forest over the
/// Store): nodes are read with `get`; new ones wait until `flush`.
pub const Maps = struct {
    arena: std.mem.Allocator,
    store: Store,
    forest: mst.Forest,

    pub fn create(arena: std.mem.Allocator, s: Store) !*Maps {
        const m = try arena.create(Maps);
        m.* = .{ .arena = arena, .store = s, .forest = undefined };
        m.forest = mst.Forest.init(arena, .{ .ctx = m, .get = blocksGet });
        return m;
    }

    fn blocksGet(ctx: *anyopaque, a: std.mem.Allocator, cid: []const u8) anyerror!?[]u8 {
        const m: *Maps = @ptrCast(@alignCast(ctx));
        return @constCast(try m.store.get(a, cid));
    }
    fn sinkPut(ctx: *anyopaque, cid: []const u8, bytes: []const u8) anyerror!void {
        const m: *Maps = @ptrCast(@alignCast(ctx));
        try m.store.putBlock(cid, bytes);
    }

    pub fn map(self: *Maps, root: ?[]const u8) Map {
        return .{ .maps = self, .root = root };
    }
};

/// One persistent ordered map: its root (null: empty) and the forest it lives in.
pub const Map = struct {
    maps: *Maps,
    root: ?[]const u8,
    dirty: bool = false,

    fn f(self: *Map) *mst.Forest {
        return &self.maps.forest;
    }

    pub fn get(self: *Map, key: []const u8) !?MValue {
        return self.f().get(self.maps.arena, self.root, key);
    }
    /// The link stored under key (a CID), or null.
    pub fn link(self: *Map, key: []const u8) !?[]const u8 {
        const v = (try self.get(key)) orelse return null;
        return if (v == .cid) v.cid else error.BadIndex;
    }
    pub fn has(self: *Map, key: []const u8) !bool {
        return (try self.get(key)) != null;
    }
    pub fn put(self: *Map, key: []const u8, v: MValue) !void {
        const r = try self.f().put(self.root, key, v);
        if (!eqLink(r, self.root)) self.dirty = true;
        self.root = r;
    }
    pub fn putLink(self: *Map, key: []const u8, cid: []const u8) !void {
        return self.put(key, .{ .cid = cid });
    }
    /// A set member: key → null.
    pub fn add(self: *Map, key: []const u8) !void {
        return self.put(key, .null);
    }
    pub fn remove(self: *Map, key: []const u8) !bool {
        const r = try self.f().delete(self.root, key);
        const had = !eqLink(r, self.root);
        self.dirty = self.dirty or had;
        self.root = r;
        return had;
    }
    /// Every entry whose key starts with `prefix` (all of them for ""), in key order.
    pub fn prefixed(self: *Map, prefix: []const u8) ![]mst.KV {
        var out = std.array_list.Managed(mst.KV).init(self.maps.arena);
        if (prefix.len == 0) {
            try self.f().range(self.maps.arena, self.root, null, null, &out);
        } else try self.f().prefixed(self.maps.arena, self.root, prefix, &out);
        return out.items;
    }
    /// Every entry whose key is at least `lo`, in key order.
    pub fn from(self: *Map, lo: []const u8) ![]mst.KV {
        var out = std.array_list.Managed(mst.KV).init(self.maps.arena);
        try self.f().range(self.maps.arena, self.root, lo, null, &out);
        return out.items;
    }
    pub fn count(self: *Map) !usize {
        return self.f().count(self.root);
    }
    /// The greatest key, or null for an empty map: the rightmost path.
    pub fn last(self: *Map) !?[]const u8 {
        var cur = self.root orelse return null;
        while (true) {
            const n = try self.f().load(cur);
            const e = n.entries[n.entries.len - 1];
            cur = e.right orelse return e.key;
        }
    }
    /// Put every new node this map's root reaches.
    pub fn flush(self: *Map) !void {
        try self.f().flush(self.root, .{ .ctx = self.maps, .put = Maps.sinkPut });
    }
};

fn eqLink(x: ?[]const u8, y: ?[]const u8) bool {
    if (x == null or y == null) return x == null and y == null;
    return std.mem.eql(u8, x.?, y.?);
}

// ---------------------------------------------------------------- keys

pub fn be32(n: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, n, .big);
    return b;
}

/// txid (internal byte order) ‖ vout (4 bytes, big-endian).
pub fn outpointKey(txid: [32]u8, vout: u32) [36]u8 {
    return txid ++ be32(vout);
}

pub fn outpointOf(key: []const u8) !struct { txid: [32]u8, vout: u32 } {
    if (key.len != 36) return error.BadIndex;
    return .{ .txid = key[0..32].*, .vout = std.mem.readInt(u32, key[32..36], .big) };
}

/// A string as a key prefix: its length (one byte, so names up to 255 bytes) and bytes.
pub fn nameKey(arena: std.mem.Allocator, name: []const u8, rest: []const []const u8) ![]u8 {
    if (name.len > 255) return error.NameTooLong;
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, @intCast(name.len));
    try out.appendSlice(arena, name);
    for (rest) |r| try out.appendSlice(arena, r);
    return out.toOwnedSlice(arena);
}

test "maps: MST over the store, persistent across steps" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var ms = MemStore.init(std.testing.allocator);
    defer ms.deinit();
    const maps = try Maps.create(a, ms.store());
    var m = maps.map(null);
    var i: u32 = 0;
    while (i < 300) : (i += 1) try m.putLink(&be32(i), &cbor.cidOf(&be32(i)));
    try std.testing.expectEqual(@as(usize, 300), try m.count());
    try std.testing.expectEqualSlices(u8, &be32(299), (try m.last()).?);
    try m.flush();
    // A fresh forest (the next step) reads the same map from its root.
    const maps2 = try Maps.create(a, ms.store());
    var m2 = maps2.map(m.root);
    try std.testing.expectEqualSlices(u8, &cbor.cidOf(&be32(7)), (try m2.link(&be32(7))).?);
    try std.testing.expect(try m2.remove(&be32(299)));
    try std.testing.expect(!(try m2.remove(&be32(299))));
    try std.testing.expectEqualSlices(u8, &be32(298), (try m2.last()).?);
    try std.testing.expectEqual(@as(usize, 298 - 256 + 1), (try m2.prefixed(&.{ 0, 0, 1 })).len);
}
