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
pub const mst = @import("mst");

pub const MValue = mst.Value;

pub const Store = struct {
    ptr: *anyopaque,
    getFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, cid: []const u8) anyerror![]const u8,
    putFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, bytes: []const u8) anyerror![]const u8,
    putBlockFn: *const fn (ptr: *anyopaque, cid: []const u8, bytes: []const u8) anyerror!void,

    pub fn get(self: Store, arena: std.mem.Allocator, cid: []const u8) ![]const u8 {
        return self.getFn(self.ptr, arena, cid);
    }
    pub fn put(self: Store, arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
        return self.putFn(self.ptr, arena, bytes);
    }
    pub fn putBlock(self: Store, cid: []const u8, bytes: []const u8) !void {
        return self.putBlockFn(self.ptr, cid, bytes);
    }
    /// A transaction (bitcoin-tx) or an 80-byte header (bitcoin-block), under its own CID.
    pub fn putBitcoin(self: Store, arena: std.mem.Allocator, codec: Codec, bytes: []const u8) ![]const u8 {
        const c = try arena.dupe(u8, &bitcoinCid(codec, bytes));
        try self.putBlock(c, bytes);
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

/// bitcoin-block (an 80-byte header), bitcoin-tx, bitcoin-merkle (a 64-byte
/// merkle node, #29: kernel-zig/src/cid.zig).
pub const Codec = enum(u8) { block = 0xb0, tx = 0xb1, merkle = 0xb3 };

/// CIDv1, bitcoin-tx (0xb1), bitcoin-block (0xb0) or bitcoin-merkle (0xb3),
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
    if (cid.len != 37 or cid[0] != 1 or (cid[1] != 0xb0 and cid[1] != 0xb1 and cid[1] != 0xb3) or cid[2] != 1 or cid[3] != 0x56 or cid[4] != 0x20) return null;
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
    }
    pub fn store(self: *MemStore) Store {
        return .{ .ptr = self, .getFn = getImpl, .putFn = putImpl, .putBlockFn = putBlockImpl };
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
        try self.keep(&cid, canon);
        return arena.dupe(u8, &cid);
    }
    /// As the kernel's putblock: the bytes must hash to the CID (bitcoin-tx,
    /// bitcoin-block, bitcoin-merkle, or dag-cbor sha2-256 — index nodes).
    fn putBlockImpl(ptr: *anyopaque, cid: []const u8, bytes: []const u8) anyerror!void {
        const self: *MemStore = @ptrCast(@alignCast(ptr));
        if (bitcoinHash(cid)) |h| {
            if (cid[1] == 0xb0 and bytes.len != 80) return error.HashMismatch;
            if (cid[1] == 0xb3 and bytes.len != 64) return error.HashMismatch;
            if (!std.mem.eql(u8, &h, &dblSha256(bytes))) return error.HashMismatch;
        } else if (cid.len == 36 and std.mem.eql(u8, cid[0..4], &.{ 0x01, 0x71, 0x12, 0x20 })) {
            if (!std.mem.eql(u8, cid, &cbor.cidOf(bytes))) return error.HashMismatch;
        } else return error.UnsupportedCid;
        try self.keep(cid, bytes);
    }
    fn keep(self: *MemStore, cid: []const u8, bytes: []const u8) !void {
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
