//! The record store as the wallet sees it: get a record's bytes by CID, put
//! dag-cbor bytes and get their CID. In the VM this is the `skein` get/put
//! imports (program.zig); in tests, MemStore. Index maps are records too.
const std = @import("std");
const cbor = @import("cbor.zig");

pub const Store = struct {
    ptr: *anyopaque,
    getFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, cid: []const u8) anyerror![]const u8,
    putFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, bytes: []const u8) anyerror![]const u8,

    pub fn get(self: Store, arena: std.mem.Allocator, cid: []const u8) ![]const u8 {
        return self.getFn(self.ptr, arena, cid);
    }
    pub fn put(self: Store, arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
        return self.putFn(self.ptr, arena, bytes);
    }
    pub fn getValue(self: Store, arena: std.mem.Allocator, cid: []const u8) !cbor.Value {
        return cbor.decode(arena, try self.get(arena, cid));
    }
    pub fn putValue(self: Store, arena: std.mem.Allocator, v: cbor.Value) ![]const u8 {
        return self.put(arena, try cbor.encode(arena, v));
    }
};

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
        return .{ .ptr = self, .getFn = getImpl, .putFn = putImpl };
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
        if (!self.blocks.contains(&cid)) {
            const k = try self.gpa.dupe(u8, &cid);
            errdefer self.gpa.free(k);
            try self.blocks.put(self.gpa, k, try self.gpa.dupe(u8, canon));
        }
        return arena.dupe(u8, &cid);
    }
    pub fn count(self: *const MemStore) usize {
        return self.blocks.count();
    }
};

/// An index map (issue #30's shape, flat for now): one record
/// `{kind: "wallet-index", name, entries: {key: value}}`, rewritten whole on
/// change. Keys sort as dag-cbor sorts map keys (length, then bytes), so
/// fixed-width keys (heights zero-padded, outpoints) iterate in order.
pub const Index = struct {
    name: []const u8,
    entries: std.StringArrayHashMapUnmanaged(cbor.Value) = .empty,
    dirty: bool = false,

    pub fn load(arena: std.mem.Allocator, s: Store, name: []const u8, cid: ?[]const u8) !Index {
        var ix = Index{ .name = name };
        const c = cid orelse return ix;
        const v = try s.getValue(arena, c);
        const kind = v.getText("kind") orelse return error.BadIndex;
        if (!std.mem.eql(u8, kind, "wallet-index")) return error.BadIndex;
        const entries = v.get("entries") orelse return error.BadIndex;
        if (entries != .map) return error.BadIndex;
        for (entries.map) |e| try ix.entries.put(arena, e.key, e.value);
        ix.sort();
        return ix;
    }

    fn lessThan(ctx: *const Index, a: usize, b: usize) bool {
        const ka = ctx.entries.keys()[a];
        const kb = ctx.entries.keys()[b];
        if (ka.len != kb.len) return ka.len < kb.len;
        return std.mem.lessThan(u8, ka, kb);
    }

    fn sort(self: *Index) void {
        const C = struct {
            ix: *const Index,
            pub fn lessThan(c: @This(), a: usize, b: usize) bool {
                return Index.lessThan(c.ix, a, b);
            }
        };
        self.entries.sort(C{ .ix = self });
    }

    pub fn get(self: *const Index, key: []const u8) ?cbor.Value {
        return self.entries.get(key);
    }
    pub fn put(self: *Index, arena: std.mem.Allocator, key: []const u8, v: cbor.Value) !void {
        try self.entries.put(arena, try arena.dupe(u8, key), v);
        self.dirty = true;
    }
    pub fn remove(self: *Index, key: []const u8) bool {
        const had = self.entries.orderedRemove(key);
        self.dirty = self.dirty or had;
        return had;
    }
    pub fn clear(self: *Index) void {
        if (self.entries.count() > 0) self.dirty = true;
        self.entries.clearRetainingCapacity();
    }
    pub fn count(self: *const Index) usize {
        return self.entries.count();
    }
    /// Keys in dag-cbor order.
    pub fn sortedKeys(self: *Index) []const []const u8 {
        self.sort();
        return self.entries.keys();
    }

    pub fn save(self: *Index, arena: std.mem.Allocator, s: Store) ![]const u8 {
        const es = try arena.alloc(cbor.Entry, self.entries.count());
        for (self.entries.keys(), self.entries.values(), es) |k, v, *e| e.* = .{ .key = k, .value = v };
        return s.putValue(arena, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "wallet-index" } },
            .{ .key = "name", .value = .{ .text = self.name } },
            .{ .key = "entries", .value = .{ .map = es } },
        } });
    }
};
