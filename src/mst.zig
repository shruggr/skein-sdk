// Persistent ordered maps as Merkle search trees (issue #30): dag-cbor blocks
// in the store, updated copy-on-write — each change writes new nodes along one
// path, every other node is shared with the previous version.
//
// Canonical: the tree for a set of (key, value) pairs is one tree whatever
// order they were put in (or deleted), so a map's root CID is a function of
// its contents. A key's level is the number of leading zero 5-bit groups of
// sha2-256(key) (P = 1/32 per level: fan-out ~32). A tree is the node holding
// every key of the highest level present, in key order, and between and
// around them the trees of the keys in each gap (levels below). A node with
// no keys is not written: it is its one subtree. Keys order bytewise
// (memcmp, shorter first on a tie), so a map answers range and prefix scans:
// composite keys (a CID ‖ a big-endian number ‖ a CID …) make one map per
// query shape.
//
// A node is the dag-cbor array [left, [[key, value, right] …]]: left and each
// right are a subtree's CID or null; key is bytes; value any IPLD value.
//
// Nothing here knows SQLite or the kernel: nodes are read through `Blocks`
// (get by CID) and new ones collect in `pending` until the owner flushes the
// ones a root reaches; it needs only cbor.zig and cid.zig. wallet-zig (#29)
// builds this file as a module of its own (wallet-zig/build.zig) for the
// wallet's index maps: inside the VM its Blocks are the `skein` get import
// and a flush is one `putblock` per pending node.
const std = @import("std");
const cbor = @import("cbor.zig");
const cidm = @import("cid.zig");
/// Exported for users of this file as a library module (wallet-zig, #29).
pub const Value = cbor.Value;
pub const codec = cbor;

pub const Blocks = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, a: std.mem.Allocator, cid: []const u8) anyerror!?[]u8,
};

pub const Entry = struct { key: []const u8, value: Value, right: ?[]const u8 };

pub const Node = struct {
    level: u8,
    left: ?[]const u8,
    entries: []const Entry,

    fn gapBefore(n: *const Node, i: usize) ?[]const u8 {
        return if (i == 0) n.left else n.entries[i - 1].right;
    }
};

pub const KV = struct { key: []u8, value: Value };

/// sha2-256(key)'s leading zero 5-bit groups.
pub fn level(key: []const u8) u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key, &d, .{});
    var bit: usize = 0;
    while (bit < 255) : (bit += 1) {
        if ((d[bit / 8] >> @intCast(7 - bit % 8)) & 1 != 0) break;
    }
    return @intCast(bit / 5);
}

fn lt(a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// The node store the maps share: a cache of decoded nodes and the nodes
/// written since the last flush. Roots it returns live until `reset`.
pub const Forest = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    blocks: Blocks,
    cache: std.StringHashMapUnmanaged(*const Node) = .empty,
    /// New nodes: CID → bytes, owned by gpa.
    pending: std.StringHashMapUnmanaged([]u8) = .empty,
    /// Counters: nodes and bytes handed to a sink by flush.
    flushed_nodes: usize = 0,
    flushed_bytes: usize = 0,

    pub fn init(gpa: std.mem.Allocator, blocks: Blocks) Forest {
        return .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa), .blocks = blocks };
    }

    pub fn deinit(f: *Forest) void {
        f.dropPending();
        f.pending.deinit(f.gpa);
        f.arena.deinit();
    }

    fn al(f: *Forest) std.mem.Allocator {
        return f.arena.allocator();
    }

    fn dropPending(f: *Forest) void {
        var it = f.pending.iterator();
        while (it.next()) |e| {
            f.gpa.free(e.key_ptr.*);
            f.gpa.free(e.value_ptr.*);
        }
        f.pending.clearRetainingCapacity();
    }

    /// Forget the cache and everything allocated for it (roots included: copy
    /// them first). Pending nodes stay unless `drop_pending`.
    pub fn reset(f: *Forest, drop_pending: bool) void {
        if (drop_pending) f.dropPending();
        f.cache = .empty;
        _ = f.arena.reset(.retain_capacity);
    }

    // ------------------------------------------------------------ nodes

    pub fn load(f: *Forest, cid: []const u8) !*const Node {
        if (f.cache.get(cid)) |n| return n;
        const a = f.al();
        const bytes = f.pending.get(cid) orelse (try f.blocks.get(f.blocks.ctx, a, cid)) orelse return error.MissingNode;
        const v = try cbor.decode(a, bytes);
        if (v != .array or v.array.len != 2 or v.array[1] != .array) return error.BadNode;
        const left = try link(v.array[0]);
        const es = try a.alloc(Entry, v.array[1].array.len);
        for (v.array[1].array, es) |x, *e| {
            if (x != .array or x.array.len != 3 or x.array[0] != .bytes) return error.BadNode;
            e.* = .{ .key = x.array[0].bytes, .value = x.array[1], .right = try link(x.array[2]) };
        }
        if (es.len == 0) return error.BadNode;
        const n = try a.create(Node);
        n.* = .{ .level = level(es[0].key), .left = left, .entries = es };
        try f.cache.put(a, try a.dupe(u8, cid), n);
        return n;
    }

    fn link(v: Value) !?[]const u8 {
        return switch (v) {
            .null => null,
            .cid => |c| c,
            else => error.BadNode,
        };
    }

    /// The node [left, entries] as a tree: its CID, or `left` when it has no entries.
    fn make(f: *Forest, left: ?[]const u8, entries: []const Entry) !?[]const u8 {
        if (entries.len == 0) return left;
        const a = f.al();
        const items = try a.alloc(Value, entries.len);
        for (entries, items) |e, *x| {
            const t = try a.alloc(Value, 3);
            t[0] = .{ .bytes = e.key };
            t[1] = e.value;
            t[2] = if (e.right) |r| .{ .cid = r } else .null;
            x.* = .{ .array = t };
        }
        const pair = try a.alloc(Value, 2);
        pair[0] = if (left) |l| .{ .cid = l } else .null;
        pair[1] = .{ .array = items };
        const blk = try cbor.block(a, .{ .array = pair });
        if (f.cache.contains(blk.cid)) return blk.cid;
        if (!f.pending.contains(blk.cid)) {
            const k = try f.gpa.dupe(u8, blk.cid);
            errdefer f.gpa.free(k);
            const b = try f.gpa.dupe(u8, blk.bytes);
            errdefer f.gpa.free(b);
            try f.pending.put(f.gpa, k, b);
        }
        const n = try a.create(Node);
        n.* = .{ .level = level(entries[0].key), .left = left, .entries = try a.dupe(Entry, entries) };
        try f.cache.put(a, blk.cid, n);
        return blk.cid;
    }

    /// First index whose key is >= key.
    fn search(n: *const Node, key: []const u8) usize {
        var lo: usize = 0;
        var hi: usize = n.entries.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (lt(n.entries[mid].key, key)) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// `n` with the gap before entry i replaced by `g`.
    fn withGap(f: *Forest, n: *const Node, i: usize, g: ?[]const u8) !?[]const u8 {
        if (i == 0) return f.make(g, n.entries);
        const es = try f.al().dupe(Entry, n.entries);
        es[i - 1].right = g;
        return f.make(n.left, es);
    }

    // ------------------------------------------------------------ reads

    /// The value under `key`, copied into `a`; null if absent.
    pub fn get(f: *Forest, a: std.mem.Allocator, root: ?[]const u8, key: []const u8) !?Value {
        var cur = root;
        while (cur) |c| {
            const n = try f.load(c);
            const i = search(n, key);
            if (i < n.entries.len and std.mem.eql(u8, n.entries[i].key, key)) return try clone(a, n.entries[i].value);
            cur = n.gapBefore(i);
        }
        return null;
    }

    /// Every entry with lo <= key < hi (null: unbounded), in key order, copied into `a`.
    pub fn range(f: *Forest, a: std.mem.Allocator, root: ?[]const u8, lo: ?[]const u8, hi: ?[]const u8, out: *std.array_list.Managed(KV)) !void {
        const c = root orelse return;
        const n = try f.load(c);
        const len = n.entries.len;
        var j: usize = 0;
        while (j <= len) : (j += 1) {
            // The gap before entry j: keys in (entries[j-1], entries[j]).
            const gap_lo_ok = j == len or lo == null or lt(lo.?, n.entries[j].key);
            const gap_hi_ok = j == 0 or hi == null or lt(n.entries[j - 1].key, hi.?);
            if (gap_lo_ok and gap_hi_ok) try f.range(a, n.gapBefore(j), lo, hi, out);
            if (j == len) break;
            const k = n.entries[j].key;
            if (hi != null and !lt(k, hi.?)) break;
            if (lo == null or !lt(k, lo.?)) try out.append(.{ .key = try a.dupe(u8, k), .value = try clone(a, n.entries[j].value) });
        }
    }

    /// Every entry whose key starts with `prefix`.
    pub fn prefixed(f: *Forest, a: std.mem.Allocator, root: ?[]const u8, prefix: []const u8, out: *std.array_list.Managed(KV)) !void {
        var hi_buf: [256]u8 = undefined;
        return f.range(a, root, prefix, successor(&hi_buf, prefix), out);
    }

    pub fn count(f: *Forest, root: ?[]const u8) !usize {
        const c = root orelse return 0;
        const n = try f.load(c);
        var total: usize = n.entries.len + try f.count(n.left);
        for (n.entries) |e| total += try f.count(e.right);
        return total;
    }

    // ------------------------------------------------------------ writes

    /// The tree with key → value (replacing any value there). The key and value are copied.
    pub fn put(f: *Forest, root: ?[]const u8, key: []const u8, value: Value) !?[]const u8 {
        const a = f.al();
        const k = try a.dupe(u8, key);
        const v = try clone(a, value);
        return f.putAt(root, k, level(k), v);
    }

    fn putAt(f: *Forest, root: ?[]const u8, key: []const u8, lvl: u8, value: Value) !?[]const u8 {
        const c = root orelse return f.make(null, &.{.{ .key = key, .value = value, .right = null }});
        const n = try f.load(c);
        if (lvl > n.level) {
            const s = try f.split(c, key);
            return f.make(s[0], &.{.{ .key = key, .value = value, .right = s[1] }});
        }
        const i = search(n, key);
        if (lvl < n.level) return f.withGap(n, i, try f.putAt(n.gapBefore(i), key, lvl, value));
        const a = f.al();
        if (i < n.entries.len and std.mem.eql(u8, n.entries[i].key, key)) {
            if (cbor.eql(n.entries[i].value, value)) return c;
            const es = try a.dupe(Entry, n.entries);
            es[i].value = value;
            return f.make(n.left, es);
        }
        const s = try f.split(n.gapBefore(i), key);
        const es = try a.alloc(Entry, n.entries.len + 1);
        @memcpy(es[0..i], n.entries[0..i]);
        es[i] = .{ .key = key, .value = value, .right = s[1] };
        @memcpy(es[i + 1 ..], n.entries[i..]);
        if (i == 0) return f.make(s[0], es);
        es[i - 1].right = s[0];
        return f.make(n.left, es);
    }

    /// The tree's keys below `key` and above it, as two trees (`key` is not in it).
    fn split(f: *Forest, root: ?[]const u8, key: []const u8) ![2]?[]const u8 {
        const c = root orelse return .{ null, null };
        const n = try f.load(c);
        const i = search(n, key);
        const s = try f.split(n.gapBefore(i), key);
        var left: ?[]const u8 = s[0];
        if (i > 0) {
            const es = try f.al().dupe(Entry, n.entries[0..i]);
            es[i - 1].right = s[0];
            left = try f.make(n.left, es);
        }
        const right = try f.make(s[1], n.entries[i..]);
        return .{ left, right };
    }

    /// The tree without `key` (the same root if it was not there).
    pub fn delete(f: *Forest, root: ?[]const u8, key: []const u8) !?[]const u8 {
        return f.deleteAt(root, key, level(key));
    }

    fn deleteAt(f: *Forest, root: ?[]const u8, key: []const u8, lvl: u8) !?[]const u8 {
        const c = root orelse return null;
        const n = try f.load(c);
        if (lvl > n.level) return c;
        const i = search(n, key);
        if (lvl < n.level) {
            const g = n.gapBefore(i);
            const ng = try f.deleteAt(g, key, lvl);
            if (eqLink(g, ng)) return c;
            return f.withGap(n, i, ng);
        }
        if (i >= n.entries.len or !std.mem.eql(u8, n.entries[i].key, key)) return c;
        const merged = try f.merge(n.gapBefore(i), n.entries[i].right);
        const a = f.al();
        const es = try a.alloc(Entry, n.entries.len - 1);
        @memcpy(es[0..i], n.entries[0..i]);
        @memcpy(es[i..], n.entries[i + 1 ..]);
        if (i == 0) return f.make(merged, es);
        es[i - 1].right = merged;
        return f.make(n.left, es);
    }

    /// One tree of two, every key of `x` below every key of `y`.
    fn merge(f: *Forest, x: ?[]const u8, y: ?[]const u8) !?[]const u8 {
        const xc = x orelse return y;
        const yc = y orelse return x;
        const nx = try f.load(xc);
        const ny = try f.load(yc);
        const a = f.al();
        if (nx.level > ny.level) {
            const last = nx.entries.len - 1;
            const es = try a.dupe(Entry, nx.entries);
            es[last].right = try f.merge(nx.entries[last].right, yc);
            return f.make(nx.left, es);
        }
        if (ny.level > nx.level) return f.make(try f.merge(xc, ny.left), ny.entries);
        const last = nx.entries.len - 1;
        const es = try a.alloc(Entry, nx.entries.len + ny.entries.len);
        @memcpy(es[0..nx.entries.len], nx.entries);
        @memcpy(es[nx.entries.len..], ny.entries);
        es[last].right = try f.merge(nx.entries[last].right, ny.left);
        return f.make(nx.left, es);
    }

    // ------------------------------------------------------------ flush

    pub const Sink = struct {
        ctx: *anyopaque,
        put: *const fn (ctx: *anyopaque, cid: []const u8, bytes: []const u8) anyerror!void,
    };

    /// Hand every pending node `root` reaches to `sink` (and forget it as pending).
    pub fn flush(f: *Forest, root: ?[]const u8, sink: Sink) !void {
        const c = root orelse return;
        const kv = f.pending.fetchRemove(c) orelse return; // already stored: so is all below it
        defer {
            f.gpa.free(kv.key);
            f.gpa.free(kv.value);
        }
        try sink.put(sink.ctx, kv.key, kv.value);
        f.flushed_nodes += 1;
        f.flushed_bytes += kv.value.len;
        const n = try f.load(kv.key);
        try f.flush(n.left, sink);
        for (n.entries) |e| try f.flush(e.right, sink);
    }
};

fn eqLink(x: ?[]const u8, y: ?[]const u8) bool {
    if (x == null or y == null) return x == null and y == null;
    return std.mem.eql(u8, x.?, y.?);
}

/// The least byte string above every string with this prefix; null if none.
pub fn successor(buf: []u8, prefix: []const u8) ?[]const u8 {
    var n = prefix.len;
    while (n > 0) {
        if (prefix[n - 1] != 0xff) {
            @memcpy(buf[0..n], prefix[0..n]);
            buf[n - 1] += 1;
            return buf[0..n];
        }
        n -= 1;
    }
    return null;
}

/// A deep copy of a value into `a`.
pub fn clone(a: std.mem.Allocator, v: Value) !Value {
    return switch (v) {
        .null, .bool, .int, .float => v,
        .bytes => |b| .{ .bytes = try a.dupe(u8, b) },
        .string => |s| .{ .string = try a.dupe(u8, s) },
        .cid => |c| .{ .cid = try a.dupe(u8, c) },
        .array => |xs| blk: {
            const out = try a.alloc(Value, xs.len);
            for (xs, out) |x, *o| o.* = try clone(a, x);
            break :blk .{ .array = out };
        },
        .map => |m| blk: {
            const out = try a.alloc(cbor.Entry, m.len);
            for (m, out) |e, *o| o.* = .{ .key = try a.dupe(u8, e.key), .value = try clone(a, e.value) };
            break :blk .{ .map = out };
        },
    };
}

// ================================================================ tests

const Mem = struct {
    map: std.StringHashMap([]u8),
    fn get(ctx: *anyopaque, a: std.mem.Allocator, cid: []const u8) anyerror!?[]u8 {
        const m: *Mem = @ptrCast(@alignCast(ctx));
        const b = m.map.get(cid) orelse return null;
        return try a.dupe(u8, b);
    }
    fn put(ctx: *anyopaque, cid: []const u8, bytes: []const u8) anyerror!void {
        const m: *Mem = @ptrCast(@alignCast(ctx));
        if (m.map.contains(cid)) return;
        const a = m.map.allocator;
        try m.map.put(try a.dupe(u8, cid), try a.dupe(u8, bytes));
    }
    fn blocks(m: *Mem) Blocks {
        return .{ .ctx = m, .get = get };
    }
    fn sink(m: *Mem) Forest.Sink {
        return .{ .ctx = m, .put = put };
    }
};

fn testKey(buf: *[8]u8, i: u64) []const u8 {
    std.mem.writeInt(u64, buf, i *% 0x9e3779b97f4a7c15, .big);
    return buf;
}

fn keep(a: std.mem.Allocator, r: ?[]const u8) !?[]const u8 {
    return if (r) |x| try a.dupe(u8, x) else null;
}

test "mst: put, get, replace, delete, ordered range" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var mem = Mem{ .map = std.StringHashMap([]u8).init(a) };
    var f = Forest.init(std.testing.allocator, mem.blocks());
    defer f.deinit();
    var root: ?[]const u8 = null;
    const N = 2000;
    var kb: [8]u8 = undefined;
    for (0..N) |i| root = try f.put(root, testKey(&kb, i), .{ .int = @intCast(i) });
    try std.testing.expectEqual(@as(usize, N), try f.count(root));
    for (0..N) |i| {
        const v = (try f.get(a, root, testKey(&kb, i))).?;
        try std.testing.expectEqual(@as(i128, @intCast(i)), v.int);
    }
    try std.testing.expect((try f.get(a, root, "nope")) == null);
    // replace
    const before = root;
    root = try f.put(root, testKey(&kb, 7), .{ .int = 7 });
    try std.testing.expectEqualSlices(u8, before.?, root.?);
    root = try f.put(root, testKey(&kb, 7), .{ .string = "seven" });
    try std.testing.expectEqualStrings("seven", (try f.get(a, root, testKey(&kb, 7))).?.string);
    // ordered, complete
    var all = std.array_list.Managed(KV).init(a);
    try f.range(a, root, null, null, &all);
    try std.testing.expectEqual(@as(usize, N), all.items.len);
    for (all.items[1..], 0..) |x, i| try std.testing.expect(lt(all.items[i].key, x.key));
    // a bounded range equals the filtered full list
    const lo = all.items[100].key;
    const hi = all.items[900].key;
    var part = std.array_list.Managed(KV).init(a);
    try f.range(a, root, lo, hi, &part);
    try std.testing.expectEqual(@as(usize, 800), part.items.len);
    try std.testing.expectEqualSlices(u8, lo, part.items[0].key);
    // delete half
    for (0..N) |i| if (i % 2 == 0) {
        root = try f.delete(root, testKey(&kb, i));
    };
    try std.testing.expectEqual(@as(usize, N / 2), try f.count(root));
    for (0..N) |i| try std.testing.expectEqual(i % 2 == 1, (try f.get(a, root, testKey(&kb, i))) != null);
    const same = try f.delete(root, "absent");
    try std.testing.expectEqualSlices(u8, root.?, same.?);
    for (0..N) |i| root = try f.delete(root, testKey(&kb, i));
    try std.testing.expect(root == null);
}

test "mst: canonical — same set, same root, whatever the order; deletes undo puts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var mem = Mem{ .map = std.StringHashMap([]u8).init(a) };
    var f = Forest.init(std.testing.allocator, mem.blocks());
    defer f.deinit();
    const N = 1500;
    var kb: [8]u8 = undefined;
    var r1: ?[]const u8 = null;
    for (0..N) |i| r1 = try f.put(r1, testKey(&kb, i), .{ .int = @intCast(i) });
    r1 = try keep(a, r1);
    // shuffled order, with extra keys put and deleted along the way
    var order: [N]u64 = undefined;
    for (&order, 0..) |*o, i| o.* = i;
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().shuffle(u64, &order);
    var r2: ?[]const u8 = null;
    for (order, 0..) |i, j| {
        r2 = try f.put(r2, testKey(&kb, i), .{ .int = @intCast(i) });
        if (j % 3 == 0) r2 = try f.put(r2, testKey(&kb, N + j), .{ .string = "tmp" });
    }
    for (order, 0..) |_, j| if (j % 3 == 0) {
        r2 = try f.delete(r2, testKey(&kb, N + j));
    };
    try std.testing.expectEqualSlices(u8, r1.?, r2.?);
    // descending order too
    var r3: ?[]const u8 = null;
    var i: usize = N;
    while (i > 0) {
        i -= 1;
        r3 = try f.put(r3, testKey(&kb, i), .{ .int = @intCast(i) });
    }
    try std.testing.expectEqualSlices(u8, r1.?, r3.?);
}

test "mst: copy-on-write — old roots stay readable, one put writes one path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var mem = Mem{ .map = std.StringHashMap([]u8).init(a) };
    var f = Forest.init(std.testing.allocator, mem.blocks());
    defer f.deinit();
    const N = 5000;
    var kb: [8]u8 = undefined;
    var root: ?[]const u8 = null;
    for (0..N) |i| root = try f.put(root, testKey(&kb, i), .{ .int = @intCast(i) });
    try f.flush(root, mem.sink());
    const old = try keep(a, root);
    // what is left pending is what no root reaches: the intermediate versions
    try std.testing.expect(!f.pending.contains(old.?));
    const stored = mem.map.count();
    f.reset(true); // everything now comes from the blocks
    const r2 = try keep(a, try f.put(old, testKey(&kb, 123456), .{ .string = "new" }));
    const flushed0 = f.flushed_nodes;
    try f.flush(r2, mem.sink());
    const written = f.flushed_nodes - flushed0;
    var depth: usize = 0;
    var cur = r2;
    while (cur) |c| : (depth += 1) {
        const n = try f.load(c);
        cur = n.gapBefore(Forest.search(n, testKey(&kb, 123456)));
    }
    try std.testing.expect(written <= depth + 1 and written >= 1);
    try std.testing.expectEqual(stored + written, mem.map.count());
    // the old version is intact
    f.reset(true);
    try std.testing.expect((try f.get(a, old, testKey(&kb, 123456))) == null);
    try std.testing.expectEqual(@as(usize, N), try f.count(old));
    try std.testing.expectEqual(@as(usize, N + 1), try f.count(r2));
}

test "mst: prefix scans over composite keys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var mem = Mem{ .map = std.StringHashMap([]u8).init(a) };
    var f = Forest.init(std.testing.allocator, mem.blocks());
    defer f.deinit();
    var root: ?[]const u8 = null;
    for ([_][]const u8{ "a\x00", "a\x01", "a\xff", "a\xff\xff", "b", "ab", "" }) |k| root = try f.put(root, k, .null);
    var out = std.array_list.Managed(KV).init(a);
    try f.prefixed(a, root, "a", &out);
    try std.testing.expectEqual(@as(usize, 5), out.items.len);
    out.clearRetainingCapacity();
    try f.prefixed(a, root, "a\xff", &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
    out.clearRetainingCapacity();
    try f.prefixed(a, root, "", &out);
    try std.testing.expectEqual(@as(usize, 7), out.items.len);
    try std.testing.expectEqualStrings("", out.items[0].key);
}
