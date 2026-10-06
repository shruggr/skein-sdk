//! The header chain an image tree carries (shruggr/skein#132): the whole
//! chain from the network's genesis header, as git blobs under `chain/` in
//! the tree a skein is born from, so its chain app starts with every header
//! the host had when the skein was made — no backfill, nothing pulled.
//!
//!   chain/headers/<first>   a block of headers: the raw 80-byte headers, concatenated in height
//!                           order, `per_block` (2016) of them, the first at height <first> (8
//!                           decimal digits: 00000000, 00002016, …); every block but the last is
//!                           full, the last holds the rest (1 to 2016) and is rewritten as headers arrive
//!   chain/tip               {"height": <the last header's height>, "hash": "<its hash, display hex>"}
//!                           (JSON, then a newline)
//!
//! The host grows the tree (skein's src/host/image-chain.ts writes the same
//! layout: a new tree per header, one block and the tip rewritten); `load`
//! fills an empty chain state's best chain from it, verifying as it goes
//! what `Chain.add` verifies: the first header is the network's genesis,
//! each one links to the one before, every target is usable and every hash
//! meets it. `write` builds the layout (tests, and any writer in Zig).
const std = @import("std");
const hdr = @import("header.zig");
const chain_mod = @import("chain.zig");
const store_mod = @import("store.zig");
const state_mod = @import("state.zig");

const Store = store_mod.Store;
const Allocator = std.mem.Allocator;

/// Headers per block (a difficulty period: the blocks under `chain/headers` change only at the end).
pub const per_block: u32 = 2016;

pub const Error = error{ BadImage, WrongNetwork, NotEmpty };

/// A block's name: its first height, 8 decimal digits.
pub fn blockName(buf: *[8]u8, first: u32) []const u8 {
    return std.fmt.bufPrint(buf, "{d:0>8}", .{first}) catch unreachable;
}

pub const Tip = struct { height: u32, hash: [32]u8 };

/// `chain/tip`'s text.
pub fn tipText(a: Allocator, tip: Tip) ![]u8 {
    return std.fmt.allocPrint(a, "{{\"height\":{d},\"hash\":\"{s}\"}}\n", .{ tip.height, hdr.toHex(tip.hash) });
}

pub fn parseTip(a: Allocator, text: []const u8) !Tip {
    const T = struct { height: u32, hash: []const u8 };
    const p = std.json.parseFromSliceLeaky(T, a, text, .{ .ignore_unknown_fields = true }) catch return error.BadImage;
    return .{ .height = p.height, .hash = hdr.fromHex(p.hash) catch return error.BadImage };
}

// ---------------------------------------------------------------- git objects

/// CIDv1, git-raw (0x78), sha1 (0x11): what a git object is stored under.
pub fn gitCid(object: []const u8) [24]u8 {
    var d: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(object, &d, .{});
    return .{ 0x01, 0x78, 0x11, 0x14 } ++ d;
}

/// A git object's body, after its header "<kind> <len>\0".
fn body(object: []const u8, kind: []const u8) ![]const u8 {
    const nul = std.mem.indexOfScalar(u8, object, 0) orelse return error.BadImage;
    const h = object[0..nul];
    if (h.len < kind.len + 2 or !std.mem.startsWith(u8, h, kind) or h[kind.len] != ' ') return error.BadImage;
    const n = std.fmt.parseInt(usize, h[kind.len + 1 ..], 10) catch return error.BadImage;
    if (n != object.len - nul - 1) return error.BadImage;
    return object[nul + 1 ..];
}

const TreeEntry = struct { mode: []const u8, name: []const u8, cid: [24]u8 };

fn readTree(a: Allocator, s: Store, cid: []const u8) ![]TreeEntry {
    var b = try body(try s.get(a, cid), "tree");
    var out: std.ArrayList(TreeEntry) = .empty;
    while (b.len > 0) {
        const sp = std.mem.indexOfScalar(u8, b, ' ') orelse return error.BadImage;
        const z = std.mem.indexOfScalar(u8, b, 0) orelse return error.BadImage;
        if (z < sp or z + 21 > b.len) return error.BadImage;
        try out.append(a, .{ .mode = b[0..sp], .name = b[sp + 1 .. z], .cid = .{ 0x01, 0x78, 0x11, 0x14 } ++ b[z + 1 ..][0..20].* });
        b = b[z + 21 ..];
    }
    return out.items;
}

fn entry(es: []const TreeEntry, name: []const u8) ?TreeEntry {
    for (es) |e| if (std.mem.eql(u8, e.name, name)) return e;
    return null;
}

fn isDir(e: TreeEntry) bool {
    return std.mem.eql(u8, e.mode, "40000");
}

// ---------------------------------------------------------------- reading

/// Where a tree's header chain is: its blocks' CIDs in height order, and its tip.
pub const Found = struct { blocks: []const [24]u8, tip: Tip };

/// The header chain a tree carries, or null when it has no `chain/headers`.
/// The blocks must be named 00000000, 00002016, … with none missing.
pub fn find(a: Allocator, s: Store, root: []const u8) !?Found {
    const top = entry(try readTree(a, s, root), "chain") orelse return null;
    if (!isDir(top)) return null;
    const ch = try readTree(a, s, &top.cid);
    const hd = entry(ch, "headers") orelse return null;
    if (!isDir(hd)) return error.BadImage;
    const tip_e = entry(ch, "tip") orelse return error.BadImage;
    const tip = try parseTip(a, try body(try s.get(a, &tip_e.cid), "blob"));
    const es = try readTree(a, s, &hd.cid);
    if (es.len == 0) return error.BadImage;
    const blocks = try a.alloc([24]u8, es.len);
    for (es, blocks, 0..) |e, *b, i| {
        var buf: [8]u8 = undefined;
        if (isDir(e) or !std.mem.eql(u8, e.name, blockName(&buf, @intCast(i * per_block)))) return error.BadImage;
        b.* = e.cid;
    }
    return .{ .blocks = blocks, .tip = tip };
}

pub const Loaded = struct { headers: u32, tip: u32 };

/// Fill an empty chain state's best chain (`headers`, `heights`) from the
/// header chain the tree `root` carries, verified as `Chain.add` verifies a
/// run from genesis; null when the tree carries none (the state untouched).
/// Each header is put as its bitcoin-block block — not kept: a header has no
/// edges (#42) — and both maps are built in one pass, their nodes put as they are made
/// (mst `build`).
pub fn load(st: *state_mod.State, root: []const u8) !?Loaded {
    const a = st.arena;
    const found = (try find(a, st.store, root)) orelse return null;
    if ((try st.chain().tip()) != null) return error.NotEmpty;
    const total = found.tip.height + 1;
    if (total > found.blocks.len * per_block or total <= (found.blocks.len - 1) * per_block) return error.BadImage;
    const hashes = try a.alloc([32]u8, total);
    var n: u32 = 0;
    const genesis = st.network.genesis();
    for (found.blocks, 0..) |cid, bi| {
        const raw = try body(try st.store.get(a, &cid), "blob");
        const want: usize = if (bi + 1 < found.blocks.len) per_block else total - n;
        if (raw.len != want * hdr.size) return error.BadImage;
        var i: usize = 0;
        while (i < raw.len) : (i += hdr.size) {
            const h: *const [hdr.size]u8 = raw[i..][0..hdr.size];
            if (n == 0) {
                if (!std.mem.eql(u8, h, &genesis)) return error.WrongNetwork;
            } else if (!std.mem.eql(u8, &(try hdr.Header.parse(h)).prev_hash, &hashes[n - 1])) return error.BadLink;
            try chain_mod.checkHeader(h);
            hashes[n] = hdr.hash(h);
            const c = store_mod.hashCid(.block, hashes[n]);
            try st.store.putBlock(&c, h);
            n += 1;
        }
    }
    if (!std.mem.eql(u8, &hashes[total - 1], &found.tip.hash)) return error.BadImage;

    const by_height = try a.alloc(store_mod.mst.KV, total);
    const by_hash = try a.alloc(store_mod.mst.KV, total);
    for (hashes, by_height, by_hash, 0..) |*h, *x, *y, i| {
        const k = try a.alloc(u8, 4);
        std.mem.writeInt(u32, k[0..4], @intCast(i), .big);
        x.* = .{ .key = k, .value = .{ .cid = try a.dupe(u8, &store_mod.hashCid(.block, h.*)) } };
        y.* = .{ .key = h, .value = .{ .int = @intCast(i) } };
    }
    std.mem.sort(store_mod.mst.KV, by_hash, {}, struct {
        fn less(_: void, x: store_mod.mst.KV, y: store_mod.mst.KV) bool {
            return std.mem.order(u8, x.key, y.key) == .lt;
        }
    }.less);
    const headers = st.map("headers");
    const heights = st.map("heights");
    headers.root = try st.maps.forest.build(by_height, st.maps.sink());
    heights.root = try st.maps.forest.build(by_hash, st.maps.sink());
    headers.dirty = true;
    heights.dirty = true;
    return .{ .headers = total, .tip = found.tip.height };
}

// ---------------------------------------------------------------- writing

fn putGit(a: Allocator, s: Store, kind: []const u8, content: []const u8) ![24]u8 {
    const obj = try std.fmt.allocPrint(a, "{s} {d}\x00{s}", .{ kind, content.len, content });
    const c = gitCid(obj);
    try s.putBlock(&c, obj);
    return c;
}

/// A git tree's bytes from entries already in git's order.
fn treeBytes(a: Allocator, es: []const TreeEntry) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for (es) |e| {
        try out.print(a, "{s} {s}\x00", .{ e.mode, e.name });
        try out.appendSlice(a, e.cid[4..24]);
    }
    return out.items;
}

/// The layout for `headers` (raw, from genesis, in height order) put into
/// `s`: the `chain` tree's CID (to be the root's entry `chain`, mode 40000),
/// and a root holding only it.
pub fn write(a: Allocator, s: Store, headers: []const [hdr.size]u8) !struct { chain: [24]u8, root: [24]u8 } {
    if (headers.len == 0) return error.BadImage;
    const nblocks = (headers.len + per_block - 1) / per_block;
    const es = try a.alloc(TreeEntry, nblocks);
    for (es, 0..) |*e, bi| {
        const lo = bi * per_block;
        const hi = @min(headers.len, lo + per_block);
        const name = try a.alloc(u8, 8);
        _ = blockName(name[0..8], @intCast(lo));
        e.* = .{ .mode = "100644", .name = name, .cid = try putGit(a, s, "blob", std.mem.sliceAsBytes(headers[lo..hi])) };
    }
    const hd = try putGit(a, s, "tree", try treeBytes(a, es));
    const last = headers.len - 1;
    const tip = try putGit(a, s, "blob", try tipText(a, .{ .height = @intCast(last), .hash = hdr.hash(&headers[last]) }));
    const ch = try putGit(a, s, "tree", try treeBytes(a, &.{ .{ .mode = "40000", .name = "headers", .cid = hd }, .{ .mode = "100644", .name = "tip", .cid = tip } }));
    const root = try putGit(a, s, "tree", try treeBytes(a, &.{.{ .mode = "40000", .name = "chain", .cid = ch }}));
    return .{ .chain = ch, .root = root };
}
