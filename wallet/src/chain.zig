//! Our own chain tracker over records: headers are `bitcoin-block` blocks
//! (the CID is the block hash); the `headers` map names the best chain
//! (height → header) and `heights` the way back (block hash → height), both
//! anchored at the network's genesis header — a constant here, never an
//! input: every header from any sender must chain back to it. A header is
//! accepted when its target is usable, its hash meets it, and it links to a
//! header on our best chain; a competing branch replaces ours when its work
//! from the fork point is greater.
//!
//! Not checked, by decision (#29 Q3, permanent): the difficulty adjustment
//! rule (that `bits` is the one the chain requires), timestamps and
//! versions. A peer can feed a low-difficulty branch; it only wins against
//! ours if it carries more work.
const std = @import("std");
const hdr = @import("header.zig");
const store_mod = @import("store.zig");

const Store = store_mod.Store;
const Map = store_mod.Map;

pub const Error = error{ Unconnected, BadLink, BadTarget, BadPow, InvalidHeader, BadRecord };

/// The networks, by their genesis headers (the chain's anchor).
pub const Network = enum {
    main,
    @"test",
    regtest,

    pub fn parse(text: []const u8) ?Network {
        return std.meta.stringToEnum(Network, text);
    }

    pub fn genesis(n: Network) [hdr.size]u8 {
        const h = switch (n) {
            .main => "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            .@"test" => "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18",
            .regtest => "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000",
        };
        var out: [hdr.size]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, h) catch unreachable;
        return out;
    }
};

pub const Loaded = struct { height: u32, raw: [hdr.size]u8, hash: [32]u8 };

pub const Chain = struct {
    arena: std.mem.Allocator,
    store: Store,
    /// height (4 bytes, big-endian) → header (bitcoin-block link)
    headers: *Map,
    /// block hash (internal order) → height, for the best chain
    heights: *Map,
    network: Network,

    pub fn at(self: Chain, height: u32) !?Loaded {
        const c = (try self.headers.link(&store_mod.be32(height))) orelse return null;
        const raw = try self.store.get(self.arena, c);
        if (raw.len != hdr.size) return error.BadRecord;
        const r: [hdr.size]u8 = raw[0..hdr.size].*;
        return .{ .height = height, .raw = r, .hash = hdr.hash(&r) };
    }

    /// The best chain's tip height, or null before the anchor is in.
    pub fn tip(self: Chain) !?u32 {
        const k = (try self.headers.last()) orelse return null;
        if (k.len != 4) return error.BadRecord;
        return std.mem.readInt(u32, k[0..4], .big);
    }

    /// The height of a best-chain header by its hash.
    pub fn heightOf(self: Chain, hash: [32]u8) !?u32 {
        const v = (try self.heights.get(&hash)) orelse return null;
        if (v != .int) return error.BadRecord;
        return @intCast(v.int);
    }

    /// The merkle root of the best-chain header at a height: the chain
    /// tracker's one question (go-sdk ChainTracker.IsValidRootForHeight).
    pub fn rootAt(self: Chain, height: u32) !?[32]u8 {
        const h = (try self.at(height)) orelse return null;
        return (try hdr.Header.parse(&h.raw)).merkle_root;
    }

    fn putHeader(self: Chain, height: u32, raw: *const [hdr.size]u8) !void {
        const cid = try self.store.putBitcoin(self.arena, .block, raw);
        try self.headers.putLink(&store_mod.be32(height), cid);
        try self.heights.put(&hdr.hash(raw), .{ .int = height });
    }

    /// The anchor: the network's genesis header at height 0, put when the chain is empty.
    fn anchor(self: Chain) !u32 {
        if (try self.tip()) |t| return t;
        const g = self.network.genesis();
        try self.putHeader(0, &g);
        return 0;
    }

    pub const AddResult = struct { added: u32 = 0, replaced: u32 = 0, known: u32 = 0, ignored: u32 = 0, tip: u32 = 0 };

    /// A run of consecutive headers, parents first. The first must link to a
    /// header on our best chain (or be the genesis header itself).
    pub fn add(self: Chain, raws: []const []const u8) !AddResult {
        var res = AddResult{};
        const old_tip = try self.anchor();
        res.tip = old_tip;
        if (raws.len == 0) return res;
        const batch = try self.arena.alloc([hdr.size]u8, raws.len);
        for (raws, batch) |r, *b| {
            if (r.len != hdr.size) return error.InvalidHeader;
            b.* = r[0..hdr.size].*;
            try checkHeader(b);
        }
        for (batch[1..], 0..) |*b, i| {
            const h = try hdr.Header.parse(b);
            if (!std.mem.eql(u8, &h.prev_hash, &hdr.hash(&batch[i]))) return error.BadLink;
        }
        // A batch may start at genesis itself: that one is known.
        var b0: usize = 0;
        const g = self.network.genesis();
        if (std.mem.eql(u8, &batch[0], &g)) {
            res.known += 1;
            b0 = 1;
            if (batch.len == 1) return res;
        }
        const run = batch[b0..];
        // The fork point: the best-chain header the run's first names as its parent.
        const first = try hdr.Header.parse(&run[0]);
        const base = (try self.heightOf(first.prev_hash)) orelse return error.Unconnected;
        // Skip the headers we already hold.
        var i: usize = 0;
        while (i < run.len) : (i += 1) {
            const have = (try self.at(base + 1 + @as(u32, @intCast(i)))) orelse break;
            if (!std.mem.eql(u8, &have.hash, &hdr.hash(&run[i]))) break;
            res.known += 1;
        }
        if (i == run.len) return res;
        const start = base + 1 + @as(u32, @intCast(i));
        var new_work: u256 = 0;
        for (run[i..]) |*b| new_work +|= hdr.work(hdr.target((try hdr.Header.parse(b)).bits).?);
        var old_work: u256 = 0;
        var h: u32 = start;
        while (h <= old_tip) : (h += 1) {
            const have = (try self.at(h)) orelse break;
            old_work +|= hdr.work(hdr.target((try hdr.Header.parse(&have.raw)).bits) orelse 0);
        }
        if (new_work <= old_work) {
            res.ignored = @intCast(run.len - i);
            return res;
        }
        h = start;
        while (h <= old_tip) : (h += 1) {
            const have = (try self.at(h)) orelse break;
            _ = try self.heights.remove(&have.hash);
            if (try self.headers.remove(&store_mod.be32(h))) res.replaced += 1;
        }
        for (run[i..], 0..) |*b, j| try self.putHeader(start + @as(u32, @intCast(j)), b);
        res.added = @intCast(run.len - i);
        res.tip = start + res.added - 1;
        return res;
    }
};

/// A header on its own: usable target, proof of work.
pub fn checkHeader(raw: *const [hdr.size]u8) Error!void {
    const h = hdr.Header.parse(raw) catch return error.InvalidHeader;
    _ = hdr.target(h.bits) orelse return error.BadTarget;
    if (!hdr.powOk(raw)) return error.BadPow;
}
