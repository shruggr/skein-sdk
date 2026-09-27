//! Our own chain tracker over records: header records in the `headers` index
//! map (height → header record), the best chain by accumulated work from a
//! checkpoint. A header is accepted when its target is usable, its hash
//! meets it, and it links to a header we hold; a competing branch replaces
//! ours when its work from the fork point is greater.
//!
//! Not checked (known gap, docs/WALLET.md): the difficulty adjustment rule
//! (that `bits` is the one the chain requires), timestamps (median time past,
//! future limit) and versions. A peer can therefore feed a low-difficulty
//! branch; it only wins against ours if it carries more work.
const std = @import("std");
const cbor = @import("cbor.zig");
const hdr = @import("header.zig");
const store_mod = @import("store.zig");

const Store = store_mod.Store;
const Index = store_mod.Index;

pub const Error = error{ NoCheckpoint, CheckpointConflict, Unconnected, BadLink, BadTarget, BadPow, InvalidHeader, BadRecord };

pub fn heightKey(buf: *[10]u8, height: u32) []const u8 {
    return std.fmt.bufPrint(buf, "{d:0>10}", .{height}) catch unreachable;
}

pub const Loaded = struct { height: u32, raw: [hdr.size]u8, hash: [32]u8 };

pub const Chain = struct {
    arena: std.mem.Allocator,
    store: Store,
    headers: *Index,

    pub fn at(self: Chain, height: u32) !?Loaded {
        var kb: [10]u8 = undefined;
        const v = self.headers.get(heightKey(&kb, height)) orelse return null;
        if (v != .cid) return error.BadRecord;
        const rec = try self.store.getValue(self.arena, v.cid);
        const raw = rec.getBytes("raw") orelse return error.BadRecord;
        if (raw.len != hdr.size) return error.BadRecord;
        const r: [hdr.size]u8 = raw[0..hdr.size].*;
        return .{ .height = height, .raw = r, .hash = hdr.hash(&r) };
    }

    /// The best chain's lowest and highest heights, or null when there is none.
    pub fn span(self: Chain) ?struct { low: u32, tip: u32 } {
        const keys = self.headers.sortedKeys();
        if (keys.len == 0) return null;
        const low = std.fmt.parseInt(u32, keys[0], 10) catch return null;
        const tip = std.fmt.parseInt(u32, keys[keys.len - 1], 10) catch return null;
        return .{ .low = low, .tip = tip };
    }

    /// The merkle root of the best-chain header at a height: the chain
    /// tracker's one question (go-sdk ChainTracker.IsValidRootForHeight).
    pub fn rootAt(self: Chain, height: u32) !?[32]u8 {
        const h = (try self.at(height)) orelse return null;
        return (try hdr.Header.parse(&h.raw)).merkle_root;
    }

    fn putHeader(self: Chain, height: u32, raw: *const [hdr.size]u8) !void {
        const cid = try self.store.putValue(self.arena, .{ .map = &.{
            .{ .key = "kind", .value = .{ .text = "header" } },
            .{ .key = "height", .value = .{ .uint = height } },
            .{ .key = "raw", .value = .{ .bytes = raw } },
        } });
        var kb: [10]u8 = undefined;
        try self.headers.put(self.arena, heightKey(&kb, height), .{ .cid = cid });
    }

    /// The trusted starting point. Only into an empty chain (or the same header again).
    pub fn checkpoint(self: Chain, height: u32, raw_in: []const u8) !void {
        if (raw_in.len != hdr.size) return error.InvalidHeader;
        const raw: [hdr.size]u8 = raw_in[0..hdr.size].*;
        try checkHeader(&raw);
        if (self.span()) |_| {
            const have = (try self.at(height)) orelse return error.CheckpointConflict;
            if (!std.mem.eql(u8, &have.raw, &raw)) return error.CheckpointConflict;
            return;
        }
        try self.putHeader(height, &raw);
    }

    pub const AddResult = struct { added: u32 = 0, replaced: u32 = 0, known: u32 = 0, ignored: u32 = 0, tip: u32 = 0 };

    /// A run of consecutive headers, parents first. The first must link to a
    /// header on our best chain.
    pub fn add(self: Chain, raws: []const []const u8) !AddResult {
        var res = AddResult{};
        const sp = self.span() orelse return error.NoCheckpoint;
        res.tip = sp.tip;
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
        // The fork point: the best-chain header the batch's first names as its parent.
        const first = try hdr.Header.parse(&batch[0]);
        var fork: ?u32 = null;
        var hgt = sp.tip;
        while (true) : (hgt -= 1) {
            const have = (try self.at(hgt)) orelse break;
            if (std.mem.eql(u8, &have.hash, &first.prev_hash)) {
                fork = hgt;
                break;
            }
            if (hgt == sp.low) break;
        }
        const base = fork orelse return error.Unconnected;
        // Skip the headers we already hold.
        var i: usize = 0;
        while (i < batch.len) : (i += 1) {
            const have = (try self.at(base + 1 + @as(u32, @intCast(i)))) orelse break;
            if (!std.mem.eql(u8, &have.hash, &hdr.hash(&batch[i]))) break;
            res.known += 1;
        }
        if (i == batch.len) return res;
        const start = base + 1 + @as(u32, @intCast(i));
        var new_work: u256 = 0;
        for (batch[i..]) |*b| new_work +|= hdr.work(hdr.target((try hdr.Header.parse(b)).bits).?);
        var old_work: u256 = 0;
        var h: u32 = start;
        while (h <= sp.tip) : (h += 1) {
            const have = (try self.at(h)) orelse break;
            old_work +|= hdr.work(hdr.target((try hdr.Header.parse(&have.raw)).bits) orelse 0);
        }
        if (new_work <= old_work) {
            res.ignored = @intCast(batch.len - i);
            return res;
        }
        h = start;
        while (h <= sp.tip) : (h += 1) {
            var kb: [10]u8 = undefined;
            if (self.headers.remove(heightKey(&kb, h))) res.replaced += 1;
        }
        for (batch[i..], 0..) |*b, j| try self.putHeader(start + @as(u32, @intCast(j)), b);
        res.added = @intCast(batch.len - i);
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
