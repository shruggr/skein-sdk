//! SPV over a BEEF against our own chain tracker: every BUMP's root must be
//! the merkle root of our best-chain header at its height; every transaction
//! must be in a BUMP (proven) or have all its inputs' sources proven or valid
//! before it, with every input's script verified (bsvz's interpreter). A
//! txid-only entry is accepted only for a transaction we already hold.
const std = @import("std");
const bsvz = @import("bsvz");
const beef_mod = @import("beef.zig");

pub const Error = error{ UnknownHeader, RootMismatch, NotInBump, MissingInput, UnknownTxidOnly, ScriptFailed, NotParentsFirst, OutOfMemory };

/// What SPV asks of the wallet: a header's merkle root, and a transaction we hold.
pub const Context = struct {
    ptr: *anyopaque,
    rootAtFn: *const fn (ptr: *anyopaque, height: u32) anyerror!?[32]u8,
    knownRawFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, txid: [32]u8) anyerror!?[]const u8,
};

pub const Result = struct {
    /// Per entry (BEEF order): proven by a BUMP checked against our header.
    proven: []bool,
};

pub fn verify(arena: std.mem.Allocator, b: beef_mod.Beef, ctx: Context) !Result {
    // BUMPs: every leaf a root can be computed for gives the same root, and
    // that root is our header's at the BUMP's height.
    for (b.bumps) |p| {
        if (p.path.len == 0) return error.RootMismatch;
        var root: ?[32]u8 = null;
        for (p.path[0]) |leaf| {
            const h = leaf.hash orelse continue;
            const is_ours = b.find(h.bytes) != null;
            if (!(leaf.txid orelse false) and !is_ours) continue;
            const r = beef_mod.rootFor(arena, p, h.bytes) orelse return error.RootMismatch;
            if (root) |x| {
                if (!std.mem.eql(u8, &x, &r)) return error.RootMismatch;
            } else root = r;
        }
        const r = root orelse continue; // a BUMP proving nothing here is harmless
        const want = (try ctx.rootAtFn(ctx.ptr, p.block_height)) orelse return error.UnknownHeader;
        if (!std.mem.eql(u8, &want, &r)) return error.RootMismatch;
    }

    if (!beef_mod.parentsFirst(b)) return error.NotParentsFirst;
    const proven = try arena.alloc(bool, b.entries.len);
    for (b.entries, 0..) |e, i| {
        proven[i] = false;
        switch (e.format) {
            .txid_only => {
                if ((try ctx.knownRawFn(ctx.ptr, arena, e.txid)) == null) return error.UnknownTxidOnly;
                continue;
            },
            .raw_with_bump => {
                if (!beef_mod.bumpHas(b.bumps[e.bump.?], e.txid)) return error.NotInBump;
                proven[i] = true;
                continue;
            },
            .raw => {
                for (b.bumps) |p| if (beef_mod.bumpHas(p, e.txid) and pathFlags(p, e.txid)) {
                    proven[i] = true;
                };
                if (proven[i]) continue;
            },
        }
        // Unproven: every input's source is earlier in the BEEF or ours, and its script verifies.
        const tx = e.tx.?;
        for (tx.inputs, 0..) |in, k| {
            const src_txid = in.previous_outpoint.txid.bytes;
            const src_raw = if (b.find(src_txid)) |s| (s.raw orelse (try ctx.knownRawFn(ctx.ptr, arena, src_txid)) orelse return error.MissingInput) else (try ctx.knownRawFn(ctx.ptr, arena, src_txid)) orelse return error.MissingInput;
            const src = bsvz.transaction.Transaction.parse(arena, src_raw) catch return error.MissingInput;
            if (in.previous_outpoint.index >= src.outputs.len) return error.MissingInput;
            const ok = bsvz.script.interpreter.verifyPrevout(.{
                .allocator = arena,
                .tx = &tx,
                .input_index = k,
                .previous_output = src.outputs[in.previous_outpoint.index],
                .unlocking_script = in.unlocking_script,
            }) catch false;
            if (!ok) return error.ScriptFailed;
        }
    }
    return .{ .proven = proven };
}

/// go-sdk's Beef.IsValid: structure only, no headers, no scripts. Every
/// transaction is in its BUMP or has all its inputs' sources valid in the
/// BEEF; txid-only entries count only when allowed and a BUMP holds them;
/// BUMPs at the same height agree on the root.
pub fn structurallyValid(arena: std.mem.Allocator, b: beef_mod.Beef, allow_txid_only: bool) !bool {
    var roots = std.AutoHashMapUnmanaged(u32, [32]u8).empty;
    for (b.bumps) |p| {
        if (p.path.len == 0) return false;
        for (p.path[0]) |leaf| {
            if (!(leaf.txid orelse false)) continue;
            const h = leaf.hash orelse return false;
            const r = beef_mod.rootFor(arena, p, h.bytes) orelse return false;
            const gop = try roots.getOrPut(arena, p.block_height);
            if (gop.found_existing and !std.mem.eql(u8, gop.value_ptr, &r)) return false;
            gop.value_ptr.* = r;
        }
    }
    const valid = try arena.alloc(bool, b.entries.len);
    for (b.entries, valid) |e, *v| {
        v.* = false;
        switch (e.format) {
            .txid_only => {
                if (!allow_txid_only) return false;
                for (b.bumps) |p| v.* = v.* or (beef_mod.bumpHas(p, e.txid) and pathFlags(p, e.txid));
            },
            .raw_with_bump => {
                if (!beef_mod.bumpHas(b.bumps[e.bump.?], e.txid)) return false;
                v.* = true;
            },
            .raw => for (b.bumps) |p| {
                v.* = v.* or (beef_mod.bumpHas(p, e.txid) and pathFlags(p, e.txid));
            },
        }
    }
    // The rest by fixpoint: valid when every input's source is in the BEEF and valid.
    var progress = true;
    while (progress) {
        progress = false;
        for (b.entries, valid) |e, *v| {
            if (v.* or e.tx == null) continue;
            var all = true;
            for (e.tx.?.inputs) |in| {
                const j = b.indexOf(in.previous_outpoint.txid.bytes) orelse {
                    all = false;
                    break;
                };
                all = all and valid[j];
            }
            if (all) {
                v.* = true;
                progress = true;
            }
        }
    }
    for (valid) |v| if (!v) return false;
    return true;
}

/// Whether the BUMP flags this txid as a transaction (not just a sibling hash).
fn pathFlags(p: bsvz.spv.MerklePath, txid: [32]u8) bool {
    for (p.path[0]) |leaf| if (leaf.hash) |h| if (std.mem.eql(u8, &h.bytes, &txid)) return leaf.txid orelse false;
    return false;
}
