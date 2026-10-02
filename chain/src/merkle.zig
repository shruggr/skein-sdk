//! A block's transaction merkle tree as IPLD nodes (issue #29, "Proof
//! structure"). A node is the 64 bytes left hash ‖ right hash, a
//! `bitcoin-tx` block of exactly 64 bytes (dbl-sha2-256; IPLD's convention,
//! #42: the kernel decodes it as [left, right]): its CID is its merkle hash.
//! The block header's merkle root names the root node; each node names its
//! two children — nodes, or at the bottom transactions (bitcoin-tx CIDs, the
//! txids). The tree is sparse: a wallet holds only the nodes on the paths to
//! its own transactions; other children are hashes it cannot dereference.
//!
//! - Receiving a merkle path (a BUMP, BRC-74) is putting the nodes it
//!   reveals: every node whose two children it gives or implies, hash-checked
//!   (the store's putblock), nothing rewritten. Nodes are shared by every
//!   transaction of the block and every merge: two BUMPs of one block give
//!   one set of blocks, deduplicated by CID, whatever order they arrive in.
//! - A proof is rebuilt on demand (`pathFor`): from the root, one node per
//!   level down to the transaction, turning by the bits of its leaf position
//!   (`Position`, recorded in the wallet's `proofs` when the proof arrived:
//!   #42, decided 2026-09-30) — no search — emitting each level's sibling: a
//!   BUMP again, the minimal one for that transaction.
//! - Verification is the DAG itself: a node's hash is the hash of its children.
const std = @import("std");
const bsvz = @import("bsvz");
const store_mod = @import("store.zig");

const Store = store_mod.Store;
pub const MerklePath = bsvz.spv.MerklePath;
const PathElement = std.meta.Elem(std.meta.Elem(@FieldType(MerklePath, "path")));

/// A node's CID: bitcoin-tx over its hash (a leaf's is its txid: the same codec).
pub fn nodeCid(hash: [32]u8) [37]u8 {
    return store_mod.hashCid(.tx, hash);
}

pub const Node = struct { hash: [32]u8, bytes: [64]u8 };

pub const Revealed = struct {
    /// The root the path proves (to be checked against the header's merkle root).
    root: [32]u8,
    /// The nodes it reveals, bottom level first, each level in offset order.
    nodes: []Node,
};

fn parent(left: [32]u8, right: [32]u8) Node {
    const bytes = left ++ right;
    return .{ .hash = store_mod.dblSha256(&bytes), .bytes = bytes };
}

/// The nodes a BUMP reveals: at each level, every pair of siblings it gives
/// (or implies: a `duplicate` right sibling is the left one again) makes a
/// node, whose hash is the parent one level up. A parent the BUMP also gives
/// with another hash is a conflicting node (same position, different hash):
/// refused. A one-transaction block (one level, one leaf) has no nodes: its
/// root is the txid.
pub fn reveal(a: std.mem.Allocator, p: MerklePath) !Revealed {
    const height = p.path.len;
    if (height == 0 or height > 64) return error.BadProof;
    if (height == 1 and p.path[0].len == 1) {
        const h = p.path[0][0].hash orelse return error.BadProof;
        return .{ .root = h.bytes, .nodes = &.{} };
    }
    var nodes: std.ArrayList(Node) = .empty;
    var cur: std.AutoArrayHashMapUnmanaged(u64, [32]u8) = .empty;
    var dup = std.AutoHashMap(u64, void).init(a);
    for (p.path[0]) |e| try take(a, &cur, &dup, e);
    var level: usize = 0;
    while (level < height) : (level += 1) {
        var next: std.AutoArrayHashMapUnmanaged(u64, [32]u8) = .empty;
        var next_dup = std.AutoHashMap(u64, void).init(a);
        if (level + 1 < height) for (p.path[level + 1]) |e| try take(a, &next, &next_dup, e);
        const offsets = try a.dupe(u64, cur.keys());
        std.mem.sort(u64, offsets, {}, std.sort.asc(u64));
        for (offsets) |o| {
            if (o & 1 == 1 and cur.contains(o - 1)) continue; // the pair was made from its left
            const e = o & ~@as(u64, 1);
            const left = cur.get(e) orelse continue; // a right child alone: its sibling is not given
            const right = cur.get(e + 1) orelse if (dup.contains(e + 1)) left else continue;
            const n = parent(left, right);
            try nodes.append(a, n);
            if (next.get(e >> 1)) |given| {
                if (!std.mem.eql(u8, &given, &n.hash)) return error.ConflictingNode;
            } else try next.put(a, e >> 1, n.hash);
        }
        cur = next;
        dup = next_dup;
    }
    const root = cur.get(0) orelse return error.BadProof;
    if (cur.count() != 1) return error.BadProof;
    return .{ .root = root, .nodes = nodes.items };
}

fn take(a: std.mem.Allocator, m: *std.AutoArrayHashMapUnmanaged(u64, [32]u8), dup: *std.AutoHashMap(u64, void), e: PathElement) !void {
    if (e.duplicate orelse false) {
        if (e.offset & 1 == 0) return error.BadProof; // only a right sibling repeats its left
        try dup.put(e.offset, {});
        return;
    }
    const h = e.hash orelse return error.BadProof;
    if (m.get(e.offset)) |had| if (!std.mem.eql(u8, &had, &h.bytes)) return error.ConflictingNode;
    try m.put(a, e.offset, h.bytes);
}

/// Put the nodes (hash-checked by the store; one already held is the same
/// block) and keep them. They contribute no edges (#42, decided 2026-09-30):
/// a proof is read downward from the root, never up from a leaf.
pub fn putNodes(s: Store, nodes: []const Node) !void {
    for (nodes) |n| {
        const c = nodeCid(n.hash);
        try s.putBlock(&c, &n.bytes);
        try s.keep(&c);
    }
}

/// A node we hold (its 64 bytes), or null — also for a transaction we hold
/// (a leaf: under bitcoin-tx too, and never 64 bytes).
pub fn node(a: std.mem.Allocator, s: Store, hash: [32]u8) !?[64]u8 {
    const b = s.tryGet(a, &nodeCid(hash)) orelse return null;
    if (b.len != 64) return null;
    return b[0..64].*;
}

const Step = struct { sibling: [32]u8, dup: bool };

/// Where a transaction sits in its block's tree: the BUMP's height (the
/// tree's depth, its levels below the root) and the leaf's offset (BRC-74:
/// its index among the block's transactions). Recorded in `proofs` when the
/// proof arrives (#42, decided 2026-09-30), so a proof is rebuilt by descent.
pub const Position = struct { depth: u8, offset: u64 };

/// The position a BUMP gives `txid`: its leaf's offset at level 0, the
/// BUMP's height as the depth. Null when the BUMP does not hold it.
pub fn positionIn(p: MerklePath, txid: [32]u8) ?Position {
    if (p.path.len == 0 or p.path.len > 64) return null;
    for (p.path[0]) |leaf| if (leaf.hash) |h| if (std.mem.eql(u8, &h.bytes, &txid)) return .{ .depth = @intCast(p.path.len), .offset = leaf.offset };
    return null;
}

/// The BUMP for `txid` at `pos` in the block at `block_height` whose merkle
/// root is `root`, rebuilt from the nodes we hold: from the root, one node
/// read per level, turning by the offset's bits (most significant first), no
/// search; the siblings read on the way are the BUMP (a right sibling equal
/// to the left is BRC-74's duplicate). Null when a node on the way is not
/// held, or the descent does not end at `txid`. A one-transaction block:
/// the root is the txid, no read.
pub fn pathFor(a: std.mem.Allocator, s: Store, root: [32]u8, block_height: u32, txid: [32]u8, pos: Position) !?MerklePath {
    if (std.mem.eql(u8, &root, &txid)) {
        if (pos.offset != 0) return null;
        const level = try a.alloc(PathElement, 1);
        level[0] = .{ .offset = 0, .hash = .{ .bytes = txid }, .txid = true };
        const levels = try a.alloc([]PathElement, 1);
        levels[0] = level;
        return .{ .block_height = block_height, .path = levels };
    }
    const h: usize = pos.depth;
    if (h == 0 or h > 64) return null;
    if (h < 64 and pos.offset >> @intCast(h) != 0) return null;
    const offset = pos.offset;
    const trail = try a.alloc(Step, h); // root level first
    var cur = root;
    for (trail, 0..) |*st, level| {
        const n = (try node(a, s, cur)) orelse return null;
        const left: [32]u8 = n[0..32].*;
        const right: [32]u8 = n[32..64].*;
        const same = std.mem.eql(u8, &left, &right);
        const bit: u1 = @truncate(offset >> @intCast(h - 1 - level));
        if (bit == 1 and same) return null; // the duplicate right is no leaf of its own
        st.* = .{ .sibling = if (bit == 0) right else left, .dup = bit == 0 and same };
        cur = if (bit == 0) left else right;
    }
    if (!std.mem.eql(u8, &cur, &txid)) return null;
    const levels = try a.alloc([]PathElement, h);
    for (levels, 0..) |*lv, i| {
        const st = trail[h - 1 - i];
        const sib_off = (offset >> @intCast(i)) ^ 1;
        const sib: PathElement = if (st.dup) .{ .offset = sib_off, .duplicate = true } else .{ .offset = sib_off, .hash = .{ .bytes = st.sibling } };
        if (i == 0) {
            const leaf: PathElement = .{ .offset = offset, .hash = .{ .bytes = txid }, .txid = true };
            lv.* = try a.dupe(PathElement, if (offset & 1 == 0) &.{ leaf, sib } else &.{ sib, leaf });
        } else lv.* = try a.dupe(PathElement, &.{sib});
    }
    return .{ .block_height = block_height, .path = levels };
}
