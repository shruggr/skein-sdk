//! A block's transaction merkle tree as IPLD nodes (issue #29, "Proof
//! structure"). A node is the 64 bytes left hash ‖ right hash, a
//! `bitcoin-merkle` block (0xb3, dbl-sha2-256): its CID is its merkle hash.
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
//!   level down to the transaction, emitting each level's sibling — a BUMP
//!   again, the minimal one for that transaction.
//! - Verification is the DAG itself: a node's hash is the hash of its children.
const std = @import("std");
const bsvz = @import("bsvz");
const store_mod = @import("store.zig");

const Store = store_mod.Store;
pub const MerklePath = bsvz.spv.MerklePath;
const PathElement = std.meta.Elem(std.meta.Elem(@FieldType(MerklePath, "path")));

/// A node's CID: bitcoin-merkle over its hash.
pub fn nodeCid(hash: [32]u8) [37]u8 {
    return store_mod.hashCid(.merkle, hash);
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
    var cur = std.AutoArrayHashMap(u64, [32]u8).init(a);
    var dup = std.AutoHashMap(u64, void).init(a);
    for (p.path[0]) |e| try take(&cur, &dup, e);
    var level: usize = 0;
    while (level < height) : (level += 1) {
        var next = std.AutoArrayHashMap(u64, [32]u8).init(a);
        var next_dup = std.AutoHashMap(u64, void).init(a);
        if (level + 1 < height) for (p.path[level + 1]) |e| try take(&next, &next_dup, e);
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
            } else try next.put(e >> 1, n.hash);
        }
        cur = next;
        dup = next_dup;
    }
    const root = cur.get(0) orelse return error.BadProof;
    if (cur.count() != 1) return error.BadProof;
    return .{ .root = root, .nodes = nodes.items };
}

fn take(m: *std.AutoArrayHashMap(u64, [32]u8), dup: *std.AutoHashMap(u64, void), e: PathElement) !void {
    if (e.duplicate orelse false) {
        if (e.offset & 1 == 0) return error.BadProof; // only a right sibling repeats its left
        try dup.put(e.offset, {});
        return;
    }
    const h = e.hash orelse return error.BadProof;
    if (m.get(e.offset)) |had| if (!std.mem.eql(u8, &had, &h.bytes)) return error.ConflictingNode;
    try m.put(e.offset, h.bytes);
}

/// Put the nodes (hash-checked by the store; one already held is the same block).
pub fn putNodes(s: Store, nodes: []const Node) !void {
    for (nodes) |n| try s.putBlock(&nodeCid(n.hash), &n.bytes);
}

/// A node we hold (its 64 bytes), or null.
pub fn node(a: std.mem.Allocator, s: Store, hash: [32]u8) !?[64]u8 {
    const b = s.tryGet(a, &nodeCid(hash)) orelse return null;
    if (b.len != 64) return error.BadNode;
    return b[0..64].*;
}

const Step = struct { bit: u1, sibling: [32]u8, dup: bool };

/// The BUMP for `txid` in the block at `block_height` whose merkle root is
/// `root`, rebuilt from the nodes we hold: from the root, one node per level
/// (a child we hold is a node; the transaction is a leaf), each level's
/// sibling emitted; its offset is the path's left/right turns. Null when the
/// nodes we hold do not reach the transaction.
pub fn pathFor(a: std.mem.Allocator, s: Store, root: [32]u8, block_height: u32, txid: [32]u8) !?MerklePath {
    if (std.mem.eql(u8, &root, &txid)) {
        const level = try a.alloc(PathElement, 1);
        level[0] = .{ .offset = 0, .hash = .{ .bytes = txid }, .txid = true };
        const levels = try a.alloc([]PathElement, 1);
        levels[0] = level;
        return .{ .block_height = block_height, .path = levels };
    }
    var trail: std.ArrayList(Step) = .empty;
    if (!try find(a, s, root, txid, &trail)) return null;
    const h = trail.items.len;
    var offset: u64 = 0;
    for (trail.items) |st| offset = offset * 2 + st.bit;
    const levels = try a.alloc([]PathElement, h);
    for (levels, 0..) |*lv, i| {
        const st = trail.items[h - 1 - i];
        const sib_off = (offset >> @intCast(i)) ^ 1;
        const sib: PathElement = if (st.dup) .{ .offset = sib_off, .duplicate = true } else .{ .offset = sib_off, .hash = .{ .bytes = st.sibling } };
        if (i == 0) {
            const leaf: PathElement = .{ .offset = offset, .hash = .{ .bytes = txid }, .txid = true };
            lv.* = try a.dupe(PathElement, if (offset & 1 == 0) &.{ leaf, sib } else &.{ sib, leaf });
        } else lv.* = try a.dupe(PathElement, &.{sib});
    }
    return .{ .block_height = block_height, .path = levels };
}

/// Depth-first from `h` through the nodes we hold, to the leaf `txid`; the turns taken in `trail`.
fn find(a: std.mem.Allocator, s: Store, h: [32]u8, txid: [32]u8, trail: *std.ArrayList(Step)) !bool {
    if (trail.items.len >= 64) return false;
    const n = (try node(a, s, h)) orelse return false;
    const left: [32]u8 = n[0..32].*;
    const right: [32]u8 = n[32..64].*;
    const same = std.mem.eql(u8, &left, &right);
    for ([_]u1{ 0, 1 }) |bit| {
        if (bit == 1 and same) break; // the right is the left again: one subtree
        const child = if (bit == 0) left else right;
        try trail.append(a, .{ .bit = bit, .sibling = if (bit == 0) right else left, .dup = bit == 0 and same });
        if (std.mem.eql(u8, &child, &txid)) return true;
        if (try find(a, s, child, txid, trail)) return true;
        _ = trail.pop();
    }
    return false;
}
