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

/// A transaction a revealed path covers: its txid and its offset (leaf index) in the block.
pub const Covered = struct { txid: [32]u8, offset: u64 };

/// The transactions a path covers (0.21.0), from the structure `reveal` verified: one descent from
/// the root through the revealed nodes, each the double hash of its two children, down `height`
/// levels — every hash reached at the bottom is a level-0 leaf whose path to the root is those nodes,
/// so it computes to the root. A right child equal to its left is the duplicate (BRC-74), at any
/// level: not descended, not a transaction. A subtree whose node was not revealed (a leaf given with
/// no sibling, a part of the tree the path does not give) is not reached. Linear in the nodes.
pub fn covered(a: std.mem.Allocator, rev: Revealed, height: usize) ![]Covered {
    var out: std.ArrayList(Covered) = .empty;
    if (rev.nodes.len == 0) {
        if (height == 1) try out.append(a, .{ .txid = rev.root, .offset = 0 });
        return out.items;
    }
    var by_hash = std.AutoHashMap([32]u8, [64]u8).init(a);
    for (rev.nodes) |n| try by_hash.put(n.hash, n.bytes);
    const Item = struct { hash: [32]u8, depth: usize, offset: u64 };
    var stack: std.ArrayList(Item) = .empty;
    try stack.append(a, .{ .hash = rev.root, .depth = 0, .offset = 0 });
    while (stack.pop()) |it| {
        const bytes = by_hash.get(it.hash) orelse continue;
        const left: [32]u8 = bytes[0..32].*;
        const right: [32]u8 = bytes[32..64].*;
        const dup = std.mem.eql(u8, &left, &right);
        if (it.depth + 1 == height) {
            try out.append(a, .{ .txid = left, .offset = it.offset << 1 });
            if (!dup) try out.append(a, .{ .txid = right, .offset = (it.offset << 1) | 1 });
        } else {
            if (!dup) try stack.append(a, .{ .hash = right, .depth = it.depth + 1, .offset = (it.offset << 1) | 1 });
            try stack.append(a, .{ .hash = left, .depth = it.depth + 1, .offset = it.offset << 1 });
        }
    }
    return out.items;
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

/// A transaction to prove in a block: its txid and where it sits (`Position`, from `proofs`).
pub const Leaf = struct { txid: [32]u8, pos: Position };

/// ONE BUMP for several transactions of the block at `block_height` whose merkle root is `root`,
/// selected from the nodes we hold in one flow, no merges: the descent of `pathFor` for every leaf
/// at once, from the root, each node read once however many leaves pass under it, turning by the
/// offsets' bits. At each level the entries are every leaf's siblings (BRC-74: a right sibling equal
/// to the left is a duplicate) and, at the bottom, the leaves themselves (flagged txid), each offset
/// once, in offset order. An entry whose two children the level below also gives is left out (it is
/// computable): the rule `MerklePath.combine` applies, so the BUMP is the one `combine` makes of
/// the leaves' one-leaf paths. Null when a node on the way is not held, the leaves disagree on the
/// depth, or a descent does not end at its txid. A one-transaction block: the root is the txid.
pub fn pathsFor(a: std.mem.Allocator, s: Store, root: [32]u8, block_height: u32, leaves: []const Leaf) !?MerklePath {
    if (leaves.len == 0) return null;
    if (std.mem.eql(u8, &root, &leaves[0].txid)) {
        for (leaves[1..]) |l| if (!std.mem.eql(u8, &l.txid, &leaves[0].txid)) return null;
        return pathFor(a, s, root, block_height, leaves[0].txid, leaves[0].pos);
    }
    const h: usize = leaves[0].pos.depth;
    if (h == 0 or h > 64) return null;
    const sorted = try a.dupe(Leaf, leaves);
    std.mem.sort(Leaf, sorted, {}, struct {
        fn lt(_: void, x: Leaf, y: Leaf) bool {
            return x.pos.offset < y.pos.offset;
        }
    }.lt);
    // One entry per (txid, offset): the same leaf twice is one leaf; two txids at one offset is no tree.
    var n: usize = 0;
    for (sorted) |l| {
        if (l.pos.depth != h) return null;
        if (h < 64 and l.pos.offset >> @intCast(h) != 0) return null;
        if (n > 0 and sorted[n - 1].pos.offset == l.pos.offset) {
            if (!std.mem.eql(u8, &sorted[n - 1].txid, &l.txid)) return null;
            continue;
        }
        sorted[n] = l;
        n += 1;
    }
    const levels = try a.alloc(std.ArrayList(PathElement), h);
    for (levels) |*lv| lv.* = .empty;
    var d = Descent{ .a = a, .s = s, .h = h, .levels = levels };
    if (!try d.down(root, 0, sorted[0..n])) return null;
    // Leave out what the level below makes (combine's rule: both children given there).
    const out = try a.alloc([]PathElement, h);
    out[0] = levels[0].items;
    for (1..h) |i| {
        const below = levels[i - 1].items;
        var kept: std.ArrayList(PathElement) = .empty;
        for (levels[i].items) |e| if (!(gives(below, 2 * e.offset) and gives(below, 2 * e.offset + 1))) try kept.append(a, e);
        out[i] = kept.items;
    }
    return .{ .block_height = block_height, .path = out };
}

/// Whether a level (in offset order) gives an entry at `offset`.
fn gives(level: []const PathElement, offset: u64) bool {
    var lo: usize = 0;
    var hi: usize = level.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (level[mid].offset == offset) return true;
        if (level[mid].offset < offset) lo = mid + 1 else hi = mid;
    }
    return false;
}

const Descent = struct {
    a: std.mem.Allocator,
    s: Store,
    h: usize,
    /// Bottom level first; each appended in offset order (left subtree before right).
    levels: []std.ArrayList(PathElement),

    /// The node `cur` at `depth` below the root, over `leaves` (non-empty, in offset order, all
    /// under it): read once, split by the bit of this level, each side descended; the side with no
    /// leaf is the other side's sibling.
    fn down(d: *Descent, cur: [32]u8, depth: usize, leaves: []const Leaf) !bool {
        const level = d.h - 1 - depth; // the children's level, counted from the bottom
        const n = (try node(d.a, d.s, cur)) orelse return false;
        const left: [32]u8 = n[0..32].*;
        const right: [32]u8 = n[32..64].*;
        const same = std.mem.eql(u8, &left, &right);
        var split: usize = 0;
        while (split < leaves.len and (leaves[split].pos.offset >> @intCast(level)) & 1 == 0) split += 1;
        const lo = leaves[0..split];
        const hi = leaves[split..];
        if (hi.len > 0 and same) return false; // the duplicate right is no leaf of its own
        const child = (leaves[0].pos.offset >> @intCast(level)) & ~@as(u64, 1); // the left child's offset
        const lv = &d.levels[level];
        if (level == 0) {
            if (lo.len > 0) {
                if (!std.mem.eql(u8, &left, &lo[0].txid)) return false;
                try lv.append(d.a, .{ .offset = child, .hash = .{ .bytes = left }, .txid = true });
            } else try lv.append(d.a, .{ .offset = child, .hash = .{ .bytes = left } });
            if (hi.len > 0) {
                if (!std.mem.eql(u8, &right, &hi[0].txid)) return false;
                try lv.append(d.a, .{ .offset = child + 1, .hash = .{ .bytes = right }, .txid = true });
            } else if (same) {
                try lv.append(d.a, .{ .offset = child + 1, .duplicate = true });
            } else try lv.append(d.a, .{ .offset = child + 1, .hash = .{ .bytes = right } });
            return true;
        }
        // The left child is the sibling of the leaves under the right; the right child (or the
        // duplicate) is the sibling of the leaves under the left. Both appended here, in offset
        // order, before either side descends: the depth-first walk, left first, keeps every level
        // in offset order.
        if (hi.len > 0) try lv.append(d.a, .{ .offset = child, .hash = .{ .bytes = left } });
        if (lo.len > 0) {
            if (same) try lv.append(d.a, .{ .offset = child + 1, .duplicate = true }) else try lv.append(d.a, .{ .offset = child + 1, .hash = .{ .bytes = right } });
        }
        if (lo.len > 0 and !try d.down(left, depth + 1, lo)) return false;
        if (hi.len > 0 and !try d.down(right, depth + 1, hi)) return false;
        return true;
    }
};
