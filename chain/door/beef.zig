// BEEF at the door (#121): the kernel's own decoder and encoder for the
// `beef` filter (door.zig). A BEEF that arrives in a package is never logged
// as bytes: the door decodes it, stores each transaction once as its
// `bitcoin-tx` block (CID = txid), each BUMP as the raw block of its bytes
// and the merkle nodes it reveals, and replaces the bytes with a link to the
// envelope below, which links the pointer record. The encoder (`wire`, over
// `encode`) gives back the exact wire bytes from the envelope, the record and
// the blocks: what a signature covered stays reconstructible (the door's
// lossless rule). skein-sdk's `chain.record.wireOf` is the same encoder for
// programs.
//
// Recognized by the leading pattern (`patterns`, a table: a new envelope is
// one more row):
//
//   01 00 be ef                         BEEF V1 (BRC-62; 0xEFBE0001 little-endian)
//   02 00 be ef                         BEEF V2 (BRC-96)
//   01 01 01 01 ‖ txid(32) ‖ BEEF        Atomic BEEF (BRC-95): the subject transaction
//   16 a7 be ef ‖ txid(32) ‖ vout(4) ‖ BEEF   Outpoint BEEF (BRC-158): the subject output
//   57 09 be ef ‖ txid(32) ‖ BEEF V2     Subject BEEF (BRC-233): the subject transaction, the
//                                        others any transactions (not only its ancestors)
//
// The envelope is not BEEF (#146): it is what the door puts where the bytes
// were (in an http body, a libp2p message's body, a field of a dag-cbor body),
// a map beside the link to the pointer record:
//
//   {form: "beef" | "atomic" | "outpoint" | "subject",   the pattern the bytes started with
//    beef: <pointer record CID>,             the BEEF itself (below)
//    subject?: <bitcoin-tx CID>,             an enveloped form's subject txid (absent for "beef":
//                                            a bare BEEF's subject is its last transaction)
//    vout?: int}                             Outpoint BEEF: the subject output
//
//   e.g. {form: "subject", beef: <the pointer record's CID>, subject: <the subject's bitcoin-tx CID>}
//
// The pointer record (dag-cbor) is the BEEF alone, what its bytes carry: two
// envelopes over the same BEEF (Atomic and Subject, say) share one record.
//
//   {kind: "beef",
//    version: 1 | 2,                         the BEEF's
//    txs: [<bitcoin-tx CID>, …],             every transaction, in wire order (a V2 txid-only entry
//                                            too: its CID; its block is not carried)
//    marks: [<int> | null | "txid", …],      per transaction, what the wire says beside it: the BUMP
//                                            index it names (V1 hasBump, V2 format 1), none, or a V2
//                                            txid-only entry (format 2)
//    bumps: [{height: int,                   the block height the BUMP names
//             path: <raw CID>,               the BUMP (BRC-74) exactly as received
//             block: <bitcoin-block CID>,    the header in chain/state whose root it gives
//             proves: [<tx index>, …]}]}     the transactions it proves (marked with it, or flagged
//                                            as a client txid in its level 0): skein-sdk's
//                                            verifier's proven (door.zig)
//
// This parser is structure only (what block storage and the lossless
// envelope need): the door proves every BEEF with skein-sdk's verifier
// (chain/src/spv.zig) before anything is stored (door.zig).
const std = @import("std");
const cbor = @import("cbor");
const cidm = @import("cid");
const Value = cbor.Value;

pub const Error = error{ Malformed, OutOfMemory };

pub const Form = enum { beef, atomic, outpoint, subject };

/// A leading pattern: four magic bytes, then `head` bytes of subject before an inner BEEF (none for
/// a bare BEEF, whose magic is its version).
pub const Pattern = struct { magic: [4]u8, form: Form, head: usize };

pub const patterns = [_]Pattern{
    .{ .magic = .{ 0x01, 0x00, 0xbe, 0xef }, .form = .beef, .head = 0 },
    .{ .magic = .{ 0x02, 0x00, 0xbe, 0xef }, .form = .beef, .head = 0 },
    .{ .magic = .{ 0x01, 0x01, 0x01, 0x01 }, .form = .atomic, .head = 32 },
    .{ .magic = .{ 0x16, 0xa7, 0xbe, 0xef }, .form = .outpoint, .head = 36 },
    .{ .magic = .{ 0x57, 0x09, 0xbe, 0xef }, .form = .subject, .head = 32 },
};

/// An enveloped form's pattern.
fn patternOf(f: Form) Pattern {
    for (patterns) |p| if (p.form == f and p.head > 0) return p;
    unreachable;
}

const V1: u32 = 0xEFBE0001;
const V2: u32 = 0xEFBE0002;

fn innerMagic(m: []const u8) bool {
    return m.len >= 4 and (m[0] == 1 or m[0] == 2) and m[1] == 0 and m[2] == 0xbe and m[3] == 0xef;
}

/// The pattern `b` starts with, or null: not a BEEF. An envelope's pattern takes only when an inner
/// BEEF's magic follows its subject.
pub fn recognize(b: []const u8) ?Pattern {
    for (patterns) |p| {
        if (b.len < 4 + p.head + 4) continue;
        if (!std.mem.eql(u8, b[0..4], &p.magic)) continue;
        if (p.head > 0 and !innerMagic(b[4 + p.head ..])) continue;
        return p;
    }
    return null;
}

/// One leaf of a BUMP level (BRC-74): flags bit 0 = duplicate (no hash), bit 1 = a client txid.
pub const Leaf = struct { offset: u64, flags: u8, hash: ?[32]u8 };
pub const Bump = struct { height: u32, levels: []const []const Leaf, bytes: []const u8 };
pub const Mark = union(enum) { none, bump: usize, txid };
pub const Tx = struct { txid: [32]u8, raw: ?[]const u8, mark: Mark };

pub const Beef = struct {
    form: Form,
    version: u8,
    subject: [32]u8,
    vout: ?u32 = null,
    bumps: []const Bump,
    txs: []const Tx,

    pub fn indexOf(b: Beef, txid: [32]u8) ?usize {
        for (b.txs, 0..) |t, i| if (std.mem.eql(u8, &t.txid, &txid)) return i;
        return null;
    }
};

const Reader = struct {
    b: []const u8,
    i: usize = 0,

    fn take(r: *Reader, n: usize) Error![]const u8 {
        if (n > r.b.len - r.i) return error.Malformed;
        defer r.i += n;
        return r.b[r.i .. r.i + n];
    }
    fn byte(r: *Reader) Error!u8 {
        return (try r.take(1))[0];
    }
    fn u32le(r: *Reader) Error!u32 {
        return std.mem.readInt(u32, (try r.take(4))[0..4], .little);
    }
    fn varint(r: *Reader) Error!u64 {
        const f = try r.byte();
        return switch (f) {
            0xfd => std.mem.readInt(u16, (try r.take(2))[0..2], .little),
            0xfe => try r.u32le(),
            0xff => std.mem.readInt(u64, (try r.take(8))[0..8], .little),
            else => f,
        };
    }
    /// A count of items at least `min` bytes each: no more than what is left could hold.
    fn count(r: *Reader, min: usize) Error!usize {
        const n = try r.varint();
        if (n > (r.b.len - r.i) / min) return error.Malformed;
        return @intCast(n);
    }
    fn skipBytes(r: *Reader) Error!void {
        const n = try r.varint();
        if (n > r.b.len - r.i) return error.Malformed;
        _ = try r.take(@intCast(n));
    }
    /// One transaction's standard serialization (no segwit: BSV), as a slice.
    fn tx(r: *Reader) Error![]const u8 {
        const start = r.i;
        _ = try r.take(4);
        const ins = try r.count(41);
        for (0..ins) |_| {
            _ = try r.take(36);
            try r.skipBytes();
            _ = try r.take(4);
        }
        const outs = try r.count(9);
        for (0..outs) |_| {
            _ = try r.take(8);
            try r.skipBytes();
        }
        _ = try r.take(4);
        return r.b[start..r.i];
    }
    fn bump(r: *Reader, a: std.mem.Allocator) Error!Bump {
        const start = r.i;
        const h = try r.varint();
        if (h > std.math.maxInt(u32)) return error.Malformed;
        const depth = try r.byte();
        if (depth == 0 or depth > 64) return error.Malformed;
        const levels = try a.alloc([]const Leaf, depth);
        for (levels) |*lv| {
            const n = try r.count(2);
            const leaves = try a.alloc(Leaf, n);
            for (leaves) |*l| {
                const off = try r.varint();
                const flags = try r.byte();
                if (flags > 2) return error.Malformed;
                l.* = .{ .offset = off, .flags = flags, .hash = if (flags & 1 == 1) null else (try r.take(32))[0..32].* };
            }
            lv.* = leaves;
        }
        return .{ .height = @intCast(h), .levels = levels, .bytes = r.b[start..r.i] };
    }
};

/// One BUMP (BRC-74) from its bytes alone (a pointer record's `path` block).
pub fn bumpOf(a: std.mem.Allocator, bytes: []const u8) Error!Bump {
    var r = Reader{ .b = bytes };
    const p = try r.bump(a);
    if (r.i != bytes.len) return error.Malformed;
    return p;
}

pub fn txidOf(raw: []const u8) [32]u8 {
    return cidm.dblSha256(raw);
}

/// Decode a BEEF (any form of `patterns`): the transactions in wire order, the BUMPs with their
/// exact bytes. Structure only: no headers, no scripts (the door proves the BEEF with skein-sdk's
/// verifier, door.zig).
pub fn parse(a: std.mem.Allocator, bytes: []const u8) Error!Beef {
    const p = recognize(bytes) orelse return error.Malformed;
    var r = Reader{ .b = bytes, .i = if (p.head > 0) 4 else 0 };
    var subject: ?[32]u8 = null;
    var vout: ?u32 = null;
    if (p.head >= 32) subject = (try r.take(32))[0..32].*;
    if (p.head == 36) vout = try r.u32le();
    const version: u8 = switch (try r.u32le()) {
        V1 => 1,
        V2 => 2,
        else => return error.Malformed,
    };
    if (p.form == .subject and version != 2) return error.Malformed; // BRC-233: a BEEF V2 only
    const nb = try r.count(3);
    const bumps = try a.alloc(Bump, nb);
    for (bumps) |*b| b.* = try r.bump(a);
    const nt = try r.count(1);
    const txs = try a.alloc(Tx, nt);
    for (txs) |*t| {
        if (version == 1) {
            const raw = try r.tx();
            const has = try r.byte();
            t.* = .{ .txid = txidOf(raw), .raw = raw, .mark = .none };
            if (has == 1) {
                t.mark = .{ .bump = std.math.cast(usize, try r.varint()) orelse return error.Malformed };
            } else if (has != 0) return error.Malformed;
        } else switch (try r.byte()) {
            0 => {
                const raw = try r.tx();
                t.* = .{ .txid = txidOf(raw), .raw = raw, .mark = .none };
            },
            1 => {
                const idx = std.math.cast(usize, try r.varint()) orelse return error.Malformed;
                const raw = try r.tx();
                t.* = .{ .txid = txidOf(raw), .raw = raw, .mark = .{ .bump = idx } };
            },
            2 => t.* = .{ .txid = (try r.take(32))[0..32].*, .raw = null, .mark = .txid },
            else => return error.Malformed,
        }
        if (t.mark == .bump and t.mark.bump >= bumps.len) return error.Malformed;
    }
    if (r.i != bytes.len) return error.Malformed;
    for (txs, 0..) |t, i| for (txs[0..i]) |u| if (std.mem.eql(u8, &t.txid, &u.txid)) return error.Malformed;
    const b = Beef{ .form = p.form, .version = version, .subject = undefined, .vout = vout, .bumps = bumps, .txs = txs };
    var out = b;
    if (subject) |s| {
        if (b.indexOf(s) == null) return error.Malformed; // BRC-95/158/233: the subject is in the BEEF
        out.subject = s;
    } else {
        if (txs.len == 0) return error.Malformed;
        out.subject = txs[txs.len - 1].txid;
    }
    return out;
}

// ---------------------------------------------------------------- BUMPs: the nodes, the root

/// A node of a block's transaction tree: left ‖ right, its hash its CID's (bitcoin-tx, dbl-sha2-256).
pub const Node = struct { hash: [32]u8, bytes: [64]u8 };
pub const Revealed = struct { root: [32]u8, nodes: []const Node };

fn parentOf(left: [32]u8, right: [32]u8) Node {
    const bytes = left ++ right;
    return .{ .hash = cidm.dblSha256(&bytes), .bytes = bytes };
}

const Level = std.AutoArrayHashMapUnmanaged(u64, [32]u8);

fn takeLeaf(a: std.mem.Allocator, m: *Level, dup: *std.AutoHashMapUnmanaged(u64, void), l: Leaf) Error!void {
    if (l.flags & 1 == 1) {
        if (l.offset & 1 == 0) return error.Malformed; // only a right sibling repeats its left
        try dup.put(a, l.offset, {});
        return;
    }
    const h = l.hash.?;
    if (m.get(l.offset)) |had| if (!std.mem.eql(u8, &had, &h)) return error.Malformed;
    try m.put(a, l.offset, h);
}

/// The nodes a BUMP reveals and the root it gives (skein-sdk `chain.merkle.reveal`, the same
/// rule): at each level every pair of siblings it gives (or implies: a duplicate right is the left
/// again) makes a node, its hash the parent one level up; a parent it also gives with another hash
/// is a conflict. A one-transaction block (one level, one leaf) has no nodes: its root is the txid.
pub fn reveal(a: std.mem.Allocator, p: Bump) Error!Revealed {
    const height = p.levels.len;
    if (height == 1 and p.levels[0].len == 1) {
        const h = p.levels[0][0].hash orelse return error.Malformed;
        return .{ .root = h, .nodes = &.{} };
    }
    var nodes: std.ArrayList(Node) = .empty;
    var cur: Level = .empty;
    var dup: std.AutoHashMapUnmanaged(u64, void) = .empty;
    for (p.levels[0]) |l| try takeLeaf(a, &cur, &dup, l);
    var level: usize = 0;
    while (level < height) : (level += 1) {
        var next: Level = .empty;
        var next_dup: std.AutoHashMapUnmanaged(u64, void) = .empty;
        if (level + 1 < height) for (p.levels[level + 1]) |l| try takeLeaf(a, &next, &next_dup, l);
        const offsets = try a.dupe(u64, cur.keys());
        std.mem.sort(u64, offsets, {}, std.sort.asc(u64));
        for (offsets) |o| {
            if (o & 1 == 1 and cur.contains(o - 1)) continue; // the pair was made from its left
            const e = o & ~@as(u64, 1);
            const left = cur.get(e) orelse continue; // a right child alone: its sibling is not given
            const right = cur.get(e + 1) orelse if (dup.contains(e + 1)) left else continue;
            const n = parentOf(left, right);
            var seen = false;
            for (nodes.items) |m| seen = seen or std.mem.eql(u8, &m.hash, &n.hash);
            if (!seen) try nodes.append(a, n);
            if (next.get(e >> 1)) |given| {
                if (!std.mem.eql(u8, &given, &n.hash)) return error.Malformed;
            } else try next.put(a, e >> 1, n.hash);
        }
        cur = next;
        dup = next_dup;
    }
    if (cur.count() != 1) return error.Malformed;
    const root = cur.get(0) orelse return error.Malformed;
    return .{ .root = root, .nodes = nodes.items };
}

/// Whether a BUMP's level 0 holds `txid` (with `client`: flagged as a client txid).
pub fn holds(p: Bump, txid: [32]u8, client: bool) bool {
    for (p.levels[0]) |l| if (l.hash) |h| if (std.mem.eql(u8, &h, &txid)) return !client or l.flags & 2 == 2;
    return false;
}

/// The transactions BUMP `i` proves: those the wire marks with it (it must hold them), and the
/// unmarked ones it flags as client txids in its level 0.
pub fn proves(a: std.mem.Allocator, b: Beef, i: usize) Error![]usize {
    var out: std.ArrayList(usize) = .empty;
    for (b.txs, 0..) |t, k| switch (t.mark) {
        .bump => |j| if (j == i) {
            if (!holds(b.bumps[i], t.txid, false)) return error.Malformed;
            try out.append(a, k);
        },
        .none => if (t.raw != null and holds(b.bumps[i], t.txid, true)) try out.append(a, k),
        .txid => {},
    };
    return out.items;
}

// ---------------------------------------------------------------- CIDs, the record

pub fn txCid(a: std.mem.Allocator, txid: [32]u8) ![]u8 {
    return cidm.create(a, cidm.BITCOIN_TX, cidm.DBL_SHA2_256, &txid);
}

pub fn blockCid(a: std.mem.Allocator, hash: [32]u8) ![]u8 {
    return cidm.create(a, cidm.BITCOIN_BLOCK, cidm.DBL_SHA2_256, &hash);
}

/// Per BUMP, what the door found: the header whose merkle root it gives (null: none in chain/state),
/// and the transactions it proves — those skein-sdk's verifier found proven by it (door.zig); null:
/// the ones it holds as the wire marks them (`proves`, structure only: the encoder's tests).
pub const Checked = struct { block: ?[]const u8, proves: ?[]const usize = null };

/// The pointer record for a decoded BEEF (the header's shape): the BEEF alone, no envelope.
/// `checked` is per BUMP.
pub fn record(a: std.mem.Allocator, b: Beef, checked: []const Checked) !Value {
    const txs = try a.alloc(Value, b.txs.len);
    const marks = try a.alloc(Value, b.txs.len);
    for (b.txs, txs, marks) |t, *c, *m| {
        c.* = cbor.cidv(try txCid(a, t.txid));
        m.* = switch (t.mark) {
            .none => .null,
            .bump => |i| cbor.int(i),
            .txid => cbor.string("txid"),
        };
    }
    const bumps = try a.alloc(Value, b.bumps.len);
    for (b.bumps, bumps, checked, 0..) |p, *v, ck, i| {
        const ps = ck.proves orelse try proves(a, b, i);
        const pv = try a.alloc(Value, ps.len);
        for (ps, pv) |k, *x| x.* = cbor.int(k);
        var m = cbor.MapBuilder.init(a);
        try m.put("height", cbor.int(p.height));
        try m.put("path", cbor.cidv(try cidm.ofRaw(a, p.bytes)));
        try m.put("block", if (ck.block) |c| cbor.cidv(c) else .null);
        try m.put("proves", .{ .array = pv });
        v.* = m.value();
    }
    var m = cbor.MapBuilder.init(a);
    try m.put("kind", cbor.string("beef"));
    try m.put("version", cbor.int(b.version));
    try m.put("txs", .{ .array = txs });
    try m.put("marks", .{ .array = marks });
    try m.put("bumps", .{ .array = bumps });
    return m.value();
}

/// Whether a value is a pointer record's shape (kind "beef").
pub fn isRecord(v: ?Value) bool {
    const x = v orelse return false;
    return x == .map and std.mem.eql(u8, Value.str(x.get("kind")) orelse "", "beef");
}

/// The envelope the door puts where a BEEF's bytes were (the header's shape): its form, the
/// link to its pointer record (`pointer`), and an enveloped form's subject (and vout).
pub fn envelope(a: std.mem.Allocator, b: Beef, pointer: []const u8) !Value {
    var m = cbor.MapBuilder.init(a);
    try m.put("form", cbor.string(@tagName(b.form)));
    try m.put("beef", cbor.cidv(pointer));
    if (b.form != .beef) try m.put("subject", cbor.cidv(try txCid(a, b.subject)));
    if (b.vout) |o| try m.put("vout", cbor.int(o));
    return m.value();
}

/// An envelope's pointer record CID, when `v` is an envelope's shape (a map with a known `form`
/// and a `beef` link); else null.
pub fn pointerOf(v: Value) ?[]const u8 {
    if (v != .map) return null;
    _ = std.meta.stringToEnum(Form, Value.str(v.get("form")) orelse "") orelse return null;
    return Value.cidOf(v.get("beef"));
}

// ---------------------------------------------------------------- the encoder

/// A block by CID (the store, or a test's map); null when absent.
pub const Blocks = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, a: std.mem.Allocator, cid: []const u8) anyerror!?[]const u8,
};

fn digest32(c: []const u8) Error![32]u8 {
    const p = cidm.parts(c) catch return error.Malformed;
    if (p.digest.len != 32) return error.Malformed;
    return p.digest[0..32].*;
}

fn putVarint(a: std.mem.Allocator, out: *std.ArrayList(u8), v: u64) !void {
    if (v < 0xfd) {
        try out.append(a, @intCast(v));
    } else if (v <= 0xffff) {
        try out.append(a, 0xfd);
        try out.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u16, @intCast(v))));
    } else if (v <= 0xffff_ffff) {
        try out.append(a, 0xfe);
        try out.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(v))));
    } else {
        try out.append(a, 0xff);
        try out.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u64, v)));
    }
}

fn putU32(a: std.mem.Allocator, out: *std.ArrayList(u8), v: u32) !void {
    try out.appendSlice(a, &std.mem.toBytes(std.mem.nativeToLittle(u32, v)));
}

/// The wire bytes an envelope stands for, from it, its pointer record and the blocks they name:
/// exactly the bytes the door decoded (the lossless rule) — the envelope's prefix, then the BEEF.
/// error.Malformed: not an envelope, or a form its record cannot carry (Subject BEEF: V2 only).
pub fn wire(a: std.mem.Allocator, env: Value, rec: Value, blocks: Blocks) ![]u8 {
    const form = std.meta.stringToEnum(Form, Value.str(env.get("form")) orelse "") orelse return error.Malformed;
    if (form == .beef) return encode(a, rec, blocks);
    if (form == .subject and Value.intOf(rec.get("version")) != 2) return error.Malformed;
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, &patternOf(form).magic);
    try out.appendSlice(a, &(try digest32(Value.cidOf(env.get("subject")) orelse return error.Malformed)));
    if (form == .outpoint) try putU32(a, &out, std.math.cast(u32, Value.intOf(env.get("vout")) orelse return error.Malformed) orelse return error.Malformed);
    try out.appendSlice(a, try encode(a, rec, blocks));
    return out.items;
}

/// The BEEF a pointer record stands for (no envelope), from it and the blocks it names.
/// error.Malformed: not a pointer record; error.NotFound: a block it names is not held.
pub fn encode(a: std.mem.Allocator, rec: Value, blocks: Blocks) ![]u8 {
    if (!isRecord(rec)) return error.Malformed;
    const version = Value.intOf(rec.get("version")) orelse return error.Malformed;
    if (version != 1 and version != 2) return error.Malformed;
    const txs = (rec.get("txs") orelse return error.Malformed);
    const marks = (rec.get("marks") orelse return error.Malformed);
    const bumps = (rec.get("bumps") orelse return error.Malformed);
    if (txs != .array or marks != .array or bumps != .array or marks.array.len != txs.array.len) return error.Malformed;
    var out: std.ArrayList(u8) = .empty;
    try putU32(a, &out, if (version == 1) V1 else V2);
    try putVarint(a, &out, bumps.array.len);
    for (bumps.array) |b| {
        const path = Value.cidOf(b.get("path")) orelse return error.Malformed;
        try out.appendSlice(a, (try blocks.get(blocks.ctx, a, path)) orelse return error.NotFound);
    }
    try putVarint(a, &out, txs.array.len);
    for (txs.array, marks.array) |t, m| {
        const c = Value.cidOf(t) orelse return error.Malformed;
        if (Value.str(m)) |s| {
            if (version != 2 or !std.mem.eql(u8, s, "txid")) return error.Malformed;
            try out.append(a, 2);
            try out.appendSlice(a, &(try digest32(c)));
            continue;
        }
        const raw = (try blocks.get(blocks.ctx, a, c)) orelse return error.NotFound;
        const idx: ?i128 = if (m == .null) null else Value.intOf(m) orelse return error.Malformed;
        if (version == 1) {
            try out.appendSlice(a, raw);
            if (idx) |i| {
                try out.append(a, 1);
                try putVarint(a, &out, @intCast(i));
            } else try out.append(a, 0);
        } else if (idx) |i| {
            try out.append(a, 1);
            try putVarint(a, &out, @intCast(i));
            try out.appendSlice(a, raw);
        } else {
            try out.append(a, 0);
            try out.appendSlice(a, raw);
        }
    }
    return out.items;
}

// ---------------------------------------------------------------- tests

pub const testing = struct {
    /// A map of blocks for the encoder (tests).
    pub const Map = struct {
        m: std.StringHashMapUnmanaged([]const u8) = .empty,
        fn get(ctx: *anyopaque, _: std.mem.Allocator, c: []const u8) anyerror!?[]const u8 {
            const self: *Map = @ptrCast(@alignCast(ctx));
            return self.m.get(c);
        }
        pub fn blocks(self: *Map) Blocks {
            return .{ .ctx = self, .get = get };
        }
        pub fn put(self: *Map, a: std.mem.Allocator, c: []const u8, b: []const u8) !void {
            try self.m.put(a, c, b);
        }
    };

    /// Hold every block `b`'s record names (what the door stores).
    pub fn hold(a: std.mem.Allocator, m: *Map, b: Beef) !void {
        for (b.txs) |t| if (t.raw) |r| try m.put(a, try txCid(a, t.txid), r);
        for (b.bumps) |p| try m.put(a, try cidm.ofRaw(a, p.bytes), p.bytes);
    }
};

fn unhex(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

/// A small fixture: two transactions (a parent and a child spending it) and one BUMP proving the
/// parent in a two-transaction block, built here so each form's bytes can be written both ways.
const Fixture = struct {
    parent: []const u8,
    child: []const u8,
    bump: []const u8,
    root: [32]u8,
};

fn fixture(a: std.mem.Allocator) !Fixture {
    // Block 170's spend as the parent (a real transaction), and a child spending its output 0.
    const parent = try unhex(a, "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000");
    const ptxid = txidOf(parent);
    var child: std.ArrayList(u8) = .empty;
    try child.appendSlice(a, &.{ 1, 0, 0, 0, 1 });
    try child.appendSlice(a, &ptxid);
    try child.appendSlice(a, &.{ 0, 0, 0, 0, 1, 0x51, 0xff, 0xff, 0xff, 0xff, 1 });
    try child.appendSlice(a, &.{ 0xe8, 3, 0, 0, 0, 0, 0, 0, 1, 0x51, 0, 0, 0, 0 });
    // Block 170's coinbase as the sibling: the BUMP at height 170, depth 1, the parent at offset 1.
    var sib: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sib, "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082");
    std.mem.reverse(u8, &sib);
    var bump: std.ArrayList(u8) = .empty;
    try bump.appendSlice(a, &.{ 0xaa, 1, 2, 0, 0 }); // height 170, depth 1, two leaves: offset 0 (a hash)
    try bump.appendSlice(a, &sib);
    try bump.appendSlice(a, &.{ 1, 2 }); // offset 1, a client txid
    try bump.appendSlice(a, &ptxid);
    return .{ .parent = parent, .child = child.items, .bump = bump.items, .root = parentOf(sib, ptxid).hash };
}

fn v1Of(a: std.mem.Allocator, f: Fixture) ![]u8 {
    var o: std.ArrayList(u8) = .empty;
    try o.appendSlice(a, &.{ 1, 0, 0xbe, 0xef, 1 });
    try o.appendSlice(a, f.bump);
    try o.append(a, 2);
    try o.appendSlice(a, f.parent);
    try o.appendSlice(a, &.{ 1, 0 });
    try o.appendSlice(a, f.child);
    try o.append(a, 0);
    return o.items;
}

fn v2Of(a: std.mem.Allocator, f: Fixture, txid_only_parent: bool) ![]u8 {
    var o: std.ArrayList(u8) = .empty;
    try o.appendSlice(a, &.{ 2, 0, 0xbe, 0xef, 1 });
    try o.appendSlice(a, f.bump);
    try o.append(a, 2);
    if (txid_only_parent) {
        try o.append(a, 2);
        try o.appendSlice(a, &txidOf(f.parent));
    } else {
        try o.appendSlice(a, &.{ 1, 0 });
        try o.appendSlice(a, f.parent);
    }
    try o.append(a, 0);
    try o.appendSlice(a, f.child);
    return o.items;
}

test "beef: the pattern table (V1, V2, Atomic, Outpoint; an envelope needs an inner BEEF)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqual(Form.beef, recognize(&.{ 1, 0, 0xbe, 0xef, 0, 0, 0, 0 }).?.form);
    try std.testing.expectEqual(Form.beef, recognize(&.{ 2, 0, 0xbe, 0xef, 0, 0, 0, 0 }).?.form);
    try std.testing.expect(recognize(&.{ 3, 0, 0xbe, 0xef, 0, 0, 0, 0 }) == null);
    try std.testing.expect(recognize(&.{ 1, 0, 0xbe }) == null);
    try std.testing.expect(recognize("{\"json\": true}") == null);
    const atomic = try std.mem.concat(a, u8, &.{ &.{ 1, 1, 1, 1 }, &([_]u8{7} ** 32), &.{ 2, 0, 0xbe, 0xef } });
    try std.testing.expectEqual(Form.atomic, recognize(atomic).?.form);
    // 01010101 not followed by a BEEF after the txid: not an Atomic BEEF.
    atomic[36] = 9;
    try std.testing.expect(recognize(atomic) == null);
    const outpoint = try std.mem.concat(a, u8, &.{ &.{ 0x16, 0xa7, 0xbe, 0xef }, &([_]u8{7} ** 32), &.{ 5, 0, 0, 0 }, &.{ 1, 0, 0xbe, 0xef } });
    try std.testing.expectEqual(Form.outpoint, recognize(outpoint).?.form);
    try std.testing.expectEqual(@as(usize, 36), recognize(outpoint).?.head);
    // BRC-233: 57 09 be ef on the wire (0xEFBE0957 little-endian), a txid, a BEEF.
    const subject = try std.mem.concat(a, u8, &.{ &.{ 0x57, 0x09, 0xbe, 0xef }, &([_]u8{7} ** 32), &.{ 2, 0, 0xbe, 0xef } });
    try std.testing.expectEqual(Form.subject, recognize(subject).?.form);
    try std.testing.expectEqual(@as(usize, 32), recognize(subject).?.head);
}

test "beef: every form decodes and re-encodes to the same bytes (V1, V2, V2 txid-only, Atomic, Outpoint, Subject)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fixture(a);
    const v1 = try v1Of(a, f);
    const v2 = try v2Of(a, f, false);
    const v2t = try v2Of(a, f, true);
    const ctxid = txidOf(f.child);
    const atomic = try std.mem.concat(a, u8, &.{ &.{ 1, 1, 1, 1 }, &ctxid, v2 });
    const outpoint = try std.mem.concat(a, u8, &.{ &.{ 0x16, 0xa7, 0xbe, 0xef }, &ctxid, &.{ 0, 0, 0, 0 }, v1 });
    const subject = try std.mem.concat(a, u8, &.{ &.{ 0x57, 0x09, 0xbe, 0xef }, &ctxid, v2 });
    for ([_][]const u8{ v1, v2, v2t, atomic, outpoint, subject }) |bytes| {
        const b = try parse(a, bytes);
        try std.testing.expectEqualSlices(u8, &ctxid, &b.subject);
        try std.testing.expectEqual(@as(usize, 2), b.txs.len);
        var m = testing.Map{};
        try testing.hold(a, &m, b);
        const rec = try record(a, b, &.{.{ .block = null }});
        const blk = try cbor.block(a, rec);
        // Through dag-cbor, as the log holds them: the envelope in the package, the record a block.
        const env = try cbor.decode(a, try cbor.encode(a, try envelope(a, b, blk.cid)));
        try std.testing.expectEqualSlices(u8, blk.cid, pointerOf(env).?);
        const back = try cbor.decode(a, blk.bytes);
        try std.testing.expectEqualSlices(u8, bytes, try wire(a, env, back, m.blocks()));
        // The record is the BEEF alone: no envelope in it.
        try std.testing.expect(back.get("form") == null and back.get("subject") == null and back.get("vout") == null);
    }
    // Two envelopes over the same BEEF (Atomic and Subject over v2): one record.
    const ra = try cbor.block(a, try record(a, try parse(a, atomic), &.{.{ .block = null }}));
    const rs = try cbor.block(a, try record(a, try parse(a, subject), &.{.{ .block = null }}));
    const rb = try cbor.block(a, try record(a, try parse(a, v2), &.{.{ .block = null }}));
    try std.testing.expectEqualSlices(u8, ra.cid, rs.cid);
    try std.testing.expectEqualSlices(u8, rb.cid, rs.cid);

    const o = try parse(a, outpoint);
    try std.testing.expectEqual(Form.outpoint, o.form);
    try std.testing.expectEqual(@as(?u32, 0), o.vout);
    // The txid-only parent: marked, its block not carried, and proven by nothing.
    const t = try parse(a, v2t);
    try std.testing.expect(t.txs[0].mark == .txid and t.txs[0].raw == null);
    try std.testing.expectEqual(@as(usize, 0), (try proves(a, t, 0)).len);
    // Trailing bytes, a truncated BEEF, a duplicate transaction, a BUMP index out of range: malformed.
    try std.testing.expectError(error.Malformed, parse(a, try std.mem.concat(a, u8, &.{ v1, &.{0} })));
    try std.testing.expectError(error.Malformed, parse(a, v1[0 .. v1.len - 1]));
    const bad_idx = try a.dupe(u8, v2);
    bad_idx[5 + f.bump.len + 2] = 3; // the parent's BUMP index
    try std.testing.expectError(error.Malformed, parse(a, bad_idx));
}

test "beef: the BUMP check — the root it gives, the nodes it reveals, what it proves" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fixture(a);
    const b = try parse(a, try v1Of(a, f));
    try std.testing.expectEqual(@as(u32, 170), b.bumps[0].height);
    const rev = try reveal(a, b.bumps[0]);
    // Block 170's merkle root (display 7dac2c56…cb4c10ff): the header's.
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff");
    std.mem.reverse(u8, &want);
    try std.testing.expectEqualSlices(u8, &want, &rev.root);
    try std.testing.expectEqualSlices(u8, &f.root, &rev.root);
    try std.testing.expectEqual(@as(usize, 1), rev.nodes.len);
    try std.testing.expectEqualSlices(u8, &rev.root, &rev.nodes[0].hash);
    // It proves the parent (marked with it), not the child.
    try std.testing.expectEqualSlices(usize, &.{0}, try proves(a, b, 0));
    // A BUMP whose sibling hash is changed gives another root: the door refuses it against the header.
    const bad = try a.dupe(u8, try v1Of(a, f));
    bad[5 + 5] ^= 0xff;
    const bb = try parse(a, bad);
    try std.testing.expect(!std.mem.eql(u8, &want, &(try reveal(a, bb.bumps[0])).root));
    // A marked transaction the BUMP does not hold: malformed.
    var other = b;
    var txs = try a.dupe(Tx, b.txs);
    txs[1].mark = .{ .bump = 0 };
    other.txs = txs;
    try std.testing.expectError(error.Malformed, proves(a, other, 0));
}

test "beef: Subject BEEF (BRC-233) — any transactions, the subject present, a BEEF V2 only" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try fixture(a);
    const ptxid = txidOf(f.parent);
    const ctxid = txidOf(f.child);
    // The subject is the parent, not the last transaction, and the child is no ancestor of it: allowed.
    const v2 = try v2Of(a, f, false);
    const s = try std.mem.concat(a, u8, &.{ &.{ 0x57, 0x09, 0xbe, 0xef }, &ptxid, v2 });
    const b = try parse(a, s);
    try std.testing.expectEqual(Form.subject, b.form);
    try std.testing.expectEqualSlices(u8, &ptxid, &b.subject);
    var m = testing.Map{};
    try testing.hold(a, &m, b);
    const rec = try record(a, b, &.{.{ .block = null }});
    const blk = try cbor.block(a, rec);
    const env = try envelope(a, b, blk.cid);
    try std.testing.expectEqualStrings("subject", Value.str(env.get("form")).?);
    try std.testing.expectEqualSlices(u8, try txCid(a, ptxid), Value.cidOf(env.get("subject")).?);
    try std.testing.expectEqualSlices(u8, s, try wire(a, env, rec, m.blocks()));
    // The subject not in the BEEF: malformed.
    var other = ptxid;
    other[0] ^= 1;
    try std.testing.expectError(error.Malformed, parse(a, try std.mem.concat(a, u8, &.{ &.{ 0x57, 0x09, 0xbe, 0xef }, &other, v2 })));
    // A BEEF V1 inside: malformed (recognized by its pattern, refused by the parse).
    const in_v1 = try std.mem.concat(a, u8, &.{ &.{ 0x57, 0x09, 0xbe, 0xef }, &ctxid, try v1Of(a, f) });
    try std.testing.expect(recognize(in_v1) != null);
    try std.testing.expectError(error.Malformed, parse(a, in_v1));
    // An envelope saying "subject" over a V1 record: the encoder refuses it.
    const r1 = try record(a, try parse(a, try v1Of(a, f)), &.{.{ .block = null }});
    try std.testing.expectError(error.Malformed, wire(a, env, r1, m.blocks()));
}
