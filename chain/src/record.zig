//! The BEEF pointer record (shruggr/skein#121): how a BEEF that came into a
//! skein is held. The kernel's door (skein kernel-zig/src/door.zig, its
//! decoder kernel-zig/src/beef.zig) decodes every BEEF a package carries on a
//! row whose `filter` is `beef`: each transaction stored once as its
//! `bitcoin-tx` block (CID = txid), each BUMP as the raw block of its bytes
//! (and the merkle nodes it reveals), every BUMP checked against the headers
//! in `chain/state` — and puts this record where the bytes were. A program
//! gets the record's CID: `ingest {beef: <cid>}`, an overlay's submit.
//!
//!   {kind: "beef",
//!    form: "beef" | "atomic" | "outpoint",   the envelope (BRC-62/96, BRC-95, BRC-158)
//!    version: 1 | 2,                         the inner BEEF's
//!    subject: <bitcoin-tx CID>,              the Atomic/Outpoint BEEF's txid, else the last transaction
//!    vout?: int,                             Outpoint BEEF: the subject output
//!    txs: [<bitcoin-tx CID>, …],             every transaction, in wire order (a V2 txid-only one too)
//!    marks: [<int> | null | "txid", …],      per transaction: the BUMP index the wire names, none,
//!                                            or a V2 txid-only entry
//!    bumps: [{height, path: <raw CID>,       the BUMP exactly as received
//!             block: <bitcoin-block CID> | null,   the header it was checked against
//!             proves: [<tx index>, …]}]}     the transactions it proves
//!
//! `beefOf` is the encoder beside the kernel's decoder: the exact wire bytes
//! from the record and the blocks it names (the door is lossless: what a
//! signature covered is reconstructible). Lookups and gossip serialize with
//! it; `parsed` is the same bytes through `beef.parse`.
const std = @import("std");
const cbor = @import("cbor.zig");
const store_mod = @import("store.zig");
const beef = @import("beef.zig");

const Store = store_mod.Store;
const Value = cbor.Value;

pub const Error = error{ NotARecord, OutOfMemory };

/// Whether a value is a pointer record (kind "beef").
pub fn isRecord(v: Value) bool {
    return std.mem.eql(u8, v.getText("kind") orelse "", "beef");
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

/// The wire bytes a pointer record (by CID) stands for.
pub fn beefOf(a: std.mem.Allocator, s: Store, record: []const u8) ![]u8 {
    return encode(a, s, try s.getValue(a, record));
}

/// The BEEF a pointer record stands for, parsed (beef.parse over beefOf).
pub fn parsed(a: std.mem.Allocator, s: Store, record: []const u8) !beef.Beef {
    return beef.parse(a, try beefOf(a, s, record));
}

/// The wire bytes a pointer record stands for, from the blocks it names: exactly the bytes the
/// door decoded. error.NotARecord for anything else; a block it names that the store lacks fails
/// as the store's get does.
pub fn encode(a: std.mem.Allocator, s: Store, rec: Value) ![]u8 {
    if (!isRecord(rec)) return error.NotARecord;
    const form = rec.getText("form") orelse return error.NotARecord;
    const version = rec.getUint("version") orelse return error.NotARecord;
    if (version != 1 and version != 2) return error.NotARecord;
    const txs = rec.getArray("txs") orelse return error.NotARecord;
    const marks = rec.getArray("marks") orelse return error.NotARecord;
    const bumps = rec.getArray("bumps") orelse return error.NotARecord;
    if (marks.len != txs.len) return error.NotARecord;
    var out: std.ArrayList(u8) = .empty;
    const atomic = std.mem.eql(u8, form, "atomic");
    const outpoint = std.mem.eql(u8, form, "outpoint");
    if (atomic or outpoint) {
        try putU32(a, &out, if (atomic) beef.ATOMIC else beef.OUTPOINT);
        try out.appendSlice(a, &(store_mod.bitcoinHash(rec.getCid("subject") orelse return error.NotARecord) orelse return error.NotARecord));
        if (outpoint) try putU32(a, &out, std.math.cast(u32, rec.getUint("vout") orelse return error.NotARecord) orelse return error.NotARecord);
    } else if (!std.mem.eql(u8, form, "beef")) return error.NotARecord;
    try putU32(a, &out, if (version == 1) beef.V1 else beef.V2);
    try putVarint(a, &out, bumps.len);
    for (bumps) |b| try out.appendSlice(a, try s.get(a, b.getCid("path") orelse return error.NotARecord));
    try putVarint(a, &out, txs.len);
    for (txs, marks) |t, m| {
        if (t != .cid) return error.NotARecord;
        if (m == .text) {
            if (version != 2 or !std.mem.eql(u8, m.text, "txid")) return error.NotARecord;
            try out.append(a, 2);
            try out.appendSlice(a, &(store_mod.bitcoinHash(t.cid) orelse return error.NotARecord));
            continue;
        }
        const raw = try s.get(a, t.cid);
        const idx: ?u64 = switch (m) {
            .null => null,
            .uint => |i| i,
            else => return error.NotARecord,
        };
        if (version == 1) {
            try out.appendSlice(a, raw);
            if (idx) |i| {
                try out.append(a, 1);
                try putVarint(a, &out, i);
            } else try out.append(a, 0);
        } else if (idx) |i| {
            try out.append(a, 1);
            try putVarint(a, &out, i);
            try out.appendSlice(a, raw);
        } else {
            try out.append(a, 0);
            try out.appendSlice(a, raw);
        }
    }
    return out.items;
}

/// The subject's txid (internal byte order).
pub fn subjectOf(rec: Value) ?[32]u8 {
    return store_mod.bitcoinHash(rec.getCid("subject") orelse return null);
}

/// Per transaction (the record's order), the index of the BUMP that proves it (the door checked
/// it against chain/state's headers), or null: it entered unproven.
pub fn provenBy(a: std.mem.Allocator, rec: Value) ![]?usize {
    const txs = rec.getArray("txs") orelse return error.NotARecord;
    const out = try a.alloc(?usize, txs.len);
    @memset(out, null);
    for (rec.getArray("bumps") orelse &.{}, 0..) |b, i| for (b.getArray("proves") orelse &.{}) |k| {
        if (k != .uint or k.uint >= txs.len) return error.NotARecord;
        out[@intCast(k.uint)] = i;
    };
    return out;
}
