//! The BEEF envelope and pointer record (shruggr/skein#121, #146): how a BEEF
//! that came into a skein is held. The kernel's door (skein
//! kernel-zig/src/door.zig, its decoder kernel-zig/src/beef.zig) decodes every
//! BEEF a package carries on a route whose filters name `kernel.beef`: each
//! transaction stored once as its `bitcoin-tx` block (CID = txid), each BUMP
//! as the raw block of its bytes (and the merkle nodes it reveals), every BUMP
//! checked against the headers in `chain/state`.
//!
//! The envelope is not BEEF (#146). Where the bytes were (an http body, a
//! field of a dag-cbor body) the door puts the envelope, a map beside the link
//! to the pointer record:
//!
//!   {form: "beef" | "atomic" | "outpoint" | "subject",   the pattern the bytes started with
//!                                           (BRC-62/96, BRC-95, BRC-158, BRC-233)
//!    beef: <pointer record CID>,
//!    subject?: <bitcoin-tx CID>,            an enveloped form's subject txid (absent for "beef":
//!                                           a bare BEEF's subject is its last transaction)
//!    vout?: int}                            Outpoint BEEF: the subject output
//!
//!   e.g. {form: "subject", beef: <the pointer record's CID>, subject: <the subject's bitcoin-tx CID>}
//!
//! A program gets the envelope: `ingest {beef: <envelope>}`, an overlay's
//! submit. The pointer record is the BEEF alone, so two envelopes over the
//! same BEEF share one record:
//!
//!   {kind: "beef",
//!    version: 1 | 2,                         the BEEF's
//!    txs: [<bitcoin-tx CID>, …],             every transaction, in wire order (a V2 txid-only one too)
//!    marks: [<int> | null | "txid", …],      per transaction: the BUMP index the wire names, none,
//!                                            or a V2 txid-only entry
//!    bumps: [{height, path: <raw CID>,       the BUMP exactly as received
//!             block: <bitcoin-block CID> | null,   the header it was checked against
//!             proves: [<tx index>, …]}]}     the transactions it proves
//!
//! `wireOf` is the encoder beside the kernel's decoder: the exact wire bytes
//! from the envelope, the record and the blocks they name (the door is
//! lossless: what a signature covered is reconstructible); `beefOf` the BEEF a
//! record stands for, no envelope. Lookups and gossip serialize with them;
//! `parsed` is the same bytes through `beef.parse`.
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

/// An envelope, read: its form, its pointer record's CID, an enveloped form's subject and vout.
pub const Envelope = struct {
    form: beef.Form,
    beef: []const u8,
    subject: ?[32]u8 = null,
    vout: ?u32 = null,
};

/// The envelope a value is (the door's map where the bytes were), or null: not one. An enveloped
/// form names its subject; only an Outpoint BEEF a vout.
pub fn envelopeOf(v: Value) ?Envelope {
    const form = std.meta.stringToEnum(beef.Form, v.getText("form") orelse return null) orelse return null;
    var e = Envelope{ .form = form, .beef = v.getCid("beef") orelse return null };
    if (form == .beef) return e;
    e.subject = store_mod.bitcoinHash(v.getCid("subject") orelse return null) orelse return null;
    if (form == .outpoint) e.vout = std.math.cast(u32, v.getUint("vout") orelse return null) orelse return null;
    return e;
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

/// The BEEF a pointer record (by CID) stands for, no envelope.
pub fn beefOf(a: std.mem.Allocator, s: Store, record: []const u8) ![]u8 {
    return encode(a, s, try s.getValue(a, record));
}

/// The wire bytes an envelope (the value where the bytes were) stands for: exactly the bytes the
/// door decoded — the envelope's prefix, then the BEEF its record stands for. error.NotARecord: not
/// an envelope, or a Subject BEEF over a V1 record.
pub fn wireOf(a: std.mem.Allocator, s: Store, envelope: Value) ![]u8 {
    const e = envelopeOf(envelope) orelse return error.NotARecord;
    const rec = try s.getValue(a, e.beef);
    if (e.form == .beef) return encode(a, s, rec);
    if (e.form == .subject and rec.getUint("version") != 2) return error.NotARecord;
    var out: std.ArrayList(u8) = .empty;
    try putU32(a, &out, switch (e.form) {
        .atomic => beef.ATOMIC,
        .outpoint => beef.OUTPOINT,
        .subject => beef.SUBJECT,
        .beef => unreachable,
    });
    try out.appendSlice(a, &e.subject.?);
    if (e.vout) |o| try putU32(a, &out, o);
    try out.appendSlice(a, try encode(a, s, rec));
    return out.items;
}

/// The BEEF an envelope stands for, parsed (beef.parse over wireOf): its form, subject and vout
/// the envelope's.
pub fn parsed(a: std.mem.Allocator, s: Store, envelope: Value) !beef.Beef {
    return beef.parse(a, try wireOf(a, s, envelope));
}

/// The BEEF a pointer record stands for, from the blocks it names (no envelope). error.NotARecord
/// for anything else; a block it names that the store lacks fails as the store's get does.
pub fn encode(a: std.mem.Allocator, s: Store, rec: Value) ![]u8 {
    if (!isRecord(rec)) return error.NotARecord;
    const version = rec.getUint("version") orelse return error.NotARecord;
    if (version != 1 and version != 2) return error.NotARecord;
    const txs = rec.getArray("txs") orelse return error.NotARecord;
    const marks = rec.getArray("marks") orelse return error.NotARecord;
    const bumps = rec.getArray("bumps") orelse return error.NotARecord;
    if (marks.len != txs.len) return error.NotARecord;
    var out: std.ArrayList(u8) = .empty;
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

/// The subject's txid (internal byte order): the envelope's, else (a bare BEEF) the record's last
/// transaction.
pub fn subjectOf(e: Envelope, rec: Value) ?[32]u8 {
    if (e.subject) |t| return t;
    const txs = rec.getArray("txs") orelse return null;
    if (txs.len == 0 or txs[txs.len - 1] != .cid) return null;
    return store_mod.bitcoinHash(txs[txs.len - 1].cid);
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
