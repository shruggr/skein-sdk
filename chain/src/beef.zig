//! BEEF (BRC-62 V1, BRC-96 V2, BRC-95 Atomic, BRC-158 Outpoint, BRC-233 Subject): parse and
//! serialize, keeping
//! the transactions in the order they were written. bsvz's own Beef keeps
//! them in a hash map and serializes in txid order, which breaks BRC-96's
//! parents-first rule; only its MerklePath and Transaction parsers are used
//! here. All memory comes from the caller's arena.
const std = @import("std");
const bsvz = @import("bsvz");

const MerklePath = bsvz.spv.MerklePath;
const Transaction = bsvz.transaction.Transaction;
const VarInt = bsvz.primitives.varint.VarInt;

pub const V1: u32 = 0xEFBE0001;
pub const V2: u32 = 0xEFBE0002;
pub const ATOMIC: u32 = 0x01010101;
/// BRC-158 (Outpoint BEEF): 16 a7 be ef, then the subject txid and vout (u32 LE), then a BEEF.
pub const OUTPOINT: u32 = 0xEFBEA716;
/// BRC-233 (Subject BEEF): 57 09 be ef, then the subject txid, then a BEEF V2; the subject must be
/// in it, the other transactions any (not only the subject's ancestors).
pub const SUBJECT: u32 = 0xEFBE0957;

/// The envelope a BEEF came in (shruggr/skein#146): bare, Atomic, Outpoint or Subject.
pub const Form = enum { beef, atomic, outpoint, subject };

pub const Error = error{ InvalidBeef, OutOfMemory };

pub const Format = enum(u8) { raw = 0, raw_with_bump = 1, txid_only = 2 };

pub const Entry = struct {
    /// Internal byte order.
    txid: [32]u8,
    format: Format,
    bump: ?usize = null,
    /// The standard serialization (null for txid_only).
    raw: ?[]const u8 = null,
    tx: ?Transaction = null,
};

pub const Beef = struct {
    version: u32,
    /// BRC-95: the txid an Atomic BEEF names (BRC-158: an Outpoint BEEF's, with `vout`; BRC-233: a
    /// Subject BEEF's, with `form` .subject).
    atomic: ?[32]u8 = null,
    /// The envelope as parsed. Only .subject decides anything (`formOf`): the other forms follow
    /// `atomic` and `vout`, so a Beef built or edited by hand needs none.
    form: ?Form = null,
    /// BRC-158: the subject output of an Outpoint BEEF (`atomic` its txid).
    vout: ?u32 = null,
    bumps: []MerklePath,
    entries: []Entry,

    /// The envelope: bare with no `atomic`; Outpoint with a `vout`; Subject when `form` says so;
    /// else Atomic.
    pub fn formOf(self: Beef) Form {
        if (self.atomic == null) return .beef;
        if (self.vout != null) return .outpoint;
        return if (self.form == .subject) .subject else .atomic;
    }

    /// The transaction the BEEF is about: an enveloped form's (Atomic, Outpoint, Subject), else the
    /// last one.
    pub fn subject(self: Beef) ?[32]u8 {
        if (self.atomic) |a| return a;
        if (self.entries.len == 0) return null;
        return self.entries[self.entries.len - 1].txid;
    }

    pub fn find(self: Beef, txid: [32]u8) ?*const Entry {
        for (self.entries) |*e| if (std.mem.eql(u8, &e.txid, &txid)) return e;
        return null;
    }

    pub fn indexOf(self: Beef, txid: [32]u8) ?usize {
        for (self.entries, 0..) |e, i| if (std.mem.eql(u8, &e.txid, &txid)) return i;
        return null;
    }
};

pub fn txidOf(raw: []const u8) [32]u8 {
    return bsvz.crypto.hash.hash256(raw).bytes;
}

fn readU32(b: []const u8, pos: *usize) Error!u32 {
    if (b.len < pos.* + 4) return error.InvalidBeef;
    defer pos.* += 4;
    return std.mem.readInt(u32, b[pos.*..][0..4], .little);
}

fn readVarInt(b: []const u8, pos: *usize) Error!u64 {
    if (pos.* >= b.len) return error.InvalidBeef;
    const v = VarInt.parse(b[pos.*..]) catch return error.InvalidBeef;
    pos.* += v.len;
    return v.value;
}

fn readTx(arena: std.mem.Allocator, b: []const u8, pos: *usize) Error!struct { raw: []const u8, tx: Transaction, txid: [32]u8 } {
    const start = pos.*;
    const tx = Transaction.parseFromCursor(arena, b, pos) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidBeef,
    };
    const raw = b[start..pos.*];
    // Extended-format bytes are not a BEEF transaction: the txid is of the standard form.
    const std_bytes = tx.serialize(arena) catch return error.InvalidBeef;
    if (!std.mem.eql(u8, std_bytes, raw)) return error.InvalidBeef;
    return .{ .raw = raw, .tx = tx, .txid = txidOf(raw) };
}

/// How many times `parse` ran, in a test build (#50: a submit parses its BEEF
/// exactly once; programs/overlay's tests read it). Always 0 otherwise.
pub var parses: usize = 0;

pub fn parse(arena: std.mem.Allocator, bytes: []const u8) Error!Beef {
    if (@import("builtin").is_test) parses += 1;
    var pos: usize = 0;
    var atomic: ?[32]u8 = null;
    var vout: ?u32 = null;
    var form: Form = .beef;
    var version = try readU32(bytes, &pos);
    if (version == ATOMIC or version == SUBJECT) {
        if (bytes.len < 36) return error.InvalidBeef;
        form = if (version == ATOMIC) .atomic else .subject;
        atomic = bytes[4..36].*;
        pos = 36;
        version = try readU32(bytes, &pos);
        if (form == .subject and version != V2) return error.InvalidBeef; // BRC-233: a BEEF V2 only
    } else if (version == OUTPOINT) {
        form = .outpoint;
        if (bytes.len < 40) return error.InvalidBeef;
        atomic = bytes[4..36].*;
        pos = 36;
        vout = try readU32(bytes, &pos);
        version = try readU32(bytes, &pos);
    }
    if (version != V1 and version != V2) return error.InvalidBeef;

    const nbumps = try readVarInt(bytes, &pos);
    if (nbumps > bytes.len) return error.InvalidBeef;
    const bumps = try arena.alloc(MerklePath, @intCast(nbumps));
    for (bumps) |*p| p.* = MerklePath.parseFromCursor(arena, bytes, &pos) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidBeef,
    };

    const ntx = try readVarInt(bytes, &pos);
    if (ntx > bytes.len) return error.InvalidBeef;
    const entries = try arena.alloc(Entry, @intCast(ntx));
    for (entries) |*e| {
        if (version == V1) {
            const t = try readTx(arena, bytes, &pos);
            if (pos >= bytes.len) return error.InvalidBeef;
            const has_bump = bytes[pos];
            pos += 1;
            e.* = .{ .txid = t.txid, .format = .raw, .raw = t.raw, .tx = t.tx };
            if (has_bump == 1) {
                e.format = .raw_with_bump;
                e.bump = std.math.cast(usize, try readVarInt(bytes, &pos)) orelse return error.InvalidBeef;
            } else if (has_bump != 0) return error.InvalidBeef;
        } else {
            if (pos >= bytes.len) return error.InvalidBeef;
            const fmt = std.enums.fromInt(Format, bytes[pos]) orelse return error.InvalidBeef;
            pos += 1;
            switch (fmt) {
                .txid_only => {
                    if (bytes.len < pos + 32) return error.InvalidBeef;
                    e.* = .{ .txid = bytes[pos..][0..32].*, .format = .txid_only };
                    pos += 32;
                },
                .raw_with_bump => {
                    const idx = std.math.cast(usize, try readVarInt(bytes, &pos)) orelse return error.InvalidBeef;
                    const t = try readTx(arena, bytes, &pos);
                    e.* = .{ .txid = t.txid, .format = .raw_with_bump, .bump = idx, .raw = t.raw, .tx = t.tx };
                },
                .raw => {
                    const t = try readTx(arena, bytes, &pos);
                    e.* = .{ .txid = t.txid, .format = .raw, .raw = t.raw, .tx = t.tx };
                },
            }
        }
        if (e.bump) |i| if (i >= bumps.len) return error.InvalidBeef;
    }
    if (pos != bytes.len) return error.InvalidBeef;
    for (entries, 0..) |e, i| for (entries[0..i]) |prev| if (std.mem.eql(u8, &e.txid, &prev.txid)) return error.InvalidBeef;
    if (atomic) |a| {
        var found = false;
        for (entries) |e| found = found or std.mem.eql(u8, &e.txid, &a);
        if (!found) return error.InvalidBeef;
    }
    return .{ .version = version, .atomic = atomic, .form = form, .vout = vout, .bumps = bumps, .entries = entries };
}

fn appendVarInt(arena: std.mem.Allocator, out: *std.ArrayList(u8), v: u64) Error!void {
    var buf: [9]u8 = undefined;
    const n = VarInt.encodeInto(&buf, v) catch return error.InvalidBeef;
    try out.appendSlice(arena, buf[0..n]);
}

/// Serialize in entry order (which must already be parents-first; `parse`
/// keeps the writer's order, `build.order` produces one).
pub fn serialize(arena: std.mem.Allocator, b: Beef) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    const form = b.formOf();
    if (form != .beef) {
        const a = b.atomic orelse return error.InvalidBeef;
        if (form == .subject and b.version != V2) return error.InvalidBeef;
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, switch (form) {
            .atomic => ATOMIC,
            .outpoint => OUTPOINT,
            .subject => SUBJECT,
            .beef => unreachable,
        }, .little);
        try out.appendSlice(arena, &hdr);
        try out.appendSlice(arena, &a);
        if (form == .outpoint) {
            const o = b.vout.?;
            std.mem.writeInt(u32, &hdr, o, .little);
            try out.appendSlice(arena, &hdr);
        }
    }
    var ver: [4]u8 = undefined;
    std.mem.writeInt(u32, &ver, b.version, .little);
    try out.appendSlice(arena, &ver);
    try appendVarInt(arena, &out, b.bumps.len);
    for (b.bumps) |*p| try out.appendSlice(arena, p.bytes(arena) catch return error.InvalidBeef);
    try appendVarInt(arena, &out, b.entries.len);
    for (b.entries) |e| {
        if (b.version == V1) {
            if (e.format == .txid_only) return error.InvalidBeef;
            try out.appendSlice(arena, e.raw orelse return error.InvalidBeef);
            if (e.bump) |i| {
                try out.append(arena, 1);
                try appendVarInt(arena, &out, i);
            } else try out.append(arena, 0);
        } else {
            try out.append(arena, @intFromEnum(e.format));
            switch (e.format) {
                .txid_only => try out.appendSlice(arena, &e.txid),
                .raw_with_bump => {
                    try appendVarInt(arena, &out, e.bump orelse return error.InvalidBeef);
                    try out.appendSlice(arena, e.raw orelse return error.InvalidBeef);
                },
                .raw => try out.appendSlice(arena, e.raw orelse return error.InvalidBeef),
            }
        }
    }
    return out.toOwnedSlice(arena);
}

/// Whether every transaction's in-BEEF parents come before it.
pub fn parentsFirst(b: Beef) bool {
    for (b.entries, 0..) |e, i| {
        const tx = e.tx orelse continue;
        for (tx.inputs) |in| {
            const j = b.indexOf(in.previous_outpoint.txid.bytes) orelse continue;
            if (j >= i) return false;
        }
    }
    return true;
}

/// Whether a BUMP's level 0 holds this txid.
pub fn bumpHas(p: MerklePath, txid: [32]u8) bool {
    if (p.path.len == 0) return false;
    for (p.path[0]) |leaf| if (leaf.hash) |h| if (std.mem.eql(u8, &h.bytes, &txid)) return true;
    return false;
}

/// The merkle root a BUMP gives for a txid in it.
pub fn rootFor(arena: std.mem.Allocator, p: MerklePath, txid: [32]u8) ?[32]u8 {
    if (!bumpHas(p, txid)) return null;
    const r = p.computeRoot(arena, .{ .bytes = txid }) catch return null;
    return r.bytes;
}
