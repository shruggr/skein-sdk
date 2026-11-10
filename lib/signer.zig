//! The signer app's wire (shruggr/skein-signer): BRC-100 request frames for
//! the calls the kernel's raw signer serves programs (8 getPublicKey, 11
//! encrypt, 12 decrypt, 13 createHmac, 14 verifyHmac, 15 createSignature, 16
//! verifySignature) decoded and encoded exactly as ts-sdk's
//! WalletWireProcessor / WalletWireTransceiver lay them out; the NAME a
//! request is called under; and the client every other program uses in
//! place of the raw `wallet` import.
//!
//! A frame: [call][originator length u8][originator] then, for every call but
//! an identity-key getPublicKey, the key parameters
//!   level u8, varint ‖ protocol, varint ‖ key ID,
//!   counterparty (0 absent | 11 self | 12 anyone | the 33-byte key),
//!   privileged int8 (-1 none, 0, 1), privileged reason int8 length (-1 none) ‖ bytes
//! and per call: 8 identityKey u8, then (identity) the privileged pair or
//! (else) the key parameters and forSelf int8; 11/12/13 varint ‖ bytes; 14 the
//! 32-byte HMAC, varint ‖ data; 15 1 ‖ varint ‖ data or 2 ‖ 32-byte hash; 16
//! forSelf, varint ‖ signature, then 1 ‖ data or 2 ‖ hash; every call ends
//! with seekPermission int8. Decoding is strict: every byte read, minimal
//! varints, nothing after.
//!
//! Names (the signer app's contract, checked by the kernel byte-exact and
//! never interpreted by it):
//!   (no name)                      level 0, and the identity key
//!   1/<protocol>                   level 1
//!   2/<protocol>/<counterparty>    level 2; counterparty `self`, `anyone`, or the 66-hex key
//!   *                              any derivation (admin)
//! The protocol is written as the derivation reads it (BRC-43: lower case,
//! trimmed). A counterparty is normalized before it is written: wire code 11
//! and the instance's identity key are `self`; code 12 and 1·G are `anyone`;
//! an absent counterparty is the call's default (createSignature: anyone;
//! every other call: self).
const std = @import("std");
const cbor = @import("cbor");
const sk = @import("sk");

pub const Value = cbor.Value;
const Allocator = std.mem.Allocator;
const eql = std.mem.eql;

pub const Op = enum(u8) {
    get_public_key = 8,
    encrypt = 11,
    decrypt = 12,
    create_hmac = 13,
    verify_hmac = 14,
    create_signature = 15,
    verify_signature = 16,
};

/// A counterparty as the frame carries it.
pub const Counterparty = union(enum) { none, self, anyone, key: [33]u8 };

/// A counterparty normalized (see `party`).
pub const Party = union(enum) { self, anyone, key: [33]u8 };

/// 1·G compressed: BRC-42's `anyone`.
pub const ANYONE: [33]u8 = .{ 0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 };

pub const Request = struct {
    op: Op,
    originator: []const u8 = "",
    /// getPublicKey for the identity key itself (no key parameters).
    identity: bool = false,
    level: u8 = 0,
    protocol: []const u8 = "",
    key_id: []const u8 = "",
    counterparty: Counterparty = .none,
    privileged: ?bool = null,
    privileged_reason: ?[]const u8 = null,
    /// getPublicKey and verifySignature.
    for_self: ?bool = null,
    /// encrypt's plaintext, decrypt's ciphertext, the HMAC calls' data, the signature calls' data.
    data: ?[]const u8 = null,
    /// The signature calls' 32-byte hash (signed or verified as is).
    hash: ?[32]u8 = null,
    /// verifyHmac's HMAC.
    hmac: ?[32]u8 = null,
    /// verifySignature's DER signature.
    signature: ?[]const u8 = null,
    seek_permission: ?bool = null,
};

pub const FrameError = error{ BadFrame, UnknownCall };

// ---------------------------------------------------------------- decoding

const Reader = struct {
    b: []const u8,
    i: usize = 0,

    fn u8_(r: *Reader) FrameError!u8 {
        if (r.i >= r.b.len) return error.BadFrame;
        r.i += 1;
        return r.b[r.i - 1];
    }
    fn take(r: *Reader, n: usize) FrameError![]const u8 {
        if (n > r.b.len - r.i) return error.BadFrame;
        r.i += n;
        return r.b[r.i - n .. r.i];
    }
    fn fixed(r: *Reader, comptime n: usize) FrameError![n]u8 {
        return (try r.take(n))[0..n].*;
    }
    /// A Bitcoin varint, minimally encoded.
    fn varint(r: *Reader) FrameError!usize {
        const f = try r.u8_();
        const v: u64 = switch (f) {
            0xfd => std.mem.readInt(u16, &(try r.fixed(2)), .little),
            0xfe => std.mem.readInt(u32, &(try r.fixed(4)), .little),
            0xff => std.mem.readInt(u64, &(try r.fixed(8)), .little),
            else => return f,
        };
        const min: u64 = switch (f) {
            0xfd => 0xfd,
            0xfe => 0x1_0000,
            else => 0x1_0000_0000,
        };
        if (v < min) return error.BadFrame;
        if (v > r.b.len) return error.BadFrame;
        return @intCast(v);
    }
    fn bytes(r: *Reader) FrameError![]const u8 {
        return r.take(try r.varint());
    }
    /// int8 -1 / 0 / 1.
    fn optBool(r: *Reader) FrameError!?bool {
        return switch (try r.u8_()) {
            0xff => null,
            0 => false,
            1 => true,
            else => error.BadFrame,
        };
    }
};

fn keyParams(r: *Reader, q: *Request) FrameError!void {
    q.level = try r.u8_();
    if (q.level > 2) return error.BadFrame;
    q.protocol = try r.bytes();
    q.key_id = try r.bytes();
    const c = try r.u8_();
    q.counterparty = switch (c) {
        0 => .none,
        11 => .self,
        12 => .anyone,
        2, 3 => blk: {
            var k: [33]u8 = undefined;
            k[0] = c;
            @memcpy(k[1..], try r.take(32));
            break :blk .{ .key = k };
        },
        else => return error.BadFrame,
    };
    try privilegedParams(r, q);
}

fn privilegedParams(r: *Reader, q: *Request) FrameError!void {
    q.privileged = try r.optBool();
    const n = try r.u8_();
    if (n == 0xff) {
        q.privileged_reason = null;
    } else if (n > 127) {
        return error.BadFrame;
    } else {
        q.privileged_reason = try r.take(n);
    }
}

fn dataOrHash(r: *Reader, q: *Request) FrameError!void {
    switch (try r.u8_()) {
        1 => q.data = try r.bytes(),
        2 => q.hash = try r.fixed(32),
        else => return error.BadFrame,
    }
}

/// A request frame. Slices point into `frame`.
pub fn decode(frame: []const u8) FrameError!Request {
    var r: Reader = .{ .b = frame };
    const code = try r.u8_();
    const op = std.enums.fromInt(Op, code) orelse return error.UnknownCall;
    var q: Request = .{ .op = op };
    q.originator = try r.take(try r.u8_());
    switch (op) {
        .get_public_key => {
            q.identity = switch (try r.u8_()) {
                0 => false,
                1 => true,
                else => return error.BadFrame,
            };
            if (q.identity) {
                try privilegedParams(&r, &q);
            } else {
                try keyParams(&r, &q);
                q.for_self = try r.optBool();
            }
        },
        .encrypt, .decrypt, .create_hmac => {
            try keyParams(&r, &q);
            q.data = try r.bytes();
        },
        .verify_hmac => {
            try keyParams(&r, &q);
            q.hmac = try r.fixed(32);
            q.data = try r.bytes();
        },
        .create_signature => {
            try keyParams(&r, &q);
            try dataOrHash(&r, &q);
        },
        .verify_signature => {
            try keyParams(&r, &q);
            q.for_self = try r.optBool();
            q.signature = try r.bytes();
            try dataOrHash(&r, &q);
        },
    }
    q.seek_permission = try r.optBool();
    if (r.i != frame.len) return error.BadFrame;
    return q;
}

// ---------------------------------------------------------------- encoding

const Writer = struct {
    a: Allocator,
    out: std.ArrayList(u8) = .empty,

    fn byte(w: *Writer, b: u8) !void {
        try w.out.append(w.a, b);
    }
    fn raw(w: *Writer, b: []const u8) !void {
        try w.out.appendSlice(w.a, b);
    }
    fn varint(w: *Writer, v: usize) !void {
        if (v < 0xfd) return w.byte(@intCast(v));
        if (v <= 0xffff) {
            try w.byte(0xfd);
            var b: [2]u8 = undefined;
            std.mem.writeInt(u16, &b, @intCast(v), .little);
            return w.raw(&b);
        }
        if (v <= 0xffff_ffff) {
            try w.byte(0xfe);
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, @intCast(v), .little);
            return w.raw(&b);
        }
        try w.byte(0xff);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, @intCast(v), .little);
        return w.raw(&b);
    }
    fn bytes(w: *Writer, b: []const u8) !void {
        try w.varint(b.len);
        try w.raw(b);
    }
    fn optBool(w: *Writer, v: ?bool) !void {
        try w.byte(if (v) |b| @intFromBool(b) else 0xff);
    }
};

fn writePrivileged(w: *Writer, q: Request) !void {
    try w.optBool(q.privileged);
    if (q.privileged_reason) |s| {
        if (s.len > 127) return error.BadFrame;
        try w.byte(@intCast(s.len));
        try w.raw(s);
    } else try w.byte(0xff);
}

fn writeKeyParams(w: *Writer, q: Request) !void {
    try w.byte(q.level);
    try w.bytes(q.protocol);
    try w.bytes(q.key_id);
    switch (q.counterparty) {
        .none => try w.byte(0),
        .self => try w.byte(11),
        .anyone => try w.byte(12),
        .key => |k| try w.raw(&k),
    }
    try writePrivileged(w, q);
}

fn writeDataOrHash(w: *Writer, q: Request) !void {
    if (q.hash) |h| {
        try w.byte(2);
        try w.raw(&h);
    } else {
        try w.byte(1);
        try w.bytes(q.data orelse "");
    }
}

/// The frame for a request, written as the decoder reads it.
pub fn encode(a: Allocator, q: Request) ![]u8 {
    var w: Writer = .{ .a = a };
    try w.byte(@intFromEnum(q.op));
    if (q.originator.len > 255) return error.BadFrame;
    try w.byte(@intCast(q.originator.len));
    try w.raw(q.originator);
    switch (q.op) {
        .get_public_key => {
            try w.byte(@intFromBool(q.identity));
            if (q.identity) {
                try writePrivileged(&w, q);
            } else {
                try writeKeyParams(&w, q);
                try w.optBool(q.for_self);
            }
        },
        .encrypt, .decrypt, .create_hmac => {
            try writeKeyParams(&w, q);
            try w.bytes(q.data orelse "");
        },
        .verify_hmac => {
            try writeKeyParams(&w, q);
            try w.raw(&(q.hmac orelse return error.BadFrame));
            try w.bytes(q.data orelse "");
        },
        .create_signature => {
            try writeKeyParams(&w, q);
            try writeDataOrHash(&w, q);
        },
        .verify_signature => {
            try writeKeyParams(&w, q);
            try w.optBool(q.for_self);
            try w.bytes(q.signature orelse "");
            try writeDataOrHash(&w, q);
        },
    }
    try w.optBool(q.seek_permission);
    return w.out.toOwnedSlice(a);
}

// ---------------------------------------------------------------- normalization and names

/// A protocol name as the derivation reads it (BRC-43 computeInvoiceNumber:
/// trimmed, lower case). ASCII only: whatever this maps together, the
/// derivation maps together too.
pub fn protocolName(a: Allocator, p: []const u8) ![]u8 {
    return std.ascii.allocLowerString(a, std.mem.trim(u8, p, &std.ascii.whitespace));
}

/// The counterparty normalized: the call's default when absent
/// (createSignature: anyone; every other call: self), 1·G = anyone, the
/// instance's identity key = self.
pub fn party(op: Op, c: Counterparty, identity: ?[33]u8) Party {
    return switch (c) {
        .none => if (op == .create_signature) .anyone else .self,
        .self => .self,
        .anyone => .anyone,
        .key => |k| if (eql(u8, &k, &ANYONE))
            .anyone
        else if (identity != null and eql(u8, &k, &identity.?))
            .self
        else
            .{ .key = k },
    };
}

fn partyText(a: Allocator, p: Party) ![]const u8 {
    return switch (p) {
        .self => "self",
        .anyone => "anyone",
        .key => |k| try sk.hex(a, &k),
    };
}

/// Whether a request needs no name: the identity key, and level 0.
pub fn open(q: Request) bool {
    return (q.op == .get_public_key and q.identity) or q.level == 0;
}

/// The name a request is called under, or null when it needs none (`open`).
pub fn nameFor(a: Allocator, q: Request, identity: ?[33]u8) !?[]u8 {
    if (open(q)) return null;
    const p = try protocolName(a, q.protocol);
    if (q.level == 1) return try std.fmt.allocPrint(a, "1/{s}", .{p});
    return try std.fmt.allocPrint(a, "2/{s}/{s}", .{ p, try partyText(a, party(q.op, q.counterparty, identity)) });
}

/// The admin name: any derivation.
pub const ANY = "*";

/// A level-1 name for `protocol`.
pub fn level1(a: Allocator, protocol: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "1/{s}", .{try protocolName(a, protocol)});
}

/// A level-2 name for `protocol` and counterparty `c` (normalized against `identity`).
pub fn level2(a: Allocator, protocol: []const u8, c: Counterparty, identity: ?[33]u8) ![]u8 {
    return std.fmt.allocPrint(a, "2/{s}/{s}", .{ try protocolName(a, protocol), try partyText(a, party(.get_public_key, if (c == .none) .self else c, identity)) });
}

/// A name in its normal form (protocol as the derivation reads it, the
/// counterparty normalized), `*` as is; null when it is no signer name.
pub fn normalName(a: Allocator, name: []const u8, identity: ?[33]u8) !?[]u8 {
    if (eql(u8, name, ANY)) return try a.dupe(u8, ANY);
    if (std.mem.startsWith(u8, name, "1/")) {
        if (name.len == 2) return null;
        return try level1(a, name[2..]);
    }
    if (std.mem.startsWith(u8, name, "2/")) {
        const rest = name[2..];
        const slash = std.mem.lastIndexOfScalar(u8, rest, '/') orelse return null;
        const proto = rest[0..slash];
        const cp = rest[slash + 1 ..];
        if (proto.len == 0) return null;
        const c: Counterparty = if (eql(u8, cp, "self"))
            .self
        else if (eql(u8, cp, "anyone"))
            .anyone
        else blk: {
            if (cp.len != 66) return null;
            var k: [33]u8 = undefined;
            _ = std.fmt.hexToBytes(&k, cp) catch return null;
            if (k[0] != 2 and k[0] != 3) return null;
            break :blk .{ .key = k };
        };
        return try level2(a, proto, c, identity);
    }
    return null;
}

/// The request rewritten in its normal form: the protocol as the derivation
/// reads it and the counterparty written out (11 self, 12 anyone, the key) —
/// the same derivation, one encoding.
pub fn normalized(a: Allocator, q: Request, identity: ?[33]u8) !Request {
    var n = q;
    if (open(q) and q.op == .get_public_key and q.identity) return n;
    n.protocol = try protocolName(a, q.protocol);
    n.counterparty = switch (party(q.op, q.counterparty, identity)) {
        .self => .self,
        .anyone => .anyone,
        .key => |k| .{ .key = k },
    };
    return n;
}

// ---------------------------------------------------------------- the client

/// The signer app's name and its app record's head.
pub const APP = "signer";
pub const APP_HEAD = APP ++ "/app";
/// The signer app's one function: `{frame: bytes}` → `{frame: bytes}` | `{error: text}`.
pub const FN = "wallet";

/// The signer app's program (its app record's `programs.signer`).
pub fn program(a: Allocator) ![]const u8 {
    const h = (try sk.head(a, APP_HEAD)) orelse return sk.report("signer: no signer app is installed (no head signer/app)");
    const rec = try sk.get(a, h);
    const ps: Value = rec.get("programs") orelse .null;
    return Value.cidOf(ps.get(APP)) orelse sk.report("signer: the signer app's record names no program `signer`");
}

/// The instance's identity key from a program's input (`self.identity`), if given.
pub fn identityOf(a: Allocator, in: Value) !?[33]u8 {
    const s: Value = in.get("self") orelse return null;
    const k = (try sk.keyOf(a, s.get("identity"))) orelse return null;
    if (!sk.isKey(k)) return null;
    return k[0..33].*;
}

/// The call's argument: `{frame}`.
pub fn callArg(a: Allocator, frame: []const u8) ![]u8 {
    var m = cbor.MapBuilder.init(a);
    try m.put("frame", .{ .bytes = frame });
    return cbor.encode(a, m.value());
}

pub const Answer = union(enum) { frame: []const u8, refused: []const u8 };

/// The signer app's answer: the result frame, or its refusal.
pub fn answerOf(a: Allocator, out: []const u8) !Answer {
    const v = cbor.decode(a, out) catch return error.BadAnswer;
    if (Value.bytesOf(v.get("frame"))) |f| return .{ .frame = f };
    if (Value.str(v.get("error"))) |e| return .{ .refused = e };
    return error.BadAnswer;
}

/// The contract's name-carrying in-VM call (shruggr/skein `call-permissions`;
/// plans/research/kernel-permissions-contract-2026-11-09.md §1). The ONE place
/// this module reaches it: `sk.callAs` replaces it when lib/sk.zig has it.
const named = struct {
    extern "skein" fn callAs(prog: [*]const u8, prog_len: u32, func: [*]const u8, func_len: u32, name: [*]const u8, name_len: u32, arg: [*]const u8, arg_len: u32, out: [*]u8, cap: u32) i32;
};
fn namedCall(a: Allocator, prog: []const u8, func: []const u8, name: []const u8, arg: []const u8) ![]u8 {
    return sk.result(a, named.callAs, .{ prog.ptr, @as(u32, @intCast(prog.len)), func.ptr, @as(u32, @intCast(func.len)), name.ptr, @as(u32, @intCast(name.len)), arg.ptr, @as(u32, @intCast(arg.len)) });
}

/// A request frame to the signer app under `name` (null: an unnamed call) →
/// the result frame, as the raw `wallet` import answers it (a wallet error is
/// its error frame). A refusal fails with the signer app's message.
pub fn requestAs(a: Allocator, name: ?[]const u8, frame: []const u8) ![]u8 {
    const prog = try program(a);
    const arg = try callArg(a, frame);
    const out = if (name) |n| try namedCall(a, prog, FN, n, arg) else try sk.call(a, prog, FN, arg);
    return switch (try answerOf(a, out)) {
        .frame => |f| try a.dupe(u8, f),
        .refused => |e| sk.report(try a.dupe(u8, e)),
    };
}

/// A request frame to the signer app under the name it needs (`nameFor`;
/// none for level 0 and the identity key), the counterparty normalized
/// against `in`'s `self.identity` → the result frame. The drop-in for
/// `sk.wallet(a, frame)`.
pub fn request(a: Allocator, in: Value, frame: []const u8) ![]u8 {
    const q = decode(frame) catch return sk.report("signer: the request frame does not decode");
    return requestAs(a, try nameFor(a, q, try identityOf(a, in)), frame);
}

/// The same as an admin: called under `*` (the caller is approved for any name).
pub fn requestAny(a: Allocator, frame: []const u8) ![]u8 {
    return requestAs(a, ANY, frame);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn unhexT(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "decode: go-sdk getPublicKey vectors (skein-sdk wallet/vectors/wire.json) and back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = unhexT("080000020c3332343136343531363164381163484a6c5a6d6c34206333566d5a6d6c34025e941cf6293fc6ef61a841166a3dc3f402e4728cf7e9aace1a530a954dbdce9e00ff0100");
    const q = try decode(&f);
    try testing.expectEqual(Op.get_public_key, q.op);
    try testing.expect(!q.identity);
    try testing.expectEqual(@as(u8, 2), q.level);
    try testing.expectEqualStrings("3241645161d8", q.protocol);
    try testing.expectEqualStrings("cHJlZml4 c3VmZml4", q.key_id);
    try testing.expectEqual(@as(?bool, false), q.privileged);
    try testing.expectEqual(@as(?bool, true), q.for_self);
    try testing.expectEqual(@as(?bool, false), q.seek_permission);
    try testing.expectEqualSlices(u8, &f, try encode(a, q));
    const g = unhexT("080000020c333234313634353136316438016b03efe24af16da45a3e3ce3503b7b7172d64b16b28922011f8df970dd5bf6cc6be700ffff00");
    const r = try decode(&g);
    try testing.expectEqual(@as(?bool, null), r.for_self);
    try testing.expectEqualSlices(u8, &g, try encode(a, r));
}

test "decode: the identity key frame" {
    const q = try decode(&.{ 8, 0, 1, 0, 0xff, 0 });
    try testing.expect(q.identity);
    try testing.expect(open(q));
}

test "decode/encode: every call round-trips" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = unhexT("025e941cf6293fc6ef61a841166a3dc3f402e4728cf7e9aace1a530a954dbdce9e");
    const reqs = [_]Request{
        .{ .op = .encrypt, .level = 1, .protocol = "amm pool", .key_id = "k", .counterparty = .self, .privileged = false, .data = "hi", .seek_permission = false },
        .{ .op = .decrypt, .level = 2, .protocol = "x proto", .key_id = "k", .counterparty = .{ .key = key }, .data = "ct", .privileged_reason = "why" },
        .{ .op = .create_hmac, .level = 2, .protocol = "server hmac", .key_id = "n", .counterparty = .self, .data = "d" },
        .{ .op = .verify_hmac, .level = 2, .protocol = "server hmac", .key_id = "n", .counterparty = .none, .hmac = [_]u8{7} ** 32, .data = "d" },
        .{ .op = .create_signature, .level = 1, .protocol = "amm pool", .key_id = "a_0", .counterparty = .anyone, .hash = [_]u8{9} ** 32 },
        .{ .op = .create_signature, .level = 2, .protocol = "auth message signature", .key_id = "a b", .counterparty = .{ .key = key }, .data = "body" },
        .{ .op = .verify_signature, .level = 2, .protocol = "auth message signature", .key_id = "a b", .counterparty = .{ .key = key }, .for_self = true, .signature = "\x30\x06abcd", .data = "body" },
        .{ .op = .get_public_key, .level = 0, .protocol = "open things", .key_id = "1", .counterparty = .anyone, .for_self = false },
    };
    for (reqs) |q| {
        const f = try encode(a, q);
        const d = try decode(f);
        try testing.expectEqualSlices(u8, f, try encode(a, d));
        try testing.expectEqual(q.op, d.op);
        try testing.expectEqualStrings(q.protocol, d.protocol);
    }
}

test "decode: the kernel's createSignature layout (kernel-zig/src/signer.zig)" {
    // 15, empty originator, level 2, "abcde", "k", self, privileged false, no reason, data "xy", seekPermission false.
    const f = [_]u8{ 15, 0, 2, 5, 'a', 'b', 'c', 'd', 'e', 1, 'k', 11, 0, 0xff, 1, 2, 'x', 'y', 0 };
    const q = try decode(&f);
    try testing.expectEqual(Op.create_signature, q.op);
    try testing.expectEqualStrings("xy", q.data.?);
}

test "decode: refusals" {
    try testing.expectError(error.UnknownCall, decode(&.{ 9, 0 }));
    try testing.expectError(error.UnknownCall, decode(&.{ 1, 0 }));
    try testing.expectError(error.BadFrame, decode(&.{}));
    try testing.expectError(error.BadFrame, decode(&.{ 8, 0, 1, 0, 0xff, 0, 0 })); // a byte after
    try testing.expectError(error.BadFrame, decode(&.{ 8, 0, 1, 0, 0xff })); // short
    try testing.expectError(error.BadFrame, decode(&.{ 8, 0, 2 })); // identityKey 2
    try testing.expectError(error.BadFrame, decode(&.{ 15, 0, 3, 0, 0, 11, 0, 0xff, 2 })); // level 3
    try testing.expectError(error.BadFrame, decode(&.{ 15, 0, 1, 0xfd, 1, 0 })); // non-minimal varint
    try testing.expectError(error.BadFrame, decode(&.{ 15, 0, 1, 1, 'a', 0, 5, 0, 0xff, 1, 0, 0 })); // counterparty 5
    try testing.expectError(error.BadFrame, decode(&.{ 15, 0, 1, 1, 'a', 0, 11, 2, 0xff, 1, 0, 0 })); // privileged 2
    try testing.expectError(error.BadFrame, decode(&.{ 15, 0, 1, 1, 'a', 0, 11, 0, 0xff, 3, 0 })); // data flag 3
}

test "names: levels, normalization of self/anyone and the protocol" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const id = unhexT("03efe24af16da45a3e3ce3503b7b7172d64b16b28922011f8df970dd5bf6cc6be7");
    const other = unhexT("025e941cf6293fc6ef61a841166a3dc3f402e4728cf7e9aace1a530a954dbdce9e");
    try testing.expect((try nameFor(a, .{ .op = .create_signature, .level = 0, .protocol = "zzzzz" }, id)) == null);
    try testing.expectEqualStrings("1/amm pool", (try nameFor(a, .{ .op = .create_signature, .level = 1, .protocol = " AMM Pool ", .counterparty = .anyone }, id)).?);
    const s = "2/skein instance/self";
    try testing.expectEqualStrings(s, (try nameFor(a, .{ .op = .get_public_key, .level = 2, .protocol = "skein instance", .counterparty = .self }, id)).?);
    try testing.expectEqualStrings(s, (try nameFor(a, .{ .op = .get_public_key, .level = 2, .protocol = "skein instance", .counterparty = .{ .key = id } }, id)).?);
    try testing.expectEqualStrings(s, (try nameFor(a, .{ .op = .get_public_key, .level = 2, .protocol = "skein instance", .counterparty = .none }, id)).?);
    try testing.expectEqualStrings("2/m h e/anyone", (try nameFor(a, .{ .op = .create_signature, .level = 2, .protocol = "m h e", .counterparty = .none }, id)).?);
    try testing.expectEqualStrings("2/m h e/anyone", (try nameFor(a, .{ .op = .encrypt, .level = 2, .protocol = "m h e", .counterparty = .{ .key = ANYONE } }, id)).?);
    try testing.expectEqualStrings("2/x/025e941cf6293fc6ef61a841166a3dc3f402e4728cf7e9aace1a530a954dbdce9e", (try nameFor(a, .{ .op = .encrypt, .level = 2, .protocol = "x", .counterparty = .{ .key = other } }, id)).?);
    // normalName: the written forms of one name agree.
    try testing.expectEqualStrings(s, (try normalName(a, "2/Skein Instance/03EFE24AF16DA45A3E3CE3503B7B7172D64B16B28922011F8DF970DD5BF6CC6BE7", id)).?);
    try testing.expectEqualStrings("2/a/anyone", (try normalName(a, "2/a/0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", id)).?);
    try testing.expectEqualStrings("*", (try normalName(a, "*", id)).?);
    try testing.expect((try normalName(a, "0/x", id)) == null);
    try testing.expect((try normalName(a, "2/x", id)) == null);
    try testing.expect((try normalName(a, "2/x/nobody", id)) == null);
    try testing.expect((try normalName(a, "1/", id)) == null);
    try testing.expect((try normalName(a, "", id)) == null);
}

test "client: the argument and the answers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const arg = try cbor.decode(a, try callArg(a, &.{ 1, 2 }));
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, Value.bytesOf(arg.get("frame")).?);
    var m = cbor.MapBuilder.init(a);
    try m.put("error", cbor.string("no"));
    try testing.expectEqualStrings("no", (try answerOf(a, try cbor.encode(a, m.value()))).refused);
}
