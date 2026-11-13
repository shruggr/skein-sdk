//! Answering as a check (skein next, SPEC.md section 4): a row's `checks` and `recheck` name app
//! functions ("<app>.<fn>") the kernel runs before an entry is written — CHECK runs the checks in
//! order over a committed view, COMMIT the recheck at the tip — each a kernel call in the
//! deterministic profile (no entry, no writes but in memory; its clock the arrival's time): input
//! `{kind: "call", fn, arg, check: true, …}`, `arg` (dag-cbor) the arrival as it stands —
//!
//!   a request's   {request, row, principal?, caller?, method, path, query, headers, body}
//!                 (`request` the package as earlier checks left it, the payload's fields beside it)
//!   an event's    {event, row}
//!
//! — and the program writes one of two answers to stdout (dag-cbor):
//!
//!   {reject: {status, code?, reason}}          refused: nothing is stored or logged
//!   {pass: {request?, principal?, blocks?}}    on to the next check, or ready: the package rewritten
//!                                              (the same kind), who it is from (a 33-byte key), the
//!                                              CIDs of blocks it put (carried in READY, written at
//!                                              COMMIT; a later check sees them). A recheck's pass
//!                                              hands nothing on.
//!
//! This module builds those answers; `write` puts one on stdout. (Formerly `filter`, #143: a check
//! no longer answers a request itself — a read row's handler does.)
const std = @import("std");
const cbor = @import("cbor");
const sk = @import("sk");

const Value = cbor.Value;
const Allocator = std.mem.Allocator;

/// Whether this call is a check's (the input's `check: true`).
pub fn isCheck(in: Value) bool {
    const f = in.get("check") orelse return false;
    return f == .bool and f.bool;
}

/// The principal the signature (or an earlier check) established, or null.
pub fn principal(arg: Value) ?[]const u8 {
    return Value.bytesOf(arg.get("principal"));
}

/// `{reject: {status, code?, reason}}`.
pub fn reject(a: Allocator, status: u16, code: ?[]const u8, reason: []const u8) !Value {
    var r = cbor.MapBuilder.init(a);
    try r.put("status", cbor.int(status));
    try r.put("code", cbor.optStr(code));
    try r.put("reason", cbor.string(reason));
    return wrap(a, "reject", r.value());
}

/// What a pass hands on: all optional (`{pass: {}}` passes the request as it stands).
pub const Pass = struct {
    /// The package, rewritten: a record of the same kind as the one handed in.
    request: ?Value = null,
    /// Who the request is from: a 33-byte key.
    principal: ?[]const u8 = null,
    /// The CIDs of blocks this check put that the entry should reference (written at COMMIT).
    blocks: ?[]const []const u8 = null,
};

/// `{pass: {request?, principal?, blocks?}}`.
pub fn pass(a: Allocator, p: Pass) !Value {
    var r = cbor.MapBuilder.init(a);
    try r.put("request", p.request);
    if (p.principal) |k| try r.put("principal", .{ .bytes = k });
    if (p.blocks) |bs| {
        const xs = try a.alloc(Value, bs.len);
        for (bs, xs) |b, *x| x.* = cbor.cidv(b);
        try r.put("blocks", .{ .array = xs });
    }
    return wrap(a, "pass", r.value());
}

/// Write a check's answer to stdout (dag-cbor): the call's result.
pub fn write(a: Allocator, v: Value) !void {
    return sk.answer(a, v);
}

fn wrap(a: Allocator, key: []const u8, v: Value) !Value {
    var m = cbor.MapBuilder.init(a);
    try m.put(key, v);
    return m.value();
}

const t = std.testing;

test "the two answers" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const r = try reject(a, 403, "ERR_X", "why");
    try t.expectEqual(@as(?i128, 403), Value.intOf(r.get("reject").?.get("status")));
    try t.expectEqualStrings("ERR_X", Value.str(r.get("reject").?.get("code")).?);
    try t.expectEqualStrings("why", Value.str(r.get("reject").?.get("reason")).?);
    try t.expect((try reject(a, 400, null, "x")).get("reject").?.get("code") == null);

    const key = [_]u8{2} ++ [_]u8{7} ** 32;
    const p = try pass(a, .{ .principal = &key, .blocks = &.{"\x01\x71\x12\x20abc"} });
    try t.expectEqualSlices(u8, &key, Value.bytesOf(p.get("pass").?.get("principal")).?);
    try t.expectEqual(@as(usize, 1), p.get("pass").?.get("blocks").?.array.len);
    try t.expectEqual(@as(usize, 0), (try pass(a, .{})).get("pass").?.map.len);

    // Round trip through dag-cbor: what the kernel decodes.
    const back = try cbor.decode(a, try cbor.encode(a, try pass(a, .{ .principal = &key })));
    try t.expect(back.get("pass") != null);

    var in = cbor.MapBuilder.init(a);
    try in.put("check", .{ .bool = true });
    try t.expect(isCheck(in.value()));
    try t.expect(!isCheck(Value{ .map = &.{} }));
}
