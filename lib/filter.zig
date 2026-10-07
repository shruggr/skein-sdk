//! Answering as a filter (skein docs/APPS.md §2 "Filters", shruggr/skein#143).
//!
//! An app's manifest names the functions any route may list as filters
//! (`filters: {"<name>": "<role>.<fn>" | "<fn>" | "<role>"}`). The kernel's
//! door calls one as a kernel call, before anything is recorded, in the
//! deterministic profile: input `{kind: "call", fn, arg, filter: true, …}`,
//! `arg` (dag-cbor) the request as it stands:
//!
//!   {transport, request, match, principal?, caller?,
//!    method, path, route, query, headers, body, contentType}   (the last line: http only)
//!
//! and the program writes one of three answers to stdout (dag-cbor):
//!
//!   {reject: {status, code?, reason}}                  the request ends; nothing is logged
//!   {answer: {status, type?, headers?, body}}          the request ends; nothing is logged
//!                                                      (a read route's last filter answers)
//!   {pass: {request?, principal?, blocks?}}            on to the next filter, or the handler:
//!                                                      the package rewritten (the same kind),
//!                                                      who it is from (a 33-byte key), the
//!                                                      CIDs of blocks it put
//!
//! This module builds those answers; `write` puts one on stdout. A route
//! handler's http answer `{status, type?, headers?, body}` (what `files.serve`
//! and the `app` module's `/call` route answer) becomes a filter's with
//! `answerOf`, so a function that answers a request can answer it as a filter.
const std = @import("std");
const cbor = @import("cbor");
const sk = @import("sk");

const Value = cbor.Value;
const Allocator = std.mem.Allocator;

/// Whether this call is a filter's (the input's `filter: true`).
pub fn isFilter(in: Value) bool {
    const f = in.get("filter") orelse return false;
    return f == .bool and f.bool;
}

/// The principal an earlier filter (or the transport) established, or null.
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

/// `{answer: {status, type?, headers?, body}}`; `headers` a map {name: text}.
pub fn answer(a: Allocator, status: u16, content_type: ?[]const u8, headers: ?Value, body: []const u8) !Value {
    var r = cbor.MapBuilder.init(a);
    try r.put("status", cbor.int(status));
    try r.put("type", cbor.optStr(content_type));
    try r.put("headers", headers);
    try r.put("body", .{ .bytes = body });
    return wrap(a, "answer", r.value());
}

/// A route handler's http answer `{status, type?, headers?, body}` as a filter's `{answer: …}`
/// (the fields carried as they are; a text body becomes bytes).
pub fn answerOf(a: Allocator, http: Value) !Value {
    var r = cbor.MapBuilder.init(a);
    try r.put("status", http.get("status") orelse cbor.int(200));
    try r.put("type", http.get("type"));
    try r.put("headers", http.get("headers"));
    const body: Value = if (http.get("body")) |b| switch (b) {
        .string => |s| .{ .bytes = s },
        else => b,
    } else .{ .bytes = "" };
    try r.put("body", body);
    return wrap(a, "answer", r.value());
}

/// What a pass hands on: all optional (`{pass: {}}` passes the request as it stands).
pub const Pass = struct {
    /// The package, rewritten: a record of the same kind as the one handed in.
    request: ?Value = null,
    /// Who the request is from: a 33-byte key.
    principal: ?[]const u8 = null,
    /// The CIDs of blocks this filter put that the entry should reference.
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

/// Write a filter's answer to stdout (dag-cbor): the call's result.
pub fn write(a: Allocator, v: Value) !void {
    return sk.answer(a, v);
}

fn wrap(a: Allocator, key: []const u8, v: Value) !Value {
    var m = cbor.MapBuilder.init(a);
    try m.put(key, v);
    return m.value();
}

const t = std.testing;

test "the three answers" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const r = try reject(a, 403, "ERR_X", "why");
    try t.expectEqual(@as(?i128, 403), Value.intOf(r.get("reject").?.get("status")));
    try t.expectEqualStrings("ERR_X", Value.str(r.get("reject").?.get("code")).?);
    try t.expectEqualStrings("why", Value.str(r.get("reject").?.get("reason")).?);
    try t.expect((try reject(a, 400, null, "x")).get("reject").?.get("code") == null);

    const an = try answer(a, 200, "text/plain", null, "hi");
    try t.expectEqualStrings("hi", Value.bytesOf(an.get("answer").?.get("body")).?);
    try t.expectEqualStrings("text/plain", Value.str(an.get("answer").?.get("type")).?);
    try t.expect(an.get("answer").?.get("headers") == null);

    var h = cbor.MapBuilder.init(a);
    try h.put("status", cbor.int(404));
    try h.put("body", cbor.string("gone"));
    const ao = try answerOf(a, h.value());
    try t.expectEqual(@as(?i128, 404), Value.intOf(ao.get("answer").?.get("status")));
    try t.expectEqualStrings("gone", Value.bytesOf(ao.get("answer").?.get("body")).?);

    const key = [_]u8{2} ++ [_]u8{7} ** 32;
    const p = try pass(a, .{ .principal = &key, .blocks = &.{"\x01\x71\x12\x20abc"} });
    try t.expectEqualSlices(u8, &key, Value.bytesOf(p.get("pass").?.get("principal")).?);
    try t.expectEqual(@as(usize, 1), p.get("pass").?.get("blocks").?.array.len);
    try t.expectEqual(@as(usize, 0), (try pass(a, .{})).get("pass").?.map.len);

    // Round trip through dag-cbor: what the kernel decodes.
    const back = try cbor.decode(a, try cbor.encode(a, try pass(a, .{ .principal = &key })));
    try t.expect(back.get("pass") != null);

    var in = cbor.MapBuilder.init(a);
    try in.put("filter", .{ .bool = true });
    try t.expect(isFilter(in.value()));
    try t.expect(!isFilter(Value{ .map = &.{} }));
}
