//! Calling an app (skein docs/APPS.md §4): one box per app, the function in
//! the body, the answer a message to the sender. The dispatch helper an
//! app's handler is written over.
//!
//! An app's manifest (etc/app.json) declares what it provides:
//!
//!   provides: [{interface: "demo.counter/1",
//!               functions: {add: {writes: true, args: {by: "int", "note?": "string"}, answer: {count: "int"}}, …}}]
//!
//! At install the manifest becomes the root record of the app's head
//! `<app>/app` (`{kind: "app", name, …, provides, …, tree, state?}`;
//! skein-sdk 0.3.0, shruggr/skein#77: an app writes only heads under its
//! own name, `<app>/…`); `serve` reads it from there (`headOf`). A function's full name is `<interface name>.<function>`, the
//! interface's `/<major>` dropped: `demo.counter.add`. The program lists
//! what it implements:
//!
//!   const fns = [_]app.Function{ .{ .name = "demo.counter.add", .run = add }, … };
//!   fn add(c: *app.Call) !Value { const by = Value.intOf(c.args.get("by")).?; … return result; }
//!
//! and hands every input to `serve(a, in, "<app name>", &fns, other)`. Three
//! ways reach a function, with one definition:
//!
//!   a message in the app's box    a step on {message, body, box, sender}, body {fn, args}.
//!                                 Answered with a message to the sender in the same box:
//!                                   {fn, request: <message>, replyTo: <message>, result}
//!                                   {fn, request: <message>, replyTo: <message>, error: {code, message}}
//!                                 (`replyTo`: a program that emitted the call and awaits it is
//!                                 stepped with the answer as its `reply`.) The sender must be in
//!                                 the address book to be answered; else the answer is only the
//!                                 step's result (stdout, in the log). Either way the step's stdout
//!                                 is the answer as DAG-JSON.
//!   an HTTP route                 a route {transport: "http", address: "/call", handler: "<role>.call"}:
//!                                 the front door calls fn "call" with the request; the body is
//!                                 {fn, args} (JSON, or dag-cbor as application/cbor); the answer,
//!                                 on the connection: 200 {fn, result} | an error status {fn, error}.
//!                                 Who may call is the kernel's (shruggr/skein#143): the route's
//!                                 filters (`kernel.brc104`: the caller is the client's key) and
//!                                 the gate (the manifest's `roles` for the route's fn) ran before
//!                                 the handler; the request's `caller` is the door's principal.
//!   an in-VM call                 call(<handler program>, "<interface>.<function>", args) → result
//!                                 (dag-cbor), or the call's error.
//!
//! A body without `fn` is not a call: `serve` hands it to `other` (a start
//! message, a tick), or reports it.
//!
//! `args` are checked against the declared shape before the function runs:
//! a map of keys to `string`, `int`, `ms`, `bytes`, `cid`, `bool`, `map`
//! (any map), `any`, an array `[<shape>]`, or a nested map; `<key>?` is
//! optional (absent or null); a key the shape does not name is refused.
//!
//! **`writes`.** A function's writes go through its `Call`: `put`,
//! `putBlock`, `keep`, `advance`, `setState`, `emit`/`send`, `launch`,
//! `deadline`, `awaitRecord`. For a function the manifest marks
//! `writes: false` each of them is refused (error code `read-only`): it
//! answers from the app's head as it stands. (A function that calls the raw
//! `sk` imports itself goes around this; the log shows what it did.) A
//! `writes: true` function that fails is answered with the error, and what
//! it wrote before failing stands: check first, write last.
//!
//! Error codes: `bad-request` (not {fn, args}, not JSON), `unknown-fn` (not
//! provided, or not implemented), `bad-args`, `read-only`, `failed` (the
//! function's own error). Over HTTP: 400, 404, 400, 409, 500. (No
//! `not-admitted` since skein-sdk 0.9.0: the kernel's gate refuses a caller
//! before the handler runs.)
//!
//! **State.** The app's head `<app>/app` is its handler's (§1): the root record is the
//! manifest root installed, and the app keeps its own state as the
//! root's `state` link — `Call.state()` reads it, `Call.setState(v)` puts
//! `v` and advances the head to the root with `state` replaced. An install
//! of a new version keeps `state`.
const std = @import("std");
const cbor = @import("cbor");
const sk = @import("sk");
const dagjson = @import("dagjson");

const Value = cbor.Value;
const Allocator = std.mem.Allocator;
const eql = std.mem.eql;

/// A function the program implements, by its full name (`<interface name>.<function>`).
pub const Function = struct {
    name: []const u8,
    run: *const fn (c: *Call) anyerror!Value,
};

pub const Code = enum {
    @"bad-request",
    @"unknown-fn",
    @"bad-args",
    @"read-only",
    failed,

    pub fn status(c: Code) u16 {
        return switch (c) {
            .@"bad-request", .@"bad-args" => 400,
            .@"unknown-fn" => 404,
            .@"read-only" => 409,
            .failed => 500,
        };
    }
};

/// A failure to answer with: its code and message.
pub const Failure = struct { code: Code, message: []const u8 };

/// What a call came to: the function's result, or why not.
pub const Outcome = union(enum) { ok: Value, err: Failure };

/// One call of one function: what it was asked, by whom, and the writes it may make.
pub const Call = struct {
    a: Allocator,
    /// The program's input (a step's, or a call's).
    in: Value,
    /// The app's name: its box, and the prefix of its heads (`<app>/app` the root).
    app: []const u8,
    /// The head's root record: the installed manifest.
    manifest: Value,
    /// The function's full name, and its declaration in `provides`.
    name: []const u8,
    decl: Value,
    args: Value,
    /// Who asked: the message's sender, the route's caller (the door's principal); null when the
    /// route's filters named none, or an in-VM call.
    sender: ?[]const u8,
    /// The declaration's `writes`.
    writes: bool,
    /// The first write refused (a `writes: false` function): its import's name.
    refused: ?[]const u8 = null,

    fn guard(c: *Call, what: []const u8) !void {
        if (c.writes) return;
        if (c.refused == null) c.refused = what;
        return sk.report(try std.fmt.allocPrint(c.a, "{s} is writes: false, and it called {s}", .{ c.name, what }));
    }

    // ---- reads (always allowed)

    pub fn get(c: *Call, cid: []const u8) !Value {
        return sk.get(c.a, cid);
    }
    pub fn head(c: *Call, name: []const u8) !?[]u8 {
        return sk.head(c.a, name);
    }
    /// The app's state record (the root's `state`), or null.
    pub fn state(c: *Call) !?Value {
        return stateOf(c.a, c.manifest);
    }

    // ---- writes (refused for a `writes: false` function)

    pub fn put(c: *Call, v: Value) ![]u8 {
        try c.guard("put");
        return sk.put(c.a, v);
    }
    pub fn putBlock(c: *Call, cid: []const u8, bytes: []const u8) !void {
        try c.guard("putblock");
        return sk.putBlock(cid, bytes);
    }
    pub fn keep(c: *Call, cid: []const u8) !void {
        try c.guard("keep");
        return sk.keep(cid);
    }
    pub fn advance(c: *Call, name: []const u8, cid: []const u8) !void {
        try c.guard("advance");
        return sk.advance(name, cid);
    }
    /// Put `v` and advance the app's head to its root with `state` → v. Its CID.
    pub fn setState(c: *Call, v: Value) ![]u8 {
        try c.guard("setState");
        const r = try putState(c.a, c.app, c.manifest, v);
        c.manifest = r.root;
        return r.state;
    }
    pub fn emit(c: *Call, to: []const u8, box: []const u8, body: Value, subject: ?[]const u8) ![]u8 {
        try c.guard("emit");
        return sk.emit(c.a, to, box, body, subject);
    }
    pub fn send(c: *Call, to: []const u8, box: []const u8, body: Value) ![]const u8 {
        try c.guard("emit");
        return sk.send(c.a, to, box, body);
    }
    pub fn launch(c: *Call, prog: []const u8, args: []const u8) ![]u8 {
        try c.guard("launch");
        return sk.launch(c.a, prog, args);
    }
    pub fn deadline(c: *Call, until_ms: i64) !void {
        try c.guard("deadline");
        return sk.deadline(until_ms);
    }
    pub fn awaitRecord(c: *Call, cid: []const u8) !void {
        try c.guard("await");
        return sk.awaitRecord(cid);
    }
};

/// Hand an input to the app: a message in a box, the `/call` route, or an
/// in-VM call. A message whose body has no `fn` (a start message, a tick) goes
/// to `other` (null: refused).
pub fn serve(a: Allocator, in: Value, app: []const u8, fns: []const Function, other: ?*const fn (Allocator, Value, Value) anyerror!void) !void {
    const kind = Value.str(in.get("kind")) orelse "";
    if (eql(u8, kind, "call")) {
        const func = Value.str(in.get("fn")) orelse "";
        const arg = cbor.decode(a, Value.bytesOf(in.get("arg")) orelse "") catch return sk.report("the argument is not dag-cbor");
        if (eql(u8, func, "call") and arg.get("match") != null) return sk.answer(a, try onRoute(a, in, app, fns, arg));
        return sk.answer(a, try onCall(a, in, app, fns, func, arg));
    }
    const args = in.get("args") orelse return sk.report("no args");
    const body_cid = Value.cidOf(args.get("body")) orelse return sk.report("not a message (no body)");
    const body = try sk.get(a, body_cid);
    if (body != .map or body.get("fn") == null) {
        const f = other orelse return sk.report("not a call: want {fn, args}");
        return f(a, in, body);
    }
    try onMessage(a, in, app, fns, body);
}

/// The app's root head, `<app>/app` (shruggr/skein#77: an app's heads are `<app>/…`).
pub fn headOf(a: Allocator, app: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{s}/app", .{app});
}

/// The installed manifest: the root record of the head `<app>/app`.
pub fn manifestOf(a: Allocator, app: []const u8) !Value {
    const name = try headOf(a, app);
    const root = (try sk.head(a, name)) orelse return sk.report(try std.fmt.allocPrint(a, "no head {s}: the app is not installed (its manifest is the head's root record)", .{name}));
    const m = try sk.get(a, root);
    if (!eql(u8, Value.str(m.get("kind")) orelse "", "app")) return sk.report(try std.fmt.allocPrint(a, "head {s}: its root is not an app record", .{name}));
    return m;
}

/// The app's state record (the root record's `state`), or null.
pub fn stateOf(a: Allocator, manifest: Value) !?Value {
    const s = Value.cidOf(manifest.get("state")) orelse return null;
    return try sk.get(a, s);
}

/// Put `v` as the app's state and advance its head to `manifest` with
/// `state` → v (for a handler's own steps outside a call: a tick, a start).
pub fn putState(a: Allocator, app: []const u8, manifest: Value, v: Value) !struct { state: []u8, root: Value } {
    const s = try sk.put(a, v);
    const root = try withField(a, manifest, "state", cbor.cidv(s));
    try sk.advance(try headOf(a, app), try sk.put(a, root));
    return .{ .state = s, .root = root };
}

/// A function's declaration in `provides` by its full name, or null.
pub fn declOf(a: Allocator, manifest: Value, name: []const u8) !?Value {
    const ps = manifest.get("provides") orelse return null;
    if (ps != .array) return null;
    for (ps.array) |p| {
        const iface = Value.str(p.get("interface")) orelse continue;
        const base = iface[0 .. std.mem.lastIndexOfScalar(u8, iface, '/') orelse iface.len];
        if (name.len <= base.len + 1 or !std.mem.startsWith(u8, name, base) or name[base.len] != '.') continue;
        const fs = p.get("functions") orelse continue;
        if (fs.get(name[base.len + 1 ..])) |d| return d;
    }
    _ = a;
    return null;
}

/// Run a call: find the function, check the args, run it. The result, or why not.
pub fn run(a: Allocator, in: Value, app: []const u8, manifest: Value, fns: []const Function, name: []const u8, args_in: ?Value, sender: ?[]const u8) !Outcome {
    const decl = (try declOf(a, manifest, name)) orelse return .{ .err = .{ .code = .@"unknown-fn", .message = try std.fmt.allocPrint(a, "{s}: not provided by {s}", .{ name, app }) } };
    var impl: ?Function = null;
    for (fns) |f| if (eql(u8, f.name, name)) {
        impl = f;
        break;
    };
    const f = impl orelse return .{ .err = .{ .code = .@"unknown-fn", .message = try std.fmt.allocPrint(a, "{s}: declared, not implemented", .{name}) } };
    const args: Value = switch (args_in orelse Value.null) {
        .null => .{ .map = &.{} },
        else => |v| v,
    };
    if (try check(a, decl.get("args") orelse Value{ .map = &.{} }, args, "args")) |why| return .{ .err = .{ .code = .@"bad-args", .message = why } };
    const writes = if (decl.get("writes")) |w| (w == .bool and w.bool) else false;
    var c = Call{ .a = a, .in = in, .app = app, .manifest = manifest, .name = name, .decl = decl, .args = args, .sender = sender, .writes = writes };
    const result = f.run(&c) catch |e| {
        if (c.refused != null) return .{ .err = .{ .code = .@"read-only", .message = sk.errorText(error.Reported) } };
        return .{ .err = .{ .code = .failed, .message = try a.dupe(u8, sk.errorText(e)) } };
    };
    // A refusal the function caught and went on from is still one.
    if (c.refused) |what| return .{ .err = .{ .code = .@"read-only", .message = try std.fmt.allocPrint(a, "{s} is writes: false, and it called {s}", .{ name, what }) } };
    return .{ .ok = result };
}

fn failureValue(a: Allocator, f: Failure) !Value {
    var e = cbor.MapBuilder.init(a);
    try e.put("code", cbor.string(@tagName(f.code)));
    try e.put("message", cbor.string(f.message));
    return e.value();
}

/// A message in the app's box: run it and answer the sender.
fn onMessage(a: Allocator, in: Value, app: []const u8, fns: []const Function, body: Value) !void {
    const args = in.get("args").?;
    const message = Value.cidOf(args.get("message")) orelse return sk.report("not a message (no message)");
    const box = Value.str(args.get("box")) orelse app;
    const sender = Value.bytesOf(args.get("sender"));
    var ans = cbor.MapBuilder.init(a);
    var name: []const u8 = "";
    const outcome: Outcome = blk: {
        name = Value.str(body.get("fn")) orelse break :blk .{ .err = .{ .code = .@"bad-request", .message = "fn is not text" } };
        break :blk try run(a, in, app, try manifestOf(a, app), fns, name, body.get("args"), sender);
    };
    try ans.put("fn", cbor.string(name));
    try ans.put("request", cbor.cidv(message));
    try ans.put("replyTo", cbor.cidv(message));
    switch (outcome) {
        .ok => |v| try ans.put("result", v),
        .err => |f| try ans.put("error", try failureValue(a, f)),
    }
    const answer = ans.value();
    // Answered to the sender when the address book can reach it.
    if (sender) |s| if (try sk.peerOf(a, s) != null) {
        _ = try sk.emit(a, s, box, answer, null);
    };
    try std.Io.File.stdout().writeStreamingAll(sk.io(), try dagjson.encode(a, answer));
}

/// An in-VM call: the result, or the call's error.
fn onCall(a: Allocator, in: Value, app: []const u8, fns: []const Function, name: []const u8, arg: Value) !Value {
    const manifest = try manifestOf(a, app);
    return switch (try run(a, in, app, manifest, fns, name, arg, null)) {
        .ok => |v| v,
        .err => |f| sk.report(try std.fmt.allocPrint(a, "{s}: {s}", .{ @tagName(f.code), f.message })),
    };
}

/// The `/call` route: {fn, args} in the HTTP body → the answer on the connection.
fn onRoute(a: Allocator, in: Value, app: []const u8, fns: []const Function, req: Value) !Value {
    const caller = Value.bytesOf(req.get("caller"));
    var name: []const u8 = "";
    const outcome: Outcome = blk: {
        if (!eql(u8, Value.str(req.get("method")) orelse "", "POST")) break :blk .{ .err = .{ .code = .@"bad-request", .message = "POST {fn, args}" } };
        const raw = Value.bytesOf(req.get("body")) orelse "";
        const ct = Value.str(req.get("contentType")) orelse "";
        const body = (if (eql(u8, ct, "application/cbor")) cbor.decode(a, raw) else dagjson.decode(a, raw)) catch
            break :blk .{ .err = .{ .code = .@"bad-request", .message = "the body is not {fn, args} (JSON, or dag-cbor as application/cbor)" } };
        if (body != .map) break :blk .{ .err = .{ .code = .@"bad-request", .message = "the body is not {fn, args}" } };
        name = Value.str(body.get("fn")) orelse break :blk .{ .err = .{ .code = .@"bad-request", .message = "fn is not text" } };
        break :blk try run(a, in, app, try manifestOf(a, app), fns, name, body.get("args"), caller);
    };
    var ans = cbor.MapBuilder.init(a);
    try ans.put("fn", cbor.string(name));
    var status: u16 = 200;
    switch (outcome) {
        .ok => |v| try ans.put("result", v),
        .err => |f| {
            status = f.code.status();
            try ans.put("error", try failureValue(a, f));
        },
    }
    var m = cbor.MapBuilder.init(a);
    try m.put("status", cbor.int(status));
    try m.put("type", cbor.string("application/json"));
    try m.put("body", .{ .bytes = try dagjson.encode(a, ans.value()) });
    return m.value();
}

/// A copy of map `v` with `key` set to `x`.
pub fn withField(a: Allocator, v: Value, key: []const u8, x: Value) !Value {
    var m = cbor.MapBuilder.init(a);
    if (v == .map) for (v.map) |e| try m.put(e.key, e.value);
    try m.put(key, x);
    return m.value();
}

// ---------------------------------------------------------------- shapes

/// Why `v` does not have `shape` (a problem, naming where), or null if it does.
pub fn check(a: Allocator, shape: Value, v: Value, at: []const u8) !?[]const u8 {
    switch (shape) {
        .string => |t| {
            const ok = if (eql(u8, t, "any"))
                true
            else if (eql(u8, t, "string"))
                v == .string
            else if (eql(u8, t, "int") or eql(u8, t, "ms"))
                v == .int
            else if (eql(u8, t, "bytes"))
                v == .bytes
            else if (eql(u8, t, "cid"))
                v == .cid
            else if (eql(u8, t, "bool"))
                v == .bool
            else if (eql(u8, t, "map"))
                v == .map
            else
                return try std.fmt.allocPrint(a, "{s}: the shape names an unknown type {s}", .{ at, t });
            return if (ok) null else try std.fmt.allocPrint(a, "{s}: want {s}, got {s}", .{ at, t, @tagName(v) });
        },
        .array => |s| {
            if (s.len != 1) return try std.fmt.allocPrint(a, "{s}: an array shape names one element shape", .{at});
            if (v != .array) return try std.fmt.allocPrint(a, "{s}: want an array, got {s}", .{ at, @tagName(v) });
            for (v.array, 0..) |x, i| if (try check(a, s[0], x, try std.fmt.allocPrint(a, "{s}[{d}]", .{ at, i }))) |why| return why;
            return null;
        },
        .map => |s| {
            if (v != .map) return try std.fmt.allocPrint(a, "{s}: want a map, got {s}", .{ at, @tagName(v) });
            for (s) |e| {
                const optional = std.mem.endsWith(u8, e.key, "?");
                const key = if (optional) e.key[0 .. e.key.len - 1] else e.key;
                const x = v.get(key) orelse Value.null;
                const where = try std.fmt.allocPrint(a, "{s}.{s}", .{ at, key });
                if (x == .null) {
                    if (optional) continue;
                    return try std.fmt.allocPrint(a, "{s}: missing", .{where});
                }
                if (try check(a, e.value, x, where)) |why| return why;
            }
            for (v.map) |e| {
                const named = for (s) |d| {
                    const k = if (std.mem.endsWith(u8, d.key, "?")) d.key[0 .. d.key.len - 1] else d.key;
                    if (eql(u8, k, e.key)) break true;
                } else false;
                if (!named) return try std.fmt.allocPrint(a, "{s}.{s}: not in the shape", .{ at, e.key });
            }
            return null;
        },
        else => return try std.fmt.allocPrint(a, "{s}: a shape is a type name, [shape] or {{key: shape}}", .{at}),
    }
}

test "shapes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const shape = try dagjson.decode(a, "{\"token\":\"string\",\"in\":\"int\",\"tokens?\":[\"string\"],\"at?\":\"ms\",\"opts?\":{\"deep\":\"bool\"},\"any?\":\"any\"}");
    try std.testing.expect(try check(a, shape, try dagjson.decode(a, "{\"token\":\"1\",\"in\":5}"), "args") == null);
    try std.testing.expect(try check(a, shape, try dagjson.decode(a, "{\"token\":\"1\",\"in\":5,\"tokens\":[\"a\",\"b\"],\"at\":9,\"opts\":{\"deep\":true},\"any\":[1]}"), "args") == null);
    try std.testing.expect(try check(a, shape, try dagjson.decode(a, "{\"token\":\"1\",\"in\":5,\"tokens\":null}"), "args") == null);
    try std.testing.expectEqualStrings("args.in: missing", (try check(a, shape, try dagjson.decode(a, "{\"token\":\"1\"}"), "args")).?);
    try std.testing.expectEqualStrings("args.in: want int, got string", (try check(a, shape, try dagjson.decode(a, "{\"token\":\"1\",\"in\":\"5\"}"), "args")).?);
    try std.testing.expectEqualStrings("args.tokens[1]: want string, got int", (try check(a, shape, try dagjson.decode(a, "{\"token\":\"1\",\"in\":5,\"tokens\":[\"a\",2]}"), "args")).?);
    try std.testing.expectEqualStrings("args.opts.deep: want bool, got int", (try check(a, shape, try dagjson.decode(a, "{\"token\":\"1\",\"in\":5,\"opts\":{\"deep\":1}}"), "args")).?);
    try std.testing.expectEqualStrings("args.extra: not in the shape", (try check(a, shape, try dagjson.decode(a, "{\"token\":\"1\",\"in\":5,\"extra\":1}"), "args")).?);
    try std.testing.expectEqualStrings("args: want a map, got array", (try check(a, shape, try dagjson.decode(a, "[]"), "args")).?);
    try std.testing.expectEqualStrings("args.x: the shape names an unknown type float", (try check(a, try dagjson.decode(a, "{\"x\":\"float\"}"), try dagjson.decode(a, "{\"x\":1}"), "args")).?);
    const c = try dagjson.decode(a, "{\"c\":\"cid\",\"b\":\"bytes\"}");
    try std.testing.expect(try check(a, c, try dagjson.decode(a, "{\"c\":{\"/\":\"bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yje\"},\"b\":{\"/\":{\"bytes\":\"AAE\"}}}"), "args") == null);
}

test "a function's declaration by its full name" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const m = try dagjson.decode(a,
        \\{"kind":"app","name":"amm","provides":[
        \\  {"interface":"amm.pool/1","functions":{"quote":{"writes":false,"args":{"in":"int"}},"config":{"writes":true}}},
        \\  {"interface":"amm.admin/2","functions":{"pause":{"writes":true}}}]}
    );
    try std.testing.expect((try declOf(a, m, "amm.pool.quote")).?.get("writes").?.bool == false);
    try std.testing.expect((try declOf(a, m, "amm.pool.config")).?.get("writes").?.bool);
    try std.testing.expect((try declOf(a, m, "amm.admin.pause")) != null);
    try std.testing.expect((try declOf(a, m, "amm.pool.nope")) == null);
    try std.testing.expect((try declOf(a, m, "amm.poolquote")) == null);
    try std.testing.expect((try declOf(a, m, "amm.pool")) == null);
}

test "withField" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try dagjson.decode(a, "{\"kind\":\"app\",\"state\":1}");
    const w = try withField(a, v, "state", cbor.int(2));
    try std.testing.expectEqualStrings("{\"kind\":\"app\",\"state\":2}", try dagjson.encode(a, w));
    const x = try withField(a, v, "tree", cbor.int(3));
    try std.testing.expectEqual(@as(usize, 3), x.map.len);
}
