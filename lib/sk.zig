//! The `skein` import namespace for the Zig programs (every app's handlers, checks and reads):
//! preview1 imports with f(…, out, cap) → n and `take` for a result that did not fit
//! (kernel-zig/src/program.zig), wrapped so a program says `sk.get(a, cid)` and gets the bytes or an
//! error whose message `lastError()` holds. Below the imports, what a handler builds on them: its
//! thread's kept records, events (`emitEvent`, `broadcast`), the later work (`launch`, `awaitThread`,
//! `awaitName`, `on`), and trees.
//!
//! skein next (SPEC.md section 5): later work is exactly `launch` (the launcher does not wait),
//! `await(x)` (x a fact's name or a thread's identity: THIS thread resumes, once) and `on(name, fn)`
//! (always a function). Gone: the `deadline` and `authfetch` imports, awaiting a message's reply,
//! messages to a key (`emit`/`send`), the address book (`peers`…), `launchResolve`, `fetch`.
const std = @import("std");
const cbor = @import("cbor");

pub const Value = cbor.Value;
pub const Allocator = std.mem.Allocator;

/// The program's Io: one single-threaded WASI process, no concurrency.
pub fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub const raw = struct {
    pub extern "skein" fn input(out: [*]u8, cap: u32) i32;
    pub extern "skein" fn get(cid: [*]const u8, cid_len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn put(data: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn putblock(cid: [*]const u8, cid_len: u32, data: [*]const u8, len: u32) i32;
    pub extern "skein" fn keep(cid: [*]const u8, cid_len: u32) i32;
    pub extern "skein" fn launch(prog: [*]const u8, prog_len: u32, args: [*]const u8, args_len: u32, out: [*]u8, cap: u32) i32;
    /// skein next: x a thread's identity (a binary CID) or a fact's name (text).
    pub extern "skein" fn @"await"(x: [*]const u8, x_len: u32) i32;
    pub extern "skein" fn head(name: [*]const u8, name_len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn advance(name: [*]const u8, name_len: u32, tree: [*]const u8, tree_len: u32) i32;
    pub extern "skein" fn wallet(frame: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn emit(msg: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn call(prog: [*]const u8, prog_len: u32, func: [*]const u8, func_len: u32, arg: [*]const u8, arg_len: u32, out: [*]u8, cap: u32) i32;
    /// 0.20.0 (shruggr/skein call permissions): a named in-VM call; the kernel checks the name.
    pub extern "skein" fn callAs(prog: [*]const u8, prog_len: u32, func: [*]const u8, func_len: u32, name: [*]const u8, name_len: u32, arg: [*]const u8, arg_len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn take(out: [*]u8, cap: u32) i32;
    pub extern "skein" fn @"error"(out: [*]u8, cap: u32) i32;
    pub extern "skein" fn edges(to: [*]const u8, to_len: u32, rel: [*]const u8, rel_len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn events(q: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn on(name: [*]const u8, name_len: u32, func: [*]const u8, func_len: u32) i32;
    pub extern "skein" fn off(name: [*]const u8, name_len: u32, func: [*]const u8, func_len: u32) i32;
};

/// A read of the event index (shruggr/skein 0.5.0): `query` {name | prefix, after?, limit?, latest?}
/// → [{name, place: {n, seq, i, thread}, cid, record}], newest last.
pub fn events(a: Allocator, query: Value) !Value {
    const q = try cbor.encode(a, query);
    return cbor.decode(a, try result(a, raw.events, .{ q.ptr, n32(q.len) }));
}

/// `on(name, fn)` (shruggr/skein 0.5.2; skein next: always a function): `func` — "<role>.<fn>", or
/// "<fn>" for an app with one program — of the calling app is stepped on each fact named `name`
/// exactly that lands after this step (input `args` {event, box: <the name>, fn, place}). Kept when
/// the step ends without error; refused in a kernel call. To resume THIS thread on a fact, `awaitName`.
pub fn on(name: []const u8, func: []const u8) !void {
    if (raw.on(name.ptr, n32(name.len), func.ptr, n32(func.len)) < 0) return failed();
}

/// End the calling app's one subscription of `func` to `name` (shruggr/skein 0.5.3) — the same two
/// arguments as `on`; its other subscriptions to `name` stay. When the step ends without error;
/// refused in a kernel call.
pub fn off(name: []const u8, func: []const u8) !void {
    if (raw.off(name.ptr, n32(name.len), func.ptr, n32(func.len)) < 0) return failed();
}

/// The edges into `to` (#42): dag-cbor [{from, seq, rel, locator}] from the
/// kernel's index, `rel` only if given (who spent txid:vout: `spends` into
/// the transaction's CID, locator = vout).
pub fn edges(a: Allocator, to: []const u8, rel: ?[]const u8) !Value {
    const r = rel orelse "";
    return cbor.decode(a, try result(a, raw.edges, .{ to.ptr, n32(to.len), r.ptr, n32(r.len) }));
}

var last_error: [2048]u8 = undefined;
var last_error_len: usize = 0;

/// The message of the import that failed last.
pub fn lastError() []const u8 {
    return last_error[0..last_error_len];
}

pub fn failed() error{ImportFailed} {
    const n = raw.@"error"(&last_error, last_error.len);
    last_error_len = if (n < 0) 0 else @min(@as(usize, @intCast(n)), last_error.len);
    return error.ImportFailed;
}

fn n32(x: usize) u32 {
    return @intCast(x);
}

/// Run an import that writes (out, cap), taking the held result when it did not fit.
pub fn result(a: Allocator, f: anytype, args: anytype) ![]u8 {
    var buf = try a.alloc(u8, 4096);
    const n = @call(.auto, f, args ++ .{ buf.ptr, @as(u32, @intCast(buf.len)) });
    if (n < 0) return failed();
    const len: usize = @intCast(n);
    if (len <= buf.len) return buf[0..len];
    buf = try a.alloc(u8, len);
    if (raw.take(buf.ptr, @intCast(len)) != n) return failed();
    return buf;
}

pub fn input(a: Allocator) !Value {
    return cbor.decode(a, try result(a, raw.input, .{}));
}

pub fn getBytes(a: Allocator, c: []const u8) ![]u8 {
    return result(a, raw.get, .{ c.ptr, n32(c.len) });
}

pub fn get(a: Allocator, c: []const u8) !Value {
    return cbor.decode(a, try getBytes(a, c));
}

/// A record, or null when the store does not have it (any other failure is an error).
pub fn getOpt(a: Allocator, c: []const u8) !?Value {
    const b = getBytes(a, c) catch |err| {
        if (err == error.ImportFailed and std.mem.startsWith(u8, lastError(), "not found")) return null;
        return err;
    };
    return cbor.decode(a, b) catch null;
}

pub fn put(a: Allocator, v: Value) ![]u8 {
    const bytes = try cbor.encode(a, v);
    return result(a, raw.put, .{ bytes.ptr, n32(bytes.len) });
}

pub fn putBlock(c: []const u8, bytes: []const u8) !void {
    if (raw.putblock(c.ptr, n32(c.len), bytes.ptr, n32(bytes.len)) < 0) return failed();
}

/// Keep a stored record in the thread's state: it is listed in this step's
/// update, so later steps find it with `kept` from the step's tip.
pub fn keep(c: []const u8) !void {
    if (raw.keep(c.ptr, n32(c.len)) < 0) return failed();
}

/// `await(<thread>)` (skein next): THIS thread resumes, once, when the thread `origin` (one this step
/// launched, or any other) comes to rest for good — input `resolved` [{thread, state, result, error}].
/// The step ends waiting. A thread already at rest is refused (read its state instead).
pub fn awaitThread(origin: []const u8) !void {
    if (raw.@"await"(origin.ptr, n32(origin.len)) < 0) return failed();
}

/// `await(<name>)` (skein next): THIS thread resumes, once, when a fact named `name` lands — input
/// `event` {event, box: <the name>, place}. The step ends waiting.
pub fn awaitName(name: []const u8) !void {
    if (raw.@"await"(name.ptr, n32(name.len)) < 0) return failed();
}

/// The CID a head names, or null.
pub fn head(a: Allocator, name: []const u8) !?[]u8 {
    const r = try result(a, raw.head, .{ name.ptr, n32(name.len) });
    return if (r.len == 0) null else r;
}

pub fn advance(name: []const u8, c: []const u8) !void {
    if (raw.advance(name.ptr, n32(name.len), c.ptr, n32(c.len)) < 0) return failed();
}

/// Launch a thread running `prog` (a program record) with the record `args` as its arguments; its
/// origin CID. The thread starts when this step ends. The launcher does NOT wait (skein next): to
/// have the result, `awaitThread` the CID in the same step.
pub fn launch(a: Allocator, prog: []const u8, args: []const u8) ![]u8 {
    return result(a, raw.launch, .{ prog.ptr, n32(prog.len), args.ptr, n32(args.len) });
}

// There is no `subscribe` import (skein-sdk 0.3.0, shruggr/skein#77): the route table is the
// kernel's, changed by root's requests at a `kernel.route` row, never by a program import.

/// A BRC-100 wire frame to the signer → its result frame (a recorded call in a step).
pub fn wallet(a: Allocator, frame: []const u8) ![]u8 {
    return result(a, raw.wallet, .{ frame.ptr, n32(frame.len) });
}

/// Emit an event (skein next: the one way out): `event` a map {event: <name>, …fields} — a fact
/// under the emitting app's own name, a broadcast, or a membership declaration (subscribe, beacon,
/// liveness) → the event record's CID. Handed to the host when this step ends without error.
pub fn emitEvent(a: Allocator, event: Value) ![]u8 {
    const bytes = try cbor.encode(a, event);
    return result(a, raw.emit, .{ bytes.ptr, n32(bytes.len) });
}

/// Broadcast a transaction (#65): the event {event: "broadcast", tx: <its CID, held>, beef?: <its
/// Atomic BEEF>}, addressed to no one — the host's wiring carries it to the network. → the event
/// record's CID. What became of it is the chain app's fact `chain/tx/<txid>`: `awaitName` it.
pub fn broadcast(a: Allocator, tx: []const u8, beef: ?[]const u8) ![]u8 {
    var m = cbor.MapBuilder.init(a);
    try m.put("event", .{ .string = "broadcast" });
    try m.put("tx", cbor.cidv(tx));
    if (beef) |b| try m.put("beef", .{ .bytes = b });
    const bytes = try cbor.encode(a, m.value());
    return result(a, raw.emit, .{ bytes.ptr, n32(bytes.len) });
}

/// An in-VM call: `prog`'s function `func` with `arg` → what it wrote to stdout.
pub fn call(a: Allocator, prog: []const u8, func: []const u8, arg: []const u8) ![]u8 {
    return result(a, raw.call, .{ prog.ptr, n32(prog.len), func.ptr, n32(func.len), arg.ptr, n32(arg.len) });
}

/// An in-VM call with dag-cbor in and out.
pub fn callValue(a: Allocator, prog: []const u8, func: []const u8, arg: Value) !Value {
    return cbor.decode(a, try call(a, prog, func, try cbor.encode(a, arg)));
}

/// A named in-VM call (0.20.0, shruggr/skein call permissions): the same call stating `name`. The
/// kernel runs it only when the calling app is approved to call the callee's app under that exact
/// name (the grants' `calls`); otherwise it fails (`lastError()` says why) and the callee does not
/// run. The callee reads the name with `asName(input)`.
pub fn callAs(a: Allocator, prog: []const u8, func: []const u8, name: []const u8, arg: []const u8) ![]u8 {
    return result(a, raw.callAs, .{ prog.ptr, n32(prog.len), func.ptr, n32(func.len), name.ptr, n32(name.len), arg.ptr, n32(arg.len) });
}

/// A named in-VM call with dag-cbor in and out.
pub fn callValueAs(a: Allocator, prog: []const u8, func: []const u8, name: []const u8, arg: Value) !Value {
    return cbor.decode(a, try callAs(a, prog, func, name, try cbor.encode(a, arg)));
}

/// The name a named call was made under, as the kernel checked it (a call input's `as`); null for a
/// call that stated none, and for every step.
pub fn asName(in: Value) ?[]const u8 {
    return Value.str(in.get("as"));
}

/// Write the answer of a call (stdout) as dag-cbor.
pub fn answer(a: Allocator, v: Value) !void {
    try std.Io.File.stdout().writeStreamingAll(io(), try cbor.encode(a, v));
}

pub fn isKey(b: ?[]const u8) bool {
    const k = b orelse return false;
    return k.len == 33 and (k[0] == 2 or k[0] == 3);
}

pub fn hex(a: Allocator, b: []const u8) ![]u8 {
    const out = try a.alloc(u8, b.len * 2);
    const digits = "0123456789abcdef";
    for (b, 0..) |x, i| {
        out[2 * i] = digits[x >> 4];
        out[2 * i + 1] = digits[x & 15];
    }
    return out;
}

pub fn unhex(a: Allocator, s: []const u8) ?[]u8 {
    if (s.len % 2 != 0) return null;
    const out = a.alloc(u8, s.len / 2) catch return null;
    _ = std.fmt.hexToBytes(out, s) catch return null;
    return out;
}

/// A program's main: run `f`, report an error on stderr (its last line is the call's error) and exit 1.
pub fn main(comptime name: []const u8, f: fn (Allocator) anyerror!void) u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.wasm_allocator);
    defer arena.deinit();
    f(arena.allocator()) catch |e| {
        var buf: [2400]u8 = undefined;
        const le = lastError();
        const msg = std.fmt.bufPrint(&buf, name ++ ": {s}{s}{s}\n", .{ if (e == error.Reported) "" else @errorName(e), if (le.len > 0 and e != error.Reported) ": " else "", if (e == error.Reported) reported else le }) catch name ++ ": error\n";
        std.Io.File.stderr().writeStreamingAll(io(), msg) catch {};
        return 1;
    };
    return 0;
}

var reported: []const u8 = "";

/// Fail with this message (the call's error, or the step's).
pub fn report(msg: []const u8) error{Reported} {
    reported = msg;
    return error.Reported;
}

/// The message of an error from this lib: an import's (`lastError`), a
/// report's, else the error's name.
pub fn errorText(err: anyerror) []const u8 {
    return switch (err) {
        error.ImportFailed => lastError(),
        error.Reported => reported,
        else => @errorName(err),
    };
}

/// Fail with "prefix: <err's message>" (a wrapped error).
pub fn wrap(a: Allocator, prefix: []const u8, err: anyerror) anyerror {
    if (err == error.OutOfMemory) return err;
    return report(try std.fmt.allocPrint(a, "{s}: {s}", .{ prefix, errorText(err) }));
}

/// An import's failure as the program's error: its message alone.
pub fn plain(err: anyerror) anyerror {
    return if (err == error.ImportFailed) report(lastError()) else err;
}

// ---------------------------------------------------------------- a thread's own records

/// Every record the thread's steps kept, walking its chain from `tip` (the
/// input's `tip`) back to its origin, oldest first.
pub fn kept(a: Allocator, tip: []const u8) ![]const []const u8 {
    var chain = std.array_list.Managed([]const Value).init(a);
    var c: []const u8 = tip;
    while (c.len > 0) {
        const u = try get(a, c);
        const seq = Value.intOf(u.get("seq")) orelse 0;
        if (seq < 1) break; // the origin
        try chain.append(if (u.get("kept")) |k| (if (k == .array) k.array else &.{}) else &.{});
        c = Value.cidOf(u.get("prev")) orelse "";
    }
    var out = std.array_list.Managed([]const u8).init(a);
    var i = chain.items.len;
    while (i > 0) {
        i -= 1;
        for (chain.items[i]) |k| if (Value.cidOf(k)) |x| try out.append(x);
    }
    return out.items;
}

// ---------------------------------------------------------------- keys

/// An identity key as records hold it (#33): its 33 bytes, or hex text (a
/// JSON-form sender, kept as the sender made it); null when absent or null.
pub fn keyOf(a: Allocator, v: ?Value) !?[]const u8 {
    const x = v orelse return null;
    return switch (x) {
        .null => null,
        .bytes => |b| b,
        .string => |s| unhex(a, s) orelse report(try std.fmt.allocPrint(a, "identity key \"{s}\": not hex", .{s})),
        else => report("identity key: want bytes or hex"),
    };
}

// ---------------------------------------------------------------- trees

// Trees are git objects byte for byte (kernel-zig/src/tree.zig): "tree
// <len>\0" then entries "<mode> <name>\0<20-byte sha1>"; a file is "blob
// <len>\0<bytes>". An entry's CID is CIDv1 git-raw (0x78) sha1 (0x11) over
// its sha1.

/// The empty tree: the object "tree 0\0" under CIDv1(git-raw, sha1).
pub const empty_tree_object = "tree 0\x00";
pub const empty_tree = [_]u8{ 0x01, 0x78, 0x11, 0x14 } ++ [_]u8{ 0x4b, 0x82, 0x5d, 0xc6, 0x42, 0xcb, 0x6e, 0xb9, 0xa0, 0x60, 0xe5, 0x4b, 0xf8, 0xd6, 0x92, 0x88, 0xfb, 0xee, 0x49, 0x04 };

/// Put the empty tree into the store (so it can be run over).
pub fn putEmptyTree() !void {
    try putBlock(&empty_tree, empty_tree_object);
}

/// The tree a `run` that names none starts from: the `main` head's, else
/// the empty tree (put into the store).
pub fn startTree(a: Allocator) ![]const u8 {
    if (try head(a, "main")) |t| return t;
    try putEmptyTree();
    return &empty_tree;
}

/// A git object's body, after checking its header "<kind> <len>\0".
fn gitBody(obj: []const u8, kind: []const u8) ?[]const u8 {
    const nul = std.mem.indexOfScalar(u8, obj, 0) orelse return null;
    const h = obj[0..nul];
    if (!std.mem.startsWith(u8, h, kind) or h.len < kind.len + 2 or h[kind.len] != ' ') return null;
    const digits = h[kind.len + 1 ..];
    for (digits) |d| if (d < '0' or d > '9') return null;
    const n = std.fmt.parseInt(usize, digits, 10) catch return null;
    if (n != obj.len - nul - 1) return null;
    return obj[nul + 1 ..];
}

pub const TreeEntry = struct { mode: []const u8, name: []const u8, cid: []const u8 };

/// A tree record's entries.
pub fn readTree(a: Allocator, tree: []const u8) ![]const TreeEntry {
    var b = gitBody(try getBytes(a, tree), "tree") orelse return report("not a git tree");
    var out = std.array_list.Managed(TreeEntry).init(a);
    while (b.len > 0) {
        const sp = std.mem.indexOfScalar(u8, b, ' ') orelse return report("truncated git tree");
        const z = std.mem.indexOfScalar(u8, b, 0) orelse return report("truncated git tree");
        if (z < sp or z + 21 > b.len) return report("truncated git tree");
        const c = try a.alloc(u8, 24);
        @memcpy(c[0..4], empty_tree[0..4]);
        @memcpy(c[4..], b[z + 1 .. z + 21]);
        try out.append(.{ .mode = b[0..sp], .name = b[sp + 1 .. z], .cid = c });
        b = b[z + 21 ..];
    }
    return out.items;
}

/// The content of the regular file at `path` ("a/b.md") in `tree`; null when
/// there is no such file (a missing entry, or not a file).
pub fn readFile(a: Allocator, tree: []const u8, path: []const u8) !?[]const u8 {
    var at = tree;
    var segs = std.mem.splitScalar(u8, std.mem.trim(u8, path, "/"), '/');
    while (segs.next()) |seg| {
        const last = segs.peek() == null;
        const found = for (try readTree(a, at)) |e| {
            if (std.mem.eql(u8, e.name, seg)) break e;
        } else return null;
        if (!last and !std.mem.eql(u8, found.mode, "40000")) return null;
        if (last and !std.mem.eql(u8, found.mode, "100644") and !std.mem.eql(u8, found.mode, "100755")) return null;
        at = found.cid;
    }
    return gitBody(try getBytes(a, at), "blob") orelse report("not a git blob");
}

// ---------------------------------------------------------------- reading records as the handlers' shapes

/// A text field of a record: "" when absent or null; another type is an error.
pub fn textField(v: Value, key: []const u8) ![]const u8 {
    const x = v.get(key) orelse return "";
    return switch (x) {
        .null => "",
        .string => |s| s,
        else => fieldError(key, "a string"),
    };
}

/// A link field of a record: its CID, "" when absent or null; another type is an error.
pub fn linkField(v: Value, key: []const u8) ![]const u8 {
    const x = v.get(key) orelse return "";
    return switch (x) {
        .null => "",
        .cid => |c| c,
        else => fieldError(key, "a CID"),
    };
}

/// An integer field of a record: 0 when absent or null; another type is an error.
pub fn intField(v: Value, key: []const u8) !i128 {
    const x = v.get(key) orelse return 0;
    return switch (x) {
        .null => 0,
        .int => |i| i,
        else => fieldError(key, "an integer"),
    };
}

/// A list field of a record: empty when absent or null; another type is an error.
pub fn listField(v: Value, key: []const u8) ![]const Value {
    const x = v.get(key) orelse return &.{};
    return switch (x) {
        .null => &.{},
        .array => |l| l,
        else => fieldError(key, "a list"),
    };
}

var field_error: [160]u8 = undefined;

fn fieldError(key: []const u8, want: []const u8) error{Reported} {
    return report(std.fmt.bufPrint(&field_error, "{s}: not {s}", .{ key[0..@min(key.len, 100)], want }) catch "a field of the wrong type");
}

test "asName: a named call's input carries `as`; a nameless one, and a step, none" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m = cbor.MapBuilder.init(a);
    try m.put("kind", cbor.string("call"));
    try m.put("as", cbor.string("1/amm pool"));
    try std.testing.expectEqualStrings("1/amm pool", asName(m.value()).?);
    var n = cbor.MapBuilder.init(a);
    try n.put("kind", cbor.string("step"));
    try std.testing.expect(asName(n.value()) == null);
}
