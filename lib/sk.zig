//! The `skein` import namespace for the Zig programs (the front door, the
//! messagebox, resolve, the workbench's run and loop, and every app's
//! handler): preview1 imports with f(…, out, cap) → n and `take` for a result
//! that did not fit (kernel-zig/src/program.zig), wrapped so a program says
//! `sk.get(a, cid)` and gets the bytes or an error whose message
//! `lastError()` holds. Below the imports, what a handler builds on them:
//! its thread's kept records, messages, delivery through the messagebox's
//! `send`, the address book and resolving a handle, and trees.
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
    pub extern "skein" fn @"await"(cid: [*]const u8, cid_len: u32) i32;
    pub extern "skein" fn head(name: [*]const u8, name_len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn advance(name: [*]const u8, name_len: u32, tree: [*]const u8, tree_len: u32) i32;
    pub extern "skein" fn wallet(frame: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn emit(msg: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn deadline(until_ms: i64) i32;
    pub extern "skein" fn call(prog: [*]const u8, prog_len: u32, func: [*]const u8, func_len: u32, arg: [*]const u8, arg_len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn take(out: [*]u8, cap: u32) i32;
    pub extern "skein" fn @"error"(out: [*]u8, cap: u32) i32;
    pub extern "skein" fn edges(to: [*]const u8, to_len: u32, rel: [*]const u8, rel_len: u32, out: [*]u8, cap: u32) i32;
};

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

pub fn awaitRecord(c: []const u8) !void {
    if (raw.@"await"(c.ptr, n32(c.len)) < 0) return failed();
}

/// The CID a head names, or null.
pub fn head(a: Allocator, name: []const u8) !?[]u8 {
    const r = try result(a, raw.head, .{ name.ptr, n32(name.len) });
    return if (r.len == 0) null else r;
}

pub fn advance(name: []const u8, c: []const u8) !void {
    if (raw.advance(name.ptr, n32(name.len), c.ptr, n32(c.len)) < 0) return failed();
}

/// Launch a thread running `prog` (a program record) with the record `args`
/// as its arguments; its origin CID. The thread starts when this step ends,
/// and this step's thread then waits on it.
pub fn launch(a: Allocator, prog: []const u8, args: []const u8) ![]u8 {
    return result(a, raw.launch, .{ prog.ptr, n32(prog.len), args.ptr, n32(args.len) });
}

// There is no `subscribe` (skein-sdk 0.3.0, shruggr/skein#77): the dispatch
// table is the kernel's, changed by admin messages (box `dispatch`) from the
// owner or a delegate, never by a program import.

/// A BRC-100 wire frame to the oracle → its result frame.
pub fn wallet(a: Allocator, frame: []const u8) ![]u8 {
    return result(a, raw.wallet, .{ frame.ptr, n32(frame.len) });
}

/// Emit a signed message (#70): `body` (a record) to identity `to` in `box`,
/// about `subject` if given → the message's CID. `to` must be in the address
/// book; the message goes out when this step ends without error. Its answer
/// is an entry: `awaitRecord` the CID and end the step, and the reply steps
/// the thread (input `reply`), or `undelivered` if a mailbox delivery gave up.
pub fn emit(a: Allocator, to: []const u8, box: []const u8, body: Value, subject: ?[]const u8) ![]u8 {
    var m = cbor.MapBuilder.init(a);
    try m.put("to", .{ .bytes = to });
    try m.put("box", .{ .string = box });
    try m.put("body", .{ .bytes = try cbor.encode(a, body) });
    if (subject) |s| try m.put("subject", cbor.cidv(s));
    const bytes = try cbor.encode(a, m.value());
    return result(a, raw.emit, .{ bytes.ptr, n32(bytes.len) });
}

/// Broadcast a transaction (#65): the event {event: "broadcast", tx: <its
/// CID, held>, beef?: <its Atomic BEEF>}, unauthenticated and addressed to no
/// one — the host's wiring carries it to the network. → the event record's
/// CID. Await the transaction's CID to rest on its proof (an event) or a
/// status provider's message about it.
pub fn broadcast(a: Allocator, tx: []const u8, beef: ?[]const u8) ![]u8 {
    var m = cbor.MapBuilder.init(a);
    try m.put("event", .{ .string = "broadcast" });
    try m.put("tx", cbor.cidv(tx));
    if (beef) |b| try m.put("beef", .{ .bytes = b });
    const bytes = try cbor.encode(a, m.value());
    return result(a, raw.emit, .{ bytes.ptr, n32(bytes.len) });
}

/// Rest until `until_ms` at most (#70: a wake-me to the waker, emitted when the step ends; its answer steps the thread with `woke`).
pub fn deadline(until_ms: i64) !void {
    if (raw.deadline(until_ms) < 0) return failed();
}

/// An in-VM call: `prog`'s function `func` with `arg` → what it wrote to stdout.
pub fn call(a: Allocator, prog: []const u8, func: []const u8, arg: []const u8) ![]u8 {
    return result(a, raw.call, .{ prog.ptr, n32(prog.len), func.ptr, n32(func.len), arg.ptr, n32(arg.len) });
}

/// An in-VM call with dag-cbor in and out.
pub fn callValue(a: Allocator, prog: []const u8, func: []const u8, arg: Value) !Value {
    return cbor.decode(a, try call(a, prog, func, try cbor.encode(a, arg)));
}

/// Write the answer of a call (stdout) as dag-cbor.
pub fn answer(a: Allocator, v: Value) !void {
    try std.Io.File.stdout().writeStreamingAll(io(), try cbor.encode(a, v));
}

/// The genesis program named `name` in an input's `programs`.
pub fn program(in: Value, name: []const u8) ?[]const u8 {
    const ps = in.get("programs") orelse return null;
    return Value.cidOf(ps.get(name));
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

// ---------------------------------------------------------------- messages

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

/// A message record (#40): {kind, op, sender, recipient, box, body, json?}.
/// Its CID is the message's id, what a reply's replyTo names.
pub fn readMessage(a: Allocator, message: []const u8) !Value {
    const b = getBytes(a, message) catch |e| return wrap(a, "get message", e);
    const m = cbor.decode(a, b) catch return report("message record: not dag-cbor");
    if (m != .map) return report("message record: not a map");
    return m;
}

/// A message's body record (dag-cbor), after reading the message itself.
pub fn readBody(a: Allocator, message: []const u8, body: []const u8) !Value {
    _ = try readMessage(a, message);
    const b = getBytes(a, body) catch |e| return wrap(a, "get body", e);
    return cbor.decode(a, b) catch report("body: not dag-cbor");
}

/// Whether a failure may pass (no answer, 5xx, 408, 425, 429): the
/// messagebox's delivery and resolve mark those "transient: …".
pub fn transient(msg: []const u8) bool {
    return std.mem.indexOf(u8, msg, "transient: ") != null;
}

/// Send `body` to identity `to` in `box` (#70): an `emit` — the message goes
/// out by `to`'s transport when this step ends (a mailbox recipient's
/// through the messagebox program's delivery thread, over this instance's own
/// BRC-103/104 session). Its CID is the message's id, what a reply's
/// `replyTo` names: `awaitRecord` it to rest on the reply.
pub fn send(a: Allocator, to: []const u8, box: []const u8, body: Value) ![]const u8 {
    return emit(a, to, box, body, null);
}

/// The address book (#70, the head `peers`): its peer records {kind: "peer",
/// key, transport, address, role?, handle?, domain?, since, source}, this
/// step's own writes included.
pub fn peers(a: Allocator) ![]const Value {
    const root = (try head(a, "peers")) orelse return &.{};
    const t = try get(a, root);
    const list = t.get("peers") orelse return &.{};
    if (list != .array) return report("peers: not a list");
    const out = try a.alloc(Value, list.array.len);
    for (list.array, out) |x, *o| {
        o.* = try get(a, Value.cidOf(x.get("peer")) orelse return report("peers: an entry names no peer record"));
    }
    return out;
}

/// The key the address book names for a BRC-169 handle, or null (resolve it:
/// `launchResolve`).
pub fn peerByHandle(a: Allocator, handle: []const u8, domain: []const u8) !?[]const u8 {
    for (try peers(a)) |p| {
        if (std.mem.eql(u8, Value.str(p.get("handle")) orelse "", handle) and std.mem.eql(u8, Value.str(p.get("domain")) orelse "", domain)) {
            if (try keyOf(a, p.get("key"))) |k| return k;
        }
    }
    return null;
}

/// The address book's entry for `key`, or null.
pub fn peerOf(a: Allocator, key: []const u8) !?Value {
    for (try peers(a)) |p| if (std.mem.eql(u8, Value.bytesOf(p.get("key")) orelse "", key)) return p;
    return null;
}

/// The key of the provider playing `role` for this instance (#70: `fetch`,
/// `libp2p`, `waker`; #69: `cron`; #65: `status`): the address book entry
/// with that role — on this host (`local`) or a remote one (`mailbox`).
pub fn provider(a: Allocator, role: []const u8) ![]const u8 {
    for (try peers(a)) |p| if (std.mem.eql(u8, Value.str(p.get("role")) orelse "", role)) {
        if (Value.bytesOf(p.get("key"))) |k| return k;
    };
    return report(try std.fmt.allocPrint(a, "no {s} provider in the address book (an entry with role \"{s}\")", .{ role, role }));
}

/// Resolve a BRC-169 handle (#70: external communication is a thread): launch
/// the resolve program on {handle, domain, key?}; this step then waits on it,
/// and when it finishes the address book names the handle (its result is the
/// peer record) — or it errored (`resolved[i].error`). Its origin CID.
pub fn launchResolve(a: Allocator, in: Value, handle: []const u8, domain: []const u8, key: ?[]const u8) ![]const u8 {
    const rp = program(in, "resolve") orelse return report(try std.fmt.allocPrint(a, "resolve @{s}@{s}: no resolve program in the genesis", .{ handle, domain }));
    var q = cbor.MapBuilder.init(a);
    try q.put("handle", .{ .string = handle });
    try q.put("domain", .{ .string = domain });
    if (key) |k| try q.put("key", .{ .bytes = k });
    return launch(a, rp, try put(a, q.value()));
}

/// One HTTP request through the `fetch` provider (#70): {method, url,
/// headers?, body?, timeoutMs?} emitted to it (box "fetch") → the message's
/// CID; awaited here. Its answer, the reply's body, is {replyTo, status,
/// headers, body} or {replyTo, error} (no answer at all).
pub fn fetch(a: Allocator, method: []const u8, url: []const u8, headers: ?Value, body: ?[]const u8) ![]const u8 {
    var q = cbor.MapBuilder.init(a);
    try q.put("method", .{ .string = method });
    try q.put("url", .{ .string = url });
    if (headers) |h| try q.put("headers", h);
    if (body) |b| try q.put("body", .{ .bytes = b });
    const id = try emit(a, try provider(a, "fetch"), "fetch", q.value(), null);
    try awaitRecord(id);
    return id;
}

/// A reply that woke this step (input `reply`): the message, its body record, and what it answers.
pub const Reply = struct { message: []const u8, body: Value, box: []const u8, sender: []const u8, reply_to: []const u8 };

pub fn replyOf(a: Allocator, in: Value) !?Reply {
    const r = in.get("reply") orelse return null;
    if (r != .map) return null;
    const message = Value.cidOf(r.get("message")) orelse return null;
    return .{
        .message = message,
        .body = try get(a, Value.cidOf(r.get("body")) orelse return report("reply: no body")),
        .box = Value.str(r.get("box")) orelse "",
        .sender = Value.bytesOf(r.get("sender")) orelse "",
        .reply_to = Value.cidOf(r.get("replyTo")) orelse "",
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
