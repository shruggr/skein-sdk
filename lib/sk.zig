//! The `skein` import namespace for the Zig programs (the front door, the
//! messagebox, resolve): preview1 imports with f(…, out, cap) → n and `take`
//! for a result that did not fit (kernel-zig/src/program.zig), wrapped so a
//! program says `sk.get(a, cid)` and gets the bytes or an error whose
//! message `lastError()` holds.
const std = @import("std");
const cbor = @import("cbor");

pub const Value = cbor.Value;
pub const Allocator = std.mem.Allocator;

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
    pub extern "skein" fn http(req: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    pub extern "skein" fn libp2p(req: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
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

/// A BRC-100 wire frame to the oracle → its result frame.
pub fn wallet(a: Allocator, frame: []const u8) ![]u8 {
    return result(a, raw.wallet, .{ frame.ptr, n32(frame.len) });
}

/// One HTTP request {method, url, headers?, body?} → {status, headers, body}.
pub fn http(a: Allocator, req: Value) !Value {
    const bytes = try cbor.encode(a, req);
    return cbor.decode(a, try result(a, raw.http, .{ bytes.ptr, n32(bytes.len) }));
}

/// One libp2p request (#51) {op: "publish" | "dial" | "send" | "receive" | "close", …}
/// → its result, answered by the router's libp2p host and recorded; a failure
/// (the host's {error}) is the import's error, `lastError()`.
pub fn libp2p(a: Allocator, req: Value) !Value {
    const bytes = try cbor.encode(a, req);
    return cbor.decode(a, try result(a, raw.libp2p, .{ bytes.ptr, n32(bytes.len) }));
}

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
    try std.fs.File.stdout().writeAll(try cbor.encode(a, v));
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
        std.fs.File.stderr().writeAll(msg) catch {};
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
