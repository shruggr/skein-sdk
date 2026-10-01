//! The skein calls for the component build of the wallet (issue #34): the
//! WIT interface skein:kernel/skein (../../wit/skein.wit) through the C
//! bindings wit-bindgen emits (../../wit/bindings/c/program.h, compiled in
//! with program.c), presented with the same signatures as the preview1
//! `skein` imports program.zig declares — so program.zig is one source for
//! both builds and nothing above this file knows which ABI it runs on.
//!
//! The canonical ABI hands back whole results (allocated by the guest's
//! cabi_realloc: realloc from cabi.zig); this file keeps the last one for
//! `take` and the last error for `error`, as the preview1 host does.
const std = @import("std");
const c = @cImport(@cInclude("program.h"));

comptime {
    _ = @import("cabi.zig");
}

var held: c.program_list_u8_t = .{ .ptr = null, .len = 0 };
var last_error: []const u8 = "";
var err_buf: [4096]u8 = undefined;

fn hold(r: c.program_list_u8_t, out: [*]u8, cap: u32) i32 {
    c.program_list_u8_free(&held);
    held = r;
    if (r.len <= cap and r.len > 0) @memcpy(out[0..r.len], r.ptr[0..r.len]);
    return @intCast(r.len);
}

fn holdCid(r: c.skein_kernel_skein_cid_t, out: [*]u8, cap: u32) i32 {
    return hold(.{ .ptr = r.ptr, .len = r.len }, out, cap);
}

fn fail(e: *c.program_string_t) i32 {
    const n = @min(e.len, err_buf.len);
    if (n > 0) @memcpy(err_buf[0..n], e.ptr[0..n]);
    last_error = err_buf[0..n];
    c.program_string_free(e);
    return -1;
}

fn cid(p: [*]const u8, n: u32) c.skein_kernel_skein_cid_t {
    return .{ .ptr = @constCast(p), .len = n };
}

fn list(p: [*]const u8, n: u32) c.program_list_u8_t {
    return .{ .ptr = @constCast(p), .len = n };
}

fn str(p: [*]const u8, n: u32) c.program_string_t {
    return .{ .ptr = @constCast(p), .len = n };
}

pub fn input(out: [*]u8, cap: u32) i32 {
    var r: c.program_list_u8_t = undefined;
    c.skein_kernel_skein_input(&r);
    return hold(r, out, cap);
}

pub fn get(p: [*]const u8, n: u32, out: [*]u8, cap: u32) i32 {
    var k = cid(p, n);
    var r: c.program_list_u8_t = undefined;
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_get(&k, &r, &e)) return fail(&e);
    return hold(r, out, cap);
}

pub fn put(p: [*]const u8, n: u32, out: [*]u8, cap: u32) i32 {
    var d = list(p, n);
    var r: c.skein_kernel_skein_cid_t = undefined;
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_put(&d, &r, &e)) return fail(&e);
    return holdCid(r, out, cap);
}

pub fn putblock(p: [*]const u8, n: u32, data: [*]const u8, len: u32) i32 {
    var k = cid(p, n);
    var d = list(data, len);
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_putblock(&k, &d, &e)) return fail(&e);
    return 0;
}

pub fn keep(p: [*]const u8, n: u32) i32 {
    var k = cid(p, n);
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_keep(&k, &e)) return fail(&e);
    return 0;
}

pub fn head(name: [*]const u8, n: u32, out: [*]u8, cap: u32) i32 {
    var s = str(name, n);
    var r: c.skein_kernel_skein_option_cid_t = undefined;
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_head(&s, &r, &e)) return fail(&e);
    // none: an empty result, as the preview1 import gives (n = 0)
    return if (r.is_some) holdCid(r.val, out, cap) else hold(.{ .ptr = null, .len = 0 }, out, cap);
}

pub fn advance(name: [*]const u8, n: u32, tree: [*]const u8, tree_len: u32) i32 {
    var s = str(name, n);
    var t = cid(tree, tree_len);
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_advance(&s, &t, &e)) return fail(&e);
    return 0;
}

pub fn wallet(frame: [*]const u8, n: u32, out: [*]u8, cap: u32) i32 {
    var f = list(frame, n);
    var r: c.program_list_u8_t = undefined;
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_wallet(&f, &r, &e)) return fail(&e);
    return hold(r, out, cap);
}

/// The edges into `to` (#42); rel_len = 0: any rel.
pub fn edges(to: [*]const u8, to_len: u32, rel: [*]const u8, rel_len: u32, out: [*]u8, cap: u32) i32 {
    var k = cid(to, to_len);
    var r: c.program_list_u8_t = undefined;
    var e: c.program_string_t = undefined;
    const ok = if (rel_len > 0) blk: {
        var s = str(rel, rel_len);
        break :blk c.skein_kernel_skein_edges(&k, &s, &r, &e);
    } else c.skein_kernel_skein_edges(&k, null, &r, &e);
    if (!ok) return fail(&e);
    return hold(r, out, cap);
}

/// The one outbound primitive (#70): a dag-cbor {to, box, body, subject?} → the message's CID.
pub fn emit(p: [*]const u8, n: u32, out: [*]u8, cap: u32) i32 {
    var d = list(p, n);
    var r: c.skein_kernel_skein_cid_t = undefined;
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_emit(&d, &r, &e)) return fail(&e);
    return holdCid(r, out, cap);
}

pub fn deadline(until: i64) i32 {
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_deadline(until, &e)) return fail(&e);
    return 0;
}

pub fn @"await"(p: [*]const u8, n: u32) i32 {
    var k = cid(p, n);
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_await(&k, &e)) return fail(&e);
    return 0;
}

/// An in-VM call (#40): a program's function → what it wrote to stdout.
pub fn call(p: [*]const u8, n: u32, func: [*]const u8, func_len: u32, arg: [*]const u8, arg_len: u32, out: [*]u8, cap: u32) i32 {
    var k = cid(p, n);
    var f = str(func, func_len);
    var d = list(arg, arg_len);
    var r: c.program_list_u8_t = undefined;
    var e: c.program_string_t = undefined;
    if (!c.skein_kernel_skein_call(&k, &f, &d, &r, &e)) return fail(&e);
    return hold(r, out, cap);
}

pub fn take(out: [*]u8, cap: u32) i32 {
    if (held.len > cap) {
        last_error = "take: buffer too small";
        return -1;
    }
    if (held.len > 0) @memcpy(out[0..held.len], held.ptr[0..held.len]);
    return @intCast(held.len);
}

pub fn @"error"(out: [*]u8, cap: u32) i32 {
    const n = @min(cap, last_error.len);
    @memcpy(out[0..n], last_error[0..n]);
    return @intCast(last_error.len);
}
