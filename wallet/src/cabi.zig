//! The few C library functions wit-bindgen's C bindings call (malloc, realloc
//! for cabi_realloc, free, abort, strlen), for the wallet's component build
//! (issue #34). Not wasi-libc: linking it would switch std.crypto.random to
//! libc's arc4random (another generator over the same entropy), and the
//! component must make the very same draws — and so the very same attested
//! requests — as the preview1 build. Blocks carry their size in front, over
//! std.heap.wasm_allocator as the program's own allocations are.
const std = @import("std");

const alloc = std.heap.wasm_allocator;
const header = 16; // keeps the 8-byte alignment the canonical ABI may ask for

fn block(p: *anyopaque) []align(header) u8 {
    const base: [*]align(header) u8 = @alignCast(@as([*]u8, @ptrCast(p)) - header);
    const n = std.mem.readInt(usize, base[0..@sizeOf(usize)], .little);
    return base[0 .. header + n];
}

export fn malloc(n: usize) ?*anyopaque {
    const b = alloc.alignedAlloc(u8, .fromByteUnits(header), header + n) catch return null;
    std.mem.writeInt(usize, b[0..@sizeOf(usize)], n, .little);
    return b.ptr + header;
}

export fn free(p: ?*anyopaque) void {
    alloc.free(block(p orelse return));
}

export fn realloc(p: ?*anyopaque, n: usize) ?*anyopaque {
    const old = p orelse return malloc(n);
    const b = block(old);
    const q = malloc(n) orelse return null;
    const keep = @min(n, b.len - header);
    @memcpy(@as([*]u8, @ptrCast(q))[0..keep], b[header..][0..keep]);
    alloc.free(b);
    return q;
}

export fn abort() noreturn {
    @trap();
}

export fn strlen(s: [*:0]const u8) usize {
    return std.mem.len(s);
}
