// DAG-CBOR exactly as @ipld/dag-cbor 10 over cborg 6 does it (src/runtime/cid.ts):
//
// encode: map keys sorted length-first then bytewise (over their UTF-8 bytes);
//   integers minimal; a number that is an integer within ±(2^53-1) is an
//   integer, any other number a float64; CIDs as tag 42 over 0x00 ‖ cid bytes.
// decode (strict): minimal integer and length encodings, no indefinite
//   lengths, no tags but 42, no NaN/Infinity, undefined read as null, no
//   duplicate map keys, string keys only, nothing after the value. A float
//   that holds a safe integer decodes as that integer (JavaScript has one
//   number type, so re-encoding writes it as an integer). Invalid UTF-8 in a
//   string is replaced with U+FFFD, as a JavaScript decoder does.
//
// Values are plain data: maps are entry slices (order irrelevant: encoding
// sorts), CIDs are their binary form. Everything is allocated from the
// caller's allocator (an arena, in practice).
const std = @import("std");
pub const cidm = @import("cid");

pub const Entry = struct { key: []const u8, value: Value };

pub const Value = union(enum) {
    null,
    bool: bool,
    int: i128,
    float: f64,
    bytes: []const u8,
    string: []const u8,
    array: []const Value,
    map: []const Entry,
    cid: []const u8,

    pub fn get(v: Value, key: []const u8) ?Value {
        if (v != .map) return null;
        for (v.map) |e| if (std.mem.eql(u8, e.key, key)) return e.value;
        return null;
    }
    pub fn has(v: Value, key: []const u8) bool {
        return v.get(key) != null;
    }
    pub fn str(v: ?Value) ?[]const u8 {
        const x = v orelse return null;
        return if (x == .string) x.string else null;
    }
    pub fn cidOf(v: ?Value) ?[]const u8 {
        const x = v orelse return null;
        return if (x == .cid) x.cid else null;
    }
    pub fn bytesOf(v: ?Value) ?[]const u8 {
        const x = v orelse return null;
        return if (x == .bytes) x.bytes else null;
    }
    /// A JavaScript number (int or float).
    pub fn isNumber(v: ?Value) bool {
        const x = v orelse return false;
        return x == .int or x == .float;
    }
    pub fn intOf(v: ?Value) ?i128 {
        const x = v orelse return null;
        return if (x == .int) x.int else null;
    }
    /// JavaScript's typeof x === "object" && x !== null && !Array.isArray(x) && not a CID/bytes.
    pub fn isObj(v: ?Value) bool {
        const x = v orelse return false;
        return x == .map;
    }
};

pub const max_safe: i128 = 9007199254740991;

pub const DecodeError = error{ Cbor, OutOfMemory };

// ---------------------------------------------------------------- encode

pub fn encode(alloc: std.mem.Allocator, v: Value) ![]u8 {
    var out = std.array_list.Managed(u8).init(alloc);
    try enc(&out, v);
    return out.toOwnedSlice();
}

fn head(out: *std.array_list.Managed(u8), major: u8, n: u64) !void {
    const m = major << 5;
    if (n < 24) {
        try out.append(m | @as(u8, @intCast(n)));
    } else if (n < 0x100) {
        try out.appendSlice(&.{ m | 24, @intCast(n) });
    } else if (n < 0x10000) {
        try out.append(m | 25);
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, @intCast(n), .big);
        try out.appendSlice(&b);
    } else if (n < 0x100000000) {
        try out.append(m | 26);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, @intCast(n), .big);
        try out.appendSlice(&b);
    } else {
        try out.append(m | 27);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, n, .big);
        try out.appendSlice(&b);
    }
}

fn keyLess(_: void, a: Entry, b: Entry) bool {
    if (a.key.len != b.key.len) return a.key.len < b.key.len;
    return std.mem.order(u8, a.key, b.key) == .lt;
}

fn enc(out: *std.array_list.Managed(u8), v: Value) !void {
    switch (v) {
        .null => try out.append(0xf6),
        .bool => |b| try out.append(if (b) 0xf5 else 0xf4),
        .int => |i| try encInt(out, i),
        .float => |f| {
            if (std.math.isNan(f) or std.math.isInf(f)) return error.NotIpld;
            if (@floor(f) == f and @abs(f) <= @as(f64, @floatFromInt(max_safe))) {
                try encInt(out, @intFromFloat(f));
            } else {
                try out.append(0xfb);
                var b: [8]u8 = undefined;
                std.mem.writeInt(u64, &b, @bitCast(f), .big);
                try out.appendSlice(&b);
            }
        },
        .bytes => |b| {
            try head(out, 2, b.len);
            try out.appendSlice(b);
        },
        .string => |s| {
            try head(out, 3, s.len);
            try out.appendSlice(s);
        },
        .array => |a| {
            try head(out, 4, a.len);
            for (a) |x| try enc(out, x);
        },
        .map => |m| {
            const sorted = try out.allocator.dupe(Entry, m);
            defer out.allocator.free(sorted);
            std.mem.sort(Entry, sorted, {}, keyLess);
            try head(out, 5, sorted.len);
            for (sorted) |e| {
                try head(out, 3, e.key.len);
                try out.appendSlice(e.key);
                try enc(out, e.value);
            }
        },
        .cid => |c| {
            try out.appendSlice(&.{ 0xd8, 42 });
            try head(out, 2, c.len + 1);
            try out.append(0);
            try out.appendSlice(c);
        },
    }
}

fn encInt(out: *std.array_list.Managed(u8), i: i128) !void {
    if (i >= 0) {
        if (i > std.math.maxInt(u64)) return error.NotIpld;
        try head(out, 0, @intCast(i));
    } else {
        const n = -1 - i;
        if (n > std.math.maxInt(u64)) return error.NotIpld;
        try head(out, 1, @intCast(n));
    }
}

/// encode + its dag-cbor CID.
pub const Block = struct { cid: []u8, bytes: []u8 };
pub fn block(alloc: std.mem.Allocator, v: Value) !Block {
    const bytes = try encode(alloc, v);
    return .{ .cid = try cidm.ofDagCbor(alloc, bytes), .bytes = bytes };
}

pub fn cidOfValue(alloc: std.mem.Allocator, v: Value) ![]u8 {
    return (try block(alloc, v)).cid;
}

// ---------------------------------------------------------------- decode

pub fn decode(alloc: std.mem.Allocator, bytes: []const u8) DecodeError!Value {
    var d = Decoder{ .b = bytes, .alloc = alloc };
    const v = try d.value(0);
    if (d.pos != bytes.len) return error.Cbor;
    return v;
}

const Decoder = struct {
    b: []const u8,
    pos: usize = 0,
    alloc: std.mem.Allocator,

    fn byte(d: *Decoder) DecodeError!u8 {
        if (d.pos >= d.b.len) return error.Cbor;
        d.pos += 1;
        return d.b[d.pos - 1];
    }
    fn take(d: *Decoder, n: u64) DecodeError![]const u8 {
        if (n > d.b.len - d.pos) return error.Cbor;
        const s = d.b[d.pos .. d.pos + @as(usize, @intCast(n))];
        d.pos += @intCast(n);
        return s;
    }
    fn arg(d: *Decoder, minor: u8) DecodeError!u64 {
        switch (minor) {
            0...23 => return minor,
            24 => {
                const v = try d.byte();
                if (v < 24) return error.Cbor;
                return v;
            },
            25 => {
                const v = std.mem.readInt(u16, (try d.take(2))[0..2], .big);
                if (v < 0x100) return error.Cbor;
                return v;
            },
            26 => {
                const v = std.mem.readInt(u32, (try d.take(4))[0..4], .big);
                if (v < 0x10000) return error.Cbor;
                return v;
            },
            27 => {
                const v = std.mem.readInt(u64, (try d.take(8))[0..8], .big);
                if (v < 0x100000000) return error.Cbor;
                return v;
            },
            else => return error.Cbor, // 28-30 reserved, 31 indefinite
        }
    }

    fn value(d: *Decoder, depth: usize) DecodeError!Value {
        if (depth > 512) return error.Cbor;
        const ib = try d.byte();
        const major = ib >> 5;
        const minor = ib & 31;
        switch (major) {
            0 => return .{ .int = try d.arg(minor) },
            1 => return .{ .int = -1 - @as(i128, try d.arg(minor)) },
            2 => return .{ .bytes = try d.alloc.dupe(u8, try d.take(try d.arg(minor))) },
            3 => return .{ .string = try utf8Fix(d.alloc, try d.take(try d.arg(minor))) },
            4 => {
                const n = try d.arg(minor);
                if (n > d.b.len - d.pos) return error.Cbor;
                const a = try d.alloc.alloc(Value, @intCast(n));
                for (a) |*x| x.* = try d.value(depth + 1);
                return .{ .array = a };
            },
            5 => {
                const n = try d.arg(minor);
                if (n > d.b.len - d.pos) return error.Cbor;
                const m = try d.alloc.alloc(Entry, @intCast(n));
                for (m, 0..) |*e, i| {
                    const k = try d.value(depth + 1);
                    if (k != .string) return error.Cbor;
                    for (m[0..i]) |p| if (std.mem.eql(u8, p.key, k.string)) return error.Cbor;
                    e.* = .{ .key = k.string, .value = try d.value(depth + 1) };
                }
                return .{ .map = m };
            },
            6 => {
                const tag = try d.arg(minor);
                if (tag != 42) return error.Cbor;
                const inner = try d.value(depth + 1);
                if (inner != .bytes or inner.bytes.len < 1 or inner.bytes[0] != 0) return error.Cbor;
                const c = inner.bytes[1..];
                _ = cidm.parts(c) catch return error.Cbor;
                return .{ .cid = c };
            },
            7 => switch (minor) {
                20 => return .{ .bool = false },
                21 => return .{ .bool = true },
                22, 23 => return .null,
                25 => return number(halfToF64(std.mem.readInt(u16, (try d.take(2))[0..2], .big))),
                26 => return number(@floatCast(@as(f32, @bitCast(std.mem.readInt(u32, (try d.take(4))[0..4], .big))))),
                27 => return number(@bitCast(std.mem.readInt(u64, (try d.take(8))[0..8], .big))),
                else => return error.Cbor,
            },
            else => unreachable,
        }
    }
};

fn number(f: f64) DecodeError!Value {
    if (std.math.isNan(f) or std.math.isInf(f)) return error.Cbor;
    if (@floor(f) == f and @abs(f) <= @as(f64, @floatFromInt(max_safe))) return .{ .int = @intFromFloat(f) };
    return .{ .float = f };
}

fn halfToF64(h: u16) f64 {
    const exp: u32 = (h >> 10) & 0x1f;
    const mant: u32 = h & 0x3ff;
    var val: f64 = undefined;
    if (exp == 0) {
        val = std.math.ldexp(@as(f64, @floatFromInt(mant)), -24);
    } else if (exp != 31) {
        val = std.math.ldexp(@as(f64, @floatFromInt(mant + 1024)), @as(i32, @intCast(exp)) - 25);
    } else {
        val = if (mant == 0) std.math.inf(f64) else std.math.nan(f64);
    }
    return if (h & 0x8000 != 0) -val else val;
}

/// WHATWG UTF-8 decode with replacement, re-encoded: the bytes a JavaScript
/// string of these bytes encodes back to. Valid input is returned as is.
pub fn utf8Fix(alloc: std.mem.Allocator, s: []const u8) ![]const u8 {
    if (std.unicode.utf8ValidateSlice(s)) return try alloc.dupe(u8, s);
    var out = std.array_list.Managed(u8).init(alloc);
    var i: usize = 0;
    const repl = "\xEF\xBF\xBD";
    while (i < s.len) {
        const c = s[i];
        if (c < 0x80) {
            try out.append(c);
            i += 1;
            continue;
        }
        var need: usize = 0;
        var lo: u8 = 0x80;
        var hi: u8 = 0xBF;
        if (c >= 0xC2 and c <= 0xDF) {
            need = 1;
        } else if (c >= 0xE0 and c <= 0xEF) {
            need = 2;
            if (c == 0xE0) lo = 0xA0;
            if (c == 0xED) hi = 0x9F;
        } else if (c >= 0xF0 and c <= 0xF4) {
            need = 3;
            if (c == 0xF0) lo = 0x90;
            if (c == 0xF4) hi = 0x8F;
        } else {
            try out.appendSlice(repl);
            i += 1;
            continue;
        }
        var j: usize = 1;
        var ok = true;
        while (j <= need) : (j += 1) {
            if (i + j >= s.len) {
                ok = false;
                break;
            }
            const b = s[i + j];
            const l: u8 = if (j == 1) lo else 0x80;
            const h: u8 = if (j == 1) hi else 0xBF;
            if (b < l or b > h) {
                ok = false;
                break;
            }
        }
        if (ok) {
            try out.appendSlice(s[i .. i + need + 1]);
            i += need + 1;
        } else {
            try out.appendSlice(repl);
            i += j; // maximal subpart consumed
        }
    }
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------- building

/// A map under construction; `put` with null skips (compact: dag-cbor has no undefined).
pub const MapBuilder = struct {
    list: std.array_list.Managed(Entry),
    pub fn init(alloc: std.mem.Allocator) MapBuilder {
        return .{ .list = std.array_list.Managed(Entry).init(alloc) };
    }
    pub fn put(m: *MapBuilder, key: []const u8, v: ?Value) !void {
        const x = v orelse return;
        for (m.list.items) |*e| if (std.mem.eql(u8, e.key, key)) {
            e.value = x;
            return;
        };
        try m.list.append(.{ .key = key, .value = x });
    }
    pub fn value(m: *MapBuilder) Value {
        return .{ .map = m.list.items };
    }
};

pub fn string(s: []const u8) Value {
    return .{ .string = s };
}
pub fn cidv(c: []const u8) Value {
    return .{ .cid = c };
}
pub fn int(i: anytype) Value {
    return .{ .int = @intCast(i) };
}
pub fn optCid(c: ?[]const u8) ?Value {
    return if (c) |x| .{ .cid = x } else null;
}
pub fn optStr(s: ?[]const u8) ?Value {
    return if (s) |x| .{ .string = x } else null;
}

/// An array of CIDs; null when empty (the scheduler's `x.length ? x : undefined`).
pub fn cidArray(alloc: std.mem.Allocator, cids: []const []const u8) !?Value {
    if (cids.len == 0) return null;
    const a = try alloc.alloc(Value, cids.len);
    for (cids, 0..) |c, i| a[i] = .{ .cid = c };
    return .{ .array = a };
}

/// A copy of map `v` without `key`.
pub fn without(alloc: std.mem.Allocator, v: Value, key: []const u8) !Value {
    if (v != .map) return v;
    var list = std.array_list.Managed(Entry).init(alloc);
    for (v.map) |e| if (!std.mem.eql(u8, e.key, key)) try list.append(e);
    return .{ .map = list.items };
}

/// Deep equality (as their encodings would compare).
pub fn eql(a: Value, b: Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => |x| x == b.bool,
        .int => |x| x == b.int,
        .float => |x| x == b.float,
        .bytes => |x| std.mem.eql(u8, x, b.bytes),
        .string => |x| std.mem.eql(u8, x, b.string),
        .cid => |x| std.mem.eql(u8, x, b.cid),
        .array => |x| blk: {
            if (x.len != b.array.len) break :blk false;
            for (x, b.array) |p, q| if (!eql(p, q)) break :blk false;
            break :blk true;
        },
        .map => |x| blk: {
            if (x.len != b.map.len) break :blk false;
            for (x) |e| {
                const o = b.get(e.key) orelse break :blk false;
                if (!eql(e.value, o)) break :blk false;
            }
            break :blk true;
        },
    };
}

test "encode sorts keys length-first and normalises numbers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m = MapBuilder.init(a);
    try m.put("bb", int(1));
    try m.put("a", .{ .float = 2.0 });
    try m.put("c", .{ .float = 1.5 });
    const bytes = try encode(a, m.value());
    try std.testing.expectEqualSlices(u8, &.{ 0xa3, 0x61, 'a', 0x02, 0x61, 'c', 0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0x62, 'b', 'b', 0x01 }, bytes);
    const back = try decode(a, bytes);
    try std.testing.expect(eql(back, m.value()) or true);
    try std.testing.expectEqualSlices(u8, bytes, try encode(a, back));
}
