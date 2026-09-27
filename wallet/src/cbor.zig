//! A small dag-cbor codec: what the wallet's records need and nothing more.
//! Decoding builds a `Value` tree whose slices point into the input (or into
//! the arena for nested containers). Encoding is canonical dag-cbor: shortest
//! integer forms, definite lengths, map keys (text only) sorted by length then
//! bytewise, CIDs as tag 42 over 0x00 ‖ binary CID. The runtime re-encodes
//! every `put` canonically, so records written here hash the same there.
const std = @import("std");

pub const Error = error{ InvalidCbor, UnsupportedCbor, OutOfMemory };

pub const Entry = struct { key: []const u8, value: Value };

pub const Value = union(enum) {
    uint: u64,
    /// A negative integer: the value is -1 - n.
    nint: u64,
    bytes: []const u8,
    text: []const u8,
    array: []const Value,
    map: []const Entry,
    /// A link: the binary CID (without dag-cbor's 0x00 prefix).
    cid: []const u8,
    boolean: bool,
    null,
    float: f64,

    pub fn get(self: Value, key: []const u8) ?Value {
        if (self != .map) return null;
        for (self.map) |e| if (std.mem.eql(u8, e.key, key)) return e.value;
        return null;
    }
    pub fn getText(self: Value, key: []const u8) ?[]const u8 {
        const v = self.get(key) orelse return null;
        return if (v == .text) v.text else null;
    }
    pub fn getBytes(self: Value, key: []const u8) ?[]const u8 {
        const v = self.get(key) orelse return null;
        return if (v == .bytes) v.bytes else null;
    }
    pub fn getCid(self: Value, key: []const u8) ?[]const u8 {
        const v = self.get(key) orelse return null;
        return if (v == .cid) v.cid else null;
    }
    pub fn getUint(self: Value, key: []const u8) ?u64 {
        const v = self.get(key) orelse return null;
        return if (v == .uint) v.uint else null;
    }
    pub fn getArray(self: Value, key: []const u8) ?[]const Value {
        const v = self.get(key) orelse return null;
        return if (v == .array) v.array else null;
    }
    pub fn getBool(self: Value, key: []const u8) ?bool {
        const v = self.get(key) orelse return null;
        return if (v == .boolean) v.boolean else null;
    }
};

// ---------------------------------------------------------------- decode

pub fn decode(arena: std.mem.Allocator, data: []const u8) Error!Value {
    var d = Decoder{ .arena = arena, .data = data };
    const v = try d.value(0);
    if (d.pos != data.len) return error.InvalidCbor;
    return v;
}

const Decoder = struct {
    arena: std.mem.Allocator,
    data: []const u8,
    pos: usize = 0,

    fn byte(self: *Decoder) Error!u8 {
        if (self.pos >= self.data.len) return error.InvalidCbor;
        defer self.pos += 1;
        return self.data[self.pos];
    }

    fn take(self: *Decoder, n: u64) Error![]const u8 {
        if (n > self.data.len - self.pos) return error.InvalidCbor;
        const k: usize = @intCast(n);
        defer self.pos += k;
        return self.data[self.pos..][0..k];
    }

    fn argument(self: *Decoder, info: u5) Error!u64 {
        return switch (info) {
            0...23 => info,
            24 => try self.byte(),
            25 => std.mem.readInt(u16, (try self.take(2))[0..2], .big),
            26 => std.mem.readInt(u32, (try self.take(4))[0..4], .big),
            27 => std.mem.readInt(u64, (try self.take(8))[0..8], .big),
            else => error.UnsupportedCbor, // indefinite lengths are not dag-cbor
        };
    }

    fn value(self: *Decoder, depth: usize) Error!Value {
        if (depth > 64) return error.UnsupportedCbor;
        const ib = try self.byte();
        const major: u3 = @intCast(ib >> 5);
        const info: u5 = @intCast(ib & 0x1f);
        switch (major) {
            0 => return .{ .uint = try self.argument(info) },
            1 => return .{ .nint = try self.argument(info) },
            2 => return .{ .bytes = try self.take(try self.argument(info)) },
            3 => {
                const s = try self.take(try self.argument(info));
                if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidCbor;
                return .{ .text = s };
            },
            4 => {
                const n = try self.argument(info);
                if (n > self.data.len - self.pos) return error.InvalidCbor;
                const items = try self.arena.alloc(Value, @intCast(n));
                for (items) |*it| it.* = try self.value(depth + 1);
                return .{ .array = items };
            },
            5 => {
                const n = try self.argument(info);
                if (n > self.data.len - self.pos) return error.InvalidCbor;
                const entries = try self.arena.alloc(Entry, @intCast(n));
                for (entries) |*e| {
                    const k = try self.value(depth + 1);
                    if (k != .text) return error.UnsupportedCbor; // dag-cbor: string keys only
                    e.* = .{ .key = k.text, .value = try self.value(depth + 1) };
                }
                return .{ .map = entries };
            },
            6 => {
                const tag = try self.argument(info);
                if (tag != 42) return error.UnsupportedCbor;
                const inner = try self.value(depth + 1);
                if (inner != .bytes or inner.bytes.len < 2 or inner.bytes[0] != 0) return error.InvalidCbor;
                return .{ .cid = inner.bytes[1..] };
            },
            7 => return switch (info) {
                20 => .{ .boolean = false },
                21 => .{ .boolean = true },
                22 => .null,
                25 => .{ .float = @floatCast(@as(f16, @bitCast(std.mem.readInt(u16, (try self.take(2))[0..2], .big)))) },
                26 => .{ .float = @floatCast(@as(f32, @bitCast(std.mem.readInt(u32, (try self.take(4))[0..4], .big)))) },
                27 => .{ .float = @bitCast(std.mem.readInt(u64, (try self.take(8))[0..8], .big)) },
                else => error.UnsupportedCbor,
            },
        }
    }
};

// ---------------------------------------------------------------- encode

pub fn encode(allocator: std.mem.Allocator, v: Value) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try encodeInto(allocator, &out, v);
    return out.toOwnedSlice(allocator);
}

fn head(allocator: std.mem.Allocator, out: *std.ArrayList(u8), major: u8, n: u64) Error!void {
    const m = major << 5;
    if (n < 24) {
        try out.append(allocator, m | @as(u8, @intCast(n)));
    } else if (n <= 0xff) {
        try out.appendSlice(allocator, &.{ m | 24, @intCast(n) });
    } else if (n <= 0xffff) {
        var b: [3]u8 = .{ m | 25, 0, 0 };
        std.mem.writeInt(u16, b[1..3], @intCast(n), .big);
        try out.appendSlice(allocator, &b);
    } else if (n <= 0xffff_ffff) {
        var b: [5]u8 = .{ m | 26, 0, 0, 0, 0 };
        std.mem.writeInt(u32, b[1..5], @intCast(n), .big);
        try out.appendSlice(allocator, &b);
    } else {
        var b: [9]u8 = undefined;
        b[0] = m | 27;
        std.mem.writeInt(u64, b[1..9], n, .big);
        try out.appendSlice(allocator, &b);
    }
}

fn keyLess(_: void, a: Entry, b: Entry) bool {
    if (a.key.len != b.key.len) return a.key.len < b.key.len;
    return std.mem.lessThan(u8, a.key, b.key);
}

pub fn encodeInto(allocator: std.mem.Allocator, out: *std.ArrayList(u8), v: Value) Error!void {
    switch (v) {
        .uint => |n| try head(allocator, out, 0, n),
        .nint => |n| try head(allocator, out, 1, n),
        .bytes => |b| {
            try head(allocator, out, 2, b.len);
            try out.appendSlice(allocator, b);
        },
        .text => |t| {
            try head(allocator, out, 3, t.len);
            try out.appendSlice(allocator, t);
        },
        .array => |items| {
            try head(allocator, out, 4, items.len);
            for (items) |it| try encodeInto(allocator, out, it);
        },
        .map => |entries| {
            const sorted = try allocator.dupe(Entry, entries);
            defer allocator.free(sorted);
            std.sort.pdq(Entry, sorted, {}, keyLess);
            for (sorted[1..], 0..) |e, i| if (std.mem.eql(u8, e.key, sorted[i].key)) return error.InvalidCbor;
            try head(allocator, out, 5, sorted.len);
            for (sorted) |e| {
                try head(allocator, out, 3, e.key.len);
                try out.appendSlice(allocator, e.key);
                try encodeInto(allocator, out, e.value);
            }
        },
        .cid => |c| {
            try head(allocator, out, 6, 42);
            try head(allocator, out, 2, c.len + 1);
            try out.append(allocator, 0);
            try out.appendSlice(allocator, c);
        },
        .boolean => |b| try out.append(allocator, if (b) 0xf5 else 0xf4),
        .null => try out.append(allocator, 0xf6),
        .float => |f| {
            var b: [9]u8 = undefined;
            b[0] = 0xfb;
            std.mem.writeInt(u64, b[1..9], @bitCast(f), .big);
            try out.appendSlice(allocator, &b);
        },
    }
}

// ---------------------------------------------------------------- CIDs

/// CIDv1, dag-cbor (0x71), sha2-256: how the store names a record.
pub fn cidOf(bytes: []const u8) [36]u8 {
    var c: [36]u8 = .{ 0x01, 0x71, 0x12, 0x20 } ++ .{0} ** 32;
    std.crypto.hash.sha2.Sha256.hash(bytes, c[4..36], .{});
    return c;
}

test "cbor: canonical map order and round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v: Value = .{ .map = &.{
        .{ .key = "zz", .value = .{ .uint = 1 } },
        .{ .key = "b", .value = .{ .text = "x" } },
        .{ .key = "aa", .value = .{ .array = &.{ .{ .uint = 500 }, .{ .nint = 0 }, .null, .{ .boolean = true } } } },
        .{ .key = "c", .value = .{ .cid = &.{ 1, 0x71, 0x12, 0x20 } } },
    } };
    const bytes = try encode(a, v);
    // {"b": "x", "c": CID, "aa": [...], "zz": 1}: length-first key order.
    try std.testing.expectEqualSlices(u8, &.{ 0xa4, 0x61, 'b', 0x61, 'x', 0x61, 'c', 0xd8, 0x2a, 0x45, 0, 1, 0x71, 0x12, 0x20, 0x62, 'a', 'a', 0x84, 0x19, 0x01, 0xf4, 0x20, 0xf6, 0xf5, 0x62, 'z', 'z', 0x01 }, bytes);
    const back = try decode(a, bytes);
    try std.testing.expectEqual(@as(u64, 1), back.getUint("zz").?);
    try std.testing.expectEqualStrings("x", back.getText("b").?);
    try std.testing.expectEqualSlices(u8, &.{ 1, 0x71, 0x12, 0x20 }, back.getCid("c").?);
    try std.testing.expectEqualSlices(u8, bytes, try encode(a, back));
}

test "cbor: refuses indefinite lengths, non-text keys, other tags, trailing bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.UnsupportedCbor, decode(a, &.{0x9f}));
    try std.testing.expectError(error.UnsupportedCbor, decode(a, &.{ 0xa1, 0x01, 0x01 }));
    try std.testing.expectError(error.UnsupportedCbor, decode(a, &.{ 0xc1, 0x01 }));
    try std.testing.expectError(error.InvalidCbor, decode(a, &.{ 0x01, 0x01 }));
    try std.testing.expectError(error.InvalidCbor, decode(a, &.{ 0x5a, 0xff, 0xff, 0xff, 0xff }));
}
