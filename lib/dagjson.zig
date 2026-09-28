//! DAG-JSON ⇄ dag-cbor values (#40): a JSON client (the stock
//! message-box-client, the front end) sends a message body as JSON; the
//! messagebox keeps it as dag-cbor, reading `{"/": "<cid>"}` as a link and
//! `{"/": {"bytes": "<base64>"}}` as bytes, and lists dag-cbor bodies back to
//! JSON clients the same way.
const std = @import("std");
const cbor = @import("cbor");
const cid = cbor.cidm;

const Value = cbor.Value;
const Allocator = std.mem.Allocator;
const b64 = std.base64.standard_no_pad;

/// Parse JSON text as DAG-JSON. Numbers without a fraction or exponent are integers.
pub fn decode(a: Allocator, text: []const u8) !Value {
    const j = try std.json.parseFromSliceLeaky(std.json.Value, a, text, .{ .parse_numbers = true });
    return fromJson(a, j);
}

pub fn fromJson(a: Allocator, j: std.json.Value) !Value {
    return switch (j) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .int = i },
        .float => |f| if (@floor(f) == f and @abs(f) < 9007199254740992) .{ .int = @intFromFloat(f) } else .{ .float = f },
        .number_string => |s| blk: {
            if (std.fmt.parseInt(i128, s, 10)) |i| break :blk .{ .int = i } else |_| {}
            break :blk .{ .float = try std.fmt.parseFloat(f64, s) };
        },
        .string => |s| .{ .string = s },
        .array => |arr| blk: {
            const out = try a.alloc(Value, arr.items.len);
            for (arr.items, 0..) |x, i| out[i] = try fromJson(a, x);
            break :blk .{ .array = out };
        },
        .object => |o| blk: {
            if (o.count() == 1) if (o.get("/")) |slash| {
                switch (slash) {
                    .string => |s| break :blk .{ .cid = try cid.parse(a, s) },
                    .object => |inner| if (inner.count() == 1) if (inner.get("bytes")) |bs| if (bs == .string) {
                        const n = b64.Decoder.calcSizeForSlice(bs.string) catch return error.BadBytes;
                        const out = try a.alloc(u8, n);
                        b64.Decoder.decode(out, bs.string) catch return error.BadBytes;
                        break :blk .{ .bytes = out };
                    },
                    else => {},
                }
            };
            var list: std.ArrayList(cbor.Entry) = .empty;
            var it = o.iterator();
            while (it.next()) |e| try list.append(a, .{ .key = e.key_ptr.*, .value = try fromJson(a, e.value_ptr.*) });
            break :blk .{ .map = list.items };
        },
    };
}

/// A dag-cbor value as DAG-JSON text.
pub fn encode(a: Allocator, v: Value) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    try write(a, &out.writer, v);
    return out.written();
}

fn write(a: Allocator, w: *std.Io.Writer, v: Value) !void {
    switch (v) {
        .null => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .int => |i| try w.print("{d}", .{i}),
        .float => |f| try w.print("{d}", .{f}),
        .string => |s| try std.json.Stringify.value(s, .{}, w),
        .bytes => |b| {
            const out = try a.alloc(u8, b64.Encoder.calcSize(b.len));
            try w.print("{{\"/\":{{\"bytes\":\"{s}\"}}}}", .{b64.Encoder.encode(out, b)});
        },
        .cid => |c| try w.print("{{\"/\":\"{s}\"}}", .{try cid.format(a, c)}),
        .array => |arr| {
            try w.writeByte('[');
            for (arr, 0..) |x, i| {
                if (i > 0) try w.writeByte(',');
                try write(a, w, x);
            }
            try w.writeByte(']');
        },
        .map => |m| {
            try w.writeByte('{');
            for (m, 0..) |e, i| {
                if (i > 0) try w.writeByte(',');
                try std.json.Stringify.value(e.key, .{}, w);
                try w.writeByte(':');
                try write(a, w, e.value);
            }
            try w.writeByte('}');
        },
    }
}
