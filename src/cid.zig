// CIDv1 in binary form (what the store keys on and dag-cbor tag 42 carries),
// and its base32 multibase text form ("bafy…", "baf4…", "bafk…"), as
// multiformats' CID does it (src/runtime/cid.ts, tree.ts, programs.ts).
const std = @import("std");

pub const DAG_CBOR: u64 = 0x71;
pub const RAW: u64 = 0x55;
pub const GIT_RAW: u64 = 0x78;
pub const SHA1: u64 = 0x11;
pub const SHA2_256: u64 = 0x12;

const alphabet = "abcdefghijklmnopqrstuvwxyz234567";

pub const Parts = struct { version: u64, codec: u64, mh: u64, digest: []const u8 };

pub const Error = error{BadCid};

fn putUvarint(buf: []u8, v0: u64) usize {
    var v = v0;
    var i: usize = 0;
    while (v >= 0x80) : (i += 1) {
        buf[i] = @as(u8, @truncate(v)) | 0x80;
        v >>= 7;
    }
    buf[i] = @truncate(v);
    return i + 1;
}

pub fn readUvarint(b: []const u8, pos: *usize) Error!u64 {
    var v: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        if (pos.* >= b.len) return error.BadCid;
        const c = b[pos.*];
        pos.* += 1;
        v |= @as(u64, c & 0x7f) << shift;
        if (c & 0x80 == 0) return v;
        if (shift >= 57) return error.BadCid;
        shift += 7;
    }
    return error.BadCid;
}

/// A CIDv1 from its parts, allocated.
pub fn create(alloc: std.mem.Allocator, codec: u64, mh: u64, digest: []const u8) ![]u8 {
    var buf: [40]u8 = undefined;
    var n: usize = 0;
    n += putUvarint(buf[n..], 1);
    n += putUvarint(buf[n..], codec);
    n += putUvarint(buf[n..], mh);
    n += putUvarint(buf[n..], digest.len);
    const out = try alloc.alloc(u8, n + digest.len);
    @memcpy(out[0..n], buf[0..n]);
    @memcpy(out[n..], digest);
    return out;
}

/// Decode a binary CID's header. A v0 CID (a bare sha2-256 multihash) reads as dag-pb.
pub fn parts(c: []const u8) Error!Parts {
    if (c.len == 34 and c[0] == 0x12 and c[1] == 0x20) return .{ .version = 0, .codec = 0x70, .mh = SHA2_256, .digest = c[2..] };
    var pos: usize = 0;
    const version = try readUvarint(c, &pos);
    if (version != 1) return error.BadCid;
    const codec = try readUvarint(c, &pos);
    const mh = try readUvarint(c, &pos);
    const len = try readUvarint(c, &pos);
    if (len != c.len - pos) return error.BadCid;
    return .{ .version = version, .codec = codec, .mh = mh, .digest = c[pos..] };
}

pub fn isValid(c: []const u8) bool {
    _ = parts(c) catch return false;
    return true;
}

pub fn codecOf(c: []const u8) u64 {
    return (parts(c) catch return 0).codec;
}

/// sha2-256 dag-cbor CID of encoded bytes.
pub fn ofDagCbor(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &d, .{});
    return create(alloc, DAG_CBOR, SHA2_256, &d);
}

/// raw sha2-256 CID (modules).
pub fn ofRaw(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &d, .{});
    return create(alloc, RAW, SHA2_256, &d);
}

/// git-raw sha1 CID of a whole git object.
pub fn ofGit(alloc: std.mem.Allocator, object: []const u8) ![]u8 {
    var d: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(object, &d, .{});
    return create(alloc, GIT_RAW, SHA1, &d);
}

/// Base32 multibase form ("b" + lowercase RFC 4648, no padding). v0 would be base58; not used.
pub fn format(alloc: std.mem.Allocator, c: []const u8) ![]u8 {
    const n = 1 + (c.len * 8 + 4) / 5;
    const out = try alloc.alloc(u8, n);
    out[0] = 'b';
    var o: usize = 1;
    var acc: u32 = 0;
    var bits: u5 = 0;
    for (c) |byte| {
        acc = (acc << 8) | byte;
        var nb: u32 = @as(u32, bits) + 8;
        while (nb >= 5) {
            nb -= 5;
            out[o] = alphabet[(acc >> @intCast(nb)) & 31];
            o += 1;
        }
        bits = @intCast(nb);
        acc &= (@as(u32, 1) << bits) - 1;
    }
    if (bits > 0) {
        out[o] = alphabet[(acc << @intCast(5 - @as(u32, bits))) & 31];
        o += 1;
    }
    std.debug.assert(o == n);
    return out;
}

/// Write the base32 form into a fixed buffer; returns the slice.
pub fn formatBuf(buf: []u8, c: []const u8) []u8 {
    var fba = std.heap.FixedBufferAllocator.init(buf);
    return format(fba.allocator(), c) catch unreachable;
}

/// Parse the base32 multibase form ("b…", case-insensitive after the prefix).
pub fn parse(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len < 2 or (s[0] != 'b' and s[0] != 'B')) return error.BadCid;
    var out = try alloc.alloc(u8, (s.len - 1) * 5 / 8);
    var o: usize = 0;
    var acc: u32 = 0;
    var bits: u32 = 0;
    for (s[1..]) |ch| {
        const l = std.ascii.toLower(ch);
        const v: u32 = if (l >= 'a' and l <= 'z') l - 'a' else if (l >= '2' and l <= '7') l - '2' + 26 else return error.BadCid;
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[o] = @truncate(acc >> @intCast(bits));
            o += 1;
            acc &= (@as(u32, 1) << @intCast(bits)) - 1;
        }
    }
    out = out[0..o];
    _ = try parts(out);
    return out;
}

/// The last 8 characters of the text form: log lines (log.ts `short`).
pub fn short(buf: *[8]u8, c: []const u8) []const u8 {
    var tmp: [128]u8 = undefined;
    const s = formatBuf(&tmp, c);
    const tail = s[s.len - 8 ..];
    @memcpy(buf, tail);
    return buf;
}

/// Does `bytes` hash to `c`? git-raw/sha1, raw/sha2-256 and dag-cbor/sha2-256 only (scheduler.ts hashMatches).
pub fn hashMatches(c: []const u8, bytes: []const u8) bool {
    const p = parts(c) catch return false;
    if (p.codec != GIT_RAW and p.codec != RAW and p.codec != DAG_CBOR) return false;
    if (p.mh == SHA1) {
        var d: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(bytes, &d, .{});
        return std.mem.eql(u8, &d, p.digest);
    }
    if (p.mh == SHA2_256) {
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &d, .{});
        return std.mem.eql(u8, &d, p.digest);
    }
    return false;
}

test "base32 round trip" {
    const a = std.testing.allocator;
    const s = "bafkreiemwcli2372geseu7l527ivxwjodogng7zoltixf6pfh5ujnpauc4";
    const c = try parse(a, s);
    defer a.free(c);
    const back = try format(a, c);
    defer a.free(back);
    try std.testing.expectEqualStrings(s, back);
    const p = try parts(c);
    try std.testing.expectEqual(RAW, p.codec);
}
