// CIDv1 in binary form (what the store keys on and dag-cbor tag 42 carries),
// and its base32 multibase text form ("bafy…", "baf4…", "bafk…"), as
// multiformats' CID does it (src/runtime/cid.ts, tree.ts, programs.ts).
const std = @import("std");

pub const DAG_CBOR: u64 = 0x71;
pub const RAW: u64 = 0x55;
pub const GIT_RAW: u64 = 0x78;
pub const SHA1: u64 = 0x11;
pub const SHA2_256: u64 = 0x12;
/// Bitcoin blocks (issues #32, #29): a transaction's CID is its txid, a
/// header's its block hash: the double SHA-256 of the bytes, in internal byte
/// order in the digest (the display form is that reversed).
pub const BITCOIN_BLOCK: u64 = 0xb0; // an 80-byte block header
pub const BITCOIN_TX: u64 = 0xb1; // a transaction's standard serialization
pub const DBL_SHA2_256: u64 = 0x56;

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

/// Does `bytes` hash to `c`? git-raw/sha1, raw/sha2-256 and dag-cbor/sha2-256
/// (scheduler.ts hashMatches), and, here only, bitcoin-tx and bitcoin-block
/// (an 80-byte header) with dbl-sha2-256.
pub fn hashMatches(c: []const u8, bytes: []const u8) bool {
    const p = parts(c) catch return false;
    if (p.codec == BITCOIN_TX or p.codec == BITCOIN_BLOCK) {
        if (p.mh != DBL_SHA2_256 or p.digest.len != 32) return false;
        if (p.codec == BITCOIN_BLOCK and bytes.len != 80) return false;
        return std.mem.eql(u8, &dblSha256(bytes), p.digest);
    }
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

pub fn dblSha256(bytes: []const u8) [32]u8 {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &a, .{});
    std.crypto.hash.sha2.Sha256.hash(&a, &b, .{});
    return b;
}

/// The CID of a transaction (bitcoin-tx) or a block header (bitcoin-block).
pub fn ofBitcoin(alloc: std.mem.Allocator, codec: u64, bytes: []const u8) ![]u8 {
    return create(alloc, codec, DBL_SHA2_256, &dblSha256(bytes));
}

test "bitcoin-tx and bitcoin-block: the CID is the txid / the block hash" {
    const a = std.testing.allocator;
    // Mainnet's and testnet's genesis headers, and the genesis coinbase: well-known hashes.
    const cases = [_]struct { codec: u64, hex: []const u8, id: []const u8 }{
        .{ .codec = BITCOIN_BLOCK, .hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c", .id = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" },
        .{ .codec = BITCOIN_BLOCK, .hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18", .id = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" },
        .{ .codec = BITCOIN_TX, .hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000", .id = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" },
    };
    for (cases) |k| {
        const bytes = try a.alloc(u8, k.hex.len / 2);
        defer a.free(bytes);
        _ = try std.fmt.hexToBytes(bytes, k.hex);
        const c = try ofBitcoin(a, k.codec, bytes);
        defer a.free(c);
        const p = try parts(c);
        try std.testing.expectEqual(k.codec, p.codec);
        try std.testing.expectEqual(DBL_SHA2_256, p.mh);
        var rev: [32]u8 = p.digest[0..32].*;
        std.mem.reverse(u8, &rev);
        try std.testing.expectEqualStrings(k.id, &std.fmt.bytesToHex(rev, .lower));
        try std.testing.expect(hashMatches(c, bytes));
        // One byte off: refused.
        bytes[bytes.len - 1] ^= 1;
        try std.testing.expect(!hashMatches(c, bytes));
        bytes[bytes.len - 1] ^= 1;
        // bitcoin-block takes 80 bytes only; bitcoin-tx any.
        const other = try create(a, if (k.codec == BITCOIN_TX) BITCOIN_BLOCK else BITCOIN_TX, DBL_SHA2_256, p.digest);
        defer a.free(other);
        try std.testing.expectEqual(bytes.len == 80, hashMatches(other, bytes));
        // The bitcoin codecs take dbl-sha2-256 only.
        const sha = try create(a, k.codec, SHA2_256, p.digest);
        defer a.free(sha);
        try std.testing.expect(!hashMatches(sha, bytes));
        // The text form round-trips.
        const text = try format(a, c);
        defer a.free(text);
        const back = try parse(a, text);
        defer a.free(back);
        try std.testing.expectEqualSlices(u8, c, back);
    }
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
