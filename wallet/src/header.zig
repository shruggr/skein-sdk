//! Block headers: the 80 bytes, their hash, the target and work their bits
//! encode, and proof of work. Pure functions; `chain.zig` builds the chain
//! tracker over them. Hashes are kept in internal byte order (as hashed); the
//! display form (hex) is byte-reversed.
const std = @import("std");

pub const size = 80;

pub const Header = struct {
    version: i32,
    prev_hash: [32]u8,
    merkle_root: [32]u8,
    time: u32,
    bits: u32,
    nonce: u32,

    pub fn parse(raw: []const u8) error{InvalidHeader}!Header {
        if (raw.len != size) return error.InvalidHeader;
        return .{
            .version = std.mem.readInt(i32, raw[0..4], .little),
            .prev_hash = raw[4..36].*,
            .merkle_root = raw[36..68].*,
            .time = std.mem.readInt(u32, raw[68..72], .little),
            .bits = std.mem.readInt(u32, raw[72..76], .little),
            .nonce = std.mem.readInt(u32, raw[76..80], .little),
        };
    }

    pub fn serialize(self: Header) [size]u8 {
        var b: [size]u8 = undefined;
        std.mem.writeInt(i32, b[0..4], self.version, .little);
        b[4..36].* = self.prev_hash;
        b[36..68].* = self.merkle_root;
        std.mem.writeInt(u32, b[68..72], self.time, .little);
        std.mem.writeInt(u32, b[72..76], self.bits, .little);
        std.mem.writeInt(u32, b[76..80], self.nonce, .little);
        return b;
    }
};

/// Double SHA-256 of the 80 bytes, internal byte order.
pub fn hash(raw: *const [size]u8) [32]u8 {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &a, .{});
    std.crypto.hash.sha2.Sha256.hash(&a, &b, .{});
    return b;
}

/// The target a compact `bits` encodes, or null when it is not a usable
/// target: zero, negative (sign bit set), or wider than 256 bits. go-chaintracks
/// and the TS toolbox disagree on those (vectors/headers.json, "note"); both
/// agree on every usable one, and a header with an unusable target is refused.
pub fn target(bits: u32) ?u256 {
    const mantissa: u32 = bits & 0x007fffff;
    const negative = bits & 0x00800000 != 0;
    const exponent: u32 = bits >> 24;
    var t: u256 = undefined;
    if (exponent <= 3) {
        t = mantissa >> @intCast(8 * (3 - exponent));
    } else {
        const shift = 8 * (exponent - 3);
        if (shift >= 256) return null;
        const m: u256 = mantissa;
        if (@clz(m) < shift) return null; // overflows 256 bits
        t = m << @intCast(shift);
    }
    if (t == 0 or negative) return null;
    return t;
}

/// Work a header with this target represents: 2^256 / (target + 1).
pub fn work(t: u256) u256 {
    // (2^256 - 1 - t) / (t + 1) + 1 == floor(2^256 / (t + 1)) for t >= 0, without 257-bit arithmetic.
    return (~t) / (t + 1) + 1;
}

/// The hash read as a 256-bit number in display (big-endian) order.
pub fn hashValue(h: [32]u8) u256 {
    return std.mem.readInt(u256, &h, .little);
}

/// Proof of work: the hash, as a number, is at most the target its own bits encode.
pub fn powOk(raw: *const [size]u8) bool {
    const hdr = Header.parse(raw) catch return false;
    const t = target(hdr.bits) orelse return false;
    return hashValue(hash(raw)) <= t;
}

pub fn toHex(h: [32]u8) [64]u8 {
    var rev = h;
    std.mem.reverse(u8, &rev);
    return std.fmt.bytesToHex(rev, .lower);
}

pub fn fromHex(text: []const u8) error{InvalidHex}![32]u8 {
    if (text.len != 64) return error.InvalidHex;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch return error.InvalidHex;
    std.mem.reverse(u8, &out);
    return out;
}

pub fn u256Hex(v: u256) [64]u8 {
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, v, .big);
    return std.fmt.bytesToHex(b, .lower);
}
