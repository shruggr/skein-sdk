// Signature checks that need no wallet (src/runtime/identity.ts): the BRC-42
// "anyone" child key of an identity for (protocol, keyID), and ECDSA over
// sha256(data) against it, as @bsv/sdk's PublicKey.verify does (DER parsed
// like Signature.fromDER; r and s in [1, n-1]; high S accepted).
const std = @import("std");
const Secp = std.crypto.ecc.Secp256k1;
const scalar = Secp.scalar;

const n_order: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

fn reduce(be: [32]u8) [32]u8 {
    var wide: [48]u8 = [_]u8{0} ** 48;
    @memcpy(wide[16..], &be);
    return scalar.reduce48(wide, .big);
}

/// The public key `identity` (compressed, 33 bytes) derives for invoice
/// "<level>-<name>-<keyID>" with counterparty anyone (private key 1): the shared
/// secret is the identity itself, so anyone can compute it.
pub fn anyoneKey(identity: []const u8, invoice: []const u8) !Secp {
    const p = try Secp.fromSec1(identity);
    const shared = p.toCompressedSec1();
    var h: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&h, invoice, &shared);
    const g = try Secp.basePoint.mul(reduce(h), .big);
    return p.add(g);
}

const Sig = struct { r: [32]u8, s: [32]u8 };

fn parseDer(d: []const u8) ?Sig {
    var p: usize = 0;
    const at = struct {
        fn f(b: []const u8, i: usize) ?u8 {
            return if (i < b.len) b[i] else null;
        }
    }.f;
    if ((at(d, p) orelse return null) != 0x30) return null;
    p += 1;
    const len = at(d, p) orelse return null;
    p += 1;
    if (len & 0x80 != 0) return null;
    if (len + p != d.len) return null;
    if ((at(d, p) orelse return null) != 0x02) return null;
    p += 1;
    const rlen = at(d, p) orelse return null;
    p += 1;
    if (rlen & 0x80 != 0) return null;
    const rend = @min(d.len, p + rlen);
    var r = d[@min(p, d.len)..rend];
    p += rlen;
    if ((at(d, p) orelse return null) != 0x02) return null;
    p += 1;
    const slen = at(d, p) orelse return null;
    p += 1;
    if (slen & 0x80 != 0) return null;
    if (d.len != slen + p) return null;
    var s = d[p .. p + slen];
    if (r.len > 0 and r[0] == 0) {
        if (r.len < 2 or r[1] & 0x80 == 0) return null;
        r = r[1..];
    }
    if (s.len > 0 and s[0] == 0) {
        if (s.len < 2 or s[1] & 0x80 == 0) return null;
        s = s[1..];
    }
    const rr = toFixed(r) orelse return null;
    const ss = toFixed(s) orelse return null;
    return .{ .r = rr, .s = ss };
}

fn toFixed(b: []const u8) ?[32]u8 {
    var x = b;
    while (x.len > 0 and x[0] == 0) x = x[1..];
    if (x.len > 32) return null;
    var out = [_]u8{0} ** 32;
    @memcpy(out[32 - x.len ..], x);
    return out;
}

/// ECDSA verify of a DER signature over sha256(data) by `key`.
pub fn verify(key: Secp, data: []const u8, der: []const u8) bool {
    const sig = parseDer(der) orelse return false;
    const r = std.mem.readInt(u256, &sig.r, .big);
    const s = std.mem.readInt(u256, &sig.s, .big);
    if (r == 0 or r >= n_order or s == 0 or s >= n_order) return false;
    var z: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &z, .{});
    const sS = scalar.Scalar.fromBytes(sig.s, .big) catch return false;
    const w = sS.invert();
    const zS = scalar.Scalar.fromBytes(reduce(z), .big) catch return false;
    const rS = scalar.Scalar.fromBytes(sig.r, .big) catch return false;
    const k1 = zS.mul(w).toBytes(.big);
    const k2 = rS.mul(w).toBytes(.big);
    const R = Secp.mulDoubleBasePublic(Secp.basePoint, k1, key, k2, .big) catch return false;
    const x = R.affineCoordinates().x.toBytes(.big);
    const xv = std.mem.readInt(u256, &x, .big) % n_order;
    return xv == r;
}

fn hexKey(buf: *[33]u8, hex: []const u8) ?[]const u8 {
    if (hex.len != 66) return null;
    _ = std.fmt.hexToBytes(buf, hex) catch return null;
    return buf;
}

/// verifyAnyone(identityKey, [level, name], keyID, data, der) (identity.ts).
pub fn verifyAnyone(identity_hex: []const u8, level: u8, name: []const u8, key_id: []const u8, data: []const u8, der: []const u8) bool {
    var kb: [33]u8 = undefined;
    const key = hexKey(&kb, identity_hex) orelse return false;
    var inv_buf: [256]u8 = undefined;
    const invoice = std.fmt.bufPrint(&inv_buf, "{d}-{s}-{s}", .{ level, name, key_id }) catch return false;
    const child = anyoneKey(key, invoice) catch return false;
    return verify(child, data, der);
}

/// A compressed secp256k1 key in hex (records.ts isIdentity: /^0[23][0-9a-f]{64}$/).
pub fn isIdentity(s: []const u8) bool {
    if (s.len != 66 or s[0] != '0' or (s[1] != '2' and s[1] != '3')) return false;
    for (s[2..]) |c| if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    return true;
}
