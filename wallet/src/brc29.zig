//! BRC-29 payments, payee side. The payer derives a key for us under
//! protocol [2, "3241645161d8"] with keyID "<derivationPrefix> <derivationSuffix>"
//! and pays P2PKH to it; we recognise the output by deriving the same key
//! (forSelf, counterparty = the sender) and comparing the locking script.
//! Inside the VM the derivation is the signing oracle's (getPublicKey over
//! the `wallet` import, wire.zig); `payeeKey` is the same computation with a
//! private key, for tests and for an oracle written in Zig.
const std = @import("std");
const bsvz = @import("bsvz");

pub const security_level: u8 = 2;
pub const protocol_name = "3241645161d8";

pub fn keyId(arena: std.mem.Allocator, prefix: []const u8, suffix: []const u8) ![]u8 {
    return std.fmt.allocPrint(arena, "{s} {s}", .{ prefix, suffix });
}

/// P2PKH locking script for a compressed public key.
pub fn p2pkh(pubkey: [33]u8) [25]u8 {
    var s: [25]u8 = undefined;
    s[0..3].* = .{ 0x76, 0xa9, 0x14 };
    s[3..23].* = bsvz.crypto.hash.hash160(&pubkey).bytes;
    s[23..25].* = .{ 0x88, 0xac };
    return s;
}

/// Whether a locking script is the P2PKH of this key.
pub fn pays(locking_script: []const u8, pubkey: [33]u8) bool {
    const want = p2pkh(pubkey);
    return std.mem.eql(u8, locking_script, &want);
}

/// The payee's derived public key, computed with its private key (BRC-42 via bsvz's KeyDeriver).
pub fn payeeKey(arena: std.mem.Allocator, recipient: [32]u8, sender: [33]u8, key_id: []const u8) ![33]u8 {
    const kd = bsvz.primitives.key_deriver.KeyDeriver.init(try bsvz.primitives.ec.PrivateKey.fromBytes(recipient));
    const pub_key = try kd.derivePublicKey(arena, .{ .security_level = security_level, .name = protocol_name }, key_id, .{
        .type_ = .other,
        .public_key = try bsvz.primitives.ec.PublicKey.fromSec1(&sender),
    }, true);
    return pub_key.toCompressedSec1();
}

/// The payer's view: the key it pays to (forSelf = false, counterparty = the recipient).
pub fn payerKey(arena: std.mem.Allocator, sender: [32]u8, recipient: [33]u8, key_id: []const u8) ![33]u8 {
    const kd = bsvz.primitives.key_deriver.KeyDeriver.init(try bsvz.primitives.ec.PrivateKey.fromBytes(sender));
    const pub_key = try kd.derivePublicKey(arena, .{ .security_level = security_level, .name = protocol_name }, key_id, .{
        .type_ = .other,
        .public_key = try bsvz.primitives.ec.PublicKey.fromSec1(&recipient),
    }, false);
    return pub_key.toCompressedSec1();
}

pub fn identityKey(priv: [32]u8) ![33]u8 {
    return (try (try bsvz.primitives.ec.PrivateKey.fromBytes(priv)).publicKey()).toCompressedSec1();
}
