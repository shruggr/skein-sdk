//! Signed messages inside the VM (#70): what `emit` makes, checked where one
//! arrives — the front door, for a provider's message (transport `local`)
//! and a message over libp2p; the messagebox, for one another instance
//! delivers over BRC-104. A message is its mail record
//!
//!   {kind: "mail", op: "put", sender: bytes(33), recipient: bytes(33), box, body: <cid>, subject?: <cid>, signature: bytes}
//!
//! signed BRC-169's way (§7.2/§7.3): ECDSA (DER) by the sender's BRC-42 child
//! for [2, "metanet handles envelope"], key ID "send", counterparty anyone,
//! over sha256 of the dag-cbor of the record without `signature`. Anyone
//! checks it with the sender's key alone (src/secp.zig, pure Zig).
const std = @import("std");
const cbor = @import("cbor");
const secp = @import("secp");

const Value = cbor.Value;
const Allocator = std.mem.Allocator;

pub const PROTOCOL = "metanet handles envelope";
pub const KEY_ID = "send";

/// Why a signed message does not hold (null: it does): its shape, its body
/// (the bytes must be the record `body` names), its signature.
pub fn problem(a: Allocator, m: Value, body: []const u8) !?[]const u8 {
    if (m != .map) return "not a map";
    if (!std.mem.eql(u8, Value.str(m.get("kind")) orelse "", "mail") or !std.mem.eql(u8, Value.str(m.get("op")) orelse "", "put")) return "not a mail record";
    const sender = Value.bytesOf(m.get("sender")) orelse return "no sender";
    if (!secp.isKey(sender)) return "the sender is not a key";
    if (!secp.isKey(Value.bytesOf(m.get("recipient")) orelse return "no recipient")) return "the recipient is not a key";
    const box = Value.str(m.get("box")) orelse return "no box";
    if (box.len == 0 or box[0] == ':') return "a bad box";
    const bc = Value.cidOf(m.get("body")) orelse return "no body";
    const sig = Value.bytesOf(m.get("signature")) orelse return "not signed";
    const bv = cbor.decode(a, body) catch return "the body is not dag-cbor";
    const blk = try cbor.block(a, bv);
    if (!std.mem.eql(u8, blk.bytes, body) or !std.mem.eql(u8, blk.cid, bc)) return "the body is not the one the message names";
    const pre = try cbor.encode(a, try cbor.without(a, m, "signature"));
    if (!secp.verifyAnyoneKey(sender, 2, PROTOCOL, KEY_ID, pre, sig)) return "the signature does not verify";
    return null;
}
