//! Messages inside the VM (#70): the mail record, checked where a package
//! carrying one arrives. A message is its mail record
//!
//!   {kind: "mail", op: "put", sender: bytes(33), recipient: bytes(33), box, body: <cid>, subject?: <cid>, nonce?: bytes}
//!
//! **Who sent it is the transport's to prove** (shruggr/skein#126, step 4): a
//! BRC-104 session to the recipient's own front door (`/sendMessage`), or
//! libp2p (the peer the stream or the GossipSub signature proves). The record
//! carries no signature of its sender: `shapeProblem` checks a record and its
//! body, and the transport says who `sender` must be.
//!
//! Two records sign themselves, because no session of the recipient's carries
//! them (`problem`): a **claim** (box `claim`, shruggr/skein#127) — signed by
//! the registrant before the instance it claims exists, naming no recipient,
//! forwarded by the host into that instance as its first entry; its owner is
//! the signer — and a **host provider's answer** (transport `local`), with the
//! instance's signed request for an intention it carries (#126). Their signing:
//! ECDSA (DER) by the sender's BRC-42 child for [2, "metanet handles
//! envelope"], key ID "send", counterparty anyone, over the dag-cbor of the
//! record without `signature` (BRC-169 §7.2/§7.3's signing on skein's record).
//! Anyone checks it with the sender's key alone (src/secp.zig, pure Zig).
//! Anything else inside a body that must mean something on its own signs
//! itself, in the body.
const std = @import("std");
const cbor = @import("cbor");
const secp = @import("secp");

const Value = cbor.Value;
const Allocator = std.mem.Allocator;

pub const PROTOCOL = "metanet handles envelope";
pub const KEY_ID = "send";
/// The one box a message may name no recipient in (shruggr/skein#127).
pub const CLAIM_BOX = "claim";

/// Why a mail record does not hold, its signature aside (null: it does): its
/// shape, and its body (the bytes must be the record `body` names). Who sent
/// it is the transport's to prove (the caller checks `sender` against it).
pub fn shapeProblem(a: Allocator, m: Value, body: []const u8) !?[]const u8 {
    if (m != .map) return "not a map";
    if (!std.mem.eql(u8, Value.str(m.get("kind")) orelse "", "mail") or !std.mem.eql(u8, Value.str(m.get("op")) orelse "", "put")) return "not a mail record";
    const sender = Value.bytesOf(m.get("sender")) orelse return "no sender";
    if (!secp.isKey(sender)) return "the sender is not a key";
    const box = Value.str(m.get("box")) orelse return "no box";
    if (box.len == 0 or box[0] == ':') return "a bad box";
    if (m.get("recipient")) |r| {
        if (!secp.isKey(Value.bytesOf(r) orelse "")) return "the recipient is not a key";
    } else if (!std.mem.eql(u8, box, CLAIM_BOX)) return "no recipient (only a claim names none)";
    const bc = Value.cidOf(m.get("body")) orelse return "no body";
    const bv = cbor.decode(a, body) catch return "the body is not dag-cbor";
    const blk = try cbor.block(a, bv);
    if (!std.mem.eql(u8, blk.bytes, body) or !std.mem.eql(u8, blk.cid, bc)) return "the body is not the one the message names";
    return null;
}

/// Why a signed message (a claim, a provider's answer) does not hold (null:
/// it does): `shapeProblem`, and its signature by `sender`.
pub fn problem(a: Allocator, m: Value, body: []const u8) !?[]const u8 {
    if (try shapeProblem(a, m, body)) |why| return why;
    const sig = Value.bytesOf(m.get("signature")) orelse return "not signed";
    const pre = try cbor.encode(a, try cbor.without(a, m, "signature"));
    if (!secp.verifyAnyoneKey(Value.bytesOf(m.get("sender")).?, 2, PROTOCOL, KEY_ID, pre, sig)) return "the signature does not verify";
    return null;
}

test "shapeProblem: a record and its body, no signature asked; problem asks for one" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const body = try cbor.encode(a, cbor.string("hi"));
    const blk = try cbor.block(a, try cbor.decode(a, body));
    var key: [33]u8 = undefined;
    @memset(&key, 0);
    key[0] = 2;
    key[32] = 1;
    // A key needs to be on the curve: G's x coordinate.
    _ = try std.fmt.hexToBytes(&key, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    var m = cbor.MapBuilder.init(a);
    try m.put("kind", cbor.string("mail"));
    try m.put("op", cbor.string("put"));
    try m.put("sender", .{ .bytes = &key });
    try m.put("recipient", .{ .bytes = &key });
    try m.put("box", cbor.string("chat"));
    try m.put("body", cbor.cidv(blk.cid));
    try std.testing.expect((try shapeProblem(a, m.value(), body)) == null);
    try std.testing.expectEqualStrings("not signed", (try problem(a, m.value(), body)).?);
    try std.testing.expectEqualStrings("the body is not the one the message names", (try shapeProblem(a, m.value(), try cbor.encode(a, cbor.string("other")))).?);
    var c = cbor.MapBuilder.init(a);
    for (m.value().map) |e| if (!std.mem.eql(u8, e.key, "recipient")) try c.put(e.key, e.value);
    try std.testing.expectEqualStrings("no recipient (only a claim names none)", (try shapeProblem(a, c.value(), body)).?);
}
