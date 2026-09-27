//! BRC-100 wallet wire frames for the one oracle call the wallet makes today:
//! getPublicKey (call 8), as go-sdk's WalletWireTransceiver writes it
//! (vectors/wire.json). Request: [call][originator length][originator][args];
//! result: [0][payload] or [error code][message][stack].
const std = @import("std");
const VarInt = @import("bsvz").primitives.varint.VarInt;

pub const call_get_public_key: u8 = 8;

fn varint(arena: std.mem.Allocator, out: *std.ArrayList(u8), v: u64) !void {
    var b: [9]u8 = undefined;
    const n = try VarInt.encodeInto(&b, v);
    try out.appendSlice(arena, b[0..n]);
}

fn optionalBool(v: ?bool) u8 {
    return if (v) |b| @intFromBool(b) else 0xff;
}

/// getPublicKey args for a derived key: protocol, keyID, counterparty (a
/// public key), not privileged, forSelf as given, no permission prompt.
pub fn getPublicKeyFrame(arena: std.mem.Allocator, level: u8, protocol: []const u8, key_id: []const u8, counterparty: [33]u8, for_self: ?bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, &.{ call_get_public_key, 0 }); // call, empty originator
    try out.append(arena, 0); // identityKey: false
    try out.append(arena, level);
    try varint(arena, &out, protocol.len);
    try out.appendSlice(arena, protocol);
    try varint(arena, &out, key_id.len);
    try out.appendSlice(arena, key_id);
    try out.appendSlice(arena, &counterparty);
    try out.append(arena, 0); // privileged: false
    try out.append(arena, 0xff); // privilegedReason: none
    try out.append(arena, optionalBool(for_self));
    try out.append(arena, 0); // seekPermission: false
    return out.toOwnedSlice(arena);
}

pub const ResultError = error{ WalletError, BadResultFrame };

/// The payload of a successful result frame; a wallet error is `WalletError`.
pub fn resultPayload(frame: []const u8) ResultError![]const u8 {
    if (frame.len == 0) return error.BadResultFrame;
    if (frame[0] != 0) return error.WalletError;
    return frame[1..];
}

/// A getPublicKey result: the 33-byte compressed key.
pub fn publicKeyResult(frame: []const u8) ResultError![33]u8 {
    const p = try resultPayload(frame);
    if (p.len != 33 or (p[0] != 2 and p[0] != 3)) return error.BadResultFrame;
    return p[0..33].*;
}

/// A wallet error frame's message.
pub fn errorMessage(frame: []const u8) ?[]const u8 {
    if (frame.len < 2 or frame[0] == 0) return null;
    const n = VarInt.parse(frame[1..]) catch return null;
    const start = 1 + n.len;
    if (n.value > frame.len - start) return null;
    return frame[start..][0..@intCast(n.value)];
}
