//! The transaction builder behind createAction / signAction: inputs are our
//! spendable P2PKH outputs (BRC-29 keys), the outputs are the caller's, then
//! one change output to a fresh BRC-29 key of our own (counterparty self);
//! the fee is SatoshisPerKilobyte over the size with each P2PKH unlocking
//! script estimated at 106 bytes (go-sdk's p2pkh.EstimateLength), change
//! included; a change of zero drops the change output (go-sdk Fee,
//! ChangeDistributionEqual). Every key operation goes to the signing oracle:
//! getPublicKey for each input's and the change key, createSignature over the
//! BIP143/ForkID sighash (ALL|FORKID) as hashToDirectlySign — the oracle
//! never sees anything but a key reference and a 32-byte hash, and nothing
//! here holds a key. Vectors: vectors/signing.json (go-sdk ProtoWallet).
//!
//! A caller's input (#93, BRC-100 createAction `inputs`) is not ours to sign:
//! no key, its unlocking script is the caller's (given at createAction or as
//! a signAction spend), estimated for the fee at its unlockingScriptLength.
//! It counts toward the inputs' total like any other; the wallet signs only
//! its own (each sighash is BIP143's, which commits to no other input's
//! unlocking script, so the order of signing does not matter).
const std = @import("std");
const bsvz = @import("bsvz");
const wire = @import("wire.zig");
const brc29 = @import("brc29.zig");

const Transaction = bsvz.transaction.Transaction;
const Script = bsvz.script.Script;

pub const sighash_all_forkid: u32 = 0x41;
/// go-sdk p2pkh.EstimateLength: the unlocking script's length for the fee.
pub const p2pkh_unlock_estimate: usize = 106;

/// A key the oracle holds: BRC-29 protocol, this keyID and counterparty.
pub const Key = struct { key_id: []const u8, counterparty: wire.Counterparty };

/// The signing oracle as the builder asks it. `WireSigner` makes one over
/// BRC-100 wire frames (the `wallet` import in the VM).
pub const Signer = struct {
    ptr: *anyopaque,
    publicKeyFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, key: Key) anyerror![33]u8,
    signFn: *const fn (ptr: *anyopaque, arena: std.mem.Allocator, key: Key, hash: [32]u8) anyerror![]const u8,

    pub fn publicKey(s: Signer, arena: std.mem.Allocator, key: Key) ![33]u8 {
        return s.publicKeyFn(s.ptr, arena, key);
    }
    pub fn sign(s: Signer, arena: std.mem.Allocator, key: Key, hash: [32]u8) ![]const u8 {
        return s.signFn(s.ptr, arena, key, hash);
    }
};

/// A Signer over wire frames: `call` sends a request frame, returns the result frame.
pub const WireSigner = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, frame: []const u8) anyerror![]const u8,

    fn publicKeyImpl(ptr: *anyopaque, arena: std.mem.Allocator, key: Key) anyerror![33]u8 {
        const self: *WireSigner = @ptrCast(@alignCast(ptr));
        const frame = try wire.getPublicKeyFrameFor(arena, brc29.security_level, brc29.protocol_name, key.key_id, key.counterparty, true);
        return wire.publicKeyResult(try self.call(self.ctx, arena, frame));
    }
    fn signImpl(ptr: *anyopaque, arena: std.mem.Allocator, key: Key, hash: [32]u8) anyerror![]const u8 {
        const self: *WireSigner = @ptrCast(@alignCast(ptr));
        const frame = try wire.createSignatureFrame(arena, brc29.security_level, brc29.protocol_name, key.key_id, key.counterparty, hash);
        return wire.signatureResult(try self.call(self.ctx, arena, frame));
    }
    pub fn signer(self: *WireSigner) Signer {
        return .{ .ptr = self, .publicKeyFn = publicKeyImpl, .signFn = signImpl };
    }
};

pub const Input = struct {
    source_txid: [32]u8,
    vout: u32,
    satoshis: u64,
    locking_script: []const u8,
    /// Ours: the BRC-29 key the oracle signs this P2PKH input with. Null: a caller's input.
    key: ?Key = null,
    /// A caller's input: its unlocking script, once given.
    unlocking_script: ?[]const u8 = null,
    /// The unlocking script's length for the fee: P2PKH's estimate for ours, the caller's
    /// unlockingScriptLength (or its script's length) for a caller's.
    unlocking_script_length: usize = p2pkh_unlock_estimate,
    sequence: u32 = 0xffffffff,
};

pub const Output = struct { satoshis: u64, locking_script: []const u8 };

pub const Built = struct {
    tx: Transaction,
    raw: []const u8,
    txid: [32]u8,
    fee: u64,
    /// The change output's index and amount, or null when dropped.
    change: ?struct { vout: u32, satoshis: u64 },
};

pub fn feeFor(tx: *const Transaction, sats_per_kb: u64) !u64 {
    const model = bsvz.transaction.fee_model.SatoshisPerKilobyte{ .satoshis = sats_per_kb };
    return model.computeFee(tx);
}

/// The fee for `n_inputs` of ours (P2PKH) and these outputs (change included), unsigned.
pub fn estimateFee(arena: std.mem.Allocator, n_inputs: usize, outputs: []const Output, change_script_len: usize, sats_per_kb: u64) !u64 {
    const ins = try arena.alloc(Input, n_inputs);
    for (ins) |*in| in.* = .{ .source_txid = @splat(0), .vout = 0, .satoshis = 0, .locking_script = &.{} };
    return estimateFeeFor(arena, ins, outputs, change_script_len, sats_per_kb);
}

/// The fee for these inputs (each at its unlocking script's length) and
/// outputs (change included), unsigned.
pub fn estimateFeeFor(arena: std.mem.Allocator, inputs: []const Input, outputs: []const Output, change_script_len: usize, sats_per_kb: u64) !u64 {
    const ins = try arena.alloc(bsvz.transaction.Input, inputs.len);
    for (inputs, ins) |src, *in| {
        const placeholder = try arena.alloc(u8, src.unlocking_script_length);
        @memset(placeholder, 0);
        in.* = .{ .previous_outpoint = .{ .txid = .zero(), .index = 0 }, .unlocking_script = Script.init(placeholder), .sequence = src.sequence };
    }
    const outs = try arena.alloc(bsvz.transaction.Output, outputs.len + 1);
    for (outputs, outs[0..outputs.len]) |o, *x| x.* = .{ .satoshis = @intCast(o.satoshis), .locking_script = Script.init(o.locking_script) };
    const cs = try arena.alloc(u8, change_script_len);
    @memset(cs, 0);
    outs[outputs.len] = .{ .satoshis = 0, .locking_script = Script.init(cs) };
    const tx = Transaction{ .version = 1, .inputs = ins, .outputs = outs, .lock_time = 0 };
    return feeFor(&tx, sats_per_kb);
}

/// The caller's inputs, then ours from `funding` (largest first, as given)
/// until they cover the outputs and the fee over all of them (a P2PKH change
/// output included). None of ours when the caller's cover it; a funding coin
/// the caller names is not taken twice.
pub fn select(arena: std.mem.Allocator, caller: []const Input, funding: []const Input, outputs: []const Output, sats_per_kb: u64) ![]Input {
    var all: std.ArrayList(Input) = .empty;
    try all.appendSlice(arena, caller);
    var need: u64 = 0;
    for (outputs) |o| need += o.satoshis;
    var have: u64 = 0;
    for (caller) |in| have += in.satoshis;
    var i: usize = 0;
    while (true) {
        if (all.items.len > 0 and have >= need + try estimateFeeFor(arena, all.items, outputs, 25, sats_per_kb)) return all.items;
        while (i < funding.len) : (i += 1) {
            const f = funding[i];
            const named = for (caller) |c| {
                if (c.vout == f.vout and std.mem.eql(u8, &c.source_txid, &f.source_txid)) break true;
            } else false;
            if (!named) break;
        }
        if (i == funding.len) return error.InsufficientFunds;
        try all.append(arena, funding[i]);
        have += funding[i].satoshis;
        i += 1;
    }
}

/// Build and sign: inputs in order, the outputs in order, then the change
/// (P2PKH to `change_key`) unless it comes to zero. With `sign`, every input
/// of ours is signed and every caller's input must carry its unlocking
/// script; without, a signable draft (ours unsigned, the caller's as given).
pub fn build(arena: std.mem.Allocator, signer: Signer, inputs: []const Input, outputs: []const Output, change_key: Key, sats_per_kb: u64, sign: bool) !Built {
    if (inputs.len == 0) return error.NoInputs;
    for (inputs) |in| if (in.key == null) {
        if (in.unlocking_script) |u| if (u.len > in.unlocking_script_length) return error.UnlockingScriptTooLong;
        if (sign and in.unlocking_script == null) return error.MissingUnlockingScript;
    };
    const change_pub = try signer.publicKey(arena, change_key);
    const change_script = try arena.dupe(u8, &brc29.p2pkh(change_pub));
    const fee = try estimateFeeFor(arena, inputs, outputs, change_script.len, sats_per_kb);
    var total_in: u64 = 0;
    for (inputs) |in| total_in += in.satoshis;
    var total_out: u64 = 0;
    for (outputs) |o| total_out += o.satoshis;
    if (total_in < total_out + fee) return error.InsufficientFunds;
    const change = total_in - total_out - fee;

    const ins = try arena.alloc(bsvz.transaction.Input, inputs.len);
    for (inputs, ins) |in, *x| x.* = .{
        .previous_outpoint = .{ .txid = .{ .bytes = in.source_txid }, .index = in.vout },
        .unlocking_script = if (in.key == null) Script.init(in.unlocking_script orelse &.{}) else Script.empty(),
        .sequence = in.sequence,
    };
    const n_out = outputs.len + @as(usize, if (change > 0) 1 else 0);
    const outs = try arena.alloc(bsvz.transaction.Output, n_out);
    for (outputs, outs[0..outputs.len]) |o, *x| x.* = .{ .satoshis = @intCast(o.satoshis), .locking_script = Script.init(o.locking_script) };
    if (change > 0) outs[outputs.len] = .{ .satoshis = @intCast(change), .locking_script = Script.init(change_script) };
    var tx = Transaction{ .version = 1, .inputs = ins, .outputs = outs, .lock_time = 0 };

    // Sign each input of ours through the oracle (unless building a signable draft).
    if (sign) for (inputs, 0..) |in, i| {
        const key = in.key orelse continue;
        const pub_key = try signer.publicKey(arena, key);
        if (!brc29.pays(in.locking_script, pub_key)) return error.NotOurKey;
        const digest = try bsvz.transaction.sighash.digest(arena, &tx, i, Script.init(in.locking_script), @intCast(in.satoshis), sighash_all_forkid);
        const der = try signer.sign(arena, key, digest.bytes);
        ins[i].unlocking_script = Script.init(try unlockingScript(arena, der, pub_key));
    };
    const raw = try tx.serialize(arena);
    return .{
        .tx = tx,
        .raw = raw,
        .txid = bsvz.crypto.hash.hash256(raw).bytes,
        .fee = fee,
        .change = if (change > 0) .{ .vout = @intCast(outputs.len), .satoshis = change } else null,
    };
}

/// <DER ‖ ALL|FORKID> <public key>
pub fn unlockingScript(arena: std.mem.Allocator, der: []const u8, pub_key: [33]u8) ![]u8 {
    if (der.len > 72) return error.BadSignature;
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, @intCast(der.len + 1));
    try out.appendSlice(arena, der);
    try out.append(arena, @intCast(sighash_all_forkid));
    try out.append(arena, 33);
    try out.appendSlice(arena, &pub_key);
    return out.toOwnedSlice(arena);
}

/// A Signer with the root key in hand (tests; a Zig oracle): BRC-42 via bsvz's KeyDeriver.
pub const KeySigner = struct {
    root: [32]u8,
    calls: usize = 0,

    fn deriver(self: *KeySigner) !bsvz.primitives.key_deriver.KeyDeriver {
        return bsvz.primitives.key_deriver.KeyDeriver.init(try bsvz.primitives.ec.PrivateKey.fromBytes(self.root));
    }
    fn cp(key: Key) !bsvz.primitives.key_deriver.Counterparty {
        return switch (key.counterparty) {
            .self => .{ .type_ = .self },
            .anyone => .{ .type_ = .anyone },
            .other => |k| .{ .type_ = .other, .public_key = try bsvz.primitives.ec.PublicKey.fromSec1(&k) },
        };
    }
    const proto = bsvz.primitives.key_deriver.Protocol{ .security_level = brc29.security_level, .name = brc29.protocol_name };
    fn publicKeyImpl(ptr: *anyopaque, arena: std.mem.Allocator, key: Key) anyerror![33]u8 {
        const self: *KeySigner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        const kd = try self.deriver();
        return (try kd.derivePublicKey(arena, proto, key.key_id, try cp(key), true)).toCompressedSec1();
    }
    fn signImpl(ptr: *anyopaque, arena: std.mem.Allocator, key: Key, hash: [32]u8) anyerror![]const u8 {
        const self: *KeySigner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        const kd = try self.deriver();
        const priv = try kd.derivePrivateKey(arena, proto, key.key_id, try cp(key));
        const sig = try priv.signDigest(hash);
        return arena.dupe(u8, sig.asSlice());
    }
    pub fn signer(self: *KeySigner) Signer {
        return .{ .ptr = self, .publicKeyFn = publicKeyImpl, .signFn = signImpl };
    }
};
