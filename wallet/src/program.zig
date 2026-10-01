//! wallet: the handler program for the `wallet` box (issue #29), a
//! wasm32-wasi command stepped with the `skein` imports (kernel-zig
//! program.zig). One run is one step over one input: an owner's message
//! (args.body), a plain entry routed by subscription (args.event: a
//! `header`, `proof` or `status` record), or — for a thread resting after a
//! broadcast — the entry for its transaction (input.event) or its deadline
//! (input.woke).
//!
//! The wallet's state is the record the head `wallet` names (a
//! `wallet-state`: its index maps by name); each step loads it, applies the
//! body's operation, saves new index records and a new state record, and
//! advances the head. Every step also stores a result record, keeps it in
//! the thread, and prints its CID (hex) on stdout.
//!
//! Body operations (dag-cbor; docs/WALLET.md):
//!   {op: "headers", headers: [bytes]}           a run of headers, parents first (ChainTracks)
//!   {op: "internalize", tx, outputs, description, labels?}   BRC-100 internalizeAction (Atomic BEEF)
//!   {op: "proof", txid, path}                   a merkle path (BRC-74) for a transaction we hold
//!   {op: "createAction", description, outputs, labels?, options?: {signAndProcess?, noSend?}}   BRC-100 createAction
//!   {op: "signAction", reference}                BRC-100 signAction for a draft (signAndProcess: false)
//!   {op: "list", basket?, includeSpent?}        our outputs in a basket (default "default")
//!
//! Plain entries (docs/WALLET.md): {kind: "header", raw}, {kind: "proof",
//! subject, txid, path}, {kind: "status", subject, txid, txStatus, merklePath?}.
//!
//! Recorded calls: the oracle over the `wallet` import (getPublicKey,
//! createSignature: no key is ever here). Broadcasting is a message (#70,
//! #67: external communication is a thread): the wallet emits the Atomic BEEF
//! to the address book's `broadcast` provider (box "broadcast", {tx}, about
//! the transaction: `subject` its CID) and ends its step awaiting the answer —
//! the provider's signed message {replyTo, status, body}, Arcade's own answer
//! (the host's broadcaster, #58) — and the transaction's CID, for a
//! `status`/`proof` entry, with a deadline. The answer, an entry, or the
//! deadline steps it. At the deadline the broadcaster is asked again (box
//! "status", {txid}); a 404 (Arcade never took the transaction) posts it
//! again. No `broadcast` provider in the address book: nothing is broadcast.
//! A transaction never mined within
//! defaults.walletAbandonMs of its broadcast is abandoned (rejected); a reorg
//! that turns ours back to unproven broadcasts them again and awaits them.
//!
//! Settlement (#37) is state to read, not an event to deliver: a `status`
//! entry that rejects a transaction writes its settlement record and walks
//! what depended on it (wallet.zig `reject`); nothing is sent anywhere —
//! whoever cares reads the state when it next acts. A result record names
//! the transactions it is about as `refs` with rel `mentions` (kernel
//! edges; a mention never propagates a rejection).
const std = @import("std");
const w = @import("wallet");

const cbor = w.cbor;
const Value = cbor.Value;

/// The skein calls: the preview1 `skein` imports, or (the component build, issue
/// #34) the same calls over the WIT interface skein:kernel/skein (skein_wit.zig).
const component = @import("build_options").component;
const sk = if (component) @import("skein_wit.zig") else struct {
    extern "skein" fn input(out: [*]u8, cap: u32) i32;
    extern "skein" fn get(cid: [*]const u8, cid_len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn put(data: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn putblock(cid: [*]const u8, cid_len: u32, data: [*]const u8, len: u32) i32;
    extern "skein" fn keep(cid: [*]const u8, cid_len: u32) i32;
    extern "skein" fn head(name: [*]const u8, name_len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn advance(name: [*]const u8, name_len: u32, tree: [*]const u8, tree_len: u32) i32;
    extern "skein" fn wallet(frame: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn emit(msg: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn deadline(until: i64) i32;
    extern "skein" fn @"await"(cid: [*]const u8, cid_len: u32) i32;
    extern "skein" fn call(prog: [*]const u8, prog_len: u32, func: [*]const u8, func_len: u32, arg: [*]const u8, arg_len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn take(out: [*]u8, cap: u32) i32;
    extern "skein" fn @"error"(out: [*]u8, cap: u32) i32;
    extern "skein" fn edges(to: [*]const u8, to_len: u32, rel: [*]const u8, rel_len: u32, out: [*]u8, cap: u32) i32;
};

var last_error: [1024]u8 = undefined;
var last_error_len: usize = 0;

fn failed() error{ImportFailed} {
    const n = sk.@"error"(&last_error, last_error.len);
    last_error_len = if (n < 0) 0 else @min(@as(usize, @intCast(n)), last_error.len);
    return error.ImportFailed;
}

/// Run an import that writes (out, cap), taking the held result when it did not fit.
fn result(arena: std.mem.Allocator, call: anytype, args: anytype) ![]u8 {
    var buf = try arena.alloc(u8, 4096);
    const n = @call(.auto, call, args ++ .{ buf.ptr, @as(u32, @intCast(buf.len)) });
    if (n < 0) return failed();
    const len: usize = @intCast(n);
    if (len <= buf.len) return buf[0..len];
    buf = try arena.alloc(u8, len);
    if (sk.take(buf.ptr, @intCast(len)) != n) return failed();
    return buf;
}

const VmStore = struct {
    fn getImpl(_: *anyopaque, arena: std.mem.Allocator, cid: []const u8) anyerror![]const u8 {
        return result(arena, sk.get, .{ cid.ptr, @as(u32, @intCast(cid.len)) });
    }
    fn putImpl(_: *anyopaque, arena: std.mem.Allocator, bytes: []const u8) anyerror![]const u8 {
        return result(arena, sk.put, .{ bytes.ptr, @as(u32, @intCast(bytes.len)) });
    }
    fn putBlockImpl(_: *anyopaque, cid: []const u8, bytes: []const u8) anyerror!void {
        if (sk.putblock(cid.ptr, @intCast(cid.len), bytes.ptr, @intCast(bytes.len)) < 0) return failed();
    }
    fn keepImpl(_: *anyopaque, cid: []const u8) anyerror!void {
        if (sk.keep(cid.ptr, @intCast(cid.len)) < 0) return failed();
    }
    fn edgesImpl(_: *anyopaque, arena: std.mem.Allocator, to: []const u8, rel: ?[]const u8) anyerror![]const w.store.Edge {
        const r = rel orelse "";
        return w.store.decodeEdges(arena, try result(arena, sk.edges, .{ to.ptr, @as(u32, @intCast(to.len)), r.ptr, @as(u32, @intCast(r.len)) }));
    }
    var dummy: u8 = 0;
    fn store() w.store.Store {
        return .{ .ptr = &dummy, .getFn = getImpl, .putFn = putImpl, .putBlockFn = putBlockImpl, .keepFn = keepImpl, .edgesFn = edgesImpl };
    }
};

/// The signing oracle over the `wallet` import: getPublicKey(protocol [2, "3241645161d8"], keyID, counterparty = sender, forSelf).
const VmOracle = struct {
    var dummy: u8 = 0;
    fn derive(_: *anyopaque, arena: std.mem.Allocator, key_id: []const u8, sender: [33]u8) anyerror![33]u8 {
        const frame = try w.wire.getPublicKeyFrame(arena, w.brc29.security_level, w.brc29.protocol_name, key_id, sender, true);
        const res = try result(arena, sk.wallet, .{ frame.ptr, @as(u32, @intCast(frame.len)) });
        return w.wire.publicKeyResult(res) catch |e| {
            if (w.wire.errorMessage(res)) |m| std.log.err("oracle: {s}", .{m});
            return e;
        };
    }
    fn oracle() w.wallet.Oracle {
        return .{ .ptr = &dummy, .derivePayeeFn = derive };
    }
    /// A wire frame to the oracle and its result frame (getPublicKey, createSignature: attested).
    fn call(_: *anyopaque, arena: std.mem.Allocator, frame: []const u8) anyerror![]const u8 {
        const res = try result(arena, sk.wallet, .{ frame.ptr, @as(u32, @intCast(frame.len)) });
        if (w.wire.errorMessage(res)) |m| std.log.err("oracle: {s}", .{m});
        return res;
    }
};

/// In-VM calls (#40) for the overlay's lookup services (#50: a rejection
/// here tells each topic's services, `rejected`).
const VmCaller = struct {
    var dummy: u8 = 0;
    fn call(_: *anyopaque, arena: std.mem.Allocator, program: []const u8, func: []const u8, arg: Value) anyerror!Value {
        const bytes = try cbor.encode(arena, arg);
        return cbor.decode(arena, try result(arena, sk.call, .{ program.ptr, @as(u32, @intCast(program.len)), func.ptr, @as(u32, @intCast(func.len)), bytes.ptr, @as(u32, @intCast(bytes.len)) }));
    }
    fn caller() w.overlay.Caller {
        return .{ .ctx = &dummy, .callFn = call };
    }
};

const head_name = "wallet";

pub fn main() u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.wasm_allocator);
    defer arena_state.deinit();
    run(arena_state.allocator()) catch |e| {
        var buf: [1400]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "wallet: {s}{s}{s}\n", .{ @errorName(e), if (last_error_len > 0) ": " else "", last_error[0..last_error_len] }) catch "wallet: error\n";
        std.Io.File.stderr().writeStreamingAll(io(), msg) catch {};
        return 1;
    };
    return 0;
}

/// The program's Io: one single-threaded WASI process, no concurrency.
fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// The thread's random: the kernel's random_get, keyed by the entry, so a
/// replay draws the same. One random_get of exactly `out`, as Zig 0.15's
/// std.crypto.random made on wasm32-wasi (no CSPRNG in between), so the
/// change keys the wallet derives, and its entries, are byte-identical
/// across the move to 0.16.
fn threadRandom(out: []u8) void {
    io().randomSecure(out) catch @panic("random_get failed");
}

fn hexAlloc(arena: std.mem.Allocator, b: []const u8) ![]u8 {
    const out = try arena.alloc(u8, b.len * 2);
    for (b, 0..) |x, i| _ = std.fmt.bufPrint(out[2 * i ..][0..2], "{x:0>2}", .{x}) catch unreachable;
    return out;
}

fn field(v: Value, key: []const u8) !Value {
    return v.get(key) orelse {
        std.log.err("body: missing {s}", .{key});
        return error.BadBody;
    };
}

fn textList(arena: std.mem.Allocator, v: ?Value) ![]const []const u8 {
    const items = if (v) |x| (if (x == .array) x.array else return error.BadBody) else return &.{};
    const out = try arena.alloc([]const u8, items.len);
    for (items, out) |it, *o| o.* = if (it == .text) it.text else return error.BadBody;
    return out;
}

fn run(a: std.mem.Allocator) !void {
    const s = VmStore.store();
    const input_bytes = try result(a, sk.input, .{});
    const step = cbor.decode(a, input_bytes) catch |e| {
        std.log.err("input record ({d} bytes): {s}", .{ input_bytes.len, @errorName(e) });
        return e;
    };
    const args = step.get("args") orelse return error.BadInput;
    // What this step is about: a callback for a transaction we broadcast, an
    // owner's message, or a plain entry.
    const callback = step.get("event");
    const woke = step.getBool("woke") orelse false;
    // The broadcaster's answer to what this thread asked it (#70: a reply to our message).
    const reply: ?Value = if (step.get("reply")) |r| (if (r == .map) r else null) else null;
    var body: Value = .null;
    var op: []const u8 = undefined;
    if (callback != null or woke or reply != null) {
        op = "callback";
        if (callback) |c| body = try s.getValue(a, c.getCid("event") orelse return error.BadInput);
    } else if (args.getCid("body")) |bc| {
        body = s.getValue(a, bc) catch |e| {
            std.log.err("body record: {s}", .{@errorName(e)});
            return e;
        };
        op = body.getText("op") orelse return error.BadBody;
    } else if (args.getCid("event")) |ec| {
        body = try s.getValue(a, ec);
        op = "event";
    } else return error.BadInput;
    const defaults = step.get("defaults");
    // The broadcaster (#70): the address book's `broadcast` provider, if there is one.
    var bc = Broadcaster{ .key = try broadcasterKey(a, s) };
    const recheck_ms: i64 = if (defaults) |d| std.fmt.parseInt(i64, d.getText("walletRecheckMs") orelse "600000", 10) catch return error.BadConfig else 600000;
    const abandon_ms: i64 = if (defaults) |d| std.fmt.parseInt(i64, d.getText("walletAbandonMs") orelse "86400000", 10) catch return error.BadConfig else 86400000;
    const now: i64 = @intCast(step.getUint("at") orelse return error.BadInput);
    // After the step: await these transactions (their CIDs) until the deadline.
    var await_txs: std.ArrayList([32]u8) = .empty;

    // The network (its genesis header anchors the chain): genesis defaults.walletNetwork, else mainnet.
    const net_name = if (step.get("defaults")) |d| d.getText("walletNetwork") orelse "main" else "main";
    const network = w.chain.Network.parse(net_name) orelse {
        std.log.err("defaults.walletNetwork: {s} is not main, test or regtest", .{net_name});
        return error.BadConfig;
    };
    // The fee rate for what we build: defaults.walletFeeRate (satoshis per kB), else 100.
    const rate_text = if (step.get("defaults")) |d| d.getText("walletFeeRate") orelse "100" else "100";
    const fee_rate = std.fmt.parseInt(u64, rate_text, 10) catch return error.BadConfig;
    const state_cid = try result(a, sk.head, .{ head_name.ptr, @as(u32, head_name.len) });
    var wal = try w.wallet.Wallet.load(a, s, if (state_cid.len > 0) state_cid else null, network);
    wal.now = now;

    var out: std.ArrayList(cbor.Entry) = .empty;
    try out.appendSlice(a, &.{
        .{ .key = "kind", .value = .{ .text = "wallet-result" } },
        .{ .key = "op", .value = .{ .text = op } },
    });
    var mutates = true;

    if (std.mem.eql(u8, op, "headers")) {
        const list = try field(body, "headers");
        if (list != .array) return error.BadBody;
        const raws = try a.alloc([]const u8, list.array.len);
        for (list.array, raws) |x, *r| r.* = if (x == .bytes) x.bytes else return error.BadBody;
        const res = try wal.addHeaders(raws);
        try rebroadcast(a, &wal, &bc, &await_txs, &out);
        try out.appendSlice(a, &.{
            .{ .key = "added", .value = .{ .uint = res.added } },
            .{ .key = "known", .value = .{ .uint = res.known } },
            .{ .key = "replaced", .value = .{ .uint = res.replaced } },
            .{ .key = "ignored", .value = .{ .uint = res.ignored } },
            .{ .key = "tip", .value = .{ .uint = res.tip } },
        });
    } else if (std.mem.eql(u8, op, "internalize")) {
        const tx = try field(body, "tx");
        const outs = try field(body, "outputs");
        if (tx != .bytes or outs != .array) return error.BadBody;
        const specs = try a.alloc(w.wallet.InternalizeOutput, outs.array.len);
        for (outs.array, specs) |o, *spec| {
            const idx = o.getUint("outputIndex") orelse return error.BadBody;
            const protocol = o.getText("protocol") orelse return error.BadBody;
            spec.* = .{ .output_index = @intCast(idx) };
            if (std.mem.eql(u8, protocol, "wallet payment")) {
                const r = o.get("paymentRemittance") orelse return error.BadBody;
                const sender_hex = r.getText("senderIdentityKey") orelse return error.BadBody;
                var sender: [33]u8 = undefined;
                if (sender_hex.len != 66) return error.BadBody;
                _ = std.fmt.hexToBytes(&sender, sender_hex) catch return error.BadBody;
                spec.payment = .{
                    .derivation_prefix = r.getText("derivationPrefix") orelse return error.BadBody,
                    .derivation_suffix = r.getText("derivationSuffix") orelse return error.BadBody,
                    .sender_identity_key = sender,
                };
            } else if (std.mem.eql(u8, protocol, "basket insertion")) {
                const r = o.get("insertionRemittance") orelse return error.BadBody;
                spec.insertion = .{
                    .basket = r.getText("basket") orelse return error.BadBody,
                    .custom_instructions = r.getText("customInstructions"),
                    .tags = try textList(a, r.get("tags")),
                };
            } else return error.BadBody;
        }
        const res = try wal.internalize(.{
            .tx = tx.bytes,
            .outputs = specs,
            .description = body.getText("description") orelse "",
            .labels = try textList(a, body.get("labels")),
        }, VmOracle.oracle());
        try out.appendSlice(a, &.{
            .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &w.header.toHex(res.txid)) } },
            .{ .key = "status", .value = .{ .text = @tagName(res.status) } },
            .{ .key = "outputs", .value = .{ .uint = res.outputs } },
        });
    } else if (std.mem.eql(u8, op, "proof")) {
        const txid = body.getText("txid") orelse return error.BadBody;
        const path = body.getBytes("path") orelse return error.BadBody;
        const st = try wal.addProof(try w.header.fromHex(txid), path);
        try out.appendSlice(a, &.{
            .{ .key = "txid", .value = .{ .text = txid } },
            .{ .key = "status", .value = .{ .text = @tagName(st) } },
        });
    } else if (std.mem.eql(u8, op, "event")) {
        // A plain entry, by subscription: the feed's header, proof or status.
        const kind = body.getText("kind") orelse return error.BadEvent;
        try out.append(a, .{ .key = "event", .value = .{ .text = kind } });
        if (std.mem.eql(u8, kind, "header")) {
            const res = try wal.addHeaders(&.{body.getBytes("raw") orelse return error.BadEvent});
            try rebroadcast(a, &wal, &bc, &await_txs, &out);
            try out.appendSlice(a, &.{
                .{ .key = "added", .value = .{ .uint = res.added } },
                .{ .key = "known", .value = .{ .uint = res.known } },
                .{ .key = "replaced", .value = .{ .uint = res.replaced } },
                .{ .key = "ignored", .value = .{ .uint = res.ignored } },
                .{ .key = "tip", .value = .{ .uint = res.tip } },
            });
        } else if (std.mem.eql(u8, kind, "proof") or std.mem.eql(u8, kind, "status")) {
            const txid = try eventTxid(body);
            const outcome = try applyEvent(&wal, txid, kind, body);
            try out.appendSlice(a, &.{
                .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &w.header.toHex(txid)) } },
                .{ .key = "outcome", .value = .{ .text = @tagName(outcome) } },
            });
        } else return error.BadEvent;
    } else if (std.mem.eql(u8, op, "callback")) {
        // Transactions we broadcast: a status entry for one of them, or the
        // deadline (each still awaited is abandoned if due, else ARC is asked again).
        var awaited = try awaitedFromTip(a, s, step);
        // The questions to the broadcaster still unanswered (#70): awaited again, but for the one answered now.
        try bc.carry(a, s, step, if (reply) |r| r.getCid("replyTo") else null);
        var txid: [32]u8 = undefined;
        var outcome: w.wallet.Wallet.Outcome = .pending;
        if (callback != null) {
            txid = try eventTxid(body);
            const kind = body.getText("kind") orelse return error.BadEvent;
            outcome = try applyEvent(&wal, txid, kind, body);
            try out.append(a, .{ .key = "event", .value = .{ .text = kind } });
            if (!contains(awaited.items, txid)) try awaited.insert(a, 0, txid);
        } else if (reply) |r| {
            // The broadcaster's answer: Arcade's, to a broadcast or to the question at a deadline.
            const asked = try s.getValue(a, r.getCid("message") orelse return error.BadInput);
            txid = w.store.bitcoinHash(asked.getCid("subject") orelse return error.BadInput) orelse return error.BadInput;
            const ans_body = try s.getValue(a, r.getCid("body") orelse return error.BadInput);
            if (ans_body.getText("error")) |e| std.log.err("the broadcaster: {s}", .{e});
            var ans = try arcAnswer(a, ans_body);
            // 404 to the question: Arcade never took it (the broadcast failed transiently, or it lost its history): post it again.
            if (std.mem.eql(u8, r.getText("box") orelse "", "status") and ans.http_status == 404) if (try wal.beefOf(txid)) |beef| {
                try bc.broadcast(a, txid, beef);
                ans.tx_status = "";
            };
            outcome = try wal.applyStatus(txid, ans.tx_status, ans.merkle_path);
            try out.append(a, .{ .key = "arc", .value = try ans.value(a) });
            if (!contains(awaited.items, txid)) try awaited.insert(a, 0, txid);
        } else {
            if (awaited.items.len == 0) return error.BadInput;
            txid = awaited.items[0];
            for (awaited.items) |t| {
                if ((try wal.awaitingRecord(t)) == null) continue;
                if (try wal.abandonIfDue(t, abandon_ms)) continue;
                // Ask the broadcaster again; its answer is the next step's.
                try bc.ask(a, t);
            }
            outcome = switch (try wal.status(txid)) {
                .proven => .proven,
                .rejected => .rejected,
                .unproven => .pending,
            };
        }
        try out.appendSlice(a, &.{
            .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &w.header.toHex(txid)) } },
            .{ .key = "outcome", .value = .{ .text = @tagName(outcome) } },
        });
        for (awaited.items) |t| if ((try wal.awaitingRecord(t)) != null) try await_txs.append(a, t);
    } else if (std.mem.eql(u8, op, "createAction") or std.mem.eql(u8, op, "signAction")) {
        var ws = w.builder.WireSigner{ .ctx = &VmOracle.dummy, .call = VmOracle.call };
        const created = if (std.mem.eql(u8, op, "createAction")) blk: {
            const opts = body.get("options");
            // The change key: a fresh BRC-29 derivation of our own, drawn from the thread's random (replayable).
            var rnd: [24]u8 = undefined;
            threadRandom(&rnd);
            const enc = std.base64.standard.Encoder;
            const prefix = try a.alloc(u8, enc.calcSize(12));
            const suffix = try a.alloc(u8, enc.calcSize(12));
            _ = enc.encode(prefix, rnd[0..12]);
            _ = enc.encode(suffix, rnd[12..24]);
            break :blk try wal.createAction(.{
                .description = body.getText("description") orelse "",
                .outputs = try w.wallet.decodeOutputs(a, (try field(body, "outputs")).array),
                .labels = try textList(a, body.get("labels")),
                .sign_and_process = if (opts) |o| o.getBool("signAndProcess") orelse true else true,
                .no_send = if (opts) |o| o.getBool("noSend") orelse false else false,
            }, ws.signer(), prefix, suffix, fee_rate);
        } else try wal.signAction(body.getCid("reference") orelse return error.BadBody, ws.signer());
        try out.appendSlice(a, &.{
            .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &w.header.toHex(created.txid)) } },
            .{ .key = "tx", .value = .{ .bytes = created.beef } },
        });
        if (created.reference) |r| try out.append(a, .{ .key = "reference", .value = .{ .cid = r } });
        // Broadcast: the Atomic BEEF to the broadcaster (#70: a message), then await its answer and the status.
        if (created.reference == null and !created.no_send and bc.key != null) {
            try wal.noteBroadcast(created.txid, "broadcast", "");
            try bc.broadcast(a, created.txid, created.beef);
            try out.append(a, .{ .key = "outcome", .value = .{ .text = "pending" } });
            try await_txs.append(a, created.txid);
        }
    } else if (std.mem.eql(u8, op, "list")) {
        mutates = false;
        const basket = body.getText("basket") orelse "default";
        const views = try wal.listOutputs(basket, body.getBool("includeSpent") orelse false);
        const items = try a.alloc(Value, views.len);
        var total: u64 = 0;
        for (views, items) |v, *it| {
            if (v.spendable) total += v.satoshis;
            it.* = .{ .map = try a.dupe(cbor.Entry, &.{
                .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &w.header.toHex(v.txid)) } },
                .{ .key = "vout", .value = .{ .uint = v.vout } },
                .{ .key = "satoshis", .value = .{ .uint = v.satoshis } },
                .{ .key = "lockingScript", .value = .{ .bytes = v.locking_script } },
                .{ .key = "spendable", .value = .{ .boolean = v.spendable } },
                .{ .key = "status", .value = .{ .text = @tagName(v.status) } },
            }) };
        }
        try out.appendSlice(a, &.{
            .{ .key = "basket", .value = .{ .text = basket } },
            .{ .key = "outputs", .value = .{ .array = items } },
            .{ .key = "total", .value = .{ .uint = total } },
        });
    } else {
        std.log.err("unknown op {s}", .{op});
        return error.BadBody;
    }

    if (mutates) {
        const new_state = try wal.save();
        if (sk.advance(head_name.ptr, head_name.len, new_state.ptr, @intCast(new_state.len)) < 0) return failed();
        try out.append(a, .{ .key = "state", .value = .{ .cid = new_state } });
    } else if (state_cid.len > 0) {
        try out.append(a, .{ .key = "state", .value = .{ .cid = state_cid } });
    }
    // Topics' judgements the rejections removed (an instance that is also an
    // overlay): each topic's lookup services are told, in this step (#50).
    if (wal.unapplied.items.len > 0) try w.overlay.hookRejected(a, VmCaller.caller(), step, wal.unapplied.items);
    if (await_txs.items.len > 0) {
        // Rest until a `status` / `proof` entry for one of these transactions (a CID is its txid), or the deadline.
        const hexes = try a.alloc(Value, await_txs.items.len);
        for (await_txs.items, hexes) |t, *h| {
            const subject = txCid(t);
            if (sk.@"await"(&subject, subject.len) < 0) return failed();
            h.* = .{ .text = try a.dupe(u8, &w.header.toHex(t)) };
        }
        if (sk.deadline(now + recheck_ms) < 0) return failed();
        try out.appendSlice(a, &.{
            .{ .key = "txid", .value = hexes[0] },
            .{ .key = "awaited", .value = .{ .array = hexes } },
            .{ .key = "awaiting", .value = .{ .boolean = true } },
        });
    }
    // What this thread asked the broadcaster and has no answer to yet: awaited (the answer steps it), and kept on the result.
    if (bc.asked.items.len > 0) {
        const ids = try a.alloc(Value, bc.asked.items.len);
        for (bc.asked.items, ids) |id, *v| {
            if (sk.@"await"(id.ptr, @intCast(id.len)) < 0) return failed();
            v.* = .{ .cid = id };
        }
        try out.append(a, .{ .key = "asked", .value = .{ .array = ids } });
    }
    // The transactions this result is about, as `mentions` (kernel edges from the thread).
    {
        var named: std.ArrayList([32]u8) = .empty;
        for (out.items) |e| if (std.mem.eql(u8, e.key, "txid") and e.value == .text) {
            const t = w.header.fromHex(e.value.text) catch continue;
            if (!contains(named.items, t)) try named.append(a, t);
        };
        if (named.items.len > 0) {
            const refs = try a.alloc(Value, named.items.len);
            for (named.items, refs) |t, *r| r.* = .{ .map = try a.dupe(cbor.Entry, &.{
                .{ .key = "to", .value = .{ .cid = try a.dupe(u8, &txCid(t)) } },
                .{ .key = "rel", .value = .{ .text = "mentions" } },
            }) };
            try out.append(a, .{ .key = "refs", .value = .{ .array = refs } });
        }
    }
    const res_cid = try s.putValue(a, .{ .map = try dedupe(a, out.items) });
    if (sk.keep(res_cid.ptr, @intCast(res_cid.len)) < 0) return failed();
    var line = try hexAlloc(a, res_cid);
    line = try std.mem.concat(a, u8, &.{ line, "\n" });
    try std.Io.File.stdout().writeStreamingAll(io(), line);
}

/// Later entries win (a result may name its txid twice).
fn dedupe(a: std.mem.Allocator, es: []const cbor.Entry) ![]const cbor.Entry {
    var out: std.ArrayList(cbor.Entry) = .empty;
    for (es, 0..) |e, i| {
        var later = false;
        for (es[i + 1 ..]) |x| later = later or std.mem.eql(u8, x.key, e.key);
        if (!later) try out.append(a, e);
    }
    return out.items;
}

/// The txid a `proof` / `status` record is about: its subject (a bitcoin-tx CID), else its txid (hex).
fn eventTxid(ev: Value) ![32]u8 {
    if (ev.getCid("subject")) |c| return w.store.bitcoinHash(c) orelse error.BadEvent;
    return w.header.fromHex(ev.getText("txid") orelse return error.BadEvent);
}

fn applyEvent(wal: *w.wallet.Wallet, txid: [32]u8, kind: []const u8, ev: Value) !w.wallet.Wallet.Outcome {
    if (std.mem.eql(u8, kind, "proof")) return wal.applyStatus(txid, "MINED", ev.getBytes("path") orelse return error.BadEvent);
    if (std.mem.eql(u8, kind, "status")) return wal.applyStatus(txid, ev.getText("txStatus") orelse "", ev.getBytes("merklePath"));
    return error.BadEvent;
}

/// The txids the thread awaits: in the result its last step kept (`awaited`, else its `txid`).
fn awaitedFromTip(a: std.mem.Allocator, s: w.store.Store, step: Value) !std.ArrayList([32]u8) {
    var out: std.ArrayList([32]u8) = .empty;
    const tip = try s.getValue(a, step.getCid("tip") orelse return out);
    const kept = tip.getArray("kept") orelse return out;
    if (kept.len == 0 or kept[kept.len - 1] != .cid) return out;
    const res = try s.getValue(a, kept[kept.len - 1].cid);
    if (res.getArray("awaited")) |xs| {
        for (xs) |x| if (x == .text) try out.append(a, try w.header.fromHex(x.text));
    } else if (res.getText("txid")) |t| try out.append(a, try w.header.fromHex(t));
    return out;
}

fn contains(xs: []const [32]u8, t: [32]u8) bool {
    for (xs) |x| if (std.mem.eql(u8, &x, &t)) return true;
    return false;
}

/// A transaction's CID: bitcoin-tx (0xb1), dbl-sha2-256, the txid.
fn txCid(txid: [32]u8) [37]u8 {
    return .{ 0x01, 0xb1, 0x01, 0x56, 0x20 } ++ txid;
}

/// After a reorg: our transactions turned back to unproven are broadcast
/// again (as after createAction) and awaited.
fn rebroadcast(a: std.mem.Allocator, wal: *w.wallet.Wallet, bc: *Broadcaster, await_txs: *std.ArrayList([32]u8), out: *std.ArrayList(cbor.Entry)) !void {
    if (wal.reverted.items.len == 0) return;
    const hexes = try a.alloc(Value, wal.reverted.items.len);
    for (wal.reverted.items, hexes) |t, *h| h.* = .{ .text = try a.dupe(u8, &w.header.toHex(t)) };
    try out.append(a, .{ .key = "reverted", .value = .{ .array = hexes } });
    if (bc.key == null) return;
    for (wal.reverted.items) |t| {
        const beef = (try wal.beefOf(t)) orelse continue;
        try wal.noteBroadcast(t, "broadcast", "");
        try bc.broadcast(a, t, beef);
        if (!contains(await_txs.items, t)) try await_txs.append(a, t);
    }
}

/// The address book's `broadcast` provider's key (#70: the entry with role
/// "broadcast" under the head `peers`), or null.
fn broadcasterKey(a: std.mem.Allocator, s: w.store.Store) !?[]const u8 {
    const name = "peers";
    const root = try result(a, sk.head, .{ name.ptr, @as(u32, name.len) });
    if (root.len == 0) return null;
    const book = try s.getValue(a, root);
    for (book.getArray("peers") orelse return null) |e| {
        const p = try s.getValue(a, e.getCid("peer") orelse continue);
        if (std.mem.eql(u8, p.getText("role") orelse "", "broadcast")) return p.getBytes("key");
    }
    return null;
}

/// The broadcaster as this step talks to it (#70): what it is asked — a
/// message each, emitted, about the transaction (`subject` its CID) — and
/// what the thread still awaits an answer to.
const Broadcaster = struct {
    key: ?[]const u8,
    asked: std.ArrayList([]const u8) = .empty,

    /// The thread's questions still unanswered (the last result's `asked`), but for `answered`.
    fn carry(self: *Broadcaster, a: std.mem.Allocator, s: w.store.Store, step: Value, answered: ?[]const u8) !void {
        const tip = try s.getValue(a, step.getCid("tip") orelse return);
        const kept = tip.getArray("kept") orelse return;
        if (kept.len == 0 or kept[kept.len - 1] != .cid) return;
        const res = try s.getValue(a, kept[kept.len - 1].cid);
        for (res.getArray("asked") orelse return) |x| {
            if (x != .cid) continue;
            if (answered) |c| if (std.mem.eql(u8, c, x.cid)) continue;
            try self.asked.append(a, x.cid);
        }
    }

    /// A message to the broadcaster in `box` about `txid`.
    fn emit(self: *Broadcaster, a: std.mem.Allocator, box: []const u8, txid: [32]u8, body: Value) !void {
        const to = self.key orelse return;
        const subject = txCid(txid);
        const msg = try cbor.encode(a, .{ .map = try a.dupe(cbor.Entry, &.{
            .{ .key = "to", .value = .{ .bytes = to } },
            .{ .key = "box", .value = .{ .text = box } },
            .{ .key = "body", .value = .{ .bytes = try cbor.encode(a, body) } },
            .{ .key = "subject", .value = .{ .cid = try a.dupe(u8, &subject) } },
        }) });
        try self.asked.append(a, try result(a, sk.emit, .{ msg.ptr, @as(u32, @intCast(msg.len)) }));
    }

    /// Broadcast a transaction: its Atomic BEEF (box "broadcast", {tx}).
    fn broadcast(self: *Broadcaster, a: std.mem.Allocator, txid: [32]u8, beef: []const u8) !void {
        try self.emit(a, "broadcast", txid, .{ .map = try a.dupe(cbor.Entry, &.{.{ .key = "tx", .value = .{ .bytes = beef } }}) });
    }

    /// Ask after a transaction (box "status", {txid}).
    fn ask(self: *Broadcaster, a: std.mem.Allocator, txid: [32]u8) !void {
        try self.emit(a, "status", txid, .{ .map = try a.dupe(cbor.Entry, &.{.{ .key = "txid", .value = .{ .text = try a.dupe(u8, &w.header.toHex(txid)) } }}) });
    }
};

const ArcAnswer = struct {
    http_status: u64,
    tx_status: []const u8,
    merkle_path: ?[]const u8,
    extra: []const u8,

    fn value(self: ArcAnswer, a: std.mem.Allocator) !Value {
        var es: std.ArrayList(cbor.Entry) = .empty;
        try es.appendSlice(a, &.{
            .{ .key = "status", .value = .{ .uint = self.http_status } },
            .{ .key = "txStatus", .value = .{ .text = self.tx_status } },
            .{ .key = "extraInfo", .value = .{ .text = self.extra } },
        });
        if (self.merkle_path) |p| try es.append(a, .{ .key = "merklePath", .value = .{ .bytes = p } });
        return .{ .map = es.items };
    }
};

/// The broadcaster's answer {status, body} (Arcade's HTTP status and JSON):
/// a 4xx is a rejection unless Arcade names a status; anything else
/// unanswered (no answer at all: {error}) stays pending.
fn arcAnswer(a: std.mem.Allocator, ans: Value) !ArcAnswer {
    const status = ans.getUint("status") orelse 0;
    const text = ans.getBytes("body") orelse "";
    var out = ArcAnswer{ .http_status = status, .tx_status = "", .merkle_path = null, .extra = ans.getText("error") orelse "" };
    if (std.json.parseFromSliceLeaky(std.json.Value, a, text, .{})) |j| {
        if (j == .object) {
            if (j.object.get("txStatus")) |t| if (t == .string) {
                out.tx_status = t.string;
            };
            if (j.object.get("extraInfo")) |t| if (t == .string) {
                out.extra = t.string;
            };
            if (j.object.get("merklePath")) |t| if (t == .string and t.string.len > 0) {
                const p = try a.alloc(u8, t.string.len / 2);
                _ = std.fmt.hexToBytes(p, t.string) catch return error.BadHttpResponse;
                out.merkle_path = p;
            };
        }
    } else |_| {}
    if (out.tx_status.len == 0 and status >= 400 and status < 500) out.tx_status = "REJECTED";
    return out;
}

