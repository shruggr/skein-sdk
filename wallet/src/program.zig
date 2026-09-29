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
//!   {op: "watch", settlement?: bool}            the sender opts in (default) or out of settlement messages
//!
//! Plain entries (docs/WALLET.md): {kind: "header", raw}, {kind: "proof",
//! subject, txid, path}, {kind: "status", subject, txid, txStatus, merklePath?}.
//!
//! Recorded calls: the oracle over the `wallet` import (getPublicKey,
//! createSignature: no key is ever here), and HTTP to ARC (broadcast, status
//! re-query) — the `http` import in the preview1 build, standard wasi:http in
//! the component build (#15, wasi_http.zig), the same requests either way. After a broadcast the thread awaits its transaction's CID with
//! a deadline; a `status`/`proof` entry for it, or the deadline, steps it.
//! A transaction never mined within
//! defaults.walletAbandonMs of its broadcast is abandoned (rejected); a reorg
//! that turns ours back to unproven broadcasts them again and awaits them.
//!
//! Settlement (#37): every change of a transaction of ours (proven,
//! unproven after a reorg, rejected — with what the rejection bubbled to) is
//! sent as a `{kind: "settlement", txid, status, reason, cause?}` message to
//! each identity that opted in (`watch`), in its `settlement` box. A
//! result record names the transactions it is about as `refs` with rel
//! `mentions` (kernel edges; a mention never propagates a rejection).
const std = @import("std");
const w = @import("wallet");

const cbor = w.cbor;
const Value = cbor.Value;

/// The skein calls: the preview1 `skein` imports, or (the component build, issue
/// #34) the same calls over the WIT interface skein:kernel/skein (skein_wit.zig).
const component = @import("build_options").component;
/// Outgoing HTTP in the component build (#15): standard wasi:http.
const wasi_http = if (component) @import("wasi_http.zig") else struct {};
const sk = if (component) @import("skein_wit.zig") else struct {
    extern "skein" fn input(out: [*]u8, cap: u32) i32;
    extern "skein" fn get(cid: [*]const u8, cid_len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn put(data: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn putblock(cid: [*]const u8, cid_len: u32, data: [*]const u8, len: u32) i32;
    extern "skein" fn keep(cid: [*]const u8, cid_len: u32) i32;
    extern "skein" fn head(name: [*]const u8, name_len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn advance(name: [*]const u8, name_len: u32, tree: [*]const u8, tree_len: u32) i32;
    extern "skein" fn wallet(frame: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn http(req: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
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

const head_name = "wallet";

pub fn main() u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.wasm_allocator);
    defer arena_state.deinit();
    run(arena_state.allocator()) catch |e| {
        var buf: [1400]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "wallet: {s}{s}{s}\n", .{ @errorName(e), if (last_error_len > 0) ": " else "", last_error[0..last_error_len] }) catch "wallet: error\n";
        std.fs.File.stderr().writeAll(msg) catch {};
        return 1;
    };
    return 0;
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
    var body: Value = .null;
    var op: []const u8 = undefined;
    if (callback != null or woke) {
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
    const arc_url: ?[]const u8 = if (defaults) |d| d.getText("walletArc") else null;
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
        try rebroadcast(a, &wal, arc_url, &await_txs, &out);
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
            try rebroadcast(a, &wal, arc_url, &await_txs, &out);
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
        var txid: [32]u8 = undefined;
        var outcome: w.wallet.Wallet.Outcome = .pending;
        if (callback != null) {
            txid = try eventTxid(body);
            const kind = body.getText("kind") orelse return error.BadEvent;
            outcome = try applyEvent(&wal, txid, kind, body);
            try out.append(a, .{ .key = "event", .value = .{ .text = kind } });
            if (!contains(awaited.items, txid)) try awaited.insert(a, 0, txid);
        } else {
            if (awaited.items.len == 0) return error.BadInput;
            txid = awaited.items[0];
            for (awaited.items) |t| {
                const r = (try wal.awaitingRecord(t)) orelse continue;
                if (try wal.abandonIfDue(t, abandon_ms)) continue;
                const arc = r.getText("arc") orelse return error.BadRecord;
                const url = try std.fmt.allocPrint(a, "{s}/v1/tx/{s}", .{ arc, w.header.toHex(t) });
                const ans = try arcCall(a, "GET", url, null);
                _ = try wal.applyStatus(t, ans.tx_status, ans.merkle_path);
                if (std.mem.eql(u8, &t, &txid)) try out.append(a, .{ .key = "arc", .value = try ans.value(a) });
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
            std.crypto.random.bytes(&rnd);
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
        // Broadcast: the Atomic BEEF to ARC over http, then await the status.
        if (created.reference == null and !created.no_send) if (arc_url) |arc| {
            try wal.noteBroadcast(created.txid, arc, "");
            const ans = try arcCall(a, "POST", try std.fmt.allocPrint(a, "{s}/v1/tx", .{arc}), created.beef);
            const outcome = try wal.applyStatus(created.txid, ans.tx_status, ans.merkle_path);
            try out.appendSlice(a, &.{
                .{ .key = "arc", .value = try ans.value(a) },
                .{ .key = "outcome", .value = .{ .text = @tagName(outcome) } },
            });
            if (outcome == .pending) try await_txs.append(a, created.txid);
        };
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
    } else if (std.mem.eql(u8, op, "watch")) {
        // The sender opts in (or out) of settlement messages in its `settlement` box.
        const sender = args.getBytes("sender") orelse return error.BadBody;
        if (sender.len != 33) return error.BadBody;
        const on = body.getBool("settlement") orelse true;
        try wal.watch(sender[0..33].*, on);
        try out.append(a, .{ .key = "settlement", .value = .{ .boolean = on } });
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
    // Settlement changes: in the result, and to each watcher's `settlement` box.
    if (wal.changes.items.len > 0) {
        const items = try a.alloc(Value, wal.changes.items.len);
        for (wal.changes.items, items) |c, *it| it.* = try settlementBody(a, c);
        try out.append(a, .{ .key = "settlement", .value = .{ .array = items } });
        const watchers = try wal.watchers();
        var sent: u64 = 0;
        for (watchers) |to| for (items) |it| {
            if (try sendTo(a, s, step, to, "settlement", it)) sent += 1;
        };
        if (watchers.len > 0) try out.append(a, .{ .key = "sent", .value = .{ .uint = sent } });
    }
    // The transactions this result is about, as `mentions` (kernel edges from the thread).
    {
        var named: std.ArrayList([32]u8) = .empty;
        for (out.items) |e| if (std.mem.eql(u8, e.key, "txid") and e.value == .text) {
            const t = w.header.fromHex(e.value.text) catch continue;
            if (!contains(named.items, t)) try named.append(a, t);
        };
        for (wal.changes.items) |c| if (!contains(named.items, c.txid)) try named.append(a, c.txid);
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
    try std.fs.File.stdout().writeAll(line);
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
fn rebroadcast(a: std.mem.Allocator, wal: *w.wallet.Wallet, arc_url: ?[]const u8, await_txs: *std.ArrayList([32]u8), out: *std.ArrayList(cbor.Entry)) !void {
    if (wal.reverted.items.len == 0) return;
    const hexes = try a.alloc(Value, wal.reverted.items.len);
    for (wal.reverted.items, hexes) |t, *h| h.* = .{ .text = try a.dupe(u8, &w.header.toHex(t)) };
    try out.append(a, .{ .key = "reverted", .value = .{ .array = hexes } });
    const arc = arc_url orelse return;
    for (wal.reverted.items) |t| {
        const beef = (try wal.beefOf(t)) orelse continue;
        try wal.noteBroadcast(t, arc, "");
        const ans = try arcCall(a, "POST", try std.fmt.allocPrint(a, "{s}/v1/tx", .{arc}), beef);
        if ((try wal.applyStatus(t, ans.tx_status, ans.merkle_path)) == .pending and !contains(await_txs.items, t)) try await_txs.append(a, t);
    }
}

/// What the `settlement` box is sent: {kind: "settlement", txid, status, reason, cause?}.
fn settlementBody(a: std.mem.Allocator, c: w.wallet.Change) !Value {
    var es: std.ArrayList(cbor.Entry) = .empty;
    try es.appendSlice(a, &.{
        .{ .key = "kind", .value = .{ .text = "settlement" } },
        .{ .key = "txid", .value = .{ .text = try a.dupe(u8, &w.header.toHex(c.txid)) } },
        .{ .key = "status", .value = .{ .text = @tagName(c.status) } },
        .{ .key = "reason", .value = .{ .text = c.reason } },
    });
    if (c.cause) |x| try es.append(a, .{ .key = "cause", .value = .{ .text = try a.dupe(u8, &w.header.toHex(x)) } });
    return .{ .map = es.items };
}

var identity_key: ?[33]u8 = null;

/// This instance's identity key, from the oracle (once per step).
fn identity(a: std.mem.Allocator) ![33]u8 {
    if (identity_key) |k| return k;
    const frame = try w.wire.identityKeyFrame(a);
    const res = try result(a, sk.wallet, .{ frame.ptr, @as(u32, @intCast(frame.len)) });
    identity_key = try w.wire.publicKeyResult(res);
    return identity_key.?;
}

/// ISO 8601 of a time in ms since the epoch (as JavaScript's toISOString).
fn isoTime(a: std.mem.Allocator, ms: i64) ![]u8 {
    const secs: u64 = @intCast(@divFloor(ms, 1000));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{ yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(), @as(u64, @intCast(@mod(ms, 1000))) });
}

/// Send `body` to identity `to` in `box` (#40): the messagebox program
/// delivers it over http (an in-VM call; its http calls are this step's,
/// recorded). True if it was delivered; a failure is logged on stderr and the
/// step goes on (a watcher that cannot be reached misses a settlement message).
fn sendTo(a: std.mem.Allocator, s: w.store.Store, step: Value, to: [33]u8, box: []const u8, body: Value) !bool {
    const bc = try s.putValue(a, body);
    const plain = try s.get(a, bc);
    const progs = step.get("programs") orelse return false;
    const mb = switch (progs.get("messagebox") orelse return false) {
        .cid => |x| x,
        else => return false,
    };
    const arg = try cbor.encode(a, .{ .map = try a.dupe(cbor.Entry, &.{
        .{ .key = "to", .value = .{ .bytes = try a.dupe(u8, &to) } },
        .{ .key = "box", .value = .{ .text = box } },
        .{ .key = "body", .value = .{ .bytes = plain } },
    }) });
    _ = result(a, sk.call, .{ mb.ptr, @as(u32, @intCast(mb.len)), "send".ptr, @as(u32, 4), arg.ptr, @as(u32, @intCast(arg.len)) }) catch |err| {
        if (err != error.ImportFailed) return err;
        var buf: [1200]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "wallet: {s} to {s}: {s}\n", .{ box, std.fmt.bytesToHex(to, .lower)[58..], last_error[0..last_error_len] }) catch "wallet: send failed\n";
        std.fs.File.stderr().writeAll(line) catch {};
        return false;
    };
    return true;
}

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

/// One call to ARC's API: over the `http` import in the preview1 build (this
/// function as it was before #15, so the pinned module is unchanged), over
/// standard wasi:http in the component build (wasiArcCall, #15), which the
/// kernel serializes into the very same recorded request.
const arcCall = if (component) wasiArcCall else p1ArcCall;

/// One call to ARC's API over the `http` import (attested: request and
/// response are recorded, so replay never touches the network). A 4xx is a
/// rejection unless ARC names a status; anything else unanswered stays pending.
fn p1ArcCall(a: std.mem.Allocator, method: []const u8, url: []const u8, body: ?[]const u8) !ArcAnswer {
    var req: std.ArrayList(cbor.Entry) = .empty;
    try req.appendSlice(a, &.{
        .{ .key = "method", .value = .{ .text = method } },
        .{ .key = "url", .value = .{ .text = url } },
        .{ .key = "headers", .value = .{ .map = if (body != null) &.{
            .{ .key = "Content-Type", .value = .{ .text = "application/octet-stream" } },
            .{ .key = "Accept", .value = .{ .text = "application/json" } },
        } else &.{.{ .key = "Accept", .value = .{ .text = "application/json" } }} } },
    });
    if (body) |b| try req.append(a, .{ .key = "body", .value = .{ .bytes = b } });
    const req_bytes = try cbor.encode(a, .{ .map = req.items });
    const res_bytes = try result(a, sk.http, .{ req_bytes.ptr, @as(u32, @intCast(req_bytes.len)) });
    const res = try cbor.decode(a, res_bytes);
    const status = res.getUint("status") orelse return error.BadHttpResponse;
    const text = res.getBytes("body") orelse "";
    var ans = ArcAnswer{ .http_status = status, .tx_status = "", .merkle_path = null, .extra = "" };
    if (std.json.parseFromSliceLeaky(std.json.Value, a, text, .{})) |j| {
        if (j == .object) {
            if (j.object.get("txStatus")) |t| if (t == .string) {
                ans.tx_status = t.string;
            };
            if (j.object.get("extraInfo")) |t| if (t == .string) {
                ans.extra = t.string;
            };
            if (j.object.get("merklePath")) |t| if (t == .string and t.string.len > 0) {
                const p = try a.alloc(u8, t.string.len / 2);
                _ = std.fmt.hexToBytes(p, t.string) catch return error.BadHttpResponse;
                ans.merkle_path = p;
            };
        }
    } else |_| {}
    if (ans.tx_status.len == 0 and status >= 400 and status < 500) ans.tx_status = "REJECTED";
    return ans;
}

/// The same call over wasi:http (the component build): the same method, URL,
/// headers and body, so the kernel records the same request; the same reading
/// of the answer as p1ArcCall's.
fn wasiArcCall(a: std.mem.Allocator, method: []const u8, url: []const u8, body: ?[]const u8) !ArcAnswer {
    const headers: []const wasi_http.Header = if (body != null) &.{
        .{ .name = "Content-Type", .value = "application/octet-stream" },
        .{ .name = "Accept", .value = "application/json" },
    } else &.{.{ .name = "Accept", .value = "application/json" }};
    const r = wasi_http.request(a, method, url, headers, body) catch |e| {
        const n = @min(wasi_http.last_error.len, last_error.len);
        @memcpy(last_error[0..n], wasi_http.last_error[0..n]);
        last_error_len = n;
        return e;
    };
    const status: u64 = r.status;
    const text = r.body;
    var ans = ArcAnswer{ .http_status = status, .tx_status = "", .merkle_path = null, .extra = "" };
    if (std.json.parseFromSliceLeaky(std.json.Value, a, text, .{})) |j| {
        if (j == .object) {
            if (j.object.get("txStatus")) |t| if (t == .string) {
                ans.tx_status = t.string;
            };
            if (j.object.get("extraInfo")) |t| if (t == .string) {
                ans.extra = t.string;
            };
            if (j.object.get("merklePath")) |t| if (t == .string and t.string.len > 0) {
                const p = try a.alloc(u8, t.string.len / 2);
                _ = std.fmt.hexToBytes(p, t.string) catch return error.BadHttpResponse;
                ans.merkle_path = p;
            };
        }
    } else |_| {}
    if (ans.tx_status.len == 0 and status >= 400 and status < 500) ans.tx_status = "REJECTED";
    return ans;
}
