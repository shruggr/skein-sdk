//! wallet: the handler program for the `wallet` box (issue #29, phase 1), a
//! wasm32-wasi command stepped with the `skein` imports
//! (src/runtime/wasi/skein-imports.ts). One run is one step over one input.
//!
//! The wallet's state is the record the head `wallet` names (a
//! `wallet-state`: its index maps by name); each step loads it, applies the
//! body's operation, saves new index records and a new state record, and
//! advances the head. Every step also stores a result record, keeps it in
//! the thread, and prints its CID (hex) on stdout.
//!
//! Body operations (dag-cbor; docs/WALLET.md):
//!   {op: "checkpoint", height, header}          the trusted starting header (into an empty chain)
//!   {op: "headers", headers: [bytes]}           a run of headers, parents first (ChainTracks)
//!   {op: "internalize", tx, outputs, description, labels?}   BRC-100 internalizeAction (Atomic BEEF)
//!   {op: "proof", txid, path}                   a merkle path (BRC-74) for a transaction we hold
//!   {op: "list", basket?, includeSpent?}        our outputs in a basket (default "default")
//!
//! The only attested call is getPublicKey, to derive our BRC-29 payee key
//! (the oracle, over the `wallet` import). Nothing here signs.
const std = @import("std");
const w = @import("wallet");

const cbor = w.cbor;
const Value = cbor.Value;

const sk = struct {
    extern "skein" fn input(out: [*]u8, cap: u32) i32;
    extern "skein" fn get(cid: [*]const u8, cid_len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn put(data: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn keep(cid: [*]const u8, cid_len: u32) i32;
    extern "skein" fn head(name: [*]const u8, name_len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn advance(name: [*]const u8, name_len: u32, tree: [*]const u8, tree_len: u32) i32;
    extern "skein" fn wallet(frame: [*]const u8, len: u32, out: [*]u8, cap: u32) i32;
    extern "skein" fn take(out: [*]u8, cap: u32) i32;
    extern "skein" fn @"error"(out: [*]u8, cap: u32) i32;
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
    var dummy: u8 = 0;
    fn store() w.store.Store {
        return .{ .ptr = &dummy, .getFn = getImpl, .putFn = putImpl };
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
    const body_cid = args.getCid("body") orelse return error.BadInput;
    const body = s.getValue(a, body_cid) catch |e| {
        std.log.err("body record: {s}", .{@errorName(e)});
        return e;
    };
    const op = body.getText("op") orelse return error.BadBody;

    const state_cid = try result(a, sk.head, .{ head_name.ptr, @as(u32, head_name.len) });
    var wal = try w.wallet.Wallet.load(a, s, if (state_cid.len > 0) state_cid else null);

    var out: std.ArrayList(cbor.Entry) = .empty;
    try out.appendSlice(a, &.{
        .{ .key = "kind", .value = .{ .text = "wallet-result" } },
        .{ .key = "op", .value = .{ .text = op } },
    });
    var mutates = true;

    if (std.mem.eql(u8, op, "checkpoint")) {
        const height = (try field(body, "height"));
        const raw = try field(body, "header");
        if (height != .uint or raw != .bytes) return error.BadBody;
        try wal.checkpoint(@intCast(height.uint), raw.bytes);
        try out.append(a, .{ .key = "height", .value = height });
    } else if (std.mem.eql(u8, op, "headers")) {
        const list = try field(body, "headers");
        if (list != .array) return error.BadBody;
        const raws = try a.alloc([]const u8, list.array.len);
        for (list.array, raws) |x, *r| r.* = if (x == .bytes) x.bytes else return error.BadBody;
        const res = try wal.addHeaders(raws);
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
    const res_cid = try s.putValue(a, .{ .map = out.items });
    if (sk.keep(res_cid.ptr, @intCast(res_cid.len)) < 0) return failed();
    var line = try hexAlloc(a, res_cid);
    line = try std.mem.concat(a, u8, &.{ line, "\n" });
    try std.fs.File.stdout().writeAll(line);
}
