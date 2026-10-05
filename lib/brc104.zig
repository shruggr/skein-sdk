//! BRC-103/104 over HTTP inside the VM (#40): the server side — the front
//! door verifies requests and signs responses. The client is the kernel's
//! (shruggr/skein#126: the `authfetch` import, sk.authfetch: the session,
//! the request's signature and the answer's check happen in the kernel, a
//! recorded call). Every signature, HMAC and key goes through the signer
//! (the `wallet` import: BRC-100 wire frames): in a kernel call it is
//! answered and not recorded, in a step it is a recorded call. The framing is
//! @bsv/sdk's SimplifiedFetchTransport's, so the stock AuthFetch talks to the
//! front door.
const std = @import("std");
const cbor = @import("cbor");
const sk = @import("sk");

const Allocator = std.mem.Allocator;

pub const AUTH_PROTOCOL = "auth message signature";
pub const NONCE_PROTOCOL = "server hmac";
pub const WELL_KNOWN = "/.well-known/auth";
pub const VERSION = "0.1";

const b64 = std.base64.standard;

// ---------------------------------------------------------------- BRC-100 wire frames (the signer)

pub const Counterparty = union(enum) { self, anyone, other: []const u8 };

pub fn varint(a: Allocator, out: *std.ArrayList(u8), v: u64) !void {
    if (v < 0xfd) {
        try out.append(a, @intCast(v));
    } else if (v <= 0xffff) {
        try out.append(a, 0xfd);
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, @intCast(v), .little);
        try out.appendSlice(a, &b);
    } else if (v <= 0xffff_ffff) {
        try out.append(a, 0xfe);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, @intCast(v), .little);
        try out.appendSlice(a, &b);
    } else {
        try out.append(a, 0xff);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try out.appendSlice(a, &b);
    }
}

fn keyParams(a: Allocator, out: *std.ArrayList(u8), call: u8, protocol: []const u8, key_id: []const u8, cp: Counterparty) !void {
    try out.appendSlice(a, &.{ call, 0 }); // the call, an empty originator
    try out.append(a, 2); // security level 2
    try varint(a, out, protocol.len);
    try out.appendSlice(a, protocol);
    try varint(a, out, key_id.len);
    try out.appendSlice(a, key_id);
    switch (cp) {
        .self => try out.append(a, 11),
        .anyone => try out.append(a, 12),
        .other => |k| try out.appendSlice(a, k),
    }
    try out.append(a, 0); // privileged: false
    try out.append(a, 0xff); // privilegedReason: none
}

/// The payload of a successful result frame, or null for a wallet error.
fn ok(frame: []const u8) ?[]const u8 {
    if (frame.len == 0 or frame[0] != 0) return null;
    return frame[1..];
}

/// This instance's identity key (33 bytes).
pub fn identityKey(a: Allocator) ![]const u8 {
    const res = try sk.wallet(a, &.{ 8, 0, 1, 0, 0xff, 0 });
    const p = ok(res) orelse return error.OracleIdentity;
    if (p.len != 33) return error.OracleIdentity;
    return p;
}

pub fn createHmac(a: Allocator, protocol: []const u8, key_id: []const u8, cp: Counterparty, data: []const u8) ![]const u8 {
    var f: std.ArrayList(u8) = .empty;
    try keyParams(a, &f, 13, protocol, key_id, cp);
    try varint(a, &f, data.len);
    try f.appendSlice(a, data);
    try f.append(a, 0); // seekPermission: false
    const p = ok(try sk.wallet(a, f.items)) orelse return error.OracleHmac;
    if (p.len != 32) return error.OracleHmac;
    return p;
}

pub fn createSignature(a: Allocator, protocol: []const u8, key_id: []const u8, cp: Counterparty, data: []const u8) ![]const u8 {
    var f: std.ArrayList(u8) = .empty;
    try keyParams(a, &f, 15, protocol, key_id, cp);
    try f.append(a, 1); // data follows
    try varint(a, &f, data.len);
    try f.appendSlice(a, data);
    try f.append(a, 0);
    const p = ok(try sk.wallet(a, f.items)) orelse return error.OracleSignature;
    if (p.len < 8 or p[0] != 0x30) return error.OracleSignature;
    return p;
}

pub fn verifySignature(a: Allocator, protocol: []const u8, key_id: []const u8, cp: Counterparty, data: []const u8, sig: []const u8) !bool {
    var f: std.ArrayList(u8) = .empty;
    try keyParams(a, &f, 16, protocol, key_id, cp);
    try f.append(a, 0xff); // forSelf: none
    try varint(a, &f, sig.len);
    try f.appendSlice(a, sig);
    try f.append(a, 1);
    try varint(a, &f, data.len);
    try f.appendSlice(a, data);
    try f.append(a, 0);
    return ok(try sk.wallet(a, f.items)) != null;
}

// ---------------------------------------------------------------- nonces

/// A session nonce (BRC-104 createNonce): 16 random bytes — printable ASCII,
/// so the SDK's keyID (the bytes read as UTF-8) is the same string on every
/// side — and their HMAC under [2, "server hmac"], counterparty self; base64
/// of the 48 bytes.
pub fn createNonce(a: Allocator) ![]const u8 {
    var first: [16]u8 = undefined;
    sk.io().randomSecure(&first) catch return error.Random;
    for (&first) |*b| b.* = 33 + b.* % 94;
    const mac = try createHmac(a, NONCE_PROTOCOL, &first, .self, &first);
    var raw: [48]u8 = undefined;
    @memcpy(raw[0..16], &first);
    @memcpy(raw[16..], mac);
    return encode64(a, &raw);
}

/// A request or response nonce: 32 random bytes, base64 (the SDK's).
pub fn random64(a: Allocator) ![]const u8 {
    var raw: [32]u8 = undefined;
    sk.io().randomSecure(&raw) catch return error.Random;
    return encode64(a, &raw);
}

pub fn encode64(a: Allocator, b: []const u8) ![]const u8 {
    const out = try a.alloc(u8, b64.Encoder.calcSize(b.len));
    return b64.Encoder.encode(out, b);
}

pub fn decode64(a: Allocator, s: []const u8) ?[]u8 {
    const n = b64.Decoder.calcSizeForSlice(s) catch return null;
    const out = a.alloc(u8, n) catch return null;
    b64.Decoder.decode(out, s) catch return null;
    return out;
}

// ---------------------------------------------------------------- the HTTP framing (SimplifiedFetchTransport)

fn writeField(a: Allocator, w: *std.ArrayList(u8), s: ?[]const u8) !void {
    const x = s orelse {
        try varint(a, w, std.math.maxInt(u64)); // -1: absent
        return;
    };
    if (x.len == 0) {
        try varint(a, w, std.math.maxInt(u64));
        return;
    }
    try varint(a, w, x.len);
    try w.appendSlice(a, x);
}

pub const Header = struct { name: []const u8, value: []const u8 };

fn lessHeader(_: void, x: Header, y: Header) bool {
    return std.mem.order(u8, x.name, y.name) == .lt;
}

/// The headers a request signs: x-bsv-* (not x-bsv-auth*), content-type (its media type only) and authorization; lower-cased, sorted.
pub fn signedRequestHeaders(a: Allocator, headers: []const Header) ![]Header {
    var out: std.ArrayList(Header) = .empty;
    for (headers) |h| {
        const k = try std.ascii.allocLowerString(a, h.name);
        var v = h.value;
        if (std.mem.eql(u8, k, "content-type")) {
            v = std.mem.trim(u8, v[0 .. std.mem.indexOfScalar(u8, v, ';') orelse v.len], " ");
        }
        if ((std.mem.startsWith(u8, k, "x-bsv-") or std.mem.eql(u8, k, "content-type") or std.mem.eql(u8, k, "authorization")) and !std.mem.startsWith(u8, k, "x-bsv-auth")) {
            try out.append(a, .{ .name = k, .value = v });
        }
    }
    std.mem.sort(Header, out.items, {}, lessHeader);
    return out.items;
}

/// The payload a request signs: requestId (32 bytes), method, path, query, the signed headers, the body.
pub fn requestPayload(a: Allocator, request_id: []const u8, method: []const u8, path: []const u8, query: []const u8, headers: []const Header, body: []const u8) ![]u8 {
    var w: std.ArrayList(u8) = .empty;
    try w.appendSlice(a, request_id);
    try varint(a, &w, method.len);
    try w.appendSlice(a, method);
    try writeField(a, &w, path);
    try writeField(a, &w, query);
    const signed = try signedRequestHeaders(a, headers);
    try varint(a, &w, signed.len);
    for (signed) |h| {
        try varint(a, &w, h.name.len);
        try w.appendSlice(a, h.name);
        try varint(a, &w, h.value.len);
        try w.appendSlice(a, h.value);
    }
    try writeField(a, &w, body);
    return w.items;
}

/// The payload a response signs: requestId, status, the signed headers (none here), the body.
pub fn responsePayload(a: Allocator, request_id: []const u8, status: u64, headers: []const Header, body: []const u8) ![]u8 {
    var w: std.ArrayList(u8) = .empty;
    try w.appendSlice(a, request_id);
    try varint(a, &w, status);
    try varint(a, &w, headers.len);
    for (headers) |h| {
        try varint(a, &w, h.name.len);
        try w.appendSlice(a, h.name);
        try varint(a, &w, h.value.len);
        try w.appendSlice(a, h.value);
    }
    try writeField(a, &w, body);
    return w.items;
}

const Reader = struct {
    b: []const u8,
    i: usize = 0,
    fn take(r: *Reader, n: usize) ?[]const u8 {
        if (n > r.b.len - r.i) return null;
        defer r.i += n;
        return r.b[r.i..][0..n];
    }
    fn varint(r: *Reader) ?u64 {
        const f = (r.take(1) orelse return null)[0];
        return switch (f) {
            0xfd => std.mem.readInt(u16, (r.take(2) orelse return null)[0..2], .little),
            0xfe => std.mem.readInt(u32, (r.take(4) orelse return null)[0..4], .little),
            0xff => std.mem.readInt(u64, (r.take(8) orelse return null)[0..8], .little),
            else => f,
        };
    }
    fn field(r: *Reader) ?[]const u8 {
        const n = r.varint() orelse return null;
        if (n == std.math.maxInt(u64)) return "";
        return r.take(@intCast(n));
    }
};

/// The body a signed request payload carries (after requestId, method, path, query, headers).
pub fn payloadBody(payload: []const u8) ?[]const u8 {
    var r = Reader{ .b = payload };
    _ = r.take(32) orelse return null;
    _ = r.field() orelse return null;
    _ = r.field() orelse return null;
    _ = r.field() orelse return null;
    const n = r.varint() orelse return null;
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        _ = r.field() orelse return null;
        _ = r.field() orelse return null;
    }
    return r.field();
}

// ---------------------------------------------------------------- a header map as dag-cbor carries it

/// A request's headers ({name: value}, names lower-cased by the host) as a list.
pub fn headerList(a: Allocator, m: ?cbor.Value) ![]Header {
    const v = m orelse return &.{};
    if (v != .map) return &.{};
    var out: std.ArrayList(Header) = .empty;
    for (v.map) |e| if (e.value == .string) try out.append(a, .{ .name = e.key, .value = e.value.string });
    return out.items;
}

pub fn headerOf(m: ?cbor.Value, name: []const u8) ?[]const u8 {
    const v = m orelse return null;
    if (v != .map) return null;
    for (v.map) |e| if (std.ascii.eqlIgnoreCase(e.key, name)) return cbor.Value.str(e.value);
    return null;
}
