//! Files from a git tree, for a route handler (moved out of shruggr/skein-static
//! by shruggr/skein#125: serving files is a function any http handler calls,
//! not an app). The front door calls the handler with the request and the
//! dispatch row that matched (`match`); the handler picks the tree — its own
//! app's (`app.manifestOf(a, "<app>").get("tree")`), a head's, any CID — and
//! answers `serve(a, req, tree, rowOptions(req))`:
//!
//!   an http row  {transport: "http", address: "/", prefix: true, sender: "*" | "session",
//!                 program: <the handler>, fn: <its fn>, root?: "www", index?: "index.html"}
//!                (or an exact row, no `prefix`)
//!
//! The path is the request's route (the host strips `/@<handle>`) past the
//! row's prefix (an exact row serves its root's index), percent-decoded,
//! split on `/`; empty and `.` segments are dropped. `root` (default: the
//! tree's top) and the path are both in the tree; a `..` segment, a NUL, or
//! a bad escape is a 404 (nothing is served from outside the root). A path
//! ending in `/` names a directory: its `index` (default `index.html`); so
//! does an exact row whose root is a directory. A directory named without
//! the `/` (the bare prefix too) is a 301 to the same path with it (the
//! client's path, so relative links resolve). A root that is a file serves
//! that file at the row itself (`{address: "/favicon.ico", root:
//! "www/favicon.ico"}`). Only regular files are served (not links or
//! submodules).
//!
//!   GET/HEAD → 200 {type: by extension, body: the blob (HEAD: none), headers: {etag, cache-control: no-cache}}
//!              304 when `If-None-Match` names the ETag (or `*`)
//!              404 no such file; 405 any other method (`Allow: GET, HEAD`)
//! The ETag is the blob's CID (git-raw, sha1) in quotes: the same bytes
//! answer the same ETag in any instance and any tree.
const std = @import("std");
const cbor = @import("cbor");
const sk = @import("sk");

const Value = cbor.Value;
const Allocator = std.mem.Allocator;
const eql = std.mem.eql;

pub const DEFAULT_INDEX = "index.html";

// ---------------------------------------------------------------- answers

const Answer = struct {
    status: u64,
    type: []const u8 = "text/plain; charset=utf-8",
    body: []const u8 = "",
    etag: ?[]const u8 = null,
    location: ?[]const u8 = null,
    allow: bool = false,

    fn value(r: Answer, a: Allocator) !Value {
        var h = cbor.MapBuilder.init(a);
        if (r.etag) |e| {
            try h.put("etag", cbor.string(e));
            // The ETag is the blob's CID: a revalidation is one cheap 304, so caches (a browser, a CDN in
            // front of the host) keep nothing stale — without this a CDN applies its own default lifetime.
            try h.put("cache-control", cbor.string("no-cache"));
        }
        if (r.location) |l| try h.put("location", cbor.string(l));
        if (r.allow) try h.put("allow", cbor.string("GET, HEAD"));
        var m = cbor.MapBuilder.init(a);
        try m.put("status", cbor.int(r.status));
        try m.put("type", cbor.string(r.type));
        try m.put("body", .{ .bytes = r.body });
        try m.put("headers", h.value());
        return m.value();
    }
};

fn notFound(head: bool) Answer {
    return .{ .status = 404, .body = if (head) "" else "not found\n" };
}

/// The row's own settings, as the front door hands them to the handler in the
/// request's `match`: `root` (default: the tree's top) and `index` (default
/// `index.html`).
pub fn rowOptions(req: Value) Options {
    const match: Value = req.get("match") orelse .null;
    return .{
        .root = Value.str(match.get("root")) orelse "",
        .index = Value.str(match.get("index")) orelse DEFAULT_INDEX,
    };
}

/// Where in the tree a request is served from.
pub const Options = struct {
    /// A path in the tree: a directory, or a single file for an exact row ("" the tree's top).
    root: []const u8 = "",
    /// A directory's file.
    index: []const u8 = DEFAULT_INDEX,
};

/// The answer to `req` (the route handler's request: `method`, `route`,
/// `path`, `query`, `headers`, `match`) from the git tree `tree` (its CID;
/// null: there is none, every file is a 404), under `opt.root`. The prefix a
/// path is taken past is the matched row's (`match`: `prefix`, `address`).
pub fn serve(a: Allocator, req: Value, tree_cid: ?[]const u8, opt: Options) !Value {
    const method = Value.str(req.get("method")) orelse "GET";
    const head = eql(u8, method, "HEAD");
    if (!head and !eql(u8, method, "GET")) {
        const r = Answer{ .status = 405, .body = "method not allowed (GET, HEAD)\n", .allow = true };
        return r.value(a);
    }
    const match: Value = req.get("match") orelse .null;
    const route = Value.str(req.get("route")) orelse Value.str(req.get("path")) orelse "/";
    const rest = restOf(route, prefixOf(match)) orelse return notFound(head).value(a);
    const p = (try resolvePath(a, opt.root, rest)) orelse return notFound(head).value(a);
    const tree = tree_cid orelse return notFound(head).value(a);

    var e = (try lookup(a, tree, p.segs)) orelse return notFound(head).value(a);
    var name = if (p.segs.len > 0) p.segs[p.segs.len - 1] else "";
    if (isDir(e.mode)) {
        // Not for an exact route (its path is the only one it answers).
        const bare_prefix = rest.len == 0 and prefixOf(match) != null and !std.mem.endsWith(u8, route, "/");
        if (!p.dir or bare_prefix) {
            // The directory without its `/`: relative links would resolve against the parent.
            const path = Value.str(req.get("path")) orelse route;
            const query = Value.str(req.get("query")) orelse "";
            const r = Answer{ .status = 301, .location = try std.mem.concat(a, u8, &.{ path, "/", query }) };
            return r.value(a);
        }
        const ix = (try resolvePath(a, "", opt.index)) orelse return notFound(head).value(a);
        e = (try lookup(a, e.cid, ix.segs)) orelse return notFound(head).value(a);
        name = opt.index;
    } else if (rest.len > 0 and p.dir) return notFound(head).value(a); // a file named as a directory
    // (An exact route, or the bare prefix, whose root is a file serves that file.)
    if (!isFile(e.mode)) return notFound(head).value(a);

    const etag = try std.mem.concat(a, u8, &.{ "\"", try cbor.cidm.format(a, e.cid), "\"" });
    const ctype = contentType(name);
    if (matches(etag, headerOf(req.get("headers"), "if-none-match"))) {
        const r = Answer{ .status = 304, .type = ctype, .etag = etag };
        return r.value(a);
    }
    const bytes = try sk.getBytes(a, e.cid);
    const body = gitBlob(bytes) orelse return sk.report("the tree names an object that is not a git blob");
    const r = Answer{ .status = 200, .type = ctype, .body = if (head) "" else body, .etag = etag };
    return r.value(a);
}

fn headerOf(m: ?Value, name: []const u8) ?[]const u8 {
    const v = m orelse return null;
    if (v != .map) return null;
    for (v.map) |x| if (std.ascii.eqlIgnoreCase(x.key, name)) return Value.str(x.value);
    return null;
}

/// Whether `If-None-Match` (a list of entity tags, weak or strong, or `*`) names `etag`.
pub fn matches(etag: []const u8, header: ?[]const u8) bool {
    const h = header orelse return false;
    var it = std.mem.splitScalar(u8, h, ',');
    while (it.next()) |raw| {
        var t = std.mem.trim(u8, raw, " \t");
        if (eql(u8, t, "*")) return true;
        if (std.mem.startsWith(u8, t, "W/")) t = t[2..];
        if (eql(u8, t, etag)) return true;
    }
    return false;
}

// ---------------------------------------------------------------- paths

/// A prefix row's path (#77: `prefix: true`, the path its `address`, as served), or null: an exact row.
pub fn prefixOf(match: Value) ?[]const u8 {
    const p = match.get("prefix") orelse return null;
    if (p == .bool and p.bool) return Value.str(match.get("address"));
    return null;
}

/// The part of `route` past the route's prefix; null when the prefix ends
/// mid-segment (`/sitemap` under `/site`). An exact route (no prefix): "".
pub fn restOf(route: []const u8, prefix: ?[]const u8) ?[]const u8 {
    const p = prefix orelse return "";
    if (!std.mem.startsWith(u8, route, p)) return null;
    const rest = route[p.len..];
    if (rest.len > 0 and !std.mem.endsWith(u8, p, "/") and rest[0] != '/') return null;
    return rest;
}

pub const Resolved = struct {
    /// The tree path's segments, root's first.
    segs: []const []const u8,
    /// The request named a directory (it ended in `/`, or was empty).
    dir: bool,
};

/// `root` and the percent-decoded `rest` as one path in the tree; null when
/// either escapes (a `..` segment), holds a NUL, or has a bad `%` escape.
pub fn resolvePath(a: Allocator, root: []const u8, rest: []const u8) !?Resolved {
    var segs: std.ArrayList([]const u8) = .empty;
    if (!try appendSegments(a, &segs, root, false)) return null;
    if (!try appendSegments(a, &segs, rest, true)) return null;
    const dir = rest.len == 0 or rest[rest.len - 1] == '/';
    return .{ .segs = segs.items, .dir = dir };
}

fn appendSegments(a: Allocator, segs: *std.ArrayList([]const u8), path: []const u8, decode: bool) !bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |raw| {
        const seg = if (decode) (try percentDecode(a, raw)) orelse return false else raw;
        if (seg.len == 0 or eql(u8, seg, ".")) continue;
        if (eql(u8, seg, "..")) return false;
        // A decoded `/` or NUL is not part of a name in a git tree.
        if (std.mem.indexOfAny(u8, seg, "/\x00") != null) return false;
        try segs.append(a, seg);
    }
    return true;
}

/// `%XX` decoded; null on a bad escape.
pub fn percentDecode(a: Allocator, s: []const u8) !?[]const u8 {
    if (std.mem.indexOfScalar(u8, s, '%') == null) return s;
    const out = try a.alloc(u8, s.len);
    var i: usize = 0;
    var o: usize = 0;
    while (i < s.len) : (o += 1) {
        if (s[i] != '%') {
            out[o] = s[i];
            i += 1;
            continue;
        }
        if (i + 3 > s.len) return null;
        out[o] = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch return null;
        i += 3;
    }
    return out[0..o];
}

// ---------------------------------------------------------------- the tree

fn isDir(mode: []const u8) bool {
    return eql(u8, mode, "40000");
}

fn isFile(mode: []const u8) bool {
    return eql(u8, mode, "100644") or eql(u8, mode, "100755");
}

/// The entry at `segs` under `tree` (no segments: the tree itself); null when missing.
fn lookup(a: Allocator, tree: []const u8, segs: []const []const u8) !?sk.TreeEntry {
    var e = sk.TreeEntry{ .mode = "40000", .name = "", .cid = tree };
    for (segs) |seg| {
        if (!isDir(e.mode)) return null;
        e = for (try sk.readTree(a, e.cid)) |x| {
            if (eql(u8, x.name, seg)) break x;
        } else return null;
    }
    return e;
}

/// A git blob's content, after its header "blob <len>\0".
fn gitBlob(obj: []const u8) ?[]const u8 {
    const nul = std.mem.indexOfScalar(u8, obj, 0) orelse return null;
    const h = obj[0..nul];
    if (!std.mem.startsWith(u8, h, "blob ")) return null;
    const n = std.fmt.parseInt(usize, h[5..], 10) catch return null;
    if (n != obj.len - nul - 1) return null;
    return obj[nul + 1 ..];
}

// ---------------------------------------------------------------- content types

const types = [_][2][]const u8{
    .{ "html", "text/html; charset=utf-8" },
    .{ "htm", "text/html; charset=utf-8" },
    .{ "css", "text/css; charset=utf-8" },
    .{ "js", "text/javascript; charset=utf-8" },
    .{ "mjs", "text/javascript; charset=utf-8" },
    .{ "json", "application/json" },
    .{ "map", "application/json" },
    .{ "svg", "image/svg+xml" },
    .{ "png", "image/png" },
    .{ "jpg", "image/jpeg" },
    .{ "jpeg", "image/jpeg" },
    .{ "gif", "image/gif" },
    .{ "webp", "image/webp" },
    .{ "ico", "image/x-icon" },
    .{ "txt", "text/plain; charset=utf-8" },
    .{ "md", "text/markdown; charset=utf-8" },
    .{ "wasm", "application/wasm" },
    .{ "woff2", "font/woff2" },
    .{ "pdf", "application/pdf" },
};

/// The content type of a file name, by its extension (any case); default octet-stream.
pub fn contentType(name: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "application/octet-stream";
    if (dot == 0) return "application/octet-stream"; // a dotfile: no extension
    const ext = name[dot + 1 ..];
    for (types) |x| if (std.ascii.eqlIgnoreCase(x[0], ext)) return x[1];
    return "application/octet-stream";
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "content types by extension" {
    try testing.expectEqualStrings("text/html; charset=utf-8", contentType("index.html"));
    try testing.expectEqualStrings("text/html; charset=utf-8", contentType("INDEX.HTML"));
    try testing.expectEqualStrings("text/css; charset=utf-8", contentType("a.b.css"));
    try testing.expectEqualStrings("text/javascript; charset=utf-8", contentType("app.js"));
    try testing.expectEqualStrings("text/javascript; charset=utf-8", contentType("mod.mjs"));
    try testing.expectEqualStrings("application/json", contentType("x.json"));
    try testing.expectEqualStrings("image/svg+xml", contentType("logo.svg"));
    try testing.expectEqualStrings("image/png", contentType("a.png"));
    try testing.expectEqualStrings("image/jpeg", contentType("a.jpg"));
    try testing.expectEqualStrings("image/gif", contentType("a.gif"));
    try testing.expectEqualStrings("image/webp", contentType("a.webp"));
    try testing.expectEqualStrings("image/x-icon", contentType("favicon.ico"));
    try testing.expectEqualStrings("text/plain; charset=utf-8", contentType("a.txt"));
    try testing.expectEqualStrings("text/markdown; charset=utf-8", contentType("README.md"));
    try testing.expectEqualStrings("application/wasm", contentType("k.wasm"));
    try testing.expectEqualStrings("font/woff2", contentType("f.woff2"));
    try testing.expectEqualStrings("application/pdf", contentType("d.pdf"));
    try testing.expectEqualStrings("application/octet-stream", contentType("Makefile"));
    try testing.expectEqualStrings("application/octet-stream", contentType(".htaccess"));
    try testing.expectEqualStrings("application/octet-stream", contentType("a.tar.zst"));
    try testing.expectEqualStrings("application/octet-stream", contentType("trailing."));
}

fn expectSegs(want: []const []const u8, dir: bool, got: ?Resolved) !void {
    const r = got orelse return error.TestExpectedResolved;
    try testing.expectEqual(want.len, r.segs.len);
    for (want, r.segs) |w, g| try testing.expectEqualStrings(w, g);
    try testing.expectEqual(dir, r.dir);
}

test "path normalisation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectSegs(&.{ "www", "css", "a.css" }, false, try resolvePath(a, "www", "/css/a.css"));
    try expectSegs(&.{ "www", "css", "a.css" }, false, try resolvePath(a, "/www/", "//css/./a.css"));
    try expectSegs(&.{"www"}, true, try resolvePath(a, "www", ""));
    try expectSegs(&.{"www"}, true, try resolvePath(a, "www", "/"));
    try expectSegs(&.{ "www", "docs" }, true, try resolvePath(a, "www", "/docs/"));
    try expectSegs(&.{ "www", "docs" }, false, try resolvePath(a, "www", "/docs"));
    try expectSegs(&.{"a.css"}, false, try resolvePath(a, "", "/a.css"));
    try expectSegs(&.{ "my file.html" }, false, try resolvePath(a, "", "/my%20file.html"));
    try expectSegs(&.{"%.txt"}, false, try resolvePath(a, "", "/%25.txt"));
}

test "escaping the root is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect(try resolvePath(a, "www", "/../etc/routes.json") == null);
    try testing.expect(try resolvePath(a, "www", "/css/../../x") == null);
    try testing.expect(try resolvePath(a, "www", "/..") == null);
    try testing.expect(try resolvePath(a, "www", "/%2e%2e/etc/routes.json") == null);
    try testing.expect(try resolvePath(a, "www", "/%2E%2E/x") == null);
    try testing.expect(try resolvePath(a, "www", "/a%2f..%2f..%2fx") == null); // an encoded `/` is not a separator
    try testing.expect(try resolvePath(a, "www", "/a%00b") == null);
    try testing.expect(try resolvePath(a, "www", "/a%zz") == null);
    try testing.expect(try resolvePath(a, "www", "/a%2") == null);
    try testing.expect(try resolvePath(a, "../www", "/a") == null);
}

test "a row's prefix: its address when prefix is true" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m = cbor.MapBuilder.init(a);
    try m.put("address", cbor.string("/static/site"));
    try m.put("prefix", .{ .bool = true });
    try testing.expectEqualStrings("/static/site", prefixOf(m.value()).?);
    var e = cbor.MapBuilder.init(a);
    try e.put("address", cbor.string("/static/"));
    try testing.expect(prefixOf(e.value()) == null);
}

test "the part past the prefix" {
    try testing.expectEqualStrings("/a.css", restOf("/site/a.css", "/site").?);
    try testing.expectEqualStrings("", restOf("/site", "/site").?);
    try testing.expectEqualStrings("a.css", restOf("/site/a.css", "/site/").?);
    try testing.expectEqualStrings("/x", restOf("/x", "").?);
    try testing.expect(restOf("/sitemap.xml", "/site") == null);
    try testing.expectEqualStrings("", restOf("/", null).?);
}

test "If-None-Match" {
    const e = "\"bafyx\"";
    try testing.expect(matches(e, "\"bafyx\""));
    try testing.expect(matches(e, "W/\"bafyx\""));
    try testing.expect(matches(e, "\"other\", \"bafyx\""));
    try testing.expect(matches(e, "*"));
    try testing.expect(!matches(e, "\"other\""));
    try testing.expect(!matches(e, null));
    try testing.expect(!matches(e, "bafyx"));
}

test "a git blob's content" {
    try testing.expectEqualStrings("hi\n", gitBlob("blob 3\x00hi\n").?);
    try testing.expect(gitBlob("blob 4\x00hi\n") == null);
    try testing.expect(gitBlob("tree 3\x00hi\n") == null);
}

test "a row's settings: root and index, with defaults" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m = cbor.MapBuilder.init(a);
    try m.put("root", cbor.string("www"));
    try m.put("index", cbor.string("home.html"));
    var r = cbor.MapBuilder.init(a);
    try r.put("match", m.value());
    const o = rowOptions(r.value());
    try testing.expectEqualStrings("www", o.root);
    try testing.expectEqualStrings("home.html", o.index);
    const d = rowOptions(.null);
    try testing.expectEqualStrings("", d.root);
    try testing.expectEqualStrings(DEFAULT_INDEX, d.index);
}
