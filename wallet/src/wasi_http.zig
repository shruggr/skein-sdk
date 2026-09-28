//! One outgoing HTTP request over standard `wasi:http` (issue #15), through
//! the C bindings wit-bindgen emits for world skein:kernel/program
//! (../../wit/bindings/c). Plain wasi:http/outgoing-handler client code: the
//! program knows nothing of skein here — the kernel records the request and
//! its answer (kernel-zig/src/http.zig).
//!
//! Used by the wallet's component build (skein_wit.zig) and by the `fetch`
//! component (programs/fetch). Bodies are whole slices in both directions.
const std = @import("std");
const c = @cImport(@cInclude("program.h"));

pub const Header = struct { name: []const u8, value: []const u8 };
pub const Response = struct { status: u16, body: []u8 };

pub const Error = error{ BadUrl, HeaderRefused, RequestRefused, HttpFailed, BodyFailed, OutOfMemory };

/// The last failure's wasi:http error-code case (or what failed), for messages.
pub var last_error: []const u8 = "";
var msg_buf: [512]u8 = undefined;

fn str(s: []const u8) c.program_string_t {
    return .{ .ptr = @constCast(s.ptr), .len = s.len };
}

fn list(s: []const u8) c.program_list_u8_t {
    return .{ .ptr = @constCast(s.ptr), .len = s.len };
}

/// scheme "://" authority path-with-query; no path: "/".
const Url = struct { scheme: []const u8, authority: []const u8, path: []const u8 };
fn parseUrl(url: []const u8) Error!Url {
    const sep = std.mem.indexOf(u8, url, "://") orelse return error.BadUrl;
    const rest = url[sep + 3 ..];
    const end = std.mem.indexOfAny(u8, rest, "/?") orelse rest.len;
    if (end == 0) return error.BadUrl;
    return .{ .scheme = url[0..sep], .authority = rest[0..end], .path = if (end == rest.len) "/" else rest[end..] };
}

fn errorCase(tag: u8) []const u8 {
    return switch (tag) {
        c.WASI_HTTP_TYPES_ERROR_CODE_DNS_TIMEOUT => "DNS-timeout",
        c.WASI_HTTP_TYPES_ERROR_CODE_DNS_ERROR => "DNS-error",
        c.WASI_HTTP_TYPES_ERROR_CODE_DESTINATION_NOT_FOUND => "destination-not-found",
        c.WASI_HTTP_TYPES_ERROR_CODE_CONNECTION_REFUSED => "connection-refused",
        c.WASI_HTTP_TYPES_ERROR_CODE_CONNECTION_TIMEOUT => "connection-timeout",
        c.WASI_HTTP_TYPES_ERROR_CODE_HTTP_REQUEST_DENIED => "HTTP-request-denied",
        c.WASI_HTTP_TYPES_ERROR_CODE_HTTP_REQUEST_URI_INVALID => "HTTP-request-URI-invalid",
        c.WASI_HTTP_TYPES_ERROR_CODE_INTERNAL_ERROR => "internal-error",
        else => "error-code",
    };
}

fn failCode(code: *c.wasi_http_types_error_code_t) void {
    const case = errorCase(code.tag);
    if (code.tag == c.WASI_HTTP_TYPES_ERROR_CODE_INTERNAL_ERROR and code.val.internal_error.is_some) {
        const m = code.val.internal_error.val;
        last_error = std.fmt.bufPrint(&msg_buf, "{s}: {s}", .{ case, m.ptr[0..m.len] }) catch case;
    } else last_error = case;
    c.wasi_http_types_error_code_free(code);
}

/// Send one request and read the whole response.
pub fn request(a: std.mem.Allocator, method: []const u8, url: []const u8, headers: []const Header, body: ?[]const u8) Error!Response {
    const u = try parseUrl(url);

    const fields = c.wasi_http_types_constructor_fields();
    for (headers) |h| {
        var n = str(h.name);
        var v: c.wasi_http_types_field_value_t = .{ .ptr = @constCast(h.value.ptr), .len = h.value.len };
        var herr: c.wasi_http_types_header_error_t = undefined;
        if (!c.wasi_http_types_method_fields_append(c.wasi_http_types_borrow_fields(fields), &n, &v, &herr)) {
            last_error = h.name;
            return error.HeaderRefused;
        }
    }
    const req = c.wasi_http_types_constructor_outgoing_request(fields);
    const breq = c.wasi_http_types_borrow_outgoing_request(req);

    var m: c.wasi_http_types_method_t = undefined;
    const std_methods = [_][]const u8{ "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH" };
    m.tag = c.WASI_HTTP_TYPES_METHOD_OTHER;
    for (std_methods, 0..) |sm, i| if (std.mem.eql(u8, sm, method)) {
        m.tag = @intCast(i);
    };
    if (m.tag == c.WASI_HTTP_TYPES_METHOD_OTHER) m.val.other = str(method);
    var sc: c.wasi_http_types_scheme_t = undefined;
    if (std.mem.eql(u8, u.scheme, "https")) {
        sc.tag = c.WASI_HTTP_TYPES_SCHEME_HTTPS;
    } else if (std.mem.eql(u8, u.scheme, "http")) {
        sc.tag = c.WASI_HTTP_TYPES_SCHEME_HTTP;
    } else {
        sc.tag = c.WASI_HTTP_TYPES_SCHEME_OTHER;
        sc.val.other = str(u.scheme);
    }
    var auth = str(u.authority);
    var path = str(u.path);
    if (!c.wasi_http_types_method_outgoing_request_set_method(breq, &m) or
        !c.wasi_http_types_method_outgoing_request_set_scheme(breq, &sc) or
        !c.wasi_http_types_method_outgoing_request_set_authority(breq, &auth) or
        !c.wasi_http_types_method_outgoing_request_set_path_with_query(breq, &path))
    {
        last_error = "outgoing-request refused the method, scheme, authority or path";
        return error.RequestRefused;
    }

    // The body: written whole and finished before the request is handed on.
    if (body) |b| {
        var ob: c.wasi_http_types_own_outgoing_body_t = undefined;
        if (!c.wasi_http_types_method_outgoing_request_body(breq, &ob)) return error.BodyFailed;
        var os: c.wasi_http_types_own_output_stream_t = undefined;
        if (!c.wasi_http_types_method_outgoing_body_write(c.wasi_http_types_borrow_outgoing_body(ob), &os)) return error.BodyFailed;
        var off: usize = 0;
        while (off < b.len) {
            const n = @min(b.len - off, 4096);
            var chunk = list(b[off .. off + n]);
            var serr: c.wasi_io_streams_stream_error_t = undefined;
            if (!c.wasi_io_streams_method_output_stream_blocking_write_and_flush(c.wasi_io_streams_borrow_output_stream(os), &chunk, &serr)) return error.BodyFailed;
            off += n;
        }
        c.wasi_io_streams_output_stream_drop_own(os);
        var ferr: c.wasi_http_types_error_code_t = undefined;
        if (!c.wasi_http_types_static_outgoing_body_finish(ob, null, &ferr)) {
            failCode(&ferr);
            return error.BodyFailed;
        }
    }

    var future: c.wasi_http_outgoing_handler_own_future_incoming_response_t = undefined;
    var herr: c.wasi_http_outgoing_handler_error_code_t = undefined;
    if (!c.wasi_http_outgoing_handler_handle(req, null, &future, &herr)) {
        failCode(&herr);
        return error.HttpFailed;
    }
    const bfut = c.wasi_http_types_borrow_future_incoming_response(future);
    var got: c.wasi_http_types_result_result_own_incoming_response_error_code_void_t = undefined;
    while (true) {
        const p = c.wasi_http_types_method_future_incoming_response_subscribe(bfut);
        c.wasi_io_poll_method_pollable_block(c.wasi_io_poll_borrow_pollable(p));
        c.wasi_io_poll_pollable_drop_own(p);
        if (c.wasi_http_types_method_future_incoming_response_get(bfut, &got)) break;
    }
    c.wasi_http_types_future_incoming_response_drop_own(future);
    if (got.is_err) {
        last_error = "future-incoming-response: already taken";
        return error.HttpFailed;
    }
    if (got.val.ok.is_err) {
        failCode(&got.val.ok.val.err);
        return error.HttpFailed;
    }
    const resp = got.val.ok.val.ok;
    const bresp = c.wasi_http_types_borrow_incoming_response(resp);
    const status = c.wasi_http_types_method_incoming_response_status(bresp);

    var ib: c.wasi_http_types_own_incoming_body_t = undefined;
    if (!c.wasi_http_types_method_incoming_response_consume(bresp, &ib)) return error.BodyFailed;
    var is: c.wasi_http_types_own_input_stream_t = undefined;
    if (!c.wasi_http_types_method_incoming_body_stream(c.wasi_http_types_borrow_incoming_body(ib), &is)) return error.BodyFailed;
    var out: std.ArrayList(u8) = .empty;
    while (true) {
        var chunk: c.program_list_u8_t = undefined;
        var serr: c.wasi_io_streams_stream_error_t = undefined;
        if (!c.wasi_io_streams_method_input_stream_blocking_read(c.wasi_io_streams_borrow_input_stream(is), 65536, &chunk, &serr)) {
            if (serr.tag == c.WASI_IO_STREAMS_STREAM_ERROR_CLOSED) break;
            c.wasi_io_streams_stream_error_free(&serr);
            return error.BodyFailed;
        }
        try out.appendSlice(a, chunk.ptr[0..chunk.len]);
        c.program_list_u8_free(&chunk);
    }
    c.wasi_io_streams_input_stream_drop_own(is);
    c.wasi_http_types_future_trailers_drop_own(c.wasi_http_types_static_incoming_body_finish(ib));
    c.wasi_http_types_incoming_response_drop_own(resp);
    return .{ .status = status, .body = out.items };
}
