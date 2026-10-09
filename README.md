# skein-sdk

The Zig package a program for a [skein](https://github.com/shruggr/skein)
is written against: the `skein` imports, the codecs, the app-calling helper,
the chain library and the wallet library. skein's kernel and its own
programs build against it too, so each file has one copy, here. Version
**0.11.0**, Zig 0.16.0.

## What it is

| module | file | what |
|---|---|---|
| `sk` | `lib/sk.zig` | the preview1 `skein` imports (`input`, `get`, `put`, `putblock`, `keep`, `head`, `advance`, `edges`, `launch`, `await`, `deadline`, `call`, `emit`, `wallet`, `authfetch`) and helpers over them: kept records, messages, the intentions the runtime answers (`deadline`, `fetch`: shruggr/skein#126), `authfetch` (the kernel's BRC-104 client), the address book (`peers`, `peerOf`, `peerAt`: no roles), trees |
| `app` | `lib/app.zig` | calling an app: `{fn, args}` dispatched by the manifest's `provides` (read from `<app>/app`), args checked against the declared shapes, `writes: false` enforced, the answer message to the sender, the `/call` route, the app's state |
| `filter` | `lib/filter.zig` | answering as a filter (skein `docs/APPS.md` §2, shruggr/skein#143): `reject`, `answer`, `pass` (a principal, a rewritten request, blocks), `answerOf` (a route handler's http answer as a filter's), `isFilter`, `write` |
| `files` | `lib/files.zig` | files from a git tree for an http handler (shruggr/skein#125, moved out of skein-static): `serve(a, req, tree, rowOptions(req))` answers the request from the tree under the row's `root`, with its `index` for a directory, a 301 for a directory named without its `/`, the blob's CID as the ETag (304 on `If-None-Match`), the content type by extension, 404 (missing, `..`, NUL, a bad escape) and 405 (`Allow: GET, HEAD`) |
| `cbor` | `src/cbor.zig` | dag-cbor values, canonical encode/decode, the CID of a value |
| `cid` | `src/cid.zig` | CIDs: parse, format; the codecs skein uses (raw, dag-cbor, git-raw, bitcoin-block, bitcoin-tx) |
| `mst` | `src/mst.zig` | Merkle search trees over dag-cbor blocks: the kernel's index maps and every app's maps |
| `secp` | `src/secp.zig` | BRC-42 "anyone" child keys and ECDSA verification, pure Zig |
| `dagjson` | `lib/dagjson.zig` | dag-json (manifests, `etc/*.json`) |
| `message` | `lib/message.zig` | the mail record: `shapeProblem` (its shape and body; who sent it is the transport's to prove — a BRC-104 session, libp2p) and `problem` (plus the signature of the records that sign themselves: a claim, a host provider's answer; BRC-169's signing, checked with the sender's key alone) |
| `brc104` | `lib/brc104.zig` | BRC-103/104 framing for a server program (the front door); a client is the kernel's `authfetch` |
| `chain` | `chain/src/lib.zig` | the chain library (over bsvz): headers and the chain tracker, BEEF (V1, V2, Atomic, Outpoint, Subject — BRC-233), the BEEF envelope and pointer record and `record.wireOf` (shruggr/skein#121, #146: the exact bytes back from the envelope and the record the kernel's door writes), SPV, merkle paths as IPLD nodes, the record store and its maps, and `state`: the chain app's records (`chain-state`), which shruggr/skein-chain writes and every reader of `chain/state` reads; `image`: the header chain an image tree carries (`chain/headers/<first>`, `chain/tip`; shruggr/skein#132) and `load`, which fills an empty state's best chain from it |
| `wallet` | `wallet/src/lib.zig` | the wallet library over `chain` (re-exported under the same names): BRC-29, the transaction builder, the BRC-100 wire frames |
| `skein_wit` | `wit/zig/skein_wit.zig` | the same calls as `sk` over the WIT interface `skein:kernel/skein`, for a WASI 0.2 component build |
| `cabi` | `wit/zig/cabi.zig` | `malloc`/`realloc`/`free`/`abort`/`strlen` for wit-bindgen's C bindings, without wasi-libc |

`wit/` is the WIT package `skein:kernel@0.1.0` and the WASI 0.2.12 packages
it depends on (`wit/README.md`). The ABI itself (what the kernel answers) is
specified in skein's `docs/VM.md`.

**The wallet module's combined `Wallet` record and `wallet/src/overlay.zig`**
(chain, wallet and overlay maps in one state record) are not used by skein's
programs since shruggr/skein#79: the chain state is the chain app's, the
wallet's records are `programs/wallet`'s in skein, and an overlay's are
shruggr/skein-overlay's. skein's wallet program still uses this module's
builder, BRC-29 and wire code.

## Use it

Depend on it by tag:

```
zig fetch --save=skein_sdk https://github.com/shruggr/skein-sdk/archive/refs/tags/v0.8.0.tar.gz
```

which writes into `build.zig.zon`:

```zig
.skein_sdk = .{
    .url = "https://github.com/shruggr/skein-sdk/archive/refs/tags/v0.8.0.tar.gz",
    .hash = "skein_sdk-0.8.0-YroFBJjiGQAPsofAfk4gxZYPzOdNK9XUNs-guXRk2FEK",
},
```

Take the modules you need in `build.zig`:

```zig
const wasi = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .wasi });
const sdk = b.dependency("skein_sdk", .{ .target = wasi, .optimize = .ReleaseSafe, .wallet = false });
const exe = b.addExecutable(.{
    .name = "counter",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = wasi,
        .optimize = .ReleaseSafe,
        .strip = true,
        .imports = &.{
            .{ .name = "cbor", .module = sdk.module("cbor") },
            .{ .name = "sk", .module = sdk.module("sk") },
            .{ .name = "app", .module = sdk.module("app") },
        },
    }),
});
b.installArtifact(exe);
```

`.wallet = false` leaves out `chain` and `wallet` and never fetches bsvz;
drop it to use them.

A minimal app handler, named `counter`, providing `demo.counter/1` with
`get` and `add` (its manifest declares the interface; skein's
`docs/APPS.md` §2 has the manifest, and skein's `programs/test/app-demo` is a
complete app with a tick and a route):

```zig
const std = @import("std");
const cbor = @import("cbor");
const sk = @import("sk");
const app = @import("app");
const Value = cbor.Value;

const fns = [_]app.Function{
    .{ .name = "demo.counter.get", .run = get },
    .{ .name = "demo.counter.add", .run = add },
};

pub fn main() u8 {
    return sk.main("counter", run);
}

fn run(a: std.mem.Allocator) !void {
    return app.serve(a, try sk.input(a), "counter", &fns, null);
}

fn count(c: *app.Call) !i128 {
    const s = (try c.state()) orelse return 0;
    return Value.intOf(s.get("count")) orelse 0;
}

fn answer(a: std.mem.Allocator, n: i128) !Value {
    var m = cbor.MapBuilder.init(a);
    try m.put("count", cbor.int(n));
    return m.value();
}

fn get(c: *app.Call) !Value {
    return answer(c.a, try count(c));
}

fn add(c: *app.Call) !Value {
    const n = try count(c) + Value.intOf(c.args.get("by")).?; // args already checked against {by: "int"}
    _ = try c.setState(try answer(c.a, n)); // refused if the manifest says writes: false
    return answer(c.a, n);
}
```

Its tree is `bin/counter.wasm` (the built module) and `etc/app.json`:

```json
{
  "kind": "app",
  "name": "counter",
  "version": "0.1.0",
  "programs": { "counter": "bin/counter.wasm" },
  "provides": [{ "interface": "demo.counter/1", "functions": {
    "get": { "writes": false, "args": {}, "answer": { "count": "int" } },
    "add": { "writes": true, "args": { "by": "int" }, "answer": { "count": "int" } } } }],
  "requires": [],
  "routes": [{ "address": "", "handler": "counter.message" }],
  "roles": { "root": ["message"] }
}
```

`skein-host install <dir> --instance <handle>` installs it; root then
sends `{fn: "demo.counter.add", args: {by: 2}}` to box `counter` (the
route's function `message` is gated by `root`; no `roles`: anyone who can
reach the box).

Three callers reach a function with one definition: a message `{fn, args}`
in the app's box (answered to the sender `{fn, request, replyTo, result |
error: {code, message}}`), the route `{transport: "http", address: "/call",
filters: ["kernel.brc104"], handler: "<role>.call"}` (answered on the
connection), and an in-VM `call`. Who may call is the kernel's: a route's
filters and the gate (the manifest's `roles`) run before the handler
(shruggr/skein#143). The error
codes and the HTTP statuses are at the top of `lib/app.zig`. The app's state
is the `state` link of its app record, the root of `<app>/app`: an app writes
only heads under its own name.

### bsvz

`chain` and `wallet` are over [bsvz](https://github.com/opldotdev/bsvz) (the
BSV primitives), a **lazy** URL dependency fetched only when one of them is
asked for:

| pin | commit | why |
|---|---|---|
| `shruggr/bsvz` branch `skein-sdk` | `309085f` | the Chronicle branch (`8e1c956`, open as opldotdev/bsvz#2) plus the one hunk wasm32 needs (`wallet/patches/bsvz.patch`) |

When the Chronicle PR is merged upstream with that fix, the pin moves to the
merged commit.

## Build and test

```
zig build test         # cid, cbor, mst, secp, dagjson, files, filter, app; chain/test.zig; the wallet's tests and vector corpus (55 tests)
zig build test-wasm    # the wallet's tests built for wasm32-wasi, under Node's WASI (needs node)
```

The vector corpus (`wallet/vectors/*.json`) is made by go-sdk
(`wallet/vectors/gen-go`) and cross-checked against the TS wallet-toolbox
(`wallet/vectors/gen-ts`). A run prints its counts; at 0.7.1: tx 39 (fees
429), beef 27, merkle 43, headers 46, brc29 24, wire 13, signing 10,
chronicle 3, wallet scenarios 6. The TS cross-check runs from a skein
checkout beside this one, where `@bsv/sdk` resolves:
`node ../skein-sdk/wallet/vectors/gen-ts/run.mjs`.

Developing skein and the SDK together: clone this repo next to skein and
prefix a skein build with its `scripts/sdk-local.sh`, which overrides the
fetched dependency with `../skein-sdk` (Zig's `--fork`), with no edit to any
`build.zig.zon`. Any other dependent can do the same with
`zig build --fork=<this checkout>`.

## Docs

| what | where |
|---|---|
| the ABI (imports, records, threads, emit) | skein `docs/VM.md` |
| apps: tree, manifest, install, calling | skein `docs/APPS.md` |
| the wire, the dispatch table, providers | skein `docs/MESSAGES.md` |
| the wallet and SPV | skein `docs/WALLET.md` |
| the chain app's contract | shruggr/skein-chain `docs/CHAIN.md` |
| the WIT package | `wit/README.md` |

## Versions

| version | change |
|---|---|
| 0.11.0 | the BEEF envelope beside the pointer record (shruggr/skein#146): the pointer record `{kind: "beef", version, txs, marks, bumps}` is the BEEF alone, no form/subject/vout; the envelope `{form, beef, subject?, vout?}` sits beside it where the bytes were; Subject BEEF (BRC-233) is one more form, `"subject"`; `record.subjectOf(env, rec)`, `record.parsed(env)`, `record.wireOf(env)` take the envelope; `record.beefOf(record)` is the BEEF without envelope |
| 0.10.0 | the wallet takes caller-supplied inputs (shruggr/skein#93): createAction `inputs` (`outpoint`, `unlockingScript` or `unlockingScriptLength`, `inputDescription`, `sequenceNumber`) and `inputBEEF`; a signable draft when any input lacks its script; signAction `spends`; fee and change over caller and wallet inputs together; the builder signs only the wallet's own inputs |
| 0.9.0 | routes, filters, roles (shruggr/skein#143): `filter`, the module a filter answers with (`{reject}`, `{answer}`, `{pass}`); `app`: no `admitted`, no `not-admitted` — the `/call` route no longer reads the dispatch rows' senders (there are none): the kernel's filters and gate admit the caller before the handler runs; no `owner` anywhere in the step or call input |
| 0.8.0 | chain `image` (shruggr/skein#132): the header-chain layout of an image tree — `chain/headers/<first height, 8 digits>` blocks of 2016 raw headers in height order, `chain/tip` `{height, hash}` — `find`, `load` (fills an empty state's `headers` and `heights` from it, verified from genesis as `Chain.add` verifies: genesis, links, targets, proof of work) and `write`; `mst` `Forest.build` (a map from sorted entries in one pass, its nodes handed to a sink as made: the same root as putting them); `MemStore` holds git-raw objects; `Maps.sink` |
| 0.7.2 | `message`: `shapeProblem` — a mail record carries no signature of its sender (shruggr/skein#126 step 4: the BRC-104 session or libp2p proves it); `problem` stays for a claim and a host provider's answer |
| 0.7.1 | chain: a proven transaction's broadcast watchers survive a reorg; the proof in the new block tells them again (shruggr/skein-chain#2) |
| 0.7.0 | intentions, `authfetch` (the kernel's BRC-104 client), no `provider(role)` (shruggr/skein#126) |
| 0.6.1 | `message`: a claim (box `claim`) may name no recipient — signed before the instance it claims exists, forwarded into it by the host; the same signing (shruggr/skein#127) |
| 0.6.0 | `files`: the file server for any http handler, moved out of shruggr/skein-static with its tests (shruggr/skein#125) |
| 0.5.1 | `State.beefOf` serves a proven subject with its own BUMP and nothing above it |
| 0.5.0 | the BEEF pointer record and `chain.record` (`beefOf`, `parsed`, `subjectOf`, `provenBy`), Outpoint BEEF in `beef.parse`/`serialize`, raw blocks in `MemStore` (shruggr/skein#121); no `State.abandonIfDue` (shruggr/skein-chain#1) |
| 0.4.0 | the `chain` module split out of `wallet`, with the chain app's state (shruggr/skein#78) |
| 0.3.0 | no `subscribe` import (the dispatch table is the kernel's); an app's record is `<app>/app` (shruggr/skein#77) |
| 0.2.0 | the `app` module |

skein's kernel and every program in skein pin the SDK by tag (URL and hash
in each `build.zig.zon`). The kernel takes its codecs (`cid`, `cbor`, `mst`,
`secp`) from here, so a codec change is a log format change for skein: a new
tag, a new pin, and new stores. A dependency pinned by hash is a fixed
program: a changed codec is a different program. A change to a module's API
or to the ABI is a new minor version until 1.0.

## Contributing

Work is tracked in shruggr/skein; start at issue
[#31](https://github.com/shruggr/skein/issues/31). MIT, as skein.
