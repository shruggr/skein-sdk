# skein-sdk

The Zig package a program for a [skein](https://github.com/shruggr/skein)
is written against: the `skein` imports, the codecs, the app-calling helper,
the chain library and the wallet library. skein's kernel and its own
programs build against it too, so each file has one copy, here. Version
**0.4.0**, Zig 0.16.0.

## What it is

| module | file | what |
|---|---|---|
| `sk` | `lib/sk.zig` | the preview1 `skein` imports (`input`, `get`, `put`, `putblock`, `keep`, `head`, `advance`, `edges`, `launch`, `await`, `deadline`, `call`, `emit`, `wallet`) and helpers over them: kept records, messages, the address book, trees |
| `app` | `lib/app.zig` | calling an app: `{fn, args}` dispatched by the manifest's `provides` (read from `<app>/app`), args checked against the declared shapes, `writes: false` enforced, the answer message to the sender, the `/call` route, the app's state |
| `cbor` | `src/cbor.zig` | dag-cbor values, canonical encode/decode, the CID of a value |
| `cid` | `src/cid.zig` | CIDs: parse, format; the codecs skein uses (raw, dag-cbor, git-raw, bitcoin-block, bitcoin-tx) |
| `mst` | `src/mst.zig` | Merkle search trees over dag-cbor blocks: the kernel's index maps and every app's maps |
| `secp` | `src/secp.zig` | BRC-42 "anyone" child keys and ECDSA verification, pure Zig |
| `dagjson` | `lib/dagjson.zig` | dag-json (manifests, `etc/*.json`) |
| `message` | `lib/message.zig` | BRC-169 messages: build, sign through the signer, verify with the sender's key alone |
| `brc104` | `lib/brc104.zig` | BRC-103/104 framing for programs |
| `chain` | `chain/src/lib.zig` | the chain library (over bsvz): headers and the chain tracker, BEEF, SPV, merkle paths as IPLD nodes, the record store and its maps, and `state`: the chain app's records (`chain-state`), which shruggr/skein-chain writes and every reader of `chain/state` reads |
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
zig fetch --save=skein_sdk https://github.com/shruggr/skein-sdk/archive/refs/tags/v0.4.0.tar.gz
```

which writes into `build.zig.zon`:

```zig
.skein_sdk = .{
    .url = "https://github.com/shruggr/skein-sdk/archive/refs/tags/v0.4.0.tar.gz",
    .hash = "skein_sdk-0.4.0-YroFBDfGGADreMJWF41zqUyuS71zsF4uG8GNoPswWhek",
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
  "dispatch": [{ "address": "counter", "sender": "$owner", "program": "counter" }]
}
```

`skein-host install <dir> --instance <handle>` installs it; the owner then
sends `{fn: "demo.counter.add", args: {by: 2}}` to box `counter`.

Three callers reach a function with one definition: a message `{fn, args}`
in the app's box (answered to the sender `{fn, request, replyTo, result |
error: {code, message}}`), the route `{transport: "http", address: "/call",
fn: "call"}` (answered on the connection), and an in-VM `call`. The error
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
zig build test         # cid, cbor, mst, secp, dagjson, app; chain/test.zig; the wallet's tests and vector corpus (44 tests)
zig build test-wasm    # the wallet's tests built for wasm32-wasi, under Node's WASI (needs node)
```

The vector corpus (`wallet/vectors/*.json`) is made by go-sdk
(`wallet/vectors/gen-go`) and cross-checked against the TS wallet-toolbox
(`wallet/vectors/gen-ts`). A run prints its counts; at 0.4.0: tx 39 (fees
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
