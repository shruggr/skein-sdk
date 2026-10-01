# skein-sdk

What a program for a [skein](https://github.com/shruggr/skein) VM is written
against, as a Zig package (Zig 0.16.0). Split out of skein by
shruggr/skein#71, with the history of the moved paths: skein's
`programs/lib` (→ `lib/`), `wallet-zig` (→ `wallet/`), `wit` (→ `wit/`) and
the kernel's codecs `kernel-zig/src/{cid,cbor,mst,secp}.zig` (→ `src/`).
skein's kernel and its own programs build against this package too: there
is one copy of each file, here.

## Modules

| module | file | what |
|---|---|---|
| `cid` | `src/cid.zig` | CIDs: parse, format; the codecs skein uses (raw, dag-cbor, git-raw, the bitcoin codecs) |
| `cbor` | `src/cbor.zig` | dag-cbor values, canonical encode/decode, the CID of a value (`cbor.cidm` is `cid`) |
| `mst` | `src/mst.zig` | Merkle search trees over dag-cbor blocks: the ordered maps of the kernel's index and the wallet's |
| `secp` | `src/secp.zig` | BRC-42 "anyone" child keys and ECDSA verification, pure Zig |
| `sk` | `lib/sk.zig` | the preview1 `skein` imports (`get`, `put`, `emit`, `head`, `advance`, `call`, …; no `subscribe` since 0.3.0) and the helpers over them: kept records, messages, the address book, trees |
| `brc104` | `lib/brc104.zig` | BRC-103/104 framing for programs |
| `dagjson` | `lib/dagjson.zig` | dag-json (manifests, `etc/*.json`) |
| `message` | `lib/message.zig` | BRC-169 messages: build, sign through the oracle, verify with the sender's key alone |
| `app` | `lib/app.zig` | calling an app (skein `docs/APPS.md` §4): `{fn, args}` dispatched by the manifest's `provides` (read from the app's head), `args` checked against the declared shapes, `writes: false` enforced, the answer message to the sender; the `/call` route; the app's state under its head `<app>/app` (since 0.2.0; the head name since 0.3.0) |
| `cabi` | `wit/zig/cabi.zig` | `malloc`/`realloc`/`free`/`abort`/`strlen` for wit-bindgen's C bindings, without wasi-libc |
| `skein_wit` | `wit/zig/skein_wit.zig` | the same calls as `sk`'s preview1 imports over the WIT interface `skein:kernel/skein`, for a WASI 0.2 component build (the C bindings in `wit/bindings/c` are compiled in) |
| `wallet` | `wallet/src/lib.zig` | the wallet library: headers and our chain tracker, SPV, BEEF, BRC-29, the transaction builder, the wallet's records and index maps, the overlay's state (over bsvz) |

`wit/` is the WIT package `skein:kernel@0.1.0` and the WASI 0.2.12 packages
it depends on (`wit/README.md`). The program ABI itself (what the kernel
answers) is specified in skein's `docs/VM.md`.

## Depending on it

An app (docs/APPS.md in skein: a tree with `bin/`, `etc/app.json`, …)
names the SDK in its `build.zig.zon`:

```
zig fetch --save=skein_sdk "git+https://github.com/shruggr/skein-sdk#<commit>"
```

which writes

```zig
.dependencies = .{
    .skein_sdk = .{
        .url = "git+https://github.com/shruggr/skein-sdk#<commit>",
        .hash = "skein_sdk-0.1.0-…",
    },
},
```

and takes the modules it needs in `build.zig`:

```zig
const wasi = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .wasi });
const sdk = b.dependency("skein_sdk", .{ .target = wasi, .optimize = .ReleaseSafe });
const exe = b.addExecutable(.{
    .name = "my-handler",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = wasi,
        .optimize = .ReleaseSafe,
        .strip = true,
        .imports = &.{
            .{ .name = "cbor", .module = sdk.module("cbor") },
            .{ .name = "sk", .module = sdk.module("sk") },
        },
    }),
});
```

`shruggr/skein-static` and `shruggr/skein-workbench` are built this way.
A program built in a checkout of skein depends on the same package the same
way (#75: `skein_sdk` by URL+hash, not a submodule). skein's
`scripts/sdk-local.sh` overrides the dependency with a sibling `../skein-sdk`
checkout for developing both at once, with no edit to committed files.

### bsvz

The wallet module is over [bsvz](https://github.com/opldotdev/bsvz) (the BSV
primitives). It is a **lazy** URL dependency: `zig build` fetches it the
first time something asks for the `wallet` module, and never otherwise. The
pin is branch `skein-sdk` of `shruggr/bsvz` (commit `309085f`): the Chronicle
branch skein was pinned at (`8e1c956`, open as opldotdev/bsvz#2) plus the one
hunk wasm32 needs (`wallet/patches/bsvz.patch`: `Preimage.parse` casts the
script length to `usize` before slicing). When the Chronicle PR is merged
upstream with that fix, the dependency moves to the merged commit.

`-Dwallet=false` leaves the wallet module (and bsvz) out entirely; skein's
kernel builds that way.

## Calling an app (`app`, 0.2.0; the head `<app>/app` since 0.3.0)

An app's handler lists the functions it implements and hands every input
to `app.serve`; the manifest's `provides` (the root record of the app's
head, written by skein's install) says which exist, their argument shapes
and whether they write:

```zig
const app = @import("app");
const fns = [_]app.Function{
    .{ .name = "demo.counter.get", .run = get },   // demo.counter/1's `get`
    .{ .name = "demo.counter.add", .run = add },
};
fn add(c: *app.Call) !Value {
    const by = Value.intOf(c.args.get("by")).?;      // checked against {by: "int"} already
    _ = try c.setState(newState);                    // refused if the manifest says writes: false
    return result;
}
pub fn main() u8 { return sk.main("demo", run); }
fn run(a: Allocator) !void { return app.serve(a, try sk.input(a), "demo", &fns, other); }
```

The three callers (a message `{fn, args}` in the app's box, answered to the
sender `{fn, request, replyTo, result | error: {code, message}}`; the route
`{path: "/call", fn: "call"}`, answered on the connection; an in-VM `call`)
and the error codes are documented at the top of `lib/app.zig`. A
function's writes go through its `Call` (`put`, `keep`, `advance`,
`setState`, `emit`, `launch`, `deadline`, `awaitRecord`); for a
`writes: false` function each is refused with `read-only`.

## Tests

```
zig build test         # cid, cbor, mst, secp, dagjson, app; the wallet's library tests and vector corpus (26)
zig build test-wasm    # the wallet's tests built for wasm32-wasi, under Node's WASI (needs node)
```

The wallet's vectors (`wallet/vectors/*.json`) are made by go-sdk
(`wallet/vectors/gen-go`) and cross-checked against the TS wallet-toolbox
(`wallet/vectors/gen-ts`, run from a skein checkout, where `@bsv/sdk`
resolves: `node sdk/wallet/vectors/gen-ts/run.mjs`).

## Versions

`build.zig.zon` carries the version (0.2.0: the `app` module; 0.3.0: no
`subscribe` import — the dispatch table is the kernel's, shruggr/skein#77 —
and an app's root head is `<app>/app`, under its own name, as every head an
app writes is). A change to a module's API or
to the ABI the `sk`/`skein_wit` calls describe is a new minor version until
1.0; skein's kernel and the SDK move together (skein pins a tagged release
by URL+hash, #75).

MIT, as skein.
