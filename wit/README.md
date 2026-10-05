# wit

This directory holds skein's WIT package, `skein:kernel@0.1.0` (issue #34),
and the WASI 0.2 packages it depends on.

| path | what |
|---|---|
| `skein.wit` | The interface `skein` and the worlds `program` and `handler`. |
| `deps/*.wit` | WASI 0.2.12: `cli`, `clocks`, `filesystem`, `io`, `random` and `sockets`, vendored unchanged from wasmtime v49.0.1's `crates/wasi/src/p2/wit/deps` (`http` went with #70: no world imports it). That is the version wasmtime v49 implements and its preview1 adapter imports. |
| `bindings/c/` | The guest's C bindings for world `program`, from `wit-bindgen c` 0.62.0. They are committed so that builds need no wit-bindgen. |

## The interface `skein:kernel/skein`

The interface has the same calls, with the same behaviour, as the preview1
`skein` import namespace (skein's `kernel-zig/src/program.zig`). Only the ABI differs:

| preview1 | WIT |
|---|---|
| `f(…, out, cap) → n`, and `take(out, cap)` for a result that did not fit | returns `list<u8>` (the canonical ABI hands the guest the whole result through its `cabi_realloc`) |
| `n < 0`, and `error(out, cap)` for the message | `result<_, string>`, whose error is the same message |
| a failure that ends the run (diverged replay, missing witness, out of fuel) | the call traps, as before |
| a CID as pointer and length | `cid` (`list<u8>`, binary) |
| a name as pointer and length (decoded as UTF-8 with replacement) | `string` (the canonical ABI requires valid UTF-8) |
| `head` → n = 0 when there is no head | `result<option<cid>, string>` |

Two differences from preview1 were accepted on #34 (David, 2026-09-28):

- `take` and `error` are **not** in the WIT. They exist only for preview1's
  caller-supplied buffers, and the canonical ABI makes those unnecessary.
- `head` returns `option<cid>`.

Fuel is also **not** the same across the two ABIs, and that is accepted:
the adapter and the canonical-ABI glue are instructions too. Every other
field of an update is the same.

The calls are `input`, `get`, `put`, `putblock`, `keep`, `launch`, `await`,
`head`, `advance`, `wallet`, `emit`, `deadline`, `call`,
`edges` (#42: the edges into a record, from the kernel's index; docs/VM.md "Edges")
and `authfetch` (shruggr/skein#126: the kernel's BRC-104 client, a recorded call).
There is no plain `http` and no `libp2p` (#70, #67: format 6 removed them;
a `fetch` is an intention the runtime answers, #126); a handle is looked up by
launching the `resolve` program.

- **`call`** (#40) runs a program record as a function: its entry, with
  `input()` = `{kind: "call", fn, arg, …}`, and returns what it wrote to
  stdout (a non-zero exit is the error: its last stderr line). From a step,
  the callee is part of the step: its recorded calls, records and head moves
  are the step's. From the kernel's own `call` (a request to the front door,
  a read), it only reads. Calls nest to depth 8.

- **`emit`** (#70, #67) is the one way out: `emit(message: list<u8>) ->
  result<cid, string>`, `message` the dag-cbor `{to: bytes(33), box, body:
  bytes, subject?: cid}`; the kernel signs the message record through the
  oracle and returns its CID, and the message goes out when the step ends
  without error. A program reaches HTTP and libp2p by emitting to the
  address book's providers (`fetch`, `libp2p`), and awaits the answer, which
  steps it again (`docs/VM.md`, "emit"; `docs/MESSAGES.md`, "Outbound").
  `programs/fetch` and `programs/p2p-component` are components that do.
- **`deadline`** is sugar over `emit`: a wake-me to the address book's
  waker, awaited when the step ends.
- **`wallet`** takes BRC-100 wire frames as bytes, for now.

## The worlds

- **`program`**: imports `skein` only. A preview1 program (Zig, C, Rust
  `wasm32-wasip1`) embeds this world with wit-bindgen. The preview1 command
  adapter (`wasm-tools component new --adapt`) then adds the WASI imports
  and the `wasi:cli/run` export. The result satisfies `handler`.
- **`handler`**: a handler program as a component. It imports:
  - WASI 0.2.12's `cli` (environment, exit, stdio, terminal), `clocks`
    (monotonic, wall), `filesystem` (types, preopens), `io` (error, poll,
    streams) and `random` (random, insecure, insecure-seed);
  - `skein`.

  It exports `wasi:cli/run`. There are no sockets and no `wasi:http`.
  The kernel answers every import over the graph (`kernel-zig/README.md`,
  "Components"). A component built against an older 0.2.x WASI links by
  semver: wasi-sdk 34's `wasm32-wasip2` output runs unchanged.

## Regenerating the bindings

```
wit-bindgen c wit --world program --out-dir wit/bindings/c
```

`program.c` calls `malloc`, `realloc`, `free`, `abort` and `strlen`. The
component provides them itself (`wit/zig/cabi.zig`, the SDK module `cabi`, with headers in
`wit/zig/c`) rather than linking wasi-libc:
skein's `kernel-zig/README.md`, "Building a component handler", says why.
