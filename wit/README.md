# wit

This directory holds skein's WIT package, `skein:kernel@0.1.0` (issue #34),
and the WASI 0.2 packages it depends on.

| path | what |
|---|---|
| `skein.wit` | The interface `skein` and the worlds `program` and `handler`. |
| `deps/*.wit` | WASI 0.2.12: `cli`, `clocks`, `filesystem`, `io`, `random` and `sockets`, vendored unchanged from wasmtime v49.0.1's `crates/wasi/src/p2/wit/deps`; `http` (#15) from its `crates/wasi-http/wit/deps` (whose `cli`/`io` copies are the same files). That is the version wasmtime v49 implements and its preview1 adapter imports. |
| `bindings/c/` | The guest's C bindings for world `program`, from `wit-bindgen c` 0.62.0. They are committed so that builds need no wit-bindgen. |

## The interface `skein:kernel/skein`

The interface has the same calls, with the same behaviour, as the preview1
`skein` import namespace (`src/runtime/wasi/skein-imports.ts`,
`kernel-zig/src/program.zig`). Only the ABI differs:

| preview1 | WIT |
|---|---|
| `f(…, out, cap) → n`, and `take(out, cap)` for a result that did not fit | returns `list<u8>` (the canonical ABI hands the guest the whole result through its `cabi_realloc`) |
| `n < 0`, and `error(out, cap)` for the message | `result<_, string>`, whose error is the same message |
| a failure that ends the run (diverged replay, missing witness, out of fuel) | the call traps, as before |
| a CID as pointer and length | `cid` (`list<u8>`, binary) |
| a name as pointer and length (decoded as UTF-8 with replacement) | `string` (the canonical ABI requires valid UTF-8) |
| `head` → n = 0 when there is no head | `result<option<cid>, string>` |
| `subscribe(…, sender, sender_len = 0, …)` for any sender | `sender: option<string>` |

Two differences from preview1 were accepted on #34 (David, 2026-09-28):

- `take` and `error` are **not** in the WIT. They exist only for preview1's
  caller-supplied buffers, and the canonical ABI makes those unnecessary.
- `head` returns `option<cid>`.

Fuel is also **not** the same across the two ABIs, and that is accepted:
the adapter and the canonical-ABI glue are instructions too. Every other
field of an update is the same.

The calls are `input`, `get`, `put`, `putblock`, `keep`, `launch`, `await`,
`head`, `advance`, `subscribe`, `wallet`, `http`, `deadline`, `call` and
`edges` (#42: the edges into a record, from the kernel's index; docs/VM.md "Edges").
`emit` and `resolve` are gone (#40): an instance delivers a message itself,
its messagebox program's `send` over `http`, and looks a handle up with its
`resolve` program; both are reached through `call`.

- **`call`** (#40) runs a program record as a function: its entry, with
  `input()` = `{kind: "call", fn, arg, …}`, and returns what it wrote to
  stdout (a non-zero exit is the error: its last stderr line). From a step,
  the callee is part of the step: its recorded calls, records and head moves
  are the step's. From the kernel's own `call` (a request to the front door,
  a read), it only reads. Calls nest to depth 8.

- **`http`** is the preview1 shape: a dag-cbor request in, a dag-cbor
  response out. It stays for preview1 programs (and in the interface, which
  mirrors them). A component uses standard `wasi:http/outgoing-handler`
  (#15), which the kernel serializes into this same request and answers by
  the same path: request and response recorded on the update, replay never
  touching the network (`docs/VM.md`, "Outgoing HTTP").
- **`wallet`** takes BRC-100 wire frames as bytes, for now.

## The worlds

- **`program`**: imports `skein` and `wasi:http/outgoing-handler` (the
  latter brings `wasi:http/types` and the `wasi:io` it uses). A preview1 program (Zig, C, Rust
  `wasm32-wasip1`) embeds this world with wit-bindgen. The preview1 command
  adapter (`wasm-tools component new --adapt`) then adds the WASI imports
  and the `wasi:cli/run` export. The result satisfies `handler`.
- **`handler`**: a handler program as a component. It imports:
  - WASI 0.2.12's `cli` (environment, exit, stdio, terminal), `clocks`
    (monotonic, wall), `filesystem` (types, preopens), `io` (error, poll,
    streams) and `random` (random, insecure, insecure-seed);
  - `wasi:http/types` and `wasi:http/outgoing-handler` (#15);
  - `skein`.

  It exports `wasi:cli/run`. There are no sockets and no incoming handler.
  The kernel answers every import over the graph (`kernel-zig/README.md`,
  "Components"). A component built against an older 0.2.x WASI links by
  semver: wasi-sdk 34's `wasm32-wasip2` output runs unchanged.

## Regenerating the bindings

```
wit-bindgen c wit --world program --out-dir wit/bindings/c
```

`program.c` calls `malloc`, `realloc`, `free`, `abort` and `strlen`. The
wallet provides them itself (`wallet-zig/src/cabi.zig`, with headers in
`wallet-zig/src/c`) rather than linking wasi-libc:
`kernel-zig/README.md`, "Building a component handler", says why.
