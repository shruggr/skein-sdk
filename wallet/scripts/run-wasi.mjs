// Run a wasm32-wasi command module under Node's WASI (used to run Zig test
// binaries built for wasm32-wasi: `zig build test-wasm`). The current
// directory is preopened as "." so tests that read fixtures by relative path work.
// Usage: node run-wasi.mjs <module.wasm> [args...]
import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";

const [file, ...args] = process.argv.slice(2);
const wasi = new WASI({ version: "preview1", args: [file, ...args], env: {}, preopens: { ".": process.cwd() }, returnOnExit: true });
const mod = await WebAssembly.compile(await readFile(file));
const inst = await WebAssembly.instantiate(mod, wasi.getImportObject());
process.exitCode = wasi.start(inst);
