// Bundle check.ts (it imports the TS wallet-toolbox's sources, which have no
// node_modules of their own: @bsv/sdk resolves from skein's) and run it over
// the vectors directory. From a skein checkout: node sdk/wallet/vectors/gen-ts/run.mjs
import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const out = join(root, ".build/vectors-check.mjs");
await build({
  entryPoints: [join(here, "check.ts")],
  bundle: true,
  platform: "node",
  format: "esm",
  outfile: out,
  // The TS toolbox checkout (reference only; nothing of it ships).
  alias: { "wallet-toolbox": process.env.WALLET_TOOLBOX_SRC ?? join(process.env.HOME, "Work/bsv/wallet-toolbox/src") },
  nodePaths: [(({ p }) => p.slice(0, p.lastIndexOf("/node_modules/") + "/node_modules".length))({ p: createRequire(import.meta.url).resolve("@bsv/sdk") })],
  logLevel: "warning",
});
execFileSync(process.execPath, [out, join(here, "..")], { stdio: "inherit" });
