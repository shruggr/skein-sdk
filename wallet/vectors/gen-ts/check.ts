// Cross-check the Go-generated vectors against the TypeScript references:
// the TS wallet-toolbox's chaintracks header utilities (~/Work/bsv/wallet-toolbox)
// and @bsv/sdk (BEEF, merkle paths, transactions, BRC-42/29 key derivation).
// A vector passes only if both reference stacks agree with it.
//
//   node sdk/wallet/vectors/gen-ts/run.mjs      (bundles this file with esbuild, then runs it)

import { readFileSync } from "node:fs";
import { Beef, KeyDeriver, MerklePath, PrivateKey, PublicKey, Transaction, Utils } from "@bsv/sdk";
import {
  blockHash, convertBitsToTarget, convertBitsToWork, deserializeBaseBlockHeader, validateBufferOfHeaders, validateHeaderDifficulty,
} from "wallet-toolbox/services/chaintracker/chaintracks/util/blockHeaderUtilities";

const dir = process.argv[2];
const load = (f: string) => JSON.parse(readFileSync(`${dir}/${f}`, "utf8"));
let checks = 0;
const fail: string[] = [];
function eq(what: string, got: unknown, want: unknown) {
  checks++;
  if (JSON.stringify(got) !== JSON.stringify(want)) fail.push(`${what}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
}
const hex = (b: number[] | Uint8Array) => Buffer.from(b).toString("hex");
const bytes = (h: string) => [...Buffer.from(h, "hex")];

// ---- headers (TS toolbox)
const H = load("headers.json");
type HC = { height: number; hex: string; hash: string; prevHash: string; merkleRoot: string; bits: number; nonce: number; time: number; version: number; target: string; work: string; powOk: boolean };
const headerCheck = (name: string, c: HC) => {
  const h = deserializeBaseBlockHeader(Buffer.from(c.hex, "hex"));
  eq(`${name} hash`, blockHash(Buffer.from(c.hex, "hex")), c.hash);
  eq(`${name} fields`, [h.previousHash, h.merkleRoot, h.bits, h.nonce, h.time, h.version], [c.prevHash, c.merkleRoot, c.bits, c.nonce, c.time, c.version]);
  eq(`${name} target`, convertBitsToTarget(c.bits).toString(16).padStart(64, "0"), c.target);
  eq(`${name} work`, convertBitsToWork(c.bits), c.work);
  let ok: boolean;
  try { ok = validateHeaderDifficulty(Buffer.from(bytes(c.hash)) as never, c.bits); } catch { ok = false; }
  eq(`${name} pow`, ok, c.powOk);
};
for (const c of H.headers as HC[]) headerCheck(`header ${c.height}`, c);
for (const t of H.tampered as Array<{ name: string; case: HC; prevHashLinks: boolean }>) headerCheck(`tampered ${t.name}`, t.case);
for (const b of (H.bits as Array<{ bits: number; target: string; work: string; valid: boolean }>).filter((b) => b.valid)) {
  eq(`bits ${b.bits.toString(16)} target`, convertBitsToTarget(b.bits).toString(16).padStart(64, "0"), b.target);
  eq(`bits ${b.bits.toString(16)} work`, convertBitsToWork(b.bits), b.work);
}
{
  const run = (H.headers as HC[]).filter((h) => h.height >= H.runStart && h.height < H.runStart + H.runLen);
  const buf = new Uint8Array(Buffer.concat(run.slice(1).map((h) => Buffer.from(h.hex, "hex"))));
  const r = validateBufferOfHeaders(buf, run[0].hash, 0, -1, convertBitsToWork(run[0].bits));
  eq("run links", r.lastHeaderHash, run.at(-1)!.hash);
  eq("run work", r.lastChainWork, H.runWork);
  for (const t of H.tampered as Array<{ name: string; case: HC; prevHashLinks: boolean }>) {
    let links = true;
    try { validateBufferOfHeaders(new Uint8Array(Buffer.from(t.case.hex, "hex")), run[0].hash); } catch { links = false; }
    eq(`tampered ${t.name} links`, links, t.prevHashLinks);
  }
}

// ---- transactions (@bsv/sdk)
for (const c of load("tx.json").cases) {
  const tx = Transaction.fromHex(c.hex);
  eq(`tx ${c.name} txid`, tx.id("hex"), c.txid);
  eq(`tx ${c.name} roundtrip`, tx.toHex(), c.hex);
  eq(`tx ${c.name} io`, [tx.inputs.length, tx.outputs.length, tx.version, tx.lockTime], [c.inputs.length, c.outputs.length, c.version, c.lockTime]);
}

// ---- BEEF (@bsv/sdk)
for (const c of load("beef.json").cases) {
  const b = Beef.fromString(c.hex, "hex");
  eq(`beef ${c.name} txids`, b.txs.map((t) => t.txid).sort(), c.txs.map((t: { txid: string }) => t.txid));
  eq(`beef ${c.name} bumps`, b.bumps.map((p) => p.blockHeight), c.bumps.map((p: { blockHeight: number }) => p.blockHeight));
  eq(`beef ${c.name} valid`, b.isValid(false), c.valid);
  if (c.atomic) eq(`beef ${c.name} subject`, b.atomicTxid, c.subjectTxid);
}

// ---- merkle paths (@bsv/sdk)
for (const c of load("merkle_path.json").cases) {
  const p = MerklePath.fromHex(c.hex);
  eq(`path ${c.name} height`, p.blockHeight, c.blockHeight);
  for (const l of c.leaves) eq(`path ${c.name} root ${l.txid.slice(0, 8)}`, p.computeRoot(l.txid), l.root);
  eq(`path ${c.name} hex`, p.toHex(), c.reserialized);
}

// ---- BRC-29 (@bsv/sdk KeyDeriver)
const B = load("brc29.json");
for (const c of B.cases) {
  const payer = new KeyDeriver(PrivateKey.fromHex(c.senderPrivateKey));
  const payee = new KeyDeriver(PrivateKey.fromHex(c.recipientPrivateKey));
  eq(`brc29 ${c.name} identities`, [payer.identityKey, payee.identityKey], [c.senderIdentityKey, c.recipientIdentityKey]);
  eq(`brc29 ${c.name} payer`, payer.derivePublicKey(B.protocol, c.keyID, c.recipientIdentityKey, false).toString(), c.payerDerivedKey);
  eq(`brc29 ${c.name} payee`, payee.derivePublicKey(B.protocol, c.keyID, c.senderIdentityKey, true).toString(), c.payeeDerivedKey);
  eq(`brc29 ${c.name} payee priv`, payee.derivePrivateKey(B.protocol, c.keyID, c.senderIdentityKey).toHex().padStart(64, "0"), c.payeePrivateKey);
  eq(`brc29 ${c.name} script`, "76a914" + hex(PublicKey.fromString(c.payeeDerivedKey).toHash() as number[]) + "88ac", c.lockingScript);
}
for (const r of B.recognize) {
  const tx = Transaction.fromHex(r.txHex);
  const payee = new KeyDeriver(PrivateKey.fromHex(r.recipientPrivateKey));
  for (const m of r.remittances) {
    const k = payee.derivePublicKey(B.protocol, `${m.derivationPrefix} ${m.derivationSuffix}`, m.senderIdentityKey, true);
    eq(`recognize ${r.name} vout ${m.vout}`, tx.outputs[m.vout].lockingScript.toHex() === "76a914" + hex(k.toHash() as number[]) + "88ac", m.matches);
  }
}

// ---- wire frames: getPublicKey args decode as @bsv/sdk's WalletWireProcessor would
{
  const W = load("wire.json");
  for (const q of W.requests) {
    const r = new Utils.Reader(bytes(q.frame));
    eq(`wire ${q.name} call`, r.readUInt8(), 8);
    const olen = r.readUInt8();
    r.read(olen);
    eq(`wire ${q.name} identityKey flag`, r.readUInt8(), 0);
    eq(`wire ${q.name} protocol`, [r.readUInt8(), Utils.toUTF8(r.read(r.readVarIntNum()))], q.protocolID);
    eq(`wire ${q.name} keyID`, Utils.toUTF8(r.read(r.readVarIntNum())), q.keyID);
    eq(`wire ${q.name} counterparty`, hex(r.read(33)), q.counterparty);
  }
}

if (fail.length) {
  console.error(fail.join("\n"));
  console.error(`${fail.length} of ${checks} checks FAILED`);
  process.exit(1);
}
console.log(`ts cross-check: ${checks} checks pass`);
