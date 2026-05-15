// `capsule keygen [--out <dir>] [--label NAME] [--json]`
//
// Generates a fresh Ed25519 originator keypair and prints (or writes)
// the public + private hex. Designed for interop with the multi-language
// SDKs: every implementation accepts raw 32-byte Ed25519 keys, expressed
// as lowercase hex.
//
// When --out DIR is given, writes:
//   <DIR>/<label-or-capsule>.public.hex     (64 hex chars + \n)
//   <DIR>/<label-or-capsule>.private.hex    (64 hex chars + \n; chmod 600)
// Otherwise prints the same to stdout.

import { mkdir, writeFile, chmod } from "node:fs/promises";
import { join, resolve } from "node:path";
import { generateEd25519 } from "@capsule/sdk-v0.6-prototype";
import { parseArgs } from "../args.mjs";
import { out } from "../format.mjs";

const USAGE = "usage: capsule keygen [--out <dir>] [--label NAME] [--json]\n";

export async function keygenCmd(argv) {
  const args = parseArgs(argv, {
    booleans: ["json"],
    strings: ["out", "label"],
  });
  if (args._[0] === "help" || args.help === true) {
    process.stderr.write(USAGE);
    return 0;
  }
  const label = sanitizeLabel(args.label || "capsule");
  const k = generateEd25519();

  if (args.out) {
    const outDir = resolve(args.out);
    await mkdir(outDir, { recursive: true });
    const pubPath = join(outDir, `${label}.public.hex`);
    const privPath = join(outDir, `${label}.private.hex`);
    await writeFile(pubPath, k.publicKeyHex + "\n");
    await writeFile(privPath, k.privateKeyHex + "\n");
    try { await chmod(privPath, 0o600); } catch { /* best effort */ }
    if (args.json) {
      out(JSON.stringify({
        public_key_hex: k.publicKeyHex,
        public_key_path: pubPath,
        private_key_path: privPath,
      }, null, 2));
    } else {
      out(`Generated Ed25519 keypair (${label}):`);
      out(`  public  → ${pubPath}`);
      out(`  private → ${privPath}  (chmod 600)`);
      out(`  pubkey  : ${k.publicKeyHex}`);
      out("");
      out("To use as an allowlist entry:");
      out(`  capsule verify <file> --allowlist ${k.publicKeyHex}`);
    }
    return 0;
  }

  if (args.json) {
    out(JSON.stringify({
      algorithm: "Ed25519",
      public_key_hex: k.publicKeyHex,
      private_key_hex: k.privateKeyHex,
    }, null, 2));
    return 0;
  }

  out("Algorithm:    Ed25519");
  out(`Public  key:  ${k.publicKeyHex}`);
  out(`Private key:  ${k.privateKeyHex}`);
  out("");
  out("⚠  Keep the private key offline. Anyone with these 32 bytes can");
  out("   produce a capsule signed under this identity.");
  return 0;
}

function sanitizeLabel(s) {
  const cleaned = String(s).replace(/[^a-zA-Z0-9_.-]/g, "_");
  if (!cleaned || cleaned === "." || cleaned === "..") return "capsule";
  return cleaned.slice(0, 40);
}
