// The sdk-js README quickstart, verbatim and runnable.
//
// This file is CI-gated by the conformance harness (target
// "example-quickstart"), so the copy-paste onboarding path in
// sdk-js/README.md can never silently rot. If you change this flow,
// update the README quickstart to match.

import { readFile, writeFile } from "node:fs/promises";
import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
} from "@capsule/sdk-v0.6-prototype";

// 1. One keypair for your app (persist keys.privateKeyHex somewhere safe;
//    in a real app you generate this once, not per capsule).
const keys = generateEd25519();

// 2. Build and seal a capsule: a portable, signed unit of work.
const bytes = await new CapsuleBuilder({ originator: { ...keys, label: "MyApp" } })
  .setProgram("# Quarterly report\n\nDraft written by Alice, reviewed by AI.\n")
  .appendEvent({ actor: "human:alice", action: "wrote_draft" })
  .appendEvent({ actor: "ai:assistant", action: "suggested_edits", payload: { count: 3 } })
  .seal({ signers: keys });

await writeFile("output/quickstart.capsule", bytes);

// 3. Anywhere else (another process, another machine): open and verify.
//    The allowlist is your trust decision — which signer keys you accept.
const fileBytes = await readFile("output/quickstart.capsule");
const result = await verifyCapsule(fileBytes, { allowlist: [keys.publicKeyHex] });

console.log("verified:", result.ok); // true — math checks out
console.log("trusted signers:", result.trustedSignerCount); // 1 — and you trust the key

// 4. Read the contents.
const reader = await CapsuleReader.fromBytes(fileBytes);
console.log("capsule id:", reader.manifest().id);
console.log("program:", JSON.stringify(reader.program()));
for (const event of reader.events()) {
  console.log(`event ${event.seq}: ${event.actor} ${event.action}`);
}

// --- end of README quickstart; the assertions below keep CI honest ---

import assert from "node:assert/strict";
assert.equal(result.ok, true, JSON.stringify(result.errors));
assert.equal(result.trustedSignerCount, 1);
assert.equal(reader.events().length, 2);
assert.match(reader.manifest().id, /^[0-9a-f]{64}$/);

// A verifier who does NOT allowlist the key sees valid math, zero trust.
const untrusted = await verifyCapsule(fileBytes);
assert.equal(untrusted.ok, true);
assert.equal(untrusted.trustedSignerCount, 0);

// Garbage bytes fail closed instead of throwing.
const garbage = await verifyCapsule(Buffer.from("not a capsule"));
assert.equal(garbage.ok, false);

console.log("quickstart: ok");
