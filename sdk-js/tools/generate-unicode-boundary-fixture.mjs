#!/usr/bin/env node
// generate-unicode-boundary-fixture.mjs
//
// Freezes the C9 reproduction as a cross-lane conformance fixture: a capsule
// whose event summary is 200 astral code points, long enough that the Pith
// normalizer must truncate it. Before the surrogate-pair-safe cut in
// sdk-js/src/pith.js this capsule verified ok:true in JS and failed in
// sdk-py with "'utf-8' codec can't encode character '\ud83d'" — an encoder
// bug wearing a tampering costume. See spec/canonicalization.md and
// spec/pith.md "Truncation and the canonicalization boundary".
//
// The fixture goes through CapsuleBuilder.appendEvent on purpose: Pith is
// DEFAULT ON there, so the truncation path is the thing under test. Nothing
// here hand-writes the truncated string.
//
// Output (spec/vectors/unicode-boundary/output/):
//   astral-pith.capsule   plain, must verify ok:true in every lane
//   keys.json             the FIXED throwaway TEST originator keypair
//
// Deterministic: fixed key, fixed timestamps, fixed ZIP dates, so
// regeneration is byte-stable and `--check` compares bytes rather than
// re-signing. Regeneration is an intentional spec change; review the diff.

import { createPublicKey } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bytesToHex, hexToBytes } from "../src/canonical.js";
import { ed25519PrivateFromRaw, ed25519PublicToRaw } from "../src/crypto.js";
import { CapsuleBuilder, CapsuleReader, verifyCapsule } from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "unicode-boundary", "output");
const CHECK = process.argv.includes("--check");

// FIXED throwaway TEST key (deterministic fixtures). Never a production key.
// RFC 8032 §7.1 TEST 2 secret key.
const ORIGINATOR_PRIVATE_HEX =
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

const SIGNED_AT = "2026-07-01T12:00:00Z";

// 200 astral code points = 400 UTF-16 code units. The default Pith cut index
// (280 - 1 for the ellipsis = 279) is odd, so a naive slice lands mid-pair.
const ASTRAL_SUMMARY = "\u{1F642}".repeat(200);

// A high surrogate not followed by a low one, or a low surrogate not
// preceded by a high one.
const LONE_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function originatorKeys() {
  const privateKey = Buffer.from(hexToBytes(ORIGINATOR_PRIVATE_HEX));
  const publicKey = ed25519PublicToRaw(
    createPublicKey(ed25519PrivateFromRaw(privateKey)),
  );
  return {
    privateKey,
    publicKey,
    privateKeyHex: ORIGINATOR_PRIVATE_HEX,
    publicKeyHex: bytesToHex(publicKey),
  };
}

async function buildCapsule(originator) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: originator.publicKeyHex, label: "ConformanceOriginator" },
    participants: [{ actor_id: "human:origin", role: "originator", label: "Origin" }],
    createdAt: SIGNED_AT,
  });
  builder.setProgram("# Unicode Boundary\n\nAstral-character Pith fixture.\n");
  builder.appendEvent({
    actor: "human:origin",
    kind: "observation",
    action: "recorded",
    target: "program.md",
    timestamp: SIGNED_AT,
    payload: { summary: ASTRAL_SUMMARY },
  });
  return Buffer.from(
    await builder.seal({
      signers: [
        {
          role: "originator",
          publicKey: originator.publicKey,
          privateKey: originator.privateKey,
        },
      ],
      signedAt: SIGNED_AT,
    }),
  );
}

async function assertFixtureIsSound(bytes, publicKeyHex) {
  const reader = await CapsuleReader.fromBytes(bytes);
  const result = await verifyCapsule(reader, { allowlist: [publicKeyHex] });
  if (!result.ok) throw new Error(`fixture does not verify: ${result.errors.join("; ")}`);
  const summary = reader.events()[0].payload.summary;
  if (LONE_SURROGATE.test(summary)) {
    throw new Error("fixture summary contains an unpaired surrogate");
  }
  if (!summary.endsWith("…")) {
    throw new Error("fixture summary was not truncated; the fixture tests nothing");
  }
}

async function main() {
  const originator = originatorKeys();
  const capsule = await buildCapsule(originator);
  await assertFixtureIsSound(capsule, originator.publicKeyHex);

  const keys = {
    comment:
      "FIXED throwaway TEST keypair for deterministic conformance fixtures; never a production key.",
    originator: {
      publicKey: originator.publicKeyHex,
      privateKey: originator.privateKeyHex,
    },
  };

  const artifacts = [
    ["astral-pith.capsule", capsule],
    ["keys.json", Buffer.from(JSON.stringify(keys, null, 2) + "\n", "utf8")],
  ];

  if (!CHECK) await mkdir(OUT_DIR, { recursive: true });
  for (const [name, bytes] of artifacts) {
    const path = join(OUT_DIR, name);
    if (CHECK) {
      let checkedIn;
      try {
        checkedIn = await readFile(path);
      } catch (err) {
        throw new Error(`${name}: checked-in fixture missing or unreadable: ${err.message}`);
      }
      if (!checkedIn.equals(bytes)) {
        throw new Error(`${name}: checked-in fixture differs from deterministic generator output`);
      }
      console.log(`ok ${name} (${bytes.length} bytes)`);
    } else {
      await writeFile(path, bytes);
      console.log(`wrote ${name} (${bytes.length} bytes)`);
    }
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
