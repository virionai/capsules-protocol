#!/usr/bin/env node
// generate-pith-authoring-fixtures.mjs
//
// Freezes the P1 fix as cross-lane conformance fixtures (spec/pith.md,
// spec/chain.md "pith_normalized_fields"):
//
//   technical-prose-verbatim.capsule
//     Sealed by the DEFAULT builder. The event summary is the P1
//     reproduction prose — dots inside an identifier
//     (ledger.entry_audit) and a decimal (12.4k) — and a note holding
//     bare decimals. Pith is opt-in as of v0.7, so the prose must land
//     in the chain byte-identical to what the author wrote, with no
//     pith_normalized_fields marker. Before the fix the default
//     normalizer rewrote it to "ledger. entry_audit ... 12. 4k ..."
//     and silently deleted the last two sentences — inside the hash
//     chain, where the original is not preserved.
//
//   pith-normalized-marker.capsule
//     Sealed with { pith: true }. The summary needed normalization
//     (whitespace collapse + a dropped fourth sentence), so the event
//     carries pith_normalized_fields: ["payload.summary"] — the lossy
//     rewrite is declared in-chain, not silent. Technical tokens in the
//     kept sentences survive byte-intact.
//
// Both capsules MUST verify ok:true in every lane: the marker is an
// optional event member covered by the event hash like any other, and a
// lane that drops or rejects it diverges from the signed bytes.
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
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "pith-authoring", "output");
const CHECK = process.argv.includes("--check");

// FIXED throwaway TEST key (deterministic fixtures). Never a production key.
// RFC 8032 §7.1 TEST 3 secret key.
const ORIGINATOR_PRIVATE_HEX =
  "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";

const SIGNED_AT = "2026-08-04T12:00:00Z";

// The P1 reproduction: three sentences of ordinary technical prose.
const WAL_PROSE =
  "ledger.entry_audit is 88% of decoded WAL volume at 610 GB and roughly " +
  "12.4k inserts per second during the settlement batch. The apply worker " +
  "is pinned at 99% of one core. This is a throughput ceiling, not a " +
  "tuning problem.";

const DECIMAL_NOTE = "Pin the minor release at 14.11 or 16.4 before the batch.";

// Needs normalization under { pith: true }: messy whitespace and a
// fourth sentence past the default budget. The technical tokens sit in
// kept sentences and must survive byte-intact.
const MESSY_SUMMARY =
  "ledger.entry_audit is 88% of decoded WAL volume at 610 GB.\n\n" +
  "Inserts  hold at roughly 12.4k per second. The apply worker is pinned " +
  "at 99% of one core. This is a throughput ceiling, not a tuning problem.";
const NORMALIZED_SUMMARY =
  "ledger.entry_audit is 88% of decoded WAL volume at 610 GB. Inserts " +
  "hold at roughly 12.4k per second. The apply worker is pinned at 99% of " +
  "one core.";

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

function baseBuilder(originator, options = {}) {
  const builder = new CapsuleBuilder({
    originator: { publicKey: originator.publicKeyHex, label: "ConformanceOriginator" },
    participants: [{ actor_id: "human:origin", role: "originator", label: "Origin" }],
    createdAt: SIGNED_AT,
    ...options,
  });
  builder.setProgram("# Pith Authoring\n\nAuthoring-layer Pith fixtures.\n");
  return builder;
}

async function sealed(builder, originator) {
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

async function buildVerbatimCapsule(originator) {
  const builder = baseBuilder(originator); // Pith untouched: the default path
  builder.appendEvent({
    actor: "human:origin",
    kind: "observation",
    action: "recorded",
    target: "program.md",
    timestamp: SIGNED_AT,
    payload: { summary: WAL_PROSE, note: DECIMAL_NOTE },
  });
  return sealed(builder, originator);
}

async function buildMarkerCapsule(originator) {
  const builder = baseBuilder(originator, { pith: true });
  builder.appendEvent({
    actor: "human:origin",
    kind: "observation",
    action: "recorded",
    target: "program.md",
    timestamp: SIGNED_AT,
    payload: { summary: MESSY_SUMMARY },
  });
  return sealed(builder, originator);
}

async function verified(name, bytes, publicKeyHex) {
  const reader = await CapsuleReader.fromBytes(bytes);
  const result = await verifyCapsule(reader, { allowlist: [publicKeyHex] });
  if (!result.ok) {
    throw new Error(`${name} does not verify: ${result.errors.join("; ")}`);
  }
  return reader.events()[0];
}

async function assertFixturesAreSound(verbatim, marker, publicKeyHex) {
  const verbatimEvent = await verified("technical-prose-verbatim", verbatim, publicKeyHex);
  if (verbatimEvent.payload.summary !== WAL_PROSE) {
    throw new Error("verbatim fixture: default builder altered the summary prose");
  }
  if (verbatimEvent.payload.note !== DECIMAL_NOTE) {
    throw new Error("verbatim fixture: default builder altered the note decimals");
  }
  if ("pith_normalized_fields" in verbatimEvent) {
    throw new Error("verbatim fixture: unexpected pith_normalized_fields marker");
  }

  const markerEvent = await verified("pith-normalized-marker", marker, publicKeyHex);
  if (markerEvent.payload.summary !== NORMALIZED_SUMMARY) {
    throw new Error(
      `marker fixture: normalized summary mismatch: ${JSON.stringify(markerEvent.payload.summary)}`,
    );
  }
  for (const token of ["ledger.entry_audit", "12.4k", "99%"]) {
    if (!markerEvent.payload.summary.includes(token)) {
      throw new Error(`marker fixture: token ${token} did not survive normalization`);
    }
  }
  const marks = markerEvent.pith_normalized_fields;
  if (!Array.isArray(marks) || marks.length !== 1 || marks[0] !== "payload.summary") {
    throw new Error("marker fixture: pith_normalized_fields must be [\"payload.summary\"]");
  }
}

async function main() {
  const originator = originatorKeys();
  const verbatim = await buildVerbatimCapsule(originator);
  const marker = await buildMarkerCapsule(originator);
  await assertFixturesAreSound(verbatim, marker, originator.publicKeyHex);

  const keys = {
    comment:
      "FIXED throwaway TEST keypair for deterministic conformance fixtures; never a production key.",
    originator: {
      publicKey: originator.publicKeyHex,
      privateKey: originator.privateKeyHex,
    },
  };

  const artifacts = [
    ["technical-prose-verbatim.capsule", verbatim],
    ["pith-normalized-marker.capsule", marker],
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
