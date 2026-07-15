#!/usr/bin/env node
// generate-signing-input-vector.mjs
//
// Pins the BYTE-LEVEL signing and hashing inputs of the plain-basic
// embedded vector (spec/vectors/plain-basic.json) into
// spec/vectors/signing-input.json:
//
//   - capsule_id domain separation and preimage
//   - per-event JCS canonical bytes and hash preimage (prev_raw || canon)
//   - manifest JCS canonical bytes -> manifest_hash
//   - content_index JCS canonical bytes -> content_index_hash
//   - envelope canonical payload (JCS of envelope minus signers)
//   - per-role signing domain and full Ed25519 signing input
//
// This makes the "bytes being signed, hashed, identified" contract
// explicit for independent implementations (ROADMAP: wire-shape freeze).
// Regeneration is an intentional spec change; review the diff.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CapsuleReader } from "../src/index.js";
import { bytesToHex, concatBytes, hexToBytes, jcs, sha256 } from "../src/canonical.js";
import { envelopeCanonicalPayload, envelopeSigningInput } from "../src/envelope.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const VECTORS = join(REPO_ROOT, "spec", "vectors");

const ID_DOMAIN = "capsule-id-v0.6\x00";

function sha256Hex(bytes) {
  return bytesToHex(sha256(bytes));
}

async function main() {
  const basic = JSON.parse(await readFile(join(VECTORS, "plain-basic.json"), "utf8"));
  const reader = await CapsuleReader.fromBytes(Buffer.from(basic.capsule_bytes_b64, "base64"));
  const manifest = reader.manifest();
  const envelope = reader.envelope();

  // capsule_id = SHA-256(domain || originator_pub_raw || first_event_hash_raw)
  const idDomainBytes = Buffer.from(ID_DOMAIN, "utf8");
  const pubRaw = hexToBytes(manifest.originator.public_key);
  const fehRaw = hexToBytes(manifest.first_event_hash);
  const capsuleId = sha256Hex(concatBytes(idDomainBytes, pubRaw, fehRaw));

  // Per-event: hash = SHA-256(prev_hash_raw || JCS(event minus hash))
  const events = reader.events().map((e) => {
    const { hash, ...rest } = e;
    const canon = jcs(rest);
    const preimage = concatBytes(hexToBytes(rest.prev_hash), canon);
    const recomputed = sha256Hex(preimage);
    if (recomputed !== hash) {
      throw new Error(`event ${e.seq}: recomputed hash ${recomputed} != stored ${hash}`);
    }
    return {
      seq: e.seq,
      prev_hash_hex: rest.prev_hash,
      canonical_bytes_hex: bytesToHex(canon),
      hash_hex: recomputed,
    };
  });

  // manifest_hash = SHA-256(JCS(manifest))
  const manifestCanon = jcs(manifest);

  // content_index_hash = SHA-256(JCS(content_index.files))
  const indexCanon = jcs(manifest.content_index.files);

  // Envelope: canonical payload is JCS(envelope minus signers); the signing
  // input per role is domain_sep_bytes || canonical_payload_bytes.
  const envCanon = envelopeCanonicalPayload(envelope);
  const signers = envelope.signers.map((s) => {
    const domain = `capsule-provenance-v0.6:${s.role}\x00`;
    const input = envelopeSigningInput(envelope, s.role);
    return {
      role: s.role,
      domain_utf8: domain,
      domain_hex: bytesToHex(Buffer.from(domain, "utf8")),
      signing_input_sha256: sha256Hex(input),
      public_key_hex: s.public_key,
      signature_hex: s.signature,
    };
  });

  const doc = {
    meta: {
      kind: "signing-input",
      name: "signing-input",
      spec_version: "0.6",
      description:
        "Byte-level signing/hashing input pins for the plain-basic embedded vector. Implementations MUST reproduce every canonical byte string and hash below from the capsule in capsule_ref, and verify the Ed25519 signature over the reconstructed signing input.",
      capsule_ref: "plain-basic.json",
      generator: "sdk-js/tools/generate-signing-input-vector.mjs",
      no_warranty: "Conformance fixtures only; not production templates or advice.",
    },
    capsule_id: {
      domain_utf8: ID_DOMAIN,
      domain_hex: bytesToHex(idDomainBytes),
      originator_public_key_hex: manifest.originator.public_key,
      first_event_hash_hex: manifest.first_event_hash,
      capsule_id_hex: capsuleId,
    },
    events,
    manifest: {
      canonical_bytes_hex: bytesToHex(manifestCanon),
      sha256_hex: sha256Hex(manifestCanon),
    },
    content_index: {
      canonical_bytes_hex: bytesToHex(indexCanon),
      sha256_hex: sha256Hex(indexCanon),
    },
    envelope: {
      canonical_payload_hex: bytesToHex(envCanon),
      canonical_payload_sha256: sha256Hex(envCanon),
      signers,
    },
  };

  const out = join(VECTORS, "signing-input.json");
  await writeFile(out, JSON.stringify(doc, null, 2) + "\n", "utf8");
  console.log(`wrote ${out}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
