#!/usr/bin/env node
// generate-attestation-vectors.mjs
//
// Deterministically regenerates the identity-attestation outcome registry at
// spec/vectors/identity-attestation/vectors.json.
//
// The registry pins the ATTESTATION-LAYER outcome vocabulary of
// spec/federation.md ("Failure reporting"): `attestation_verified`,
// `attestation_unverified` (unknown — no trust roots cached), and
// `attestation_rejected` (strong negative — signature, expiry, or binding
// failure). Independent implementations SHOULD reproduce ok + status.
//
// Only the native `ed25519-jcs` profile appears here: Ed25519 signatures are
// deterministic, so the file regenerates byte-identically. ECDSA (the JWT
// profile) is randomized and cannot be pinned this way.
//
// The TEST issuer seed below is an intentional throwaway conformance
// fixture — never a production key.
//
// Pass --check to compare generated JSON with the checked-in file.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { signIdentityAttestation, attestationDomain } from "../src/federation/attestation.js";
import { ed25519PrivateFromRaw, ed25519PublicToRaw, ed25519Sign } from "../src/crypto.js";
import { bytesToHex, hexToBytes, jcs } from "../src/canonical.js";
import { CURRENT_VERSION } from "../src/versions.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const OUT_DIR = join(REPO_ROOT, "spec", "vectors", "identity-attestation");
const OUT_PATH = join(OUT_DIR, "vectors.json");
const CHECK = process.argv.includes("--check");

// Fixed test material — deterministic, throwaway.
const ISSUER_SEED_HEX = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
const OTHER_SEED_HEX = "2f2e2d2c2b2a292827262524232221201f1e1d1c1b1a19181716151413121110";
const SIGNER_PUBLIC_KEY = "aa".repeat(32);
const CAPSULE_ID = "bb".repeat(32);
const OTHER_CAPSULE_ID = "cc".repeat(32);
const ISSUER = "https://capsules.example";
const KID = "issuer-key-1";
const NOW = "2026-05-07T12:00:00Z";

function publicKeyHexFromSeed(seedHex) {
  const priv = ed25519PrivateFromRaw(hexToBytes(seedHex));
  return bytesToHex(ed25519PublicToRaw(createPublicKey(priv)));
}

// FROZEN backward-compatibility evidence: a GENUINE v0.6 attestation,
// signed by the pre-bump v0.6 SDK (spec_version "0.6", signed under the
// capsule-identity-attestation-v0.6 domain) and byte-preserved verbatim
// from the pre-bump vectors file. Its value is that no current-era code
// produced it: a current verifier accepting it proves the signing domain
// really is keyed by the attestation's DECLARED spec_version
// (spec/versioning.md applied to the attestation overlay), so
// previously issued attestations stay verifiable forever. Ed25519 is
// deterministic, so these bytes are reproducible from the fixed issuer
// seed under the v0.6 rules — but do NOT rewrite them with current
// helpers; that is exactly the sweep this constant exists to prevent.
const FROZEN_V06_ATTESTATION = {
  typ: "capsule-identity-attestation",
  spec_version: "0.6",
  alg: "ed25519-jcs",
  issuer: ISSUER,
  kid: KID,
  claims: {
    signer_public_key: SIGNER_PUBLIC_KEY,
    signer_role: "originator",
    subject: { clerk_user_id: "user_1", org_role: "admin" },
    issued_at: NOW,
    expires_at: "2027-05-07T12:00:00Z",
    capsule_id: CAPSULE_ID,
  },
  signature:
    "7a54edefdc3d9141b19e21b86031c7f8baab534e133d0240c2d53cb7a80e5362e282b992a63174c51fad9bbbbebea937b91c589a571de990ea1140f5f00c0c03",
};

// An attestation declaring a well-formed but UNKNOWN (newer) spec
// version, internally coherent under that era's domain — hand-rolled on
// purpose so only the version gate refuses it, mirroring
// spec/vectors/version-compat/.
function attestDeclaringVersion(specVersion) {
  const attestation = {
    typ: "capsule-identity-attestation",
    spec_version: specVersion,
    alg: "ed25519-jcs",
    issuer: ISSUER,
    kid: KID,
    claims: {
      signer_public_key: SIGNER_PUBLIC_KEY,
      signer_role: "originator",
      subject: { clerk_user_id: "user_1", org_role: "admin" },
      issued_at: NOW,
      expires_at: "2027-05-07T12:00:00Z",
      capsule_id: CAPSULE_ID,
    },
  };
  const input = Buffer.concat([attestationDomain(specVersion), Buffer.from(jcs(attestation))]);
  attestation.signature = bytesToHex(ed25519Sign(hexToBytes(ISSUER_SEED_HEX), input));
  return attestation;
}

function attest(claims, { seedHex = ISSUER_SEED_HEX, issuer = ISSUER, kid = KID } = {}) {
  return signIdentityAttestation({
    issuer,
    kid,
    ed25519PrivateKeyHex: seedHex,
    claims: {
      signer_public_key: SIGNER_PUBLIC_KEY,
      signer_role: "originator",
      subject: { clerk_user_id: "user_1", org_role: "admin" },
      issued_at: NOW,
      expires_at: "2027-05-07T12:00:00Z",
      ...claims,
    },
  });
}

async function main() {
  const issuerPublicKeyHex = publicKeyHexFromSeed(ISSUER_SEED_HEX);
  const otherPublicKeyHex = publicKeyHexFromSeed(OTHER_SEED_HEX);

  const tampered = attest({ capsule_id: CAPSULE_ID });
  tampered.claims.subject.org_role = "superadmin";

  const doc = {
    meta: {
      kind: "identity-attestation",
      name: "identity-attestation",
      spec_version: CURRENT_VERSION,
      description:
        "Language-neutral attestation-layer outcomes for the native ed25519-jcs profile. " +
        "Implementations SHOULD reproduce ok and status; status is the vocabulary of " +
        "spec/federation.md 'Failure reporting'.",
      generator: "sdk-js/tools/generate-attestation-vectors.mjs",
      no_warranty: "Conformance fixtures only; not production templates or advice.",
    },
    trust_roots: {
      keys: [{ kid: KID, alg: "ed25519-jcs", public_key_hex: issuerPublicKeyHex }],
    },
    context: {
      capsule_id: CAPSULE_ID,
      signer_public_key: SIGNER_PUBLIC_KEY,
      expected_issuer: ISSUER,
      now: NOW,
    },
    vectors: [
      {
        name: "valid",
        attestation: attest({ capsule_id: CAPSULE_ID }),
        expected: { ok: true, status: "attestation_verified" },
      },
      {
        name: "valid-previous-spec-version",
        note:
          "FROZEN backward-compatibility evidence: a genuine v0.6 attestation issued by the " +
          "pre-bump SDK, byte-preserved. The ed25519-jcs signing domain embeds the DECLARED " +
          "spec_version (which is itself under the signature), so a current verifier must " +
          "reconstruct capsule-identity-attestation-v0.6 for it and accept — previously " +
          "issued attestations stay verifiable forever.",
        attestation: FROZEN_V06_ATTESTATION,
        expected: { ok: true, status: "attestation_verified" },
      },
      {
        name: "spec-version-unknown-newer",
        note:
          "Declares spec_version 9.9, internally coherent under the 9.9 domain. This " +
          "verifier cannot reconstruct that era's signing domain; checking the signature " +
          "under the wrong domain would read as tampering, so the outcome is UNVERIFIED " +
          "(unknown, not negative) with a verifier-too-old diagnosis, mirroring " +
          "spec/versioning.md.",
        attestation: attestDeclaringVersion("9.9"),
        expected: {
          ok: false,
          status: "attestation_unverified",
          error_includes: "newer than this verifier supports",
        },
      },
      {
        name: "valid-okp-jwk-trust-root",
        note: "The same attestation, with the issuer's trust root published as an RFC 8037 Ed25519 OKP JWK.",
        trust_roots: {
          keys: [
            {
              kty: "OKP",
              crv: "Ed25519",
              alg: "EdDSA",
              use: "sig",
              kid: KID,
              x: Buffer.from(issuerPublicKeyHex, "hex").toString("base64url"),
            },
          ],
        },
        attestation: attest({ capsule_id: CAPSULE_ID }),
        expected: { ok: true, status: "attestation_verified" },
      },
      {
        name: "no-binding-claims",
        note: "Binding claims are mandatory; an attestation without them binds nothing.",
        attestation: (() => {
          const a = attest({ capsule_id: CAPSULE_ID });
          delete a.claims.capsule_id;
          delete a.claims.signer_public_key;
          return a;
        })(),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "missing required binding claim 'capsule_id'",
        },
      },
      {
        name: "capsule-id-replay",
        note: "Validly signed, but bound to a different capsule.",
        attestation: attest({ capsule_id: OTHER_CAPSULE_ID }),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "capsule_id binding mismatch",
        },
      },
      {
        name: "signer-key-mismatch",
        attestation: attest({ capsule_id: CAPSULE_ID, signer_public_key: "dd".repeat(32) }),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "signer_public_key binding mismatch",
        },
      },
      {
        name: "expired",
        attestation: attest({ capsule_id: CAPSULE_ID, expires_at: "2026-05-06T12:00:00Z" }),
        expected: { ok: false, status: "attestation_rejected", error_includes: "attestation expired" },
      },
      {
        name: "expires-at-unparseable",
        note: "NaN must never read as 'never expires'.",
        attestation: attest({ capsule_id: CAPSULE_ID, expires_at: "whenever" }),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "expires_at is not an RFC 3339 instant",
        },
      },
      {
        name: "tampered-claims",
        note: "A subject claim edited after signing.",
        attestation: tampered,
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "attestation signature invalid",
        },
      },
      {
        name: "issuer-mismatch",
        note: "Signed by a key the host holds, but issued under another issuer identity.",
        attestation: attest({ capsule_id: CAPSULE_ID }, { issuer: "https://other.example" }),
        expected: {
          ok: false,
          status: "attestation_rejected",
          error_includes: "attestation issuer mismatch",
        },
      },
      {
        name: "unknown-kid",
        note: "kid selects the key; an unknown kid resolves to no key rather than falling back.",
        trust_roots: {
          keys: [
            { kid: "issuer-key-1", alg: "ed25519-jcs", public_key_hex: issuerPublicKeyHex },
            { kid: "issuer-key-2", alg: "ed25519-jcs", public_key_hex: otherPublicKeyHex },
          ],
        },
        attestation: attest({ capsule_id: CAPSULE_ID }, { kid: "issuer-key-retired" }),
        expected: {
          ok: false,
          status: "attestation_unverified",
          error_includes: "no trust-root key for kid=issuer-key-retired",
        },
      },
      {
        name: "no-trust-roots",
        note: "Unknown, NOT negative: the host caches no key for this issuer.",
        trust_roots: { keys: [] },
        attestation: attest({ capsule_id: CAPSULE_ID }),
        expected: {
          ok: false,
          status: "attestation_unverified",
          error_includes: "no trust-root key",
        },
      },
    ],
  };

  const json = `${JSON.stringify(doc, null, 2)}\n`;
  if (CHECK) {
    let checkedIn;
    try {
      checkedIn = await readFile(OUT_PATH, "utf8");
    } catch (err) {
      throw new Error(`identity-attestation vectors missing or unreadable: ${err.message}`);
    }
    if (checkedIn !== json) {
      throw new Error("identity-attestation vectors differ from deterministic generator output");
    }
    console.log(`ok identity-attestation/vectors.json (${doc.vectors.length} vectors)`);
  } else {
    await mkdir(OUT_DIR, { recursive: true });
    await writeFile(OUT_PATH, json);
    console.log(`wrote identity-attestation/vectors.json (${doc.vectors.length} vectors)`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
