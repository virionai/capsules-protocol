// Version-compatibility policy (spec/versioning.md).
//
// The defect being closed: the reader threw unless manifest.format.version
// and envelope.version were exactly "0.6", so the moment the project bumps
// to 0.7 every capsule sealed today becomes unopenable — not because the
// capsule is bad, but because time passed. That is the strictest possible
// violation of the archival profile's governing rule (everything required
// to verify is captured inside the capsule at seal time).
//
// Policy under test:
//   1. A capsule declaring a KNOWN version opens and verifies under that
//      era's rules, and the verify result REPORTS the observed version.
//   2. An unknown NEWER version fails closed with a diagnosis distinct
//      from tamper detection ("this verifier is too old" is not "this
//      capsule is corrupt").
//   3. An unknown OLDER version fails closed with its own reason.
//   4. A version string that is not <major>.<minor> at all is malformed —
//      a shape violation, not a version-support gap.
//   5. Domain separation strings embed the version, so their selection is
//      keyed by the capsule's DECLARED version — deliberately, forever.
//   6. Hosts DECLARE an accepted range; the SDK reports, the host decides
//      (exactly as with signer allowlists).

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
  buildChainEvents,
  buildContentIndex,
  buildManifest,
  computeCapsuleId,
  buildEnvelope,
} from "../src/index.js";
import { manifestBytes, manifestHash } from "../src/manifest.js";
import { eventsToJsonl, firstAndEntryHash } from "../src/chain.js";
import { bytesToHex, concatBytes, jcs, sha256 } from "../src/canonical.js";
import { ed25519Sign } from "../src/crypto.js";
import { packZip } from "../src/zip.js";
import {
  KNOWN_VERSIONS,
  CURRENT_VERSION,
  SUITES,
  classifyVersion,
  idDomain,
  provenanceDomain,
  keyWrapInfo,
} from "../src/versions.js";

const TS = "2026-05-07T12:00:00Z";

async function sealedCurrentCapsule() {
  const keys = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: keys.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  builder.setProgram("# Version compat\n");
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
    payload: { summary: "submitted" },
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: keys.publicKey, privateKey: keys.privateKey }],
    signedAt: TS,
  });
  return { bytes: Buffer.from(bytes), keys };
}

/**
 * Build a capsule that DECLARES an arbitrary format version, internally
 * coherent under that version's domain strings (id domain and signing
 * domain both embed the declared version). From the point of view of a
 * hypothetical verifier that knows `version`, nothing is wrong with it;
 * our verifier must refuse it purely because the version is unknown.
 *
 * Deliberately hand-rolls the domain strings instead of using the SDK's
 * version-keyed helpers, so this test cannot be satisfied by a helper
 * that ignores its version argument.
 */
async function capsuleDeclaringVersion(version, { envelopeVersion = version } = {}) {
  const keys = generateEd25519();
  const events = buildChainEvents([
    {
      actor: "human:alice",
      kind: "decision",
      action: "submit",
      target: "program.md",
      timestamp: TS,
      payload: { summary: "submitted" },
    },
  ]);
  const { firstEventHash, entryHash } = firstAndEntryHash(events);
  const files = new Map();
  files.set("program.md", Buffer.from("# Version compat\n", "utf8"));
  files.set("chain/events.jsonl", eventsToJsonl(events));
  const contentIndex = buildContentIndex(files);
  const manifest = buildManifest({
    originator: { public_key: keys.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    contentIndex,
    firstEventHash,
    encryption: null,
    createdAt: TS,
  });
  manifest.format.version = version;
  // capsule-id domain keyed by the DECLARED version, by hand.
  manifest.id = bytesToHex(
    sha256(
      concatBytes(
        Buffer.from(`capsule-id-v${version}\x00`, "utf8"),
        keys.publicKey,
        Buffer.from(firstEventHash, "hex"),
      ),
    ),
  );
  const envelope = buildEnvelope({
    capsuleId: manifest.id,
    firstEventHash,
    entryHash,
    manifestHash: manifestHash(manifest),
    contentIndexHash: contentIndex.index_hash,
    encryptedBlobHash: null,
    cipher: "none",
    signedAt: TS,
  });
  envelope.version = envelopeVersion;
  // provenance domain keyed by the DECLARED version, by hand.
  const { signers: _drop, ...payload } = envelope;
  const input = concatBytes(
    Buffer.from(`capsule-provenance-v${envelopeVersion}:originator\x00`, "utf8"),
    jcs(payload),
  );
  envelope.signers.push({
    role: "originator",
    public_key: keys.publicKeyHex,
    signature: bytesToHex(ed25519Sign(keys.privateKey, input)),
  });
  const all = new Map(files);
  all.set("manifest.json", manifestBytes(manifest));
  all.set("provenance/envelope.json", Buffer.from(JSON.stringify(envelope, null, 2), "utf8"));
  return Buffer.from(await packZip(all));
}

test("a sealed current-version capsule verifies and reports the observed version", async () => {
  const { bytes, keys } = await sealedCurrentCapsule();
  const result = await verifyCapsule(bytes, { allowlist: [keys.publicKeyHex] });
  assert.equal(result.ok, true, result.errors.join("; "));
  assert.equal(result.formatVersion.observed, CURRENT_VERSION);
  assert.equal(result.formatVersion.supported, true);
  assert.equal(result.formatVersion.status, "known");
  // The era's algorithm suite is reported (spec/versioning.md: absence of
  // algorithm identifiers in the capsule means the v0.6 suite — 0.7
  // adopts it unchanged).
  assert.equal(result.formatVersion.suite, SUITES[CURRENT_VERSION]);
  // No policy declared: the SDK takes no acceptance position.
  assert.equal(result.formatVersion.acceptedByPolicy, null);
});

test("unknown NEWER version fails closed with a verifier-too-old diagnosis, not tamper", async () => {
  const bytes = await capsuleDeclaringVersion("9.9");
  await assert.rejects(
    () => CapsuleReader.fromBytes(bytes),
    (err) => /newer than this verifier supports/.test(err.message),
    "reader must refuse with the too-old diagnosis",
  );
  const result = await verifyCapsule(bytes);
  assert.equal(result.ok, false);
  assert.equal(result.formatVersion.observed, "9.9");
  assert.equal(result.formatVersion.supported, false);
  assert.equal(result.formatVersion.status, "unknown_newer");
  assert.ok(
    result.errors.some((e) => e.includes("newer than this verifier supports")),
    `expected the too-old diagnosis, got: ${result.errors.join("; ")}`,
  );
  // The diagnosis must be distinguishable from tamper detection: no
  // hash-mismatch / signature-invalid noise from applying the wrong
  // era's rules to a capsule we cannot understand.
  assert.ok(
    !result.errors.some((e) => /mismatch|signature invalid/.test(e)),
    `unknown-version refusal must not read as tampering: ${result.errors.join("; ")}`,
  );
});

test("unknown OLDER version fails closed with its own distinguishable reason", async () => {
  const bytes = await capsuleDeclaringVersion("0.1");
  await assert.rejects(
    () => CapsuleReader.fromBytes(bytes),
    (err) => /older than any version this verifier supports/.test(err.message),
  );
  const result = await verifyCapsule(bytes);
  assert.equal(result.ok, false);
  assert.equal(result.formatVersion.observed, "0.1");
  assert.equal(result.formatVersion.status, "unknown_older");
  assert.ok(
    result.errors.some((e) => e.includes("older than any version this verifier supports")),
  );
});

test("a version that is not <major>.<minor> is malformed, not a support gap", async () => {
  const bytes = await capsuleDeclaringVersion("banana");
  await assert.rejects(
    () => CapsuleReader.fromBytes(bytes),
    (err) => /^manifest\.format\.version/.test(err.message),
    "grammar violations are shape errors (invalid_manifest_shape), not version-support gaps",
  );
  const result = await verifyCapsule(bytes);
  assert.equal(result.ok, false);
  assert.equal(result.formatVersion.status, "invalid");
  assert.equal(result.formatVersion.observed, "banana");
});

test("an unknown envelope.version is refused with the same diagnosis class", async () => {
  const bytes = await capsuleDeclaringVersion("0.6", { envelopeVersion: "9.9" });
  await assert.rejects(
    () => CapsuleReader.fromBytes(bytes),
    (err) =>
      /envelope\.version/.test(err.message) &&
      /newer than this verifier supports/.test(err.message),
  );
  const result = await verifyCapsule(bytes);
  assert.equal(result.ok, false);
});

test("host policy: the SDK reports acceptance against a declared range, never decides", async () => {
  const { bytes, keys } = await sealedCurrentCapsule();
  const accepted = await verifyCapsule(bytes, {
    allowlist: [keys.publicKeyHex],
    acceptVersions: [CURRENT_VERSION],
  });
  assert.equal(accepted.ok, true);
  assert.equal(accepted.formatVersion.acceptedByPolicy, true);

  const rejected = await verifyCapsule(bytes, {
    allowlist: [keys.publicKeyHex],
    acceptVersions: ["0.6"],
  });
  // Integrity is intact — ok stays true. The policy verdict is REPORTED;
  // the host decides what to do with it, exactly as with allowlists.
  assert.equal(rejected.ok, true);
  assert.equal(rejected.formatVersion.acceptedByPolicy, false);
  assert.ok(
    rejected.notes.some((n) => n.includes("accepted")),
    `a PASS outside the declared range must not be silent: ${rejected.notes.join("; ")}`,
  );
});

test("domain-separation strings are keyed by the declared version, deliberately", () => {
  assert.equal(KNOWN_VERSIONS.includes(CURRENT_VERSION), true);
  assert.equal(
    Buffer.from(idDomain("0.6")).toString("latin1"),
    "capsule-id-v0.6\x00",
  );
  assert.equal(
    Buffer.from(idDomain("0.7")).toString("latin1"),
    "capsule-id-v0.7\x00",
  );
  assert.equal(
    Buffer.from(provenanceDomain("0.7", "notary")).toString("latin1"),
    "capsule-provenance-v0.7:notary\x00",
  );
  assert.equal(
    Buffer.from(keyWrapInfo("0.7")).toString("latin1"),
    "capsule-key-wrap-v0.7",
  );
  // computeCapsuleId is version-keyed: same inputs, different era, a
  // different identity — retaining old domains forever is what keeps a
  // v0.6 capsule verifiable after the bump.
  const pub = new Uint8Array(32).fill(7);
  const feh = "ab".repeat(32);
  assert.notEqual(computeCapsuleId(pub, feh, "0.6"), computeCapsuleId(pub, feh, "0.7"));
  // The default is the CURRENT sealing version.
  assert.equal(computeCapsuleId(pub, feh), computeCapsuleId(pub, feh, CURRENT_VERSION));
});

test("classifyVersion: grammar, ordering, and the closed status vocabulary", () => {
  assert.deepEqual(classifyVersion("0.6"), { observed: "0.6", status: "known" });
  assert.deepEqual(classifyVersion("9.9"), { observed: "9.9", status: "unknown_newer" });
  assert.deepEqual(classifyVersion("0.1"), { observed: "0.1", status: "unknown_older" });
  assert.deepEqual(classifyVersion("1.0"), { observed: "1.0", status: "unknown_newer" });
  // Numeric ordering, not lexicographic: 0.10 > 0.6.
  assert.deepEqual(classifyVersion("0.10"), { observed: "0.10", status: "unknown_newer" });
  assert.deepEqual(classifyVersion("banana"), { observed: "banana", status: "invalid" });
  assert.deepEqual(classifyVersion("0.6.1"), { observed: "0.6.1", status: "invalid" });
  assert.deepEqual(classifyVersion("06.1"), { observed: "06.1", status: "invalid" });
  assert.deepEqual(classifyVersion(null), { observed: null, status: "invalid" });
  assert.deepEqual(classifyVersion(6), { observed: null, status: "invalid" });
});
