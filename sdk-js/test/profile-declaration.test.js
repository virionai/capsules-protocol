// Profile declaration policy (spec/profiles.md).
//
// Policy under test:
//   1. ABSENCE of a declaration means the default profile v0.6-suite/1.0,
//      permanently; explicit declaration of the default is legal and
//      exactly equivalent — in both documents or, via normalization, one.
//   2. A declared (id, version) outside the table refuses at OPEN with
//      unsupported_profile — a limitation of the verifier, never a
//      defect of the capsule — and the refusal is EXCLUSIVE: the profile
//      diagnosis is the only error, every other channel fail-closed,
//      formatVersion.suite nulled (no suite fact for refused rules).
//   3. Disagreeing normalized declarations refuse with profile_mismatch
//      BEFORE any table lookup (a capsule defect: verdict "invalid").
//   4. Shape/grammar violations are MALFORMED documents, never
//      "unsupported".
//   5. The version gate runs FIRST: unknown-version capsules report the
//      declaration with profile.status "unevaluated".
//   6. Only the reserved members have force (x- members inert), and the
//      declaration is sealed bytes (stripping it post-seal is tamper).
//   7. acceptProfiles is host policy: reported, never decided.

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
  buildEnvelope,
  DEFAULT_PROFILE,
  SUPPORTED_PROFILES,
  classifyProfile,
  isValidProfileId,
  UnsupportedProfileError,
  ProfileMismatchError,
  InvalidProfileError,
} from "../src/index.js";
import { manifestBytes, manifestHash, computeCapsuleId } from "../src/manifest.js";
import { eventsToJsonl, firstAndEntryHash } from "../src/chain.js";
import { bytesToHex, concatBytes, jcs, sha256, parseJsonStrict } from "../src/canonical.js";
import { ed25519Sign, hexToBytes } from "../src/crypto.js";
import { packZip, unpackZip } from "../src/zip.js";

const TS = "2026-05-07T12:00:00Z";

/**
 * A capsule internally coherent under its declared version's DEFAULT
 * rules, carrying the given profile declarations. Hand-rolls domains so
 * the tests pin the spec's strings, not the SDK helpers.
 */
async function capsuleDeclaringProfile({
  version = "0.7",
  manifestProfile,
  envelopeProfile,
  extraManifestMembers,
} = {}) {
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
  files.set("program.md", Buffer.from("# Profile declaration\n", "utf8"));
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
  if (manifestProfile !== undefined) manifest.format.profile = manifestProfile;
  if (extraManifestMembers) Object.assign(manifest, extraManifestMembers);
  manifest.id = bytesToHex(
    sha256(
      concatBytes(
        Buffer.from(`capsule-id-v${version}\x00`, "utf8"),
        keys.publicKey,
        hexToBytes(firstEventHash),
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
  envelope.version = version;
  if (envelopeProfile !== undefined) envelope.profile = envelopeProfile;
  const { signers: _drop, ...payload } = envelope;
  const input = concatBytes(
    Buffer.from(`capsule-provenance-v${version}:originator\x00`, "utf8"),
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
  return { bytes: Buffer.from(await packZip(all)), keys };
}

const DEFAULT_DECL = { id: "v0.6-suite", version: "1.0" };
const VENDOR_DECL = { id: "x-test-kms-1", version: "1.0" };

test("the default table row is the frozen default-profile pin", () => {
  assert.deepEqual(DEFAULT_PROFILE, { id: "v0.6-suite", version: "1.0" });
  assert.ok(
    SUPPORTED_PROFILES.some(
      (p) => p.id === DEFAULT_PROFILE.id && p.version === DEFAULT_PROFILE.version,
    ),
    "the default row of every known era is always present",
  );
});

test("absence means the default profile, reported as an effective fact", async () => {
  const { bytes, keys } = await capsuleDeclaringProfile();
  const result = await verifyCapsule(bytes, { allowlist: [keys.publicKeyHex] });
  assert.equal(result.ok, true, result.errors.join("; "));
  assert.deepEqual(result.profile, {
    observed: null,
    observedVersion: null,
    declared: false,
    effective: "v0.6-suite",
    effectiveVersion: "1.0",
    supported: true,
    status: "default",
    acceptedByPolicy: null,
  });
  assert.equal(result.formatVersion.suite, "v0.6");
});

test("explicit default in both documents is exactly equivalent to absence", async () => {
  const { bytes, keys } = await capsuleDeclaringProfile({
    manifestProfile: DEFAULT_DECL,
    envelopeProfile: DEFAULT_DECL,
  });
  const result = await verifyCapsule(bytes, { allowlist: [keys.publicKeyHex] });
  assert.equal(result.ok, true, result.errors.join("; "));
  assert.equal(result.profile.declared, true);
  assert.equal(result.profile.status, "default");
  assert.equal(result.profile.effective, "v0.6-suite");
});

test("explicit default in ONE document normalizes coherently (no mismatch)", async () => {
  const { bytes, keys } = await capsuleDeclaringProfile({ manifestProfile: DEFAULT_DECL });
  const result = await verifyCapsule(bytes, { allowlist: [keys.publicKeyHex] });
  assert.equal(result.ok, true, result.errors.join("; "));
  assert.equal(result.profile.status, "default");
});

test("an unsupported profile refuses at open — a verifier limitation, not corruption", async () => {
  const { bytes } = await capsuleDeclaringProfile({
    manifestProfile: VENDOR_DECL,
    envelopeProfile: VENDOR_DECL,
  });
  await assert.rejects(
    () => CapsuleReader.fromBytes(bytes),
    (err) =>
      err instanceof UnsupportedProfileError &&
      /profile 'x-test-kms-1' version '1.0' is not supported by this verifier/.test(err.message) &&
      /limitation of the verifier, not corruption of the capsule/.test(err.message) &&
      /verify it with an implementation of that profile/.test(err.message),
  );
  const result = await verifyCapsule(bytes);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "unsupported");
  assert.equal(result.verdictReason, "unsupported_profile");
  assert.equal(result.profile.status, "unsupported");
  assert.equal(result.profile.observed, "x-test-kms-1");
  assert.equal(result.profile.observedVersion, "1.0");
  assert.equal(result.profile.effective, null);
  // Refusal exclusivity: the profile diagnosis is the ONLY error; no
  // hash/signature noise from applying rules that were refused.
  assert.equal(result.errors.length, 1);
  assert.ok(
    !/mismatch: |signature invalid/.test(result.errors[0]),
    `refusal must not read as tampering: ${result.errors[0]}`,
  );
  // Suite honesty: no suite fact for a capsule whose rules were refused.
  assert.equal(result.formatVersion.suite, null);
});

test("exact-match on the (id, version) pair — a known id with unknown version refuses", async () => {
  const { bytes } = await capsuleDeclaringProfile({
    manifestProfile: { id: "v0.6-suite", version: "9.9" },
    envelopeProfile: { id: "v0.6-suite", version: "9.9" },
  });
  const result = await verifyCapsule(bytes);
  assert.equal(result.verdict, "unsupported");
  assert.equal(result.verdictReason, "unsupported_profile");
});

test("the gate is era-keyed: a 0.6 capsule declaring a vendor profile refuses identically", async () => {
  const { bytes } = await capsuleDeclaringProfile({
    version: "0.6",
    manifestProfile: VENDOR_DECL,
    envelopeProfile: VENDOR_DECL,
  });
  const result = await verifyCapsule(bytes);
  assert.equal(result.verdict, "unsupported");
  assert.equal(result.verdictReason, "unsupported_profile");
  assert.equal(result.formatVersion.observed, "0.6");
  assert.equal(result.formatVersion.suite, null);
});

test("mismatched declarations refuse BEFORE table lookup, as a capsule defect", async () => {
  const { bytes } = await capsuleDeclaringProfile({
    manifestProfile: VENDOR_DECL,
    envelopeProfile: DEFAULT_DECL,
  });
  await assert.rejects(
    () => CapsuleReader.fromBytes(bytes),
    (err) =>
      err instanceof ProfileMismatchError &&
      /envelope\.profile does not match manifest\.format\.profile/.test(err.message) &&
      /x-test-kms-1/.test(err.message) &&
      /v0\.6-suite/.test(err.message),
    "mismatch wording must quote both normalized pairs",
  );
  const result = await verifyCapsule(bytes);
  // M2: a self-contradiction is a DEFECT of the capsule — verdict
  // invalid, no verdict_reason (that channel is reserved for verifier
  // limitations); the profile channel carries status mismatched.
  assert.equal(result.verdict, "invalid");
  assert.equal(result.verdictReason, null);
  assert.equal(result.profile.status, "mismatched");
  // Observed values on a mismatch are the MANIFEST's.
  assert.equal(result.profile.observed, "x-test-kms-1");
});

test("presence mismatch (manifest alternate, envelope silent) is the same defect", async () => {
  const { bytes } = await capsuleDeclaringProfile({ manifestProfile: VENDOR_DECL });
  const result = await verifyCapsule(bytes);
  assert.equal(result.verdict, "invalid");
  assert.equal(result.profile.status, "mismatched");
});

test("shape violations are malformed documents, never 'unsupported'", async () => {
  const cases = [
    [{ manifestProfile: null }, /manifest\.format\.profile/, /null is not a declaration/],
    [{ manifestProfile: "v0.6-suite" }, /manifest\.format\.profile/, /must be an object/],
    [
      { manifestProfile: { id: "Acme KMS!", version: "1.0" } },
      /manifest\.format\.profile\.id/,
      /profile identifier/,
    ],
    [
      { manifestProfile: { id: "v0.6-suite", version: "1.0", critical: ["id"] } },
      /manifest\.format\.profile\.critical/,
      /closed profile object/,
    ],
    [
      {
        manifestProfile: { id: "v0.6-suite", version: "1.0", params: { a: 1 } },
        envelopeProfile: { id: "v0.6-suite", version: "1.0", params: { a: 1 } },
      },
      /envelope\.profile\.params/,
      /single-sourced in manifest\.format\.profile/,
    ],
  ];
  for (const [shape, pathNeedle, wordingNeedle] of cases) {
    const { bytes } = await capsuleDeclaringProfile(shape);
    await assert.rejects(
      () => CapsuleReader.fromBytes(bytes),
      (err) =>
        err instanceof InvalidProfileError &&
        pathNeedle.test(err.message) &&
        wordingNeedle.test(err.message) &&
        !/unsupported/.test(err.message),
      `shape ${JSON.stringify(shape)} must refuse as malformed`,
    );
    const result = await verifyCapsule(bytes);
    assert.equal(result.verdict, "invalid", JSON.stringify(shape));
    assert.equal(result.profile.status, "invalid");
  }
});

test("params in the MANIFEST are legal on a well-formed declaration", async () => {
  const { bytes, keys } = await capsuleDeclaringProfile({
    manifestProfile: { id: "v0.6-suite", version: "1.0", params: { issuer: "https://x.example" } },
    envelopeProfile: DEFAULT_DECL,
  });
  const result = await verifyCapsule(bytes, { allowlist: [keys.publicKeyHex] });
  assert.equal(result.ok, true, result.errors.join("; "));
  assert.equal(result.profile.status, "default");
});

test("gate ordering: the version gate refuses first; the declaration reports unevaluated", async () => {
  const { bytes } = await capsuleDeclaringProfile({
    version: "9.9",
    manifestProfile: VENDOR_DECL,
    envelopeProfile: VENDOR_DECL,
  });
  const result = await verifyCapsule(bytes);
  assert.equal(result.verdict, "unsupported");
  assert.equal(result.verdictReason, "unsupported_version_newer");
  // The version diagnosis is the SOLE error…
  assert.equal(result.errors.length, 1);
  assert.ok(result.errors[0].includes("newer than this verifier supports"));
  // …and the profile declaration is still a reported observation.
  assert.equal(result.profile.status, "unevaluated");
  assert.equal(result.profile.observed, "x-test-kms-1");
  assert.equal(result.profile.observedVersion, "1.0");
});

test("an x- manifest member named like a profile is inert", async () => {
  const { bytes, keys } = await capsuleDeclaringProfile({
    extraManifestMembers: { "x-test-profile": { id: "x-acme-kms", version: "1.0" } },
  });
  const result = await verifyCapsule(bytes, { allowlist: [keys.publicKeyHex] });
  assert.equal(result.ok, true, result.errors.join("; "));
  assert.equal(result.profile.declared, false);
  assert.equal(result.profile.status, "default");
});

test("declarations are sealed bytes: stripping one post-seal is tamper", async () => {
  const { bytes, keys } = await capsuleDeclaringProfile({
    manifestProfile: DEFAULT_DECL,
    envelopeProfile: DEFAULT_DECL,
  });
  const files = await unpackZip(bytes);
  const manifest = parseJsonStrict(files.get("manifest.json"), "manifest.json");
  delete manifest.format.profile;
  files.set("manifest.json", manifestBytes(manifest));
  const tampered = Buffer.from(await packZip(files));
  const result = await verifyCapsule(tampered, { allowlist: [keys.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "invalid");
  assert.ok(
    result.errors.some((e) => e.includes("manifest_hash")),
    `stripping the declaration must break the manifest hash: ${result.errors.join("; ")}`,
  );
});

test("acceptProfiles is host policy: reported, never decided", async () => {
  const { bytes, keys } = await capsuleDeclaringProfile();
  const accepted = await verifyCapsule(bytes, {
    allowlist: [keys.publicKeyHex],
    acceptProfiles: ["v0.6-suite"],
  });
  assert.equal(accepted.ok, true);
  assert.equal(accepted.profile.acceptedByPolicy, true);

  const rejected = await verifyCapsule(bytes, {
    allowlist: [keys.publicKeyHex],
    acceptProfiles: ["x-acme-kms-es256"],
  });
  assert.equal(rejected.ok, true, "policy never fails an otherwise-valid capsule");
  assert.equal(rejected.profile.acceptedByPolicy, false);
  assert.ok(
    rejected.notes.some((n) => n.includes("not in the declared accepted set")),
    `a not-accepted report must not be silent: ${rejected.notes.join("; ")}`,
  );
});

test("the L3 inner capsule is gated independently (decrypt re-enters the reader)", async () => {
  // An encrypted capsule built by the SDK: both layers are default-
  // profile, and the inner reader construction inside decrypt() runs
  // the same open-stage gate — pinned here by the happy path.
  const keys = generateEd25519();
  const { generateX25519 } = await import("../src/crypto.js");
  const recipient = generateX25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: keys.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  builder.setProgram("# Encrypted profile gate\n");
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
    recipients: [recipient],
    signedAt: TS,
  });
  const reader = await CapsuleReader.fromBytes(bytes);
  const outer = await verifyCapsule(reader, { allowlist: [keys.publicKeyHex] });
  assert.equal(outer.ok, true, outer.errors.join("; "));
  assert.equal(outer.profile.status, "default");
  const inner = await reader.decrypt(recipient);
  const innerResult = await verifyCapsule(inner, {
    allowlist: [keys.publicKeyHex],
    outerEnvelope: reader.envelope(),
  });
  assert.equal(innerResult.ok, true, innerResult.errors.join("; "));
  assert.equal(innerResult.profile.status, "default");
});

test("identifier grammar: bounds, charset, and the x- vendor fence", () => {
  assert.equal(isValidProfileId("v0.6-suite"), true);
  assert.equal(isValidProfileId("x-acme-kms-es256"), true);
  assert.equal(isValidProfileId("a"), true);
  assert.equal(isValidProfileId("a".repeat(64)), true);
  assert.equal(isValidProfileId("a".repeat(65)), false, "cap is 64 bytes");
  assert.equal(isValidProfileId("Acme"), false, "lowercase only");
  assert.equal(isValidProfileId("0abc"), false, "first byte is a letter");
  assert.equal(isValidProfileId("abc-"), false, "no trailing dash");
  assert.equal(isValidProfileId("abc."), false, "no trailing dot");
  assert.equal(isValidProfileId("x-acme"), false, "x- ids are vendor-scoped x-<vendor>-<name>");
  assert.equal(isValidProfileId(""), false);
  assert.equal(isValidProfileId(null), false);
});

test("classifyProfile: the closed status vocabulary over the dyad", () => {
  assert.equal(classifyProfile(undefined, undefined).status, "default");
  assert.equal(classifyProfile(DEFAULT_DECL, undefined).status, "default");
  assert.equal(classifyProfile(undefined, DEFAULT_DECL).status, "default");
  assert.equal(classifyProfile(DEFAULT_DECL, DEFAULT_DECL).status, "default");
  assert.equal(classifyProfile(VENDOR_DECL, VENDOR_DECL).status, "unsupported");
  assert.equal(classifyProfile(VENDOR_DECL, DEFAULT_DECL).status, "mismatched");
  assert.equal(classifyProfile(VENDOR_DECL, undefined).status, "mismatched");
  assert.equal(classifyProfile(null, undefined).status, "invalid");
  assert.equal(
    classifyProfile({ id: "x-a-b", version: "1.0" }, { id: "x-a-b", version: "2.0" }).status,
    "mismatched",
  );
});
