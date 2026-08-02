import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
  generateX25519,
  federation,
} from "../src/index.js";

const {
  signIdentityAttestation,
  verifyIdentityAttestation,
  verifyJwt,
  resolveRecipientKeys,
  clerkRecipientDirectory,
  evaluateSignerPolicy,
} = federation;

const TS = "2026-05-07T12:00:00Z";
const AUD = "capsule-attestation";

// An issuer holding an Ed25519 trust-root key (the native ed25519-jcs profile).
function makeIssuer() {
  const ed = generateEd25519();
  const kid = "issuer-key-1";
  const trustRoots = {
    keys: [{ kid, alg: "ed25519-jcs", public_key_hex: ed.publicKeyHex }],
  };
  return { issuer: "https://capsules.acme.example", kid, ed, trustRoots };
}

// base64url without padding.
function b64u(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A mock Clerk instance: an EC P-256 signing key + JWKS, and an ES256 JWT
// minter. Faithful to how Clerk signs session/template JWTs.
function makeClerkInstance(kid = "clerk-key-abc") {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
  const jwks = { keys: [jwk] };
  // `headerKid` lets a test claim a kid it did not sign with.
  function mintJwt(claims, headerKid = kid) {
    const header = b64u(JSON.stringify({ alg: "ES256", typ: "JWT", kid: headerKid }));
    const payload = b64u(JSON.stringify(claims));
    const sig = nodeSign("sha256", Buffer.from(`${header}.${payload}`), {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    return `${header}.${payload}.${b64u(sig)}`;
  }
  return { kid, jwks, mintJwt };
}

// --------------------------------------------------------------------------
// Native ed25519-jcs attestations
// --------------------------------------------------------------------------

test("ed25519-jcs attestation signs and verifies offline with binding", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const capsuleId = "a".repeat(64);
  const att = signIdentityAttestation({
    issuer,
    kid,
    ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: capsuleId,
      signer_public_key: signer.publicKeyHex,
      signer_role: "originator",
      subject: { clerk_user_id: "user_1", clerk_org_id: "org_1", email: "a@acme.example", org_role: "admin" },
      issued_at: TS,
      expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots,
    now: new Date(TS),
    capsuleId,
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, true, JSON.stringify(res.errors));
  assert.equal(res.identity.subject.clerk_user_id, "user_1");
  assert.equal(res.identity.subject.org_role, "admin");
});

test("ed25519-jcs attestation fails when a claim is tampered", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: { org_role: "member" },
      issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  att.claims.subject.org_role = "admin"; // privilege escalation attempt
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("signature invalid")));
});

test("ed25519-jcs attestation fails when expired", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {},
      issued_at: TS, expires_at: "2026-05-08T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date("2026-06-01T00:00:00Z"),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("expired")));
});

test("ed25519-jcs attestation fails on capsule/signer binding mismatch", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {},
      issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const wrong = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS), capsuleId: "b".repeat(64),
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(wrong.ok, false);
  assert.ok(wrong.errors.some((e) => e.includes("capsule_id binding mismatch")));
});

test("attestation cannot be verified without the issuer trust root", () => {
  const { issuer, kid, ed } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots: { keys: [] }, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("no trust-root key")));
});

// --------------------------------------------------------------------------
// Clerk JWT profile
// --------------------------------------------------------------------------

test("verifyJwt validates a Clerk-style ES256 token against JWKS", () => {
  const clerk = makeClerkInstance();
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  const jwt = clerk.mintJwt({
    iss: "https://clerk.acme.example",
    sub: "user_42",
    org_id: "org_9",
    aud: AUD,
    iat: nowSec,
    exp: nowSec + 3600,
  });
  const ok = verifyJwt(jwt, {
    trustRoots: clerk.jwks, now: new Date(TS),
    issuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(ok.ok, true, JSON.stringify(ok.errors));
  assert.equal(ok.claims.sub, "user_42");

  // Tampered payload → signature fails.
  const [h, p, s] = jwt.split(".");
  const badPayload = b64u(JSON.stringify({ iss: "https://clerk.acme.example", sub: "user_ADMIN", aud: AUD, iat: nowSec, exp: nowSec + 3600 }));
  const bad = verifyJwt(`${h}.${badPayload}.${s}`, {
    trustRoots: clerk.jwks, now: new Date(TS),
    issuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some((e) => e.includes("signature invalid")));

  // Expired.
  const expired = clerk.mintJwt({
    iss: "https://clerk.acme.example", sub: "u", aud: AUD,
    iat: nowSec - 7200, exp: nowSec - 3600,
  });
  const exp = verifyJwt(expired, {
    trustRoots: clerk.jwks, now: new Date(TS),
    issuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(exp.ok, false);
  assert.ok(exp.errors.some((e) => e.includes("expired")));
});

test("verifyIdentityAttestation accepts a Clerk JWT attestation with binding", () => {
  const clerk = makeClerkInstance();
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  const jwt = clerk.mintJwt({
    iss: "https://clerk.acme.example",
    sub: "user_42", org_id: "org_9", email: "z@acme.example", org_role: "admin",
    aud: AUD, iat: nowSec, exp: nowSec + 3600,
    cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS), capsuleId, signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(res.ok, true, JSON.stringify(res.errors));
  assert.equal(res.identity.subject.clerk_user_id, "user_42");
  assert.equal(res.identity.subject.org_role, "admin");
});

// --------------------------------------------------------------------------
// Recipient key discovery for encryption (authoring time only)
// --------------------------------------------------------------------------

test("resolveRecipientKeys reads X25519 keys from a Clerk directory", async () => {
  const alice = generateX25519();
  const store = {
    "alice@acme.example": { capsule_x25519_public_key: alice.publicKeyHex },
    "org_9": {}, // published no key
  };
  const fakeClerk = { async getPublicMetadata(id) { return store[id] ?? {}; } };
  const directory = clerkRecipientDirectory(fakeClerk);
  const { resolved, missing } = await resolveRecipientKeys(directory, ["alice@acme.example", "org_9"]);
  assert.equal(resolved.length, 1);
  assert.equal(resolved[0].x25519_public_key_hex, alice.publicKeyHex);
  assert.deepEqual(missing, ["org_9"]);
});

// --------------------------------------------------------------------------
// Signer-role / quorum policy overlay
// --------------------------------------------------------------------------

test("evaluateSignerPolicy enforces role and quorum over trusted+attested signers", () => {
  const admin = "1".repeat(64);
  const reviewer = "2".repeat(64);
  const verifyResult = {
    envelope: {
      signers: [
        { public_key: admin, valid: true, trusted: true },
        { public_key: reviewer, valid: true, trusted: true },
      ],
    },
  };
  const attested = [
    { signer_public_key: admin, signer_role: "originator", subject: { org_role: "admin" } },
    { signer_public_key: reviewer, signer_role: "reviewer", subject: { org_role: "member" } },
  ];
  const ok = evaluateSignerPolicy(verifyResult, attested, {
    required: [
      { role: "originator", org_role: "admin" },
      { role: "reviewer", quorum: 1 },
    ],
  });
  assert.equal(ok.satisfied, true, JSON.stringify(ok.errors));

  const unmet = evaluateSignerPolicy(verifyResult, attested, {
    required: [{ role: "reviewer", quorum: 2 }],
  });
  assert.equal(unmet.satisfied, false);
  assert.ok(unmet.errors[0].includes("needs 2"));
});

// --------------------------------------------------------------------------
// PORTABILITY FIREWALL — the load-bearing tests
// --------------------------------------------------------------------------

function buildWithEmbeddedAttestation(issuer) {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  builder.setProgram("# Work\n");
  builder.appendEvent({ actor: "human:alice", kind: "decision", action: "approve", target: "program.md", timestamp: TS });
  // capsule_id is knowable before sealing → issuer can attest, then embed.
  const capsuleId = builder.previewCapsuleId();
  const att = signIdentityAttestation({
    issuer: issuer.issuer, kid: issuer.kid, ed25519PrivateKeyHex: issuer.ed.privateKeyHex,
    claims: {
      capsule_id: capsuleId, signer_public_key: ed.publicKeyHex, signer_role: "originator",
      subject: { clerk_user_id: "user_1", org_role: "admin" },
      issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  builder.addPayload("payload/attestations/clerk.json", Buffer.from(JSON.stringify(att), "utf8"));
  return { builder, ed, capsuleId, att };
}

test("a capsule with an embedded attestation still verifies offline with NO issuer knowledge", async () => {
  const issuer = makeIssuer();
  const { builder, ed, capsuleId } = buildWithEmbeddedAttestation(issuer);
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });

  // Core verification: no trust roots, no Clerk, no network — still ok.
  const reader = await CapsuleReader.fromBytes(bytes);
  const core = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(core.ok, true, JSON.stringify(core.errors));
  assert.equal(reader.manifest().id, capsuleId);

  // The attestation overlay verifies offline given the issuer's trust roots.
  const attBytes = reader.files_().get("payload/attestations/clerk.json");
  const embedded = JSON.parse(Buffer.from(attBytes).toString("utf8"));
  const overlay = verifyIdentityAttestation(embedded, {
    trustRoots: issuer.trustRoots, now: new Date(TS),
    capsuleId, signerPublicKeyHex: ed.publicKeyHex,
    expectedIssuer: issuer.issuer,
  });
  assert.equal(overlay.ok, true, JSON.stringify(overlay.errors));
});

test("an embedded attestation is tamper-bound by the content index", async () => {
  const issuer = makeIssuer();
  const { builder, ed } = buildWithEmbeddedAttestation(issuer);
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const { unpackZip, packZip } = await import("../src/zip.js");
  const files = await unpackZip(bytes);
  const forged = JSON.parse(Buffer.from(files.get("payload/attestations/clerk.json")).toString("utf8"));
  forged.claims.subject.org_role = "superadmin";
  files.set("payload/attestations/clerk.json", Buffer.from(JSON.stringify(forged), "utf8"));
  const tampered = await packZip(files);
  const result = await verifyCapsule(await CapsuleReader.fromBytes(tampered), { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.contentIndex.ok, false);
});

test("Clerk-directory recipients: seal encrypted, decrypt fully offline", async () => {
  // Authoring: resolve recipient X25519 key from a (fake) Clerk directory.
  const recipient = generateX25519();
  const fakeClerk = {
    async getPublicMetadata() { return { capsule_x25519_public_key: recipient.publicKeyHex }; },
  };
  const directory = clerkRecipientDirectory(fakeClerk);
  const { resolved } = await resolveRecipientKeys(directory, ["bob@acme.example"]);
  assert.equal(resolved.length, 1);

  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  builder.setProgram("# Confidential\n");
  builder.appendEvent({ actor: "human:alice", kind: "decision", action: "seal", target: "program.md", timestamp: TS });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    recipients: resolved.map((r) => ({ publicKey: Buffer.from(r.x25519_public_key_hex, "hex") })),
    signedAt: TS,
  });

  // Verification/decryption: offline, using only the recipient's local key.
  // No Clerk call happens here.
  const outer = await CapsuleReader.fromBytes(bytes);
  const l2 = await verifyCapsule(outer, { allowlist: [ed.publicKeyHex] });
  assert.equal(l2.ok, true);
  const inner = await outer.decrypt({
    recipientPublicKey: recipient.publicKey,
    recipientPrivateKey: recipient.privateKey,
  });
  assert.match(inner.program(), /Confidential/);
});

// --------------------------------------------------------------------------
// Binding is mandatory (spec/federation.md "Identity attestation")
// --------------------------------------------------------------------------

test("a validly-signed token with NO cap binding claim is rejected", () => {
  const clerk = makeClerkInstance();
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  // A raw Clerk session token: correctly signed by the instance key, but it
  // binds no capsule at all. spec/profiles/clerk.md forbids embedding one.
  const jwt = clerk.mintJwt({
    iss: "https://clerk.acme.example", sub: "user_attacker", org_id: "org_9",
    org_role: "admin", email: "e@acme.example", aud: AUD, iat: nowSec, exp: nowSec + 3600,
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS),
    capsuleId, signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(res.ok, false, "an unbound token must never verify");
  assert.ok(res.errors.some((e) => e.includes("missing required binding claim 'capsule_id'")));
  assert.ok(res.errors.some((e) => e.includes("missing required binding claim 'signer_public_key'")));
});

test("an ed25519-jcs attestation with an empty binding claim is rejected", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("missing required binding claim 'signer_role'")));
});

test("verifyIdentityAttestation refuses to run without binding options", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  assert.throws(
    () => verifyIdentityAttestation(att, { trustRoots, now: new Date(TS) }),
    /requires options\.capsuleId/,
  );
  assert.throws(
    () => verifyIdentityAttestation(att, { trustRoots, now: new Date(TS), capsuleId: "a".repeat(64) }),
    /requires options\.signerPublicKeyHex/,
  );
  assert.throws(
    () =>
      verifyIdentityAttestation(att, {
        trustRoots, now: new Date(TS),
        capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
      }),
    /requires options\.expectedIssuer/,
  );
});

test("a JWT attestation is rejected when iss is not the caller's expected issuer", () => {
  const clerk = makeClerkInstance();
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  // The attacker controls BOTH the token's `iss` and the wrapper's `issuer`.
  // Checking one against the other proves nothing.
  const jwt = clerk.mintJwt({
    iss: "https://clerk.evil.example", sub: "user_42", org_id: "org_9",
    org_role: "admin", aud: AUD, iat: nowSec, exp: nowSec + 3600,
    cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.evil.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS), capsuleId,
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("jwt: issuer mismatch")));
  assert.ok(res.errors.some((e) => e.includes("attestation issuer mismatch")));
});

test("a JWT attestation minted for another audience is rejected", () => {
  const clerk = makeClerkInstance();
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  const jwt = clerk.mintJwt({
    iss: "https://clerk.acme.example", sub: "user_42", aud: "some-other-app",
    iat: nowSec, exp: nowSec + 3600,
    cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS), capsuleId,
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("jwt: audience mismatch")));
});

test("ed25519-jcs attestation issuer must match the caller's expected issuer", () => {
  const { kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer: "https://Capsules.Acme.Example/", kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const base = {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
  };
  const wrong = verifyIdentityAttestation(att, { ...base, expectedIssuer: "other.example" });
  assert.equal(wrong.ok, false);
  assert.ok(wrong.errors.some((e) => e.includes("attestation issuer mismatch")));

  // Origin form and bare DNS form are the same issuer (federation.md).
  const right = verifyIdentityAttestation(att, { ...base, expectedIssuer: "capsules.acme.example" });
  assert.equal(right.ok, true, JSON.stringify(right.errors));
});

test("verifyJwt refuses to run without an expected issuer and audience", () => {
  const clerk = makeClerkInstance();
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  const jwt = clerk.mintJwt({ iss: "https://clerk.acme.example", sub: "u", aud: AUD, iat: nowSec, exp: nowSec + 3600 });
  assert.throws(() => verifyJwt(jwt, { trustRoots: clerk.jwks, now: new Date(TS) }), /requires an expected issuer/);
  assert.throws(
    () => verifyJwt(jwt, { trustRoots: clerk.jwks, now: new Date(TS), issuer: "https://clerk.acme.example" }),
    /requires an expected audience/,
  );
});

// --------------------------------------------------------------------------
// Timestamps are strict: unparseable or absent expiry is a rejection
// --------------------------------------------------------------------------

test("an unparseable expires_at is an error, not an absent expiry", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {},
      issued_at: TS, expires_at: "whenever",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false, "NaN must never read as 'never expires'");
  assert.ok(res.errors.some((e) => e.includes("expires_at is not an RFC 3339 instant")));
});

test("an unparseable issued_at is an error, not an absent freshness check", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {},
      issued_at: "2026-13-45T99:99:99Z", expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("issued_at is not an RFC 3339 instant")));
});

test("an attestation with no expiry is rejected", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS,
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("missing required claim 'expires_at'")));
});

test("a JWT attestation with a garbage exp is rejected, not crashed on", () => {
  const clerk = makeClerkInstance();
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  // A validly-signed token whose exp is not a number: previously the
  // claims projection threw a RangeError from Date#toISOString.
  const jwt = clerk.mintJwt({
    iss: "https://clerk.acme.example", sub: "user_42", aud: AUD,
    iat: nowSec, exp: "never",
    cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS), capsuleId,
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("expires_at is not an RFC 3339 instant")));
});

// --------------------------------------------------------------------------
// Key selection fails closed (spec/profiles/clerk.md "kid selects the key")
// --------------------------------------------------------------------------

test("an unknown kid fails closed instead of trying every cached key", () => {
  const clerkA = makeClerkInstance("clerk-key-A");
  const clerkB = makeClerkInstance("clerk-key-B");
  // One cached JWKS holding two keys, as a host that refreshes a multi-key
  // (or multi-issuer) set would have.
  const cached = { keys: [...clerkA.jwks.keys, ...clerkB.jwks.keys] };
  const signer = generateEd25519();
  const capsuleId = "c".repeat(64);
  const nowSec = Math.floor(Date.parse(TS) / 1000);
  const jwt = clerkA.mintJwt(
    {
      iss: "https://clerk.acme.example", sub: "user_42", org_role: "admin",
      aud: AUD, iat: nowSec, exp: nowSec + 3600,
      cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
    },
    "rotated-out-99", // a kid that is NOT in the cached set
  );
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: cached, now: new Date(TS), capsuleId,
    signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: "https://clerk.acme.example", audience: AUD,
  });
  assert.equal(res.ok, false, "kid selects the key; an unknown kid resolves to nothing");
  assert.ok(res.errors.some((e) => e.includes("no trust-root key for kid=rotated-out-99")));
});

test("ed25519-jcs: an unknown kid does not fall back to another issuer's key", () => {
  const a = makeIssuer();
  const b = makeIssuer();
  const cached = { keys: [...a.trustRoots.keys, { ...b.trustRoots.keys[0], kid: "issuer-key-2" }] };
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer: a.issuer, kid: "issuer-key-retired", ed25519PrivateKeyHex: a.ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots: cached, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: a.issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("no trust-root key for kid=issuer-key-retired")));
});

// --------------------------------------------------------------------------
// Native trust roots published as standard JWKs (RFC 8037 OKP)
// --------------------------------------------------------------------------

test("a native trust root published as a standard Ed25519 OKP JWK is consumable", () => {
  const { issuer, kid, ed } = makeIssuer();
  const signer = generateEd25519();
  // What loadTrustRoots() hands back when a conforming issuer publishes its
  // native attestation key as an RFC 8037 OKP JWK.
  const jwks = {
    keys: [
      {
        kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", kid,
        x: Buffer.from(ed.publicKeyHex, "hex").toString("base64url"),
      },
    ],
  };
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: { clerk_user_id: "user_1" },
      issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots: jwks, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, true, JSON.stringify(res.errors));
  assert.equal(res.identity.subject.clerk_user_id, "user_1");
});

test("an X25519 OKP JWK is never usable as an attestation key", () => {
  const { issuer, kid, ed } = makeIssuer();
  const signer = generateEd25519();
  const jwks = {
    keys: [
      {
        kty: "OKP", crv: "X25519", kid,
        x: Buffer.from(ed.publicKeyHex, "hex").toString("base64url"),
      },
    ],
  };
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const res = verifyIdentityAttestation(att, {
    trustRoots: jwks, now: new Date(TS),
    capsuleId: "a".repeat(64), signerPublicKeyHex: signer.publicKeyHex,
    expectedIssuer: issuer,
  });
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => e.includes("no trust-root key")));
});

// --------------------------------------------------------------------------
// Machine-readable outcomes (spec/federation.md "Failure reporting") and the
// nesting rule: identity never travels without its verification basis
// --------------------------------------------------------------------------

test("status distinguishes unverified (unknown) from rejected (negative)", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: {}, issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const base = {
    now: new Date(TS), capsuleId: "a".repeat(64),
    signerPublicKeyHex: signer.publicKeyHex, expectedIssuer: issuer,
  };

  // Trust roots present and everything checks out.
  const good = verifyIdentityAttestation(att, { ...base, trustRoots });
  assert.equal(good.ok, true, JSON.stringify(good.errors));
  assert.equal(good.status, "attestation_verified");

  // No trust roots cached: UNKNOWN, not negative (federation.md).
  const unknown = verifyIdentityAttestation(att, { ...base, trustRoots: { keys: [] } });
  assert.equal(unknown.ok, false);
  assert.equal(unknown.status, "attestation_unverified");

  // Trust roots present, binding does not match: STRONG NEGATIVE.
  const rejected = verifyIdentityAttestation(att, {
    ...base, trustRoots, capsuleId: "b".repeat(64),
  });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.status, "attestation_rejected");
});

test("a malformed attestation reports attestation_rejected", () => {
  const res = verifyIdentityAttestation(
    { typ: "something-else" },
    {
      capsuleId: "a".repeat(64), signerPublicKeyHex: "0".repeat(64),
      expectedIssuer: "capsules.acme.example",
    },
  );
  assert.equal(res.ok, false);
  assert.equal(res.status, "attestation_rejected");
});

test("subject identity is nested under its basis and absent unless verified", () => {
  const { issuer, kid, ed, trustRoots } = makeIssuer();
  const signer = generateEd25519();
  const att = signIdentityAttestation({
    issuer, kid, ed25519PrivateKeyHex: ed.privateKeyHex,
    claims: {
      capsule_id: "a".repeat(64), signer_public_key: signer.publicKeyHex,
      signer_role: "originator", subject: { clerk_user_id: "user_1", org_role: "admin" },
      issued_at: TS, expires_at: "2027-05-07T12:00:00Z",
    },
  });
  const base = {
    now: new Date(TS), capsuleId: "a".repeat(64),
    signerPublicKeyHex: signer.publicKeyHex, expectedIssuer: issuer,
  };

  // Verified: the subject is reachable ONLY through `identity`, which
  // carries its own basis, so the claim can never travel without it.
  const good = verifyIdentityAttestation(att, { ...base, trustRoots });
  assert.equal(good.identity.status, "attestation_verified");
  assert.equal(good.identity.subject.clerk_user_id, "user_1");
  assert.equal(good.identity.claims.signer_role, "originator");
  assert.ok(!("subject" in good), "subject must not be a skippable sibling of ok");
  assert.ok(!("claims" in good), "claims must not be a skippable sibling of ok");

  // Unverified (no trust roots): there is no verified identity to read.
  const unknown = verifyIdentityAttestation(att, { ...base, trustRoots: { keys: [] } });
  assert.equal(unknown.identity, null);

  // Rejected (signature tampered): there is no verified identity to read.
  const forged = structuredClone(att);
  forged.claims.subject.org_role = "superadmin";
  const rejected = verifyIdentityAttestation(forged, { ...base, trustRoots });
  assert.equal(rejected.status, "attestation_rejected");
  assert.equal(rejected.identity, null);
});
