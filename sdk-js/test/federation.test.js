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
function makeClerkInstance() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = "clerk-key-abc";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
  const jwks = { keys: [jwk] };
  function mintJwt(claims) {
    const header = b64u(JSON.stringify({ alg: "ES256", typ: "JWT", kid }));
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
  });
  assert.equal(res.ok, true, JSON.stringify(res.errors));
  assert.equal(res.subject.clerk_user_id, "user_1");
  assert.equal(res.subject.org_role, "admin");
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
  const res = verifyIdentityAttestation(att, { trustRoots, now: new Date(TS) });
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
  const res = verifyIdentityAttestation(att, { trustRoots, now: new Date("2026-06-01T00:00:00Z") });
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
  const res = verifyIdentityAttestation(att, { trustRoots: { keys: [] }, now: new Date(TS) });
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
    iat: nowSec,
    exp: nowSec + 3600,
  });
  const ok = verifyJwt(jwt, { trustRoots: clerk.jwks, now: new Date(TS), issuer: "https://clerk.acme.example" });
  assert.equal(ok.ok, true, JSON.stringify(ok.errors));
  assert.equal(ok.claims.sub, "user_42");

  // Tampered payload → signature fails.
  const [h, p, s] = jwt.split(".");
  const badPayload = b64u(JSON.stringify({ iss: "https://clerk.acme.example", sub: "user_ADMIN", iat: nowSec, exp: nowSec + 3600 }));
  const bad = verifyJwt(`${h}.${badPayload}.${s}`, { trustRoots: clerk.jwks, now: new Date(TS) });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some((e) => e.includes("signature invalid")));

  // Expired.
  const expired = clerk.mintJwt({ iss: "x", sub: "u", iat: nowSec - 7200, exp: nowSec - 3600 });
  const exp = verifyJwt(expired, { trustRoots: clerk.jwks, now: new Date(TS) });
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
    iat: nowSec, exp: nowSec + 3600,
    cap: { capsule_id: capsuleId, signer_public_key: signer.publicKeyHex, signer_role: "originator" },
  });
  const att = { typ: "capsule-identity-attestation", spec_version: "0.6", alg: "ES256", issuer: "https://clerk.acme.example", jwt };
  const res = verifyIdentityAttestation(att, {
    trustRoots: clerk.jwks, now: new Date(TS), capsuleId, signerPublicKeyHex: signer.publicKeyHex,
  });
  assert.equal(res.ok, true, JSON.stringify(res.errors));
  assert.equal(res.subject.clerk_user_id, "user_42");
  assert.equal(res.subject.org_role, "admin");
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
