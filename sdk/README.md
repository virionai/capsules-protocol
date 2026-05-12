# @capsule/sdk-v0.6-prototype

Reference JavaScript SDK for the Capsule v0.6 redesign. Prototype, not
production. See [../spec/](../spec/) for the protocol and
[../README.md](../README.md) for the design rationale.

## Install

```sh
npm install
```

Two runtime dependencies:

- [`canonicalize`](https://www.npmjs.com/package/canonicalize) — RFC
  8785 reference implementation. Replaces the prior in-house JCS.
- [`jszip`](https://www.npmjs.com/package/jszip) — vetted ZIP library.
  Replaces the prior custom deterministic ZIP_STORED writer.

Crypto is Node's built-in `node:crypto` module: Ed25519, X25519,
HKDF-SHA256, ChaCha20-Poly1305, SHA-256.

## Surface

```js
import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
  generateX25519,
} from "@capsule/sdk-v0.6-prototype";
```

### Build

```js
const originator = generateEd25519();
const builder = new CapsuleBuilder({
  originator: { publicKey: originator.publicKeyHex, label: "Acme" },
  participants: [
    { actor_id: "human:alice", role: "originator", label: "Alice" },
    { actor_id: "ai:claude", role: "advisor", label: "AI" },
  ],
});

builder.setProgram("# Loan Application\n...\n");
builder.setAgents("# Agents\n...\n");
builder.addSkill("intake", {
  json: { id: "intake", description: "intake routine" },
  markdown: "# Intake\n...",
  signed: true,
});
builder.addPayload("payload/data.json", new TextEncoder().encode("{}"));

await builder.appendEvent({
  actor: "human:alice",
  kind: "decision",
  action: "started_application",
  target: "program.md",
  payload: { note: "began application" },
});

const bytes = await builder.seal({
  signers: [
    { role: "originator", publicKey: originator.publicKey, privateKey: originator.privateKey },
  ],
  signedAt: "2026-05-07T12:00:00Z",
});

await fs.writeFile("acme.capsule", bytes);
```

### Read

```js
const reader = await CapsuleReader.fromBytes(await fs.readFile("acme.capsule"));
reader.manifest();
reader.program();
reader.agents();
reader.events();
reader.skills();
reader.envelope();
reader.isEncrypted();
```

### Verify

```js
const result = await verifyCapsule(reader, { allowlist: [originator.publicKeyHex] });
// result = {
//   ok: true,
//   level: "L2",
//   chain: { ok, errors[] },
//   contentIndex: { ok, errors[] },
//   envelope: { ok, signers: [{ role, public_key, valid, trusted }] },
//   trustedSignerCount: 1,
//   notes: [],
// }
```

### Encrypt

```js
const recipient = generateX25519();

const bytes = await builder.seal({
  signers: [...],
  recipients: [{ publicKey: recipient.publicKey }],
  signedAt: "...",
});

// Reader on encrypted bytes — outer layer only
const outerReader = await CapsuleReader.fromBytes(bytes);
outerReader.isEncrypted(); // true
outerReader.encryptedBlobHash();

// L2 verify (no key needed)
await verifyCapsule(outerReader, { allowlist: [...] });

// Decrypt → inner reader
const innerReader = await outerReader.decrypt({
  recipientPublicKey: recipient.publicKey,
  recipientPrivateKey: recipient.privateKey,
});

// L3 verify against the outer envelope
await verifyCapsule(innerReader, { allowlist: [...], outerEnvelope: outerReader.envelope() });
```

## Test

```sh
npm test
```

The test suite covers chain hashing, envelope signing, content index,
plain seal/read/verify, encrypted seal/decrypt/verify, and the four
tamper variants the example demo uses.
