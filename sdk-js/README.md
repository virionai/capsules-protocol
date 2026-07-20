# @capsule/sdk-v0.6-prototype

Reference JavaScript SDK for Capsule v0.6 — a portable, signed,
verifiable file format for units of AI-assisted work. A `.capsule` is a
deterministic ZIP carrying a document (`program.md`), its participants,
and a hash-chained, Ed25519-signed audit trail that anyone can verify
offline.

Prototype, not production. See [../spec/](../spec/) for the protocol and
[../README.md](../README.md) for the design rationale.

## Add it to your app

Not yet published to npm. Install from a checkout of this repository:

```sh
npm install /path/to/capsules-protocol/sdk-js
# or, in package.json:
#   "@capsule/sdk-v0.6-prototype": "file:../capsules-protocol/sdk-js"
```

Requirements: Node.js >= 20, ESM (`import`). Crypto is Node's built-in
`node:crypto` (Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305,
SHA-256) — no native modules; the only dependencies are
[`canonicalize`](https://www.npmjs.com/package/canonicalize) (RFC 8785)
and [`jszip`](https://www.npmjs.com/package/jszip). Node-only for now
(browser support would need a WebCrypto backend).

TypeScript declarations ship with the package (`src/index.d.ts`) — you
get autocomplete and checked options with no extra setup.

## Quickstart

Create, save, verify, and read a capsule in ~20 lines. This exact code
runs in CI as [`examples/quickstart/`](../examples/quickstart/), so it
cannot silently rot:

```js
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
console.log("program:", reader.program());
for (const event of reader.events()) {
  console.log(`event ${event.seq}: ${event.actor} ${event.action}`);
}
```

Sensible defaults keep the happy path short: `seal()` timestamps with
now (pass `signedAt` for reproducible builds), events default to
`kind: "observation"` / `target: "capsule"`, a signer's role defaults to
`"originator"`, and `verifyCapsule(bytes)` on unopenable input returns a
fail-closed result (`ok: false`) instead of throwing.

## Keys: hex or bytes, your choice

Every place the API takes a key accepts either a hex string (any case)
or 32 raw bytes — including the keypair objects from
`generateEd25519()` / `generateX25519()` as-is:

```js
const keys = generateEd25519();
// keys = { publicKey: Uint8Array, privateKey: Uint8Array,
//          publicKeyHex: string,  privateKeyHex: string }

new CapsuleBuilder({ originator: keys });          // keypair object
new CapsuleBuilder({ originator: { publicKey: "b440d9e6..." } }); // hex
builder.seal({ signers: keys });                   // role defaults to "originator"
builder.seal({ signers: [{ role: "reviewer", publicKey: hexPub, privateKey: hexPriv }] });
verifyCapsule(bytes, { allowlist: [keys.publicKey] });    // bytes
verifyCapsule(bytes, { allowlist: [keys.publicKeyHex] }); // hex
```

The wire format stays lowercase hex regardless of input form.

Persist the private key (e.g. `keys.privateKeyHex`) in your secret
store; publish the public key to whoever needs to verify your capsules.
Their allowlist of accepted public keys is a *trust policy*, not
cryptography — `result.ok` says the math checks out; `trusted` /
`trustedSignerCount` say the signer is one you accept (see
[../spec/trust.md](../spec/trust.md)).

## Verify

```js
const result = await verifyCapsule(bytesOrReader, { allowlist: [pubKey] });
// result = {
//   ok: true,                 // all integrity checks passed
//   level: "L2",              // L2 = as-is; L3 = decrypted inner content
//   errors: [],
//   chain: { ok, errors[] },          // hash-chained event log
//   contentIndex: { ok, errors[] },   // per-file hashes
//   envelope: { ok, signers: [{ role, public_key, valid, trusted }] },
//   trustedSignerCount: 1,    // valid AND on your allowlist
//   notes: [],
// }
```

Treat a capsule as good when `result.ok && result.trustedSignerCount >= 1`
(or your own stricter policy). Malformed or tampered bytes — including
containers that cannot even be opened — come back `ok: false`.

## Read

```js
const reader = await CapsuleReader.fromBytes(bytes);
reader.manifest();     // identity, participants, content index
reader.program();      // program.md text
reader.agents();       // agents.md text (or null)
reader.events();       // verified-format chain events
reader.skills();       // Map<id, { json, markdown, trust }>
reader.envelope();     // signatures + committed hashes
reader.isEncrypted();
```

Note: `reader.events()` parses the chain; it does not verify it. Always
gate display/consumption on `verifyCapsule` first, and treat narrative
payload fields listed in `untrusted_payload_fields` as untrusted content.

## Encrypt for specific recipients

Pass `recipients` at seal time to encrypt the capsule body
(ChaCha20-Poly1305; per-recipient X25519 key wrap). Anyone can still
verify the outer signatures (L2); only recipients can decrypt and fully
verify the content (L3):

```js
import { generateX25519 } from "@capsule/sdk-v0.6-prototype";

const recipient = generateX25519(); // recipient generates; shares publicKeyHex

const bytes = await builder.seal({
  signers: keys,
  recipients: [recipient.publicKeyHex], // hex, bytes, {publicKey}, or keypair
});

// Recipient side:
const outer = await CapsuleReader.fromBytes(bytes);
const l2 = await verifyCapsule(outer, { allowlist: [keys.publicKeyHex] }); // no key needed
const inner = await outer.decrypt(recipient); // keypair object works as-is
const l3 = await verifyCapsule(inner, {
  allowlist: [keys.publicKeyHex],
  outerEnvelope: outer.envelope(),
});
```

## Going further

- `builder.setAgents(md)` — who may do what, carried with the work
- `builder.addPayload("payload/data.json", bytes)` — arbitrary attachments,
  bound by the content index
- `builder.addSkill(id, { json, markdown, signed })` — portable skills
- `builder.previewCapsuleId()` — know the capsule id before sealing
- `builder.appendEvent(e, { pith: false })` — skip payload normalization
- CLI: [`../cli/`](../cli/) (`capsule verify`, `capsule inspect`, ...)
- Full surface: [`src/index.d.ts`](src/index.d.ts); protocol details:
  [`../spec/`](../spec/)

## Test

```sh
npm test
```

The suite covers chain hashing, envelope signing, content index, plain
seal/read/verify, encrypted seal/decrypt/verify, container strictness
(duplicate/compressed/symlink/unsafe entries), tamper variants, and the
quickstart developer-experience path.
