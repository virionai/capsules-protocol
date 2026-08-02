// Totality tests added 2026-08-02:
//   - CapsuleReader rejects a malformed manifest.content_index at parse time
//   - verifyChain reports non-canonical stored hex instead of throwing
//   - verifyCapsule converts any unexpected throw into the documented
//     fail-closed result
//   - an invalid envelope signature produces a displayable error

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
} from "../src/index.js";
import { verifyChain } from "../src/chain.js";
import { packZip, unpackZip } from "../src/zip.js";

const TS = "2026-05-07T12:00:00Z";

async function sealedCapsule() {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  builder.setProgram("# Program\n");
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "approved",
    target: "program.md",
    timestamp: TS,
    payload: {},
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  return { bytes, ed };
}

async function repack(bytes, mutate) {
  const files = await unpackZip(bytes);
  mutate(files);
  return await packZip(files);
}

function editManifest(files, mutate) {
  const mf = JSON.parse(Buffer.from(files.get("manifest.json")).toString("utf8"));
  mutate(mf);
  files.set("manifest.json", Buffer.from(JSON.stringify(mf, null, 2) + "\n", "utf8"));
}

/** Every channel the VerifyResult contract promises is present and fail-closed. */
function assertFailClosedShape(result) {
  assert.equal(result.ok, false);
  assert.ok(Array.isArray(result.errors) && result.errors.length > 0);
  assert.equal(result.chain.ok, false);
  assert.ok(Array.isArray(result.chain.errors));
  assert.equal(result.contentIndex.ok, false);
  assert.ok(Array.isArray(result.contentIndex.errors));
  assert.equal(result.envelope.ok, false);
  assert.deepEqual(result.envelope.signers, []);
  assert.equal(result.signerSet.bound, false);
  assert.ok(Array.isArray(result.signerSet.errors));
  assert.equal(result.trustedSignerCount, 0);
  assert.ok(Array.isArray(result.notes));
}

test("verifyCapsule fails closed when manifest.content_index is missing", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) =>
    editManifest(files, (mf) => {
      delete mf.content_index;
    }),
  );
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assertFailClosedShape(result);
  assert.match(result.errors[0], /manifest\.content_index must be a JSON object/);
});

test("verifyCapsule fails closed when content_index.files is not an array", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) =>
    editManifest(files, (mf) => {
      mf.content_index.files = {};
    }),
  );
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assertFailClosedShape(result);
  assert.match(result.errors[0], /manifest\.content_index\.files must be an array/);
});

test("verifyCapsule fails closed when a content_index entry has no sha256", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) =>
    editManifest(files, (mf) => {
      mf.content_index.files = mf.content_index.files.map(({ path }) => ({ path }));
    }),
  );
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assertFailClosedShape(result);
  assert.match(result.errors[0], /manifest\.content_index\.files\[0\]\.sha256/);
});

test("CapsuleReader rejects a manifest that is not a JSON object", async () => {
  const { bytes } = await sealedCapsule();
  const tampered = await repack(bytes, (files) => {
    files.set("manifest.json", Buffer.from("[]", "utf8"));
  });
  await assert.rejects(
    () => CapsuleReader.fromBytes(tampered),
    /manifest\.json is not a JSON object/,
  );
});

test("verifyChain reports a non-canonical stored hash instead of throwing", () => {
  const result = verifyChain([
    { seq: 1, prev_hash: "0".repeat(64), hash: "A".repeat(64) },
  ]);
  assert.equal(result.ok, false);
  assert.ok(
    result.errors.some((e) => /hash is not canonical lowercase hex/.test(e.message)),
    `expected a canonical-hex error, got: ${JSON.stringify(result.errors)}`,
  );
});

test("verifyChain reports a non-object event instead of throwing", () => {
  const result = verifyChain([null]);
  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, [{ seq: 1, message: "event is not a JSON object" }]);
});

test("verifyCapsule fails closed on an uppercase stored event hash", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) => {
    const lines = Buffer.from(files.get("chain/events.jsonl"))
      .toString("utf8")
      .split("\n")
      .filter((l) => l.length > 0);
    const first = JSON.parse(lines[0]);
    first.hash = first.hash.toUpperCase();
    files.set(
      "chain/events.jsonl",
      Buffer.from([JSON.stringify(first), ...lines.slice(1)].join("\n") + "\n", "utf8"),
    );
  });
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.chain.ok, false);
  assert.ok(
    result.chain.errors.some((e) => /hash is not canonical lowercase hex/.test(e.message)),
    `expected a canonical-hex chain error, got: ${JSON.stringify(result.chain.errors)}`,
  );
});

test("verifyCapsule converts an unexpected throw into the fail-closed shape", async () => {
  const { bytes, ed } = await sealedCapsule();
  const reader = await CapsuleReader.fromBytes(bytes);
  // Mutate AFTER the reader's parse-time validation: only the total-function
  // wrapper stands between this and a TypeError escaping verifyCapsule.
  delete reader.manifest().content_index;
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assertFailClosedShape(result);
  assert.match(result.errors[0], /^verification failed:/);
});

test("verifyCapsule fails closed on a hostile number in an unknown manifest member", async () => {
  // 1e999 parses as Infinity; JCS rejects non-finite numbers, so the
  // manifest-hash recompute cannot succeed. It must report, not throw.
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) => {
    const text = Buffer.from(files.get("manifest.json")).toString("utf8");
    files.set("manifest.json", Buffer.from(text.replace("{", '{"x-hostile":1e999,'), "utf8"));
  });
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.ok(
    result.errors.some((e) => /manifest hash recompute failed/.test(e)),
    `expected a manifest-hash recompute error, got: ${JSON.stringify(result.errors)}`,
  );
});

test("a missing chain file produces a displayable chain error", async () => {
  const { bytes, ed } = await sealedCapsule();
  const tampered = await repack(bytes, (files) => {
    files.delete("chain/events.jsonl");
  });
  const result = await verifyCapsule(tampered, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, false);
  assert.equal(result.chain.ok, false);
  assert.ok(
    result.chain.errors.some((e) => /missing or empty/.test(e.message)),
    `expected a chain error message, got: ${JSON.stringify(result.chain.errors)}`,
  );
});

test("verifyCapsule is total over a corpus of malformed inputs", async () => {
  const { bytes, ed } = await sealedCapsule();
  const editedManifest = (mutate) => repack(bytes, (files) => editManifest(files, mutate));
  const rawManifest = (text) =>
    repack(bytes, (files) => files.set("manifest.json", Buffer.from(text, "utf8")));
  const rawChain = (text) =>
    repack(bytes, (files) => files.set("chain/events.jsonl", Buffer.from(text, "utf8")));
  const editedEnvelope = (mutate) =>
    repack(bytes, (files) => {
      const env = JSON.parse(Buffer.from(files.get("provenance/envelope.json")).toString("utf8"));
      mutate(env);
      files.set("provenance/envelope.json", Buffer.from(JSON.stringify(env, null, 2), "utf8"));
    });

  const corpus = [
    // container-level garbage
    new Uint8Array(0),
    new Uint8Array([0x50, 0x4b, 0x03, 0x04]),
    Uint8Array.from({ length: 512 }, (_, i) => (i * 37) % 256),
    bytes.slice(0, 10),
    bytes.slice(0, bytes.length - 7),
    // valid JSON, wrong shape
    await rawManifest("null"),
    await rawManifest("123"),
    await rawManifest('"str"'),
    await rawManifest("[]"),
    await rawManifest("{}"),
    await editedManifest((mf) => { mf.content_index.index_hash = 5; }),
    await editedManifest((mf) => { mf.content_index.files = [null]; }),
    await editedManifest((mf) => { mf.content_index.files = [{ path: "", sha256: "a".repeat(64) }]; }),
    // hostile numbers
    await repack(bytes, (files) => {
      const text = Buffer.from(files.get("manifest.json")).toString("utf8");
      files.set("manifest.json", Buffer.from(text.replace("{", '{"x-evil":1e999,'), "utf8"));
    }),
    await rawChain('{"seq":1,"prev_hash":"' + "0".repeat(64) + '","x":1e999}\n'),
    // malformed chain documents
    await rawChain('"not an event"\n'),
    await rawChain("[]\n"),
    await rawChain('{"seq":1,"prev_hash":"' + "Z".repeat(64) + '","hash":"' + "f".repeat(64) + '"}\n'),
    // malformed envelope signer rows
    await editedEnvelope((env) => { env.signers[0].public_key = null; }),
    await editedEnvelope((env) => { env.signers[0].signature = "zz"; }),
    await editedEnvelope((env) => { env.signers = [42]; }),
  ];

  for (const [i, input] of corpus.entries()) {
    let result;
    try {
      result = await verifyCapsule(input, { allowlist: [ed.publicKeyHex] });
    } catch (err) {
      assert.fail(`corpus[${i}] threw: ${err.message}`);
    }
    assert.equal(result.ok, false, `corpus[${i}] must fail closed`);
    assert.ok(Array.isArray(result.errors), `corpus[${i}] must report errors`);
  }
});
