// Strictness tests added 2026-05-12:
//   - backstop event emitted when chain is empty at seal time
//   - out-of-order chain events rejected by verifier
//   - hexToBytes rejects uppercase
//   - CapsuleReader rejects malformed manifest.id / public_key / first_event_hash
//   - CapsuleReader rejects bad envelope.version

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CapsuleBuilder,
  CapsuleReader,
  verifyCapsule,
  generateEd25519,
} from "../src/index.js";
import { hexToBytes } from "../src/canonical.js";
import { buildChainEvents, verifyChain, hashEvent } from "../src/chain.js";
import { packZip, unpackZip } from "../src/zip.js";

const TS = "2026-05-07T12:00:00Z";

function builderWithoutEvents() {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [
      { actor_id: "human:alice", role: "originator", label: "Alice" },
    ],
    createdAt: TS,
  });
  builder.setProgram("# Empty\n");
  // intentionally no appendEvent
  return { builder, ed };
}

test("backstop event is appended when chain is empty at seal time", async () => {
  const { builder, ed } = builderWithoutEvents();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const reader = await CapsuleReader.fromBytes(bytes);
  const events = reader.events();
  assert.equal(events.length, 1, "expected exactly one backstop event");
  const e = events[0];
  assert.equal(e.actor, "system:host");
  assert.equal(e.kind, "observation");
  assert.equal(e.action, "session_ended");
  assert.equal(e.target, "capsule");
  assert.equal(e.seq, 1);
  // genesis prev_hash
  assert.equal(e.prev_hash, "0".repeat(64));
  // and the capsule still verifies
  const result = await verifyCapsule(reader, { allowlist: [ed.publicKeyHex] });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
});

test("verifyChain rejects out-of-order seq", () => {
  // Hand-craft a valid 2-event chain, then swap the seq numbers on disk.
  const events = buildChainEvents([
    { actor: "human:alice", kind: "decision", action: "a", target: "t", timestamp: TS, payload: {} },
    { actor: "human:alice", kind: "decision", action: "b", target: "t", timestamp: TS, payload: {} },
  ]);
  // Swap seq numbers to simulate reordering on disk
  events[0].seq = 2;
  events[1].seq = 1;
  const result = verifyChain(events);
  assert.equal(result.ok, false);
  assert.ok(
    result.errors.some((e) => /seq/i.test(e.message)),
    `expected seq error, got: ${JSON.stringify(result.errors)}`,
  );
});

test("verifyChain rejects broken prev_hash linkage", () => {
  const events = buildChainEvents([
    { actor: "human:alice", kind: "decision", action: "a", target: "t", timestamp: TS, payload: {} },
    { actor: "human:alice", kind: "decision", action: "b", target: "t", timestamp: TS, payload: {} },
  ]);
  // Corrupt event 2's prev_hash to point at genesis instead of event 1
  events[1].prev_hash = "0".repeat(64);
  // Recompute event 2's hash to be self-consistent (so we isolate the linkage check)
  const { hash, ...rest } = events[1];
  events[1].hash = Buffer.from(hashEvent(rest)).toString("hex");
  const result = verifyChain(events);
  assert.equal(result.ok, false);
  assert.ok(
    result.errors.some((e) => /prev_hash mismatch/.test(e.message)),
    `expected prev_hash mismatch, got: ${JSON.stringify(result.errors)}`,
  );
});

test("hexToBytes rejects uppercase per spec lowercase requirement", () => {
  assert.throws(() => hexToBytes("ABCDEF0123456789"), /uppercase/i);
  assert.throws(() => hexToBytes("aBcDeF0123456789"), /uppercase/i);
  // lowercase is fine
  assert.doesNotThrow(() => hexToBytes("abcdef0123456789"));
});

test("hexToBytes rejects odd length and non-hex chars", () => {
  assert.throws(() => hexToBytes("abc"), /odd length/);
  assert.throws(() => hexToBytes("zz"), /non-hex/);
  assert.throws(() => hexToBytes(123), /expected string/);
});

test("CapsuleReader rejects malformed manifest.id at parse time", async () => {
  const { builder, ed } = (() => {
    const ed = generateEd25519();
    const b = new CapsuleBuilder({
      originator: { publicKey: ed.publicKeyHex, label: "Acme" },
      participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
      createdAt: TS,
    });
    b.setProgram("# Empty\n");
    return { builder: b, ed };
  })();
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const files = await unpackZip(bytes);
  const mf = JSON.parse(Buffer.from(files.get("manifest.json")).toString("utf8"));
  mf.id = "not-hex"; // malformed
  files.set("manifest.json", Buffer.from(JSON.stringify(mf, null, 2), "utf8"));
  const tampered = await packZip(files);
  await assert.rejects(() => CapsuleReader.fromBytes(tampered), /manifest\.id/);
});

test("CapsuleReader rejects uppercase hex in originator.public_key", async () => {
  const ed = generateEd25519();
  const b = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  b.setProgram("# Empty\n");
  const bytes = await b.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const files = await unpackZip(bytes);
  const mf = JSON.parse(Buffer.from(files.get("manifest.json")).toString("utf8"));
  mf.originator.public_key = mf.originator.public_key.toUpperCase();
  files.set("manifest.json", Buffer.from(JSON.stringify(mf, null, 2), "utf8"));
  const tampered = await packZip(files);
  await assert.rejects(
    () => CapsuleReader.fromBytes(tampered),
    /public_key.*hex/i,
  );
});

test("CapsuleReader rejects envelope with wrong version", async () => {
  const ed = generateEd25519();
  const b = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  b.setProgram("# Empty\n");
  const bytes = await b.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const files = await unpackZip(bytes);
  const env = JSON.parse(Buffer.from(files.get("provenance/envelope.json")).toString("utf8"));

  // An UNKNOWN envelope.version is refused at open (spec/versioning.md).
  env.version = "9.9";
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(env, null, 2), "utf8"));
  const unknownVersion = await packZip(files);
  await assert.rejects(
    () => CapsuleReader.fromBytes(unknownVersion),
    /envelope\.version/,
  );

  // Two KNOWN versions that DISAGREE (manifest sealed at the current
  // version, envelope claiming the previous era) leave the capsule
  // ambiguous about which rules bind it: the verifier fails closed on
  // the mismatch before applying either era's rules. Reachable only
  // now that the known table has more than one row.
  env.version = "0.6";
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(env, null, 2), "utf8"));
  const mismatched = await verifyCapsule(await packZip(files));
  assert.equal(mismatched.ok, false);
  assert.ok(
    mismatched.errors.some((e) => e.includes("does not match manifest.format.version")),
    `expected the version-mismatch diagnosis, got: ${mismatched.errors.join("; ")}`,
  );
});

// --- Container strictness over the raw central directory (2026-07-15) ---
// JSZip alone silently inflates DEFLATE entries, ignores symlink mode
// bits, and lets the last duplicate name win. unpackZip must reject all
// three before JSZip parses anything.

test("unpackZip rejects duplicate entry names", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const bytes = writeRawZip([
    { name: "program.md", data: "# first\n" },
    { name: "program.md", data: "# second\n" },
  ]);
  await assert.rejects(() => unpackZip(bytes), /duplicate entry: program\.md/);
});

test("unpackZip rejects non-STORED compression", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const bytes = writeRawZip([
    { name: "blob.bin", data: Buffer.alloc(1024, 0x41), method: 8 },
  ]);
  await assert.rejects(() => unpackZip(bytes), /only STORED supported, got method 8/);
});

test("unpackZip rejects symlink entries", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const bytes = writeRawZip([
    { name: "link", data: "target", mode: 0o120777 },
  ]);
  await assert.rejects(() => unpackZip(bytes), /symlink: link/);
});

test("unpackZip still accepts its own packZip output", async () => {
  const files = new Map([
    ["a.txt", Buffer.from("aaa")],
    ["dir/b.txt", Buffer.from("bbb")],
  ]);
  const packed = await packZip(files);
  const round = await unpackZip(packed);
  assert.deepEqual([...round.keys()], ["a.txt", "dir/b.txt"]);
});

test("unpackZip rejects an understated EOCD entry count", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const bytes = writeRawZip([
    { name: "a.txt", data: "a" },
    { name: "b.txt", data: "b" },
  ]);
  const eocd = bytes.length - 22;
  bytes.writeUInt16LE(1, eocd + 8);
  bytes.writeUInt16LE(1, eocd + 10);
  await assert.rejects(() => unpackZip(bytes), /entry count mismatch/);
});

test("unpackZip rejects a later EOCD signature hidden in a comment", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const bytes = writeRawZip([{ name: "a.txt", data: "a" }]);
  const eocd = bytes.length - 22;
  const trailingSignature = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
  bytes.writeUInt16LE(trailingSignature.length, eocd + 20);
  const forged = Buffer.concat([bytes, trailingSignature]);
  await assert.rejects(() => unpackZip(forged), /multiple end-of-central-directory records/);
});

test("unpackZip rejects ZIP64 sentinel EOCD", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const bytes = writeRawZip([{ name: "a.txt", data: "a" }]);
  // Forge the EOCD total-entry count to the ZIP64 sentinel 0xFFFF.
  bytes.writeUInt16LE(0xffff, bytes.length - 22 + 10);
  await assert.rejects(() => unpackZip(bytes), /ZIP64/);
});

// --- Configurable reader limits (finding F58) ------------------------------
// spec/format.md: "File-count and total-uncompressed-size limits are
// configurable on the reader; defaults are 10,000 entries and 1 GiB."
// The module constants are defaults, not a ceiling baked into the code.

test("unpackZip honors caller-supplied reader limits", async () => {
  const packed = await packZip(
    new Map([
      ["a.txt", Buffer.from("aaa")],
      ["b.txt", Buffer.from("bbb")],
    ]),
  );
  await assert.rejects(() => unpackZip(packed, { maxEntries: 1 }), /too many entries \(2\)/);
  await assert.rejects(
    () => unpackZip(packed, { maxTotalBytes: 4 }),
    /total-size limit exceeded/,
  );
  const ok = await unpackZip(packed, { maxEntries: 2, maxTotalBytes: 6 });
  assert.deepEqual([...ok.keys()], ["a.txt", "b.txt"]);
});

test("reader limits must be positive integers", async () => {
  const packed = await packZip(new Map([["a.txt", Buffer.from("aaa")]]));
  await assert.rejects(() => unpackZip(packed, { maxEntries: 0 }), /maxEntries must be a positive integer/);
  await assert.rejects(
    () => unpackZip(packed, { maxTotalBytes: 1.5 }),
    /maxTotalBytes must be a positive integer/,
  );
});

// --- Authoritative entry set (findings F01 / F11) --------------------------
// The raw central-directory scan is the single source of truth for which
// entries a capsule contains. JSZip derives entry.dir from the DOS directory
// attribute (node_modules/jszip/lib/zipEntry.js processAttributes) and
// re-keys entries by their LOCAL header name, so both must be pinned to the
// central directory or a signed capsule can hide a file from the JS reader
// that unzip(1) and python zipfile happily extract.

function sealedEntries(files) {
  return [...files.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, data]) => ({ name, data: Buffer.from(data) }));
}

async function sealedCapsule() {
  const ed = generateEd25519();
  const b = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex, label: "Acme" },
    participants: [{ actor_id: "human:alice", role: "originator", label: "Alice" }],
    createdAt: TS,
  });
  b.setProgram("# Program\n");
  b.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "program.md",
    timestamp: TS,
    payload: {},
  });
  const bytes = await b.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  return { bytes, ed };
}

test("a DOS-dir-bit entry cannot smuggle a file past verifyCapsule", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const { bytes, ed } = await sealedCapsule();
  const entries = sealedEntries(await unpackZip(bytes));
  // externalAttrs = 0x10 is the DOS "directory" bit. JSZip reports
  // entry.dir === true for it regardless of the name; unzip(1) and python
  // zipfile see a plain 17-byte file called smuggled.md.
  const forged = writeRawZip([
    ...entries,
    { name: "smuggled.md", data: Buffer.from("# hidden payload\n", "utf8"), dosAttrs: 0x10 },
  ]);
  await assert.rejects(
    () => unpackZip(forged),
    /directory attribute on non-directory name: smuggled\.md/,
  );
  await assert.rejects(() => CapsuleReader.fromBytes(forged), /smuggled\.md/);
  // And the capsule must never verify ok with a trusted signer.
  let verified = null;
  try {
    verified = await verifyCapsule(await CapsuleReader.fromBytes(forged), {
      allowlist: [ed.publicKeyHex],
    });
  } catch {
    verified = null;
  }
  assert.equal(verified, null, "forged capsule must not open, let alone verify");
});

test("unpackZip rejects a directory marker with nonzero size", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const forged = writeRawZip([
    { name: "a.txt", data: "a" },
    { name: "dir/", data: Buffer.from("not really a directory\n", "utf8"), dosAttrs: 0x10 },
  ]);
  await assert.rejects(() => unpackZip(forged), /directory marker with nonzero size: dir\//);
});

test("unpackZip rejects a local/central file-name mismatch", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const { bytes } = await sealedCapsule();
  const entries = sealedEntries(await unpackZip(bytes));
  // Central directory says notes.md; the local header says program.md.
  // JSZip keys zip.files by the LOCAL name, so without this check the real
  // program.md is silently replaced by the attacker's body.
  const forged = writeRawZip([
    ...entries,
    { name: "notes.md", localName: "program.md", data: Buffer.from("# EVIL\n", "utf8") },
  ]);
  await assert.rejects(
    () => unpackZip(forged),
    /local\/central name mismatch: central "notes\.md", local "program\.md"/,
  );
});

test("unpackZip rejects a local name that resolves to a third path", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const forged = writeRawZip([
    { name: "a.txt", data: "a" },
    { name: "notes.md", localName: "../../evil.md", data: "pwned\n" },
  ]);
  await assert.rejects(
    () => unpackZip(forged),
    /local\/central name mismatch: central "notes\.md", local "\.\.\/\.\.\/evil\.md"/,
  );
});
