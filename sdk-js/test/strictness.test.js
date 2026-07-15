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
  env.version = "0.7";
  files.set("provenance/envelope.json", Buffer.from(JSON.stringify(env, null, 2), "utf8"));
  const tampered = await packZip(files);
  await assert.rejects(
    () => CapsuleReader.fromBytes(tampered),
    /envelope\.version/,
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

test("unpackZip rejects ZIP64 sentinel EOCD", async () => {
  const { writeRawZip } = await import("../tools/rawzip.mjs");
  const bytes = writeRawZip([{ name: "a.txt", data: "a" }]);
  // Forge the EOCD total-entry count to the ZIP64 sentinel 0xFFFF.
  bytes.writeUInt16LE(0xffff, bytes.length - 22 + 10);
  await assert.rejects(() => unpackZip(bytes), /ZIP64/);
});
