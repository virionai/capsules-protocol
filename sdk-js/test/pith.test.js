import { test } from "node:test";
import assert from "node:assert/strict";

import {
  compressText,
  compressEventPayload,
  CapsuleBuilder,
  CapsuleReader,
  generateEd25519,
  PITH_VERSION,
} from "../src/index.js";

const TS = "2026-05-07T12:00:00Z";

test("compressText: short input passes through unchanged", () => {
  const out = compressText("Alice submitted the application.");
  assert.equal(out.text, "Alice submitted the application.");
  assert.equal(out.changed, false);
  assert.equal(out.version, PITH_VERSION);
});

test("compressText: collapses whitespace", () => {
  const out = compressText("Alice\n\n   submitted\tthe   application.");
  assert.equal(out.text, "Alice submitted the application.");
  assert.equal(out.changed, true);
});

test("compressText: keeps only first N sentences", () => {
  const four = "One. Two. Three. Four.";
  const out = compressText(four, { maxSentences: 2 });
  assert.equal(out.text, "One. Two.");
  assert.equal(out.changed, true);
});

test("compressText: truncates at word boundary with ellipsis", () => {
  const long = "a".repeat(100) + " " + "b".repeat(300);
  const out = compressText(long, { maxChars: 50 });
  assert.ok(out.text.endsWith("…"));
  assert.ok(out.text.length <= 50);
});

test("compressText: rejects non-string input", () => {
  assert.throws(() => compressText(42));
  assert.throws(() => compressText(null));
  assert.throws(() => compressText(undefined));
});

test("compressEventPayload: normalizes summary and statement", () => {
  const result = compressEventPayload({
    summary: "Alice\n\nsubmitted   the application.   Then she went home. Then more sentences. And more.",
    statement: "Approved.",
    irrelevant_id: "evt_001",
  });
  assert.match(result.summary, /Alice submitted the application/);
  assert.equal(result.statement, "Approved.");
  assert.equal(result.irrelevant_id, "evt_001");
});

test("compressEventPayload: walks open_items, decisions, milestones", () => {
  const result = compressEventPayload({
    open_items: [
      { item: "Review\n\nbacklog\titem.", priority: "high" },
      { item: "Other.", priority: "low" },
    ],
    decisions: [{ text: "Decided\n  to proceed.", id: "d1" }],
    milestones: [{ text: "Phase\n\n1 complete." }],
  });
  assert.equal(result.open_items[0].item, "Review backlog item.");
  assert.equal(result.open_items[0].priority, "high");
  assert.equal(result.decisions[0].text, "Decided to proceed.");
  assert.equal(result.milestones[0].text, "Phase 1 complete.");
});

test("compressEventPayload: leaves non-targeted fields untouched", () => {
  const before = {
    summary: "  Alice   submitted.  ",
    raw_xml: "  <root>\n  <a>1</a>\n  </root>  ", // not normalized
    hashes: ["abcd", "ef01"],
    nested: { ok: true, blob: " a   b " },
  };
  const after = compressEventPayload(before);
  assert.equal(after.summary, "Alice submitted.");
  assert.equal(after.raw_xml, "  <root>\n  <a>1</a>\n  </root>  ");
  assert.deepEqual(after.hashes, ["abcd", "ef01"]);
  assert.deepEqual(after.nested, { ok: true, blob: " a   b " });
});

test("compressEventPayload: returns a clone (does not mutate input)", () => {
  const input = { summary: "  Alice   submitted.  ", open_items: [{ item: "x" }] };
  const before = JSON.parse(JSON.stringify(input));
  compressEventPayload(input);
  assert.deepEqual(input, before);
});

test("CapsuleBuilder: pith on by default normalizes event summaries at append", async () => {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  builder.setProgram("# X");
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "x",
    timestamp: TS,
    payload: {
      summary: "Alice\n\n  submitted   the   application.\nWith\n\n  multiple   spaces.",
      raw_id: "evt_001",
    },
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const reader = await CapsuleReader.fromBytes(bytes);
  const events = reader.events();
  assert.equal(events[0].payload.summary, "Alice submitted the application. With multiple spaces.");
  assert.equal(events[0].payload.raw_id, "evt_001");
});

test("CapsuleBuilder: { pith: false } at construction disables normalization", async () => {
  const ed = generateEd25519();
  const messy = "Alice\n\n  submitted   the   application.";
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
    pith: false,
  });
  builder.setProgram("# X");
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "x",
    timestamp: TS,
    payload: { summary: messy },
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const reader = await CapsuleReader.fromBytes(bytes);
  assert.equal(reader.events()[0].payload.summary, messy);
});

test("CapsuleBuilder: { pith: false } per-event opts out for one event only", async () => {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  builder.setProgram("# X");
  builder.appendEvent(
    {
      actor: "human:alice",
      kind: "decision",
      action: "a",
      target: "x",
      timestamp: TS,
      payload: { summary: "Alice\n\nsubmitted." },
    },
    { pith: false },
  );
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "b",
    target: "x",
    timestamp: TS,
    payload: { summary: "Bob\n\napproved." },
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const events = (await CapsuleReader.fromBytes(bytes)).events();
  assert.equal(events[0].payload.summary, "Alice\n\nsubmitted.");
  assert.equal(events[1].payload.summary, "Bob approved.");
});
