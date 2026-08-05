import { test } from "node:test";
import assert from "node:assert/strict";

import {
  compressText,
  compressEventPayload,
  normalizeEventPayload,
  CapsuleBuilder,
  CapsuleReader,
  generateEd25519,
  PITH_VERSION,
} from "../src/index.js";

const TS = "2026-05-07T12:00:00Z";

// The P1 reproduction: ordinary technical prose. Three sentences, dots
// inside an identifier (ledger.entry_audit) and a decimal (12.4k). The
// v0.6 splitter treated both dots as sentence boundaries, burned the
// three-sentence budget on fragments, and silently deleted the last two
// sentences.
const WAL_PROSE =
  "ledger.entry_audit is 88% of decoded WAL volume at 610 GB and roughly " +
  "12.4k inserts per second during the settlement batch. The apply worker " +
  "is pinned at 99% of one core. This is a throughput ceiling, not a " +
  "tuning problem.";

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

// ---------- sentence-boundary fidelity (the P1 defect) ----------

test("compressText: dots inside identifiers and decimals are not sentence boundaries", () => {
  const out = compressText(WAL_PROSE);
  assert.equal(out.text, WAL_PROSE);
  assert.equal(out.changed, false);
});

test("compressText: sentence selection never shortens a decimal into a different number", () => {
  const out = compressText(
    "Pin the minor release at 14.11 or 16.4 before the batch. Then bump the fleet.",
    { maxSentences: 1 },
  );
  assert.equal(out.text, "Pin the minor release at 14.11 or 16.4 before the batch.");
});

test("compressText: a decimal at a true sentence end still ends the sentence", () => {
  const out = compressText("Latency rose to 16.4. Then it fell back. Then it held. Then flat.", {
    maxSentences: 1,
  });
  assert.equal(out.text, "Latency rose to 16.4.");
});

test("compressText: version numbers, URLs and code fragments survive sentence selection", () => {
  const input =
    "Deploy v0.7.1 from https://example.com/pkg.tar.gz using pkg.install(). " +
    "Restart the worker. Verify the ledger. Close the ticket.";
  const out = compressText(input, { maxSentences: 2 });
  assert.equal(
    out.text,
    "Deploy v0.7.1 from https://example.com/pkg.tar.gz using pkg.install(). Restart the worker.",
  );
});

test("compressText: abbreviations do not end sentences", () => {
  const out = compressText(
    "Cache invalidation is hard, e.g. Redis and Memcached disagree. Pick one store. Document it. Move on.",
    { maxSentences: 1 },
  );
  assert.equal(out.text, "Cache invalidation is hard, e.g. Redis and Memcached disagree.");
});

test("compressText: a single-letter initial does not end a sentence", () => {
  const out = compressText("Reviewed by J. Smith on Tuesday. Approved for merge. Shipped. Done.", {
    maxSentences: 1,
  });
  assert.equal(out.text, "Reviewed by J. Smith on Tuesday.");
});

test("compressText: a lowercase continuation is not a new sentence", () => {
  const out = compressText(
    "restarted the daemon. systemd reported ok. Then we rotated the logs. Then we left.",
    { maxSentences: 2 },
  );
  assert.equal(out.text, "restarted the daemon. systemd reported ok. Then we rotated the logs.");
});

test("compressText: an ellipsis run does not burn the sentence budget", () => {
  const out = compressText(
    "The import stalled... retried twice more. Second attempt cleared the queue. Backlog empty. All good.",
    { maxSentences: 2 },
  );
  assert.equal(
    out.text,
    "The import stalled... retried twice more. Second attempt cleared the queue.",
  );
});

test("compressText: a closing quote after the terminator stays with its sentence", () => {
  const out = compressText('He said "ship it." Then we shipped. Then we slept. Then coffee.', {
    maxSentences: 1,
  });
  assert.equal(out.text, 'He said "ship it."');
});

test("compressText: CJK terminators split sentences without inserting spaces", () => {
  const input = "一件目を確認した。二件目も確認した。三件目は保留。四件目は明日。";
  const out = compressText(input, { maxSentences: 2 });
  assert.equal(out.text, "一件目を確認した。二件目も確認した。");
  assert.equal(out.changed, true);
});

// ---------- normalizeEventPayload: the change report ----------

test("normalizeEventPayload: reports exactly the fields it changed", () => {
  const { payload, normalizedFields } = normalizeEventPayload({
    summary: "Alice   submitted.",
    statement: "Approved.",
    note: "First. Second. Third. Fourth.",
    open_items: [{ item: "Fix  bug." }],
    decisions: [{ text: "Proceed." }],
  });
  assert.equal(payload.summary, "Alice submitted.");
  assert.equal(payload.statement, "Approved.");
  assert.equal(payload.note, "First. Second. Third.");
  assert.equal(payload.open_items[0].item, "Fix bug.");
  assert.deepEqual(normalizedFields, ["payload.summary", "payload.note", "payload.open_items"]);
});

test("normalizeEventPayload: reports nothing when nothing changed", () => {
  const input = { summary: "Alice submitted.", raw_id: "evt_001" };
  const { payload, normalizedFields } = normalizeEventPayload(input);
  assert.deepEqual(payload, input);
  assert.deepEqual(normalizedFields, []);
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

function testBuilder(ed, options = {}) {
  return new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
    ...options,
  }).setProgram("# X");
}

async function sealAndRead(builder, ed) {
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  return (await CapsuleReader.fromBytes(bytes)).events();
}

test("CapsuleBuilder: narrative payloads pass through verbatim by default", async () => {
  const ed = generateEd25519();
  const messy = "Alice\n\n  submitted   the   application.\nWith\n\n  multiple   spaces.";
  const builder = testBuilder(ed);
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "x",
    timestamp: TS,
    payload: { summary: messy, note: WAL_PROSE, raw_id: "evt_001" },
  });
  const events = await sealAndRead(builder, ed);
  assert.equal(events[0].payload.summary, messy);
  assert.equal(events[0].payload.note, WAL_PROSE);
  assert.equal(events[0].payload.raw_id, "evt_001");
  assert.ok(!("pith_normalized_fields" in events[0]));
});

test("CapsuleBuilder: { pith: true } opts in and the event records which fields changed", async () => {
  const ed = generateEd25519();
  const builder = testBuilder(ed, { pith: true });
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "x",
    timestamp: TS,
    payload: {
      summary: "Alice\n\n  submitted   the   application.\nWith\n\n  multiple   spaces.",
      statement: "Approved.",
      raw_id: "evt_001",
    },
  });
  const events = await sealAndRead(builder, ed);
  assert.equal(events[0].payload.summary, "Alice submitted the application. With multiple spaces.");
  assert.equal(events[0].payload.statement, "Approved.");
  assert.equal(events[0].payload.raw_id, "evt_001");
  assert.deepEqual(events[0].pith_normalized_fields, ["payload.summary"]);
});

test("CapsuleBuilder: a pith-enabled event that needed no rewriting carries no marker", async () => {
  const ed = generateEd25519();
  const builder = testBuilder(ed, { pith: true });
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "x",
    timestamp: TS,
    payload: { summary: "Alice submitted the application." },
  });
  const events = await sealAndRead(builder, ed);
  assert.equal(events[0].payload.summary, "Alice submitted the application.");
  assert.ok(!("pith_normalized_fields" in events[0]));
});

test("CapsuleBuilder: per-event { pith: true } enables normalization on a default builder", async () => {
  const ed = generateEd25519();
  const builder = testBuilder(ed);
  builder.appendEvent(
    {
      actor: "human:alice",
      kind: "decision",
      action: "a",
      target: "x",
      timestamp: TS,
      payload: { summary: "Alice\n\nsubmitted." },
    },
    { pith: true },
  );
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "b",
    target: "x",
    timestamp: TS,
    payload: { summary: "Bob\n\napproved." },
  });
  const events = await sealAndRead(builder, ed);
  assert.equal(events[0].payload.summary, "Alice submitted.");
  assert.deepEqual(events[0].pith_normalized_fields, ["payload.summary"]);
  assert.equal(events[1].payload.summary, "Bob\n\napproved.");
  assert.ok(!("pith_normalized_fields" in events[1]));
});

test("CapsuleBuilder: per-event { pith: false } wins over a pith-enabled builder", async () => {
  const ed = generateEd25519();
  const builder = testBuilder(ed, { pith: true });
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
  const events = await sealAndRead(builder, ed);
  assert.equal(events[0].payload.summary, "Alice\n\nsubmitted.");
  assert.ok(!("pith_normalized_fields" in events[0]));
});

test("CapsuleBuilder: caller-declared pith_normalized_fields pass through and merge", async () => {
  const ed = generateEd25519();
  const builder = testBuilder(ed, { pith: true });
  // An author (e.g. an LLM applying Pith as practice) may declare fields
  // it normalized itself; the builder unions its own findings in.
  builder.appendEvent({
    actor: "human:alice",
    kind: "decision",
    action: "submit",
    target: "x",
    timestamp: TS,
    payload: { summary: "Alice\n\nsubmitted.", statement: "Rewritten by hand." },
    pith_normalized_fields: ["payload.statement"],
  });
  const events = await sealAndRead(builder, ed);
  assert.deepEqual(events[0].pith_normalized_fields, ["payload.statement", "payload.summary"]);
});

test("CapsuleBuilder: an out-of-grammar pith_normalized_fields entry is rejected at append", () => {
  const ed = generateEd25519();
  const builder = testBuilder(ed);
  assert.throws(
    () =>
      builder.appendEvent({
        actor: "human:alice",
        kind: "decision",
        action: "submit",
        target: "x",
        timestamp: TS,
        payload: { summary: "x" },
        pith_normalized_fields: ["not-payload.summary"],
      }),
    /pith_normalized_fields/,
  );
});

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

test("compressText: truncation never splits a surrogate pair", () => {
  // The default cut index (280 - 1 ellipsis = 279) is odd, so an all-emoji
  // string lands mid-pair without a boundary guard.
  const out = compressText("🙂".repeat(200));
  assert.ok(out.text.length <= 280);
  assert.ok(!LONE_SURROGATE.test(out.text), "output must be well-formed Unicode");
  assert.ok(out.text.endsWith("…"));
});

test("compressText: surrogate-safe at every odd and even cut index", () => {
  const input = "🙂".repeat(64);
  for (let maxChars = 2; maxChars <= 128; maxChars++) {
    const { text } = compressText(input, { maxChars });
    assert.ok(!LONE_SURROGATE.test(text), `maxChars=${maxChars} split a pair`);
    assert.ok(text.length <= maxChars, `maxChars=${maxChars} overflowed`);
  }
});

test("compressText: maxChars of 1 yields the bare ellipsis", () => {
  assert.equal(compressText("hello world", { maxChars: 1 }).text, "…");
  assert.equal(compressText("🙂🙂🙂", { maxChars: 1 }).text, "…");
});

test("CapsuleBuilder: a pith-truncated emoji summary seals and its chain bytes canonicalize", async () => {
  const ed = generateEd25519();
  // pith: true on purpose — this is the C9 truncation-path regression.
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
    pith: true,
  });
  builder.setProgram("# X");
  builder.appendEvent({
    actor: "human:alice",
    kind: "observation",
    action: "note",
    target: "x",
    timestamp: TS,
    payload: { summary: "🙂".repeat(200) },
  });
  const bytes = await builder.seal({
    signers: [{ role: "originator", publicKey: ed.publicKey, privateKey: ed.privateKey }],
    signedAt: TS,
  });
  const summary = (await CapsuleReader.fromBytes(bytes)).events()[0].payload.summary;
  assert.ok(!LONE_SURROGATE.test(summary));
});
