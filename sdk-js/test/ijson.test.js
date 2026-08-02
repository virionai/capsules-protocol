// I-JSON acceptance boundary (spec/canonicalization.md).
//
// RFC 8785 is only defined over I-JSON input. The `canonicalize` package
// enforces neither the number nor the string half of that, so without an
// explicit guard the reference builder seals capsules that sdk-py and
// verifier-rust cannot recompute.

import { test } from "node:test";
import assert from "node:assert/strict";

import { assertIJson, jcs } from "../src/canonical.js";
import { CapsuleBuilder, generateEd25519 } from "../src/index.js";

const TS = "2026-05-07T12:00:00Z";

test("jcs rejects a plain integer literal outside the IEEE-754 exact range", () => {
  // Date.now() * 1e6 — a nanosecond timestamp, ~1.7e18, entirely plausible.
  assert.throws(() => jcs({ ts_ns: 1.7e18 }), /integer outside IEEE-754 exact range/);
  // 1e19 serializes as the 20-digit literal 10000000000000000000.
  assert.throws(() => jcs(1e19), /integer outside IEEE-754 exact range/);
  // 2^53 itself is one past the exact range.
  assert.throws(() => jcs(9007199254740992), /integer outside IEEE-754 exact range/);
});

test("jcs accepts the exact-range boundary and exponent-form magnitudes", () => {
  assert.equal(Buffer.from(jcs(9007199254740991)).toString("utf8"), "9007199254740991");
  assert.equal(Buffer.from(jcs(-9007199254740991)).toString("utf8"), "-9007199254740991");
  // >= 1e21 serializes in exponent form, which round-trips through every
  // lane's double path.
  assert.equal(Buffer.from(jcs(1e21)).toString("utf8"), "1e+21");
  assert.equal(Buffer.from(jcs(1.5)).toString("utf8"), "1.5");
});

test("jcs rejects unpaired surrogates in values and in keys", () => {
  assert.throws(() => jcs({ summary: "a\ud83d" }), /unpaired surrogate U\+D83D/);
  assert.throws(() => jcs({ summary: "\udc00b" }), /unpaired surrogate U\+DC00/);
  assert.throws(() => jcs({ "k\ud800": 1 }), /unpaired surrogate U\+D800/);
  assert.throws(() => jcs(["ok", "x\udfff"]), /unpaired surrogate U\+DFFF/);
});

test("jcs accepts well-formed astral characters", () => {
  assert.equal(Buffer.from(jcs({ s: "a\u{1F642}" })).toString("utf8"), '{"s":"a\u{1F642}"}');
});

test("assertIJson names the offending path", () => {
  assert.throws(
    () => assertIJson({ payload: { open_items: [{ item: "x\ud83d" }] } }),
    /at \$\.payload\.open_items\[0\]\.item/,
  );
});

test("jcs still rejects non-finite numbers", () => {
  assert.throws(() => jcs(Number.NaN), /non-finite number/);
  assert.throws(() => jcs(Number.POSITIVE_INFINITY), /non-finite number/);
});

test("appendEvent rejects an out-of-range integer before the capsule is sealed", () => {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  assert.throws(
    () =>
      builder.appendEvent({
        actor: "human:alice",
        action: "note",
        payload: { ts_ns: 1.7e18 },
      }),
    /appendEvent: JCS: integer outside IEEE-754 exact range .* at event\[0\]\.payload\.ts_ns/,
  );
});

test("appendEvent rejects an unpaired surrogate before the capsule is sealed", () => {
  const ed = generateEd25519();
  const builder = new CapsuleBuilder({
    originator: { publicKey: ed.publicKeyHex },
    participants: [{ actor_id: "human:alice", role: "originator" }],
    createdAt: TS,
  });
  assert.throws(
    () =>
      builder.appendEvent(
        { actor: "human:alice", action: "note", payload: { note: "x\ud83d" } },
        { pith: false },
      ),
    /appendEvent: JCS: unpaired surrogate U\+D83D at event\[0\]\.payload\.note/,
  );
});
