# Pith — Authoring-Layer Context Discipline

## What it is

Pith is the discipline by which capsule narrative fields are written so
that a cold-reading LLM can absorb the context fast and accurately.

It is an **authoring/profile layer**, not a protocol layer. Nothing in
capsule identity, hashing, signing, or verification depends on whether
narrative text was Pith-styled: cryptographic verification is
independent of lossy narrative normalization, and no conformant
verifier may treat un-Pithed prose as a defect. It is **not**
"deterministic compression" in the information-theoretic sense — the
prior format made that claim; v0.6 retracted it. The discipline is the
product. The reference normalizer is a helper.

Two forms of Pith coexist:

1. **Pith as practice** — an LLM applies the style rules below when it
   writes narrative fields. This is the high-quality path; the resulting
   compression is richer than any deterministic library can produce.
2. **Pith as normalizer** — a deterministic library function that
   guarantees fields written *without* LLM judgment still come out
   terse and regular. Whitespace collapsed, first N sentences kept,
   length-capped at a word boundary with an ellipsis when over budget.

The SDK ships the normalizer (`compressText`, `compressEventPayload`,
`normalizeEventPayload`). The discipline lives in the rules below and
in capsule authoring practice.

## The normalizer is opt-in

The reference builders apply the normalizer **only when asked**
(`pith: true`; see "Opting in" below). v0.6 applied it by default, and
that default corrupted ordinary technical prose *inside the hash
chain*, where the original is not preserved: an author who wrote

> ledger.entry_audit is 88% of decoded WAL volume at 610 GB and roughly
> 12.4k inserts per second during the settlement batch. The apply
> worker is pinned at 99% of one core. This is a throughput ceiling,
> not a tuning problem.

sealed a capsule that said

> ledger. entry_audit is 88% of decoded WAL volume at 610 GB and
> roughly 12. 4k inserts per second during the settlement batch.

— identifiers split, a decimal rewritten, and the last two sentences
silently deleted, because every `.` counted as a sentence boundary and
the sentence budget was spent on fragments. A capsule exists to hand
exactly this narrative to the next worker; a format that silently
rewrites it is lying about its own content. An author who writes prose
gets their prose. An author who wants the normalizer declares it.

## Style rules

When writing narrative fields a foreign LLM will read:

- **Lead with operational facts.** Actor, decision, evidence, next
  action. Not preamble.
- **Short declarative sentences.** Three is plenty.
- **Preserve exact data.** Never paraphrase: code, JSON, hashes, IDs,
  paths, timestamps, exact quoted requirements, regulator citations.
  These belong in payload structure, not narrative.
- **Don't editorialize.** No "I think," "we believe," "it seems."
- **Don't recompress history.** A historical event's narrative is
  closed. Only summarize when explicitly creating a new event that
  references it.

## Meaning preservation (normative for any Pith normalizer)

A tool that claims to apply the Pith normalizer MUST NOT silently
change what the text says. Concretely:

- **Whole sentences only.** Sentence selection keeps or drops complete
  sentences; kept text is byte-identical to the input. Cutting `14.11`
  to `14.` is worse than performing no normalization at all.
- **A terminator inside a token is not a boundary.** A sentence ends
  only at a terminator (`.`, `!`, `?`, or a fullwidth CJK terminator
  such as `。`) followed by whitespace or end of input — never at a dot
  inside an identifier (`ledger.entry_audit`), a decimal (`12.4`), a
  version (`v0.7.1`), a URL, or a code fragment.
- **When unsure, keep.** The reference scanner also refuses to end a
  sentence before a lowercase continuation, after a small set of
  common abbreviations ("e.g.", "etc."), or after a single-letter
  initial ("J. Smith"). A missed boundary merges two sentences and
  keeps more text; an invented boundary deletes content. Only the
  first failure mode is acceptable.
- **Truncation is visible.** A length cut lands on a word boundary
  where possible and always ends in the ellipsis `…`. Dropped trailing
  sentences carry no inline marker; the event-level marker below is
  what makes that discoverable.
- **The rewrite is declared.** When the builder's normalizer actually
  changed a field, the event records the affected payload members in
  `pith_normalized_fields` (grammar and reader obligations in
  [chain.md](chain.md)). An author applying Pith as *practice* may
  declare the fields it rewrote the same way. A lossy rewrite inside
  the hash chain is never silent.

## Where Pith applies

The narrative fields the normalizer targets when enabled:

- `chain/events.jsonl` per-event:
  - `payload.summary`
  - `payload.statement`
  - `payload.note`
  - `payload.open_items[].item`
  - `payload.decisions[].text`
  - `payload.milestones[].text`

`program.md` and `agents.md` are never auto-normalized. They are
human (or LLM-)authored documents whose voice is part of the work
product. Authors apply the discipline themselves.

## Library defaults

`compressText`:

- `maxChars`: 280 (enough for one good sentence, three terse ones)
- `maxSentences`: 3
- ellipsis on overflow: `…`

These defaults are a starting point, not protocol. Implementations may
tune. Two implementations producing the same JSON event after
normalization are considered conformant; byte-for-byte identical
normalized output across implementations is *not* a v0.7 promise.

## Truncation and the canonicalization boundary

Normalized text is canonicalized and hashed. The normalizer therefore MUST
NOT produce a string that JCS cannot accept.

Concretely: `maxChars` counts characters, and a truncating implementation
MUST cut on a Unicode code-point boundary. Cutting at a UTF-16 code-unit
index splits surrogate pairs — with the default `maxChars` of 280 the cut
index is odd, so ordinary text containing emoji lands mid-pair — and the
resulting unpaired surrogate is outside the acceptance boundary in
[canonicalization.md](canonicalization.md). The capsule then seals in the
implementation that produced it and fails to verify everywhere else, with
an error that reads like tampering.

This is a MUST even though byte-identical normalizer output is not a v0.7
promise: what varies across implementations is *where* the cut lands, not
*whether* the result is well-formed Unicode.

## Opting in

Per-builder:

```js
new CapsuleBuilder({ originator, participants, pith: true });
```

Per-event (overrides the builder setting in either direction):

```js
builder.appendEvent({ actor, kind, action, target, payload }, { pith: true });
builder.appendEvent({ actor, kind, action, target, payload }, { pith: false });
```

The normalizer is off by default. The discipline still reflects the
real product property — *capsules are easier for foreign LLMs to read
when the narrative fields are terse and regular* — but the format's job
is to let an author declare that intent, not to impose a lossy rewrite
on prose the author already chose.

## What Pith is not

- A protocol requirement. Verification never depends on it.
- A compression algorithm. The rewrite is lossy and meaning-bearing.
- A canonicalization. Two LLMs writing the same content in Pith style
  will not produce identical bytes; the normalizer is a floor, not a
  guarantee of equivalence.
- A security primitive. Pith does not authenticate, encrypt, or hash.
- An audit trail. Pithed text is the version of record after the
  rewrite — the original is not preserved by the SDK, which is exactly
  why the rewrite is opt-in and marked in `pith_normalized_fields`.
  Authors who need to keep the un-normalized text should put it in a
  non-targeted field (e.g. `payload.original_text` is not in the
  normalizer's field list).

## What it is for

Foreign-LLM continuity. A loan-application capsule from Acme arrives at
a regulator's audit system months later. Their model opens it, reads
the chain, and gets a uniform terse stream of decisions and
observations. They can summarize, query, and reason without spending
context on noise. That property is the product. Pith is how authoring
practice keeps it — and the format's contribution is to carry the
narrative faithfully and to say, in-chain, when a normalizer rewrote
it.

## Conformance vectors

`spec/vectors/pith-authoring/` — a default-built capsule whose
technical prose is stored byte-identical (no marker), and a
pith-enabled capsule whose event carries `pith_normalized_fields`.
`spec/vectors/unicode-boundary/` — the truncation code-point-boundary
MUST above.
