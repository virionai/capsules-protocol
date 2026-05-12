# Pith — Context-Style Discipline

## What it is

Pith is the discipline by which capsule narrative fields are written so
that a cold-reading LLM can absorb the context fast and accurately.

It is **not** "deterministic compression" in the information-theoretic
sense. The prior format made that claim; v0.6 retracts it. The discipline
is the product. The reference normalizer is a helper.

Two forms of Pith coexist:

1. **Pith as practice** — an LLM applies the style rules below when it
   writes narrative fields. This is the high-quality path; the resulting
   compression is richer than any deterministic library can produce.
2. **Pith as normalizer** — a deterministic library function that
   guarantees fields written *without* LLM judgment still come out
   terse and regular. Whitespace collapsed, first N sentences kept,
   length-capped at a word boundary with an ellipsis when over budget.

The SDK ships the normalizer (`compressText`, `compressEventPayload`).
The discipline lives in the rules below and in capsule authoring
practice.

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

## Where Pith applies

In a v0.6 capsule, the narrative fields the SDK auto-normalizes:

- `chain/events.jsonl` per-event:
  - `payload.summary`
  - `payload.statement`
  - `payload.note`
  - `payload.open_items[].item`
  - `payload.decisions[].text`
  - `payload.milestones[].text`

`program.md` and `agents.md` are **not** auto-normalized. They are
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
normalized output across implementations is *not* a v0.6 promise.

## Opting out

Per-builder:

```js
new CapsuleBuilder({ originator, participants, pith: false });
```

Per-event:

```js
builder.appendEvent({ actor, kind, action, target, payload }, { pith: false });
```

The discipline is opt-out by default. Auto-application reflects the
real product property: *capsules are easier for foreign LLMs to read
when the narrative fields are normalized.*

## What Pith is not

- A compression algorithm. The rewrite is lossy and meaning-bearing.
- A canonicalization. Two LLMs writing the same content in Pith style
  will not produce identical bytes; the normalizer is a floor, not a
  guarantee of equivalence.
- A security primitive. Pith does not authenticate, encrypt, or hash.
- An audit trail. Pithed text is the version of record after the
  rewrite — the original is not preserved by the SDK. Authors who need
  to keep the un-normalized text should put it in a non-targeted field
  (e.g. `payload.original_text` is not in the normalizer's field list).

## What it is for

Foreign-LLM continuity. A loan-application capsule from Acme arrives at
a regulator's audit system months later. Their model opens it, reads
the chain, and gets a uniform terse stream of decisions and
observations. They can summarize, query, and reason without spending
context on noise. That property is the product. Pith is how the format
keeps it.
