# Event Chain

`chain/events.jsonl` is the append-only signed audit trail. One line per
event, JSON object, no trailing whitespace, terminated by `\n`.

## Event schema

```json
{
  "seq": 1,
  "event_id": "evt_001",
  "actor": "human:alice@acme.example",
  "kind": "decision | observation | mutation | session | checkpoint",
  "action": "approved_application",
  "target": "program.md#step-3",
  "timestamp": "2026-05-07T12:00:00Z",
  "payload": { },
  "untrusted_payload_fields": ["payload.summary", "payload.statement"],
  "prev_hash": "<64-hex>",
  "hash": "<64-hex>"
}
```

## Field rules

- `seq`: 1-based integer, strictly monotonic per chain.
- `event_id`: free-form, conventionally `evt_NNN`. Not cryptographically
  bound; for human reference only.
- `actor`: `human:`, `ai:`, `system:`, or `capsule:` prefix. When the
  manifest declares a non-empty `participants[]`, the actor must appear
  there *or* be the literal `system:host` for backstop events emitted by
  the host runtime — fail-closed. When `participants[]` is empty, the
  manifest has made no claim about who acted: readers accept any actor
  and report the reduced assurance instead (see "Verification"). The
  conditional is safe because `participants[]` lives in the manifest,
  covered by `manifest_hash` inside the signed payload — an attacker
  cannot empty the list to escape the check without breaking every
  envelope signature. Writers reject an undeclared actor at append time
  rather than registering it implicitly — declaring who may act is the
  host's decision, not the SDK's.
- `kind`: one of the listed values, in EVERY profile. Readers reject
  unknown kinds and writers refuse to append them. Unlike the actor
  rule this is not an assurance tier: a capsule with a custom event
  kind is not making a weaker claim, it is unreadable to the foreign
  LLM reader the format exists to serve.
- `timestamp`: ISO 8601 UTC, no fractional seconds. Advisory only;
  authoritative time-binding is the envelope's `signed_at`.
- `payload`: free-form JSON object. May contain LLM-authored text.
- `untrusted_payload_fields`: dotted paths into `payload` whose contents
  must be treated as untrusted by readers — see "Untrusted content"
  below.
- `prev_hash`: hex of the previous event's `hash`, or 64 zeroes for the
  first event.
- `hash`: see "Hashing" below.
- Unknown members: events MAY carry extension members beyond this
  schema, under the same `x-<vendor>-<name>` key convention as
  [manifest.md](manifest.md) "Unknown members". Readers MUST preserve
  them verbatim and MUST include them in the canonicalization below —
  they are covered by the event hash, so recomputing the hash from a
  re-serialized typed projection of the event (which drops them, or
  invents defaults for absent optional fields) is a conformance
  violation. Conformance vectors: `spec/vectors/unknown-fields/`.

## Hashing

```
prev_raw   = bytes(prev_hash)              # 32 bytes; all-zero for genesis
canonical  = JCS(event without "hash")     # RFC 8785
event_hash = SHA-256(prev_raw || canonical)
```

All concatenations are over raw bytes. **No hex strings appear in any
hash input.** This is the v0.6 fix for the prior format's hex-string
hashing footgun.

The genesis previous-hash value is 32 zero bytes (not the 64 ASCII zeros
of the prior format).

## Untrusted content

Any field in a chain event whose value is LLM-authored or
externally-supplied and may contain instructions to a future LLM reader
must be listed in `untrusted_payload_fields`.

The convention exists because chain events that contain summaries of
work, model outputs, or external API responses are a designed-in
prompt-injection vector for any future cold reader that loads the chain
into a model context. Readers should:

- preserve the exact bytes of those fields
- when feeding the chain to a model, wrap them with explicit
  "untrusted-content" framing
- not allow those fields to influence host-side decision-making

The default for narrative summary/statement fields is to mark them
untrusted unless the host knows otherwise.

## Empty chains

A chain with ZERO events is legal. It is the weakest honest claim the
format supports — a template or draft capsule that carries no recorded
work yet — and it sits squarely in the open/low-assurance tier the
format must serve. Verifiers MUST NOT reject a capsule merely because
`chain/events.jsonl` is present but empty. (The FILE itself is still
required; a missing chain file is a container defect.)

What an empty chain must not do is claim anchors it does not have.
With zero events there is no first event and no entry event, so:

- `manifest.first_event_hash` MUST be `null`,
- `envelope.first_event_hash` MUST be `null`,
- `envelope.entry_hash` MUST be `null`.

A capsule carrying no events while claiming any of these anchors is
lying about its own bytes; verifiers MUST reject it fail-closed. This
matters because in a plain capsule the two envelope anchors are the
ONLY binding between the envelope and the chain — a verifier that
treats an empty chain as "nothing to check" silently skips that
binding and reports an unbound capsule as verified.

Verifiers MUST also report, machine-readably and in human output, that
a zero-event chain was NOT walked (there was nothing to walk) and that
the anchors were checked for null instead — never an unqualified pass
indistinguishable from a walked chain.

`capsule_id` for a zero-event capsule is derived with 32 zero bytes in
place of `first_event_hash_raw` (see [manifest.md](manifest.md)
"Capsule identity").

Conformance vectors: `spec/vectors/chain-binding/`
(`empty-chain-null-anchors` MUST verify; `empty-chain-claimed-anchors`
MUST fail).

## Backstop event

If a session ends without explicit chain events, the host SDK emits a
single backstop event before sealing:

```json
{
  "actor": "system:host",
  "kind": "observation",
  "action": "session_ended",
  "target": "capsule",
  "payload": {
    "note": "host emitted backstop event; LLM did not append explicit events during session"
  }
}
```

The host always controls backstop emission. The LLM cannot suppress it.
This is the mitigation for "the LLM curates its own audit log."

The backstop is a *session-host* obligation: a runtime that hosted a
session MUST NOT seal it with an empty chain, because "a session
happened and recorded nothing" is exactly the curation hazard above.
It does not forbid the zero-event shape itself — a writer sealing a
template or draft that hosted no session legitimately produces an
empty chain (see "Empty chains"), and the null anchors make that
weaker claim visible to every reader.

## Verification

The reader walks the chain in order:

1. Recompute each event's hash from `prev_hash || JCS(event-without-hash)`.
2. Compare against the stored `hash`.
3. Confirm `prev_hash` of event N equals `hash` of event N-1.
4. Confirm event 1's `prev_hash` is 32 zero bytes (hex `000...0`).
5. Confirm `seq` is strictly monotonic from 1.
6. When the manifest declares a non-empty `participants[]`, confirm
   `actor` appears in it or is `system:host`. When `participants[]` is
   empty the manifest binds no actor set: the reader MUST NOT reject,
   and MUST report — machine-readably and in human output — that the
   chain's actors are not bound to a declared participant set. This
   mirrors the signer-set rule: presence binds, absence reports.
7. Confirm `kind` is one of the five values in the enum above —
   unconditionally.

A mismatch at any step fails verification. The reader reports which
event failed which check; it does not stop at the first error.

Steps 6 and 7 are per-event field rules, not chain-integrity rules: a
capsule can have a perfectly linked, correctly signed chain and still
fail them. Conformance fixtures for both — plus the empty-participants
positive control, which MUST verify with the unbound-actor-set report —
live in `spec/vectors/chain-rules/`.

## Writer obligations

A writer MUST NOT emit an event that a reader would reject at steps 6
or 7. In practice that means the builder validates `actor` and `kind`
when the event is appended, so the failure surfaces at the call site
that introduced it rather than at some future reader. A builder that
auto-registers an undeclared actor into `participants[]` is
non-conformant: it converts an authorization question into a silent
side effect. A builder with an empty `participants[]` may append any
actor — the resulting capsule makes the visibly weaker claim above.

When the chain has zero events, steps 1-6 are vacuous; the reader
instead enforces the null-anchor rule of "Empty chains" (all three
anchor claims null, fail-closed otherwise) and reports that no events
were walked. When the chain has events, a `null` anchor fails the
envelope anchor comparison like any other mismatch.

## What the chain does *not* prove

- Time of event (advisory `timestamp`; authoritative time is the
  envelope's `signed_at` at seal time).
- Truth of payload contents.
- Authority of the actor outside of `originator` (which is the only
  participant cryptographically bound to a key in v0.6).

The chain proves: *these events, in this order, with these payloads,
were the events at seal time.* Anything stronger requires an external
anchor (Rekor, RFC 3161) which is parking-lot for v0.6.
