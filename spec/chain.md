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
  "pith_normalized_fields": ["payload.summary"],
  "prev_hash": "<64-hex>",
  "hash": "<64-hex>"
}
```

## Field rules

- `seq`: 1-based integer, strictly monotonic per chain.
- `event_id`: free-form, conventionally `evt_NNN`. Not cryptographically
  bound; for human reference only. Advisory — MAY be absent.
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
- `action`, `target`: free-form strings describing the act and the
  thing acted on, for human and LLM readers. Advisory — no verification
  rule reads them.
- `timestamp`: ISO 8601 UTC, no fractional seconds. Advisory only;
  authoritative time-binding is the envelope's `signed_at`.
- `payload`: free-form JSON object. May contain LLM-authored text.
  Advisory — an event MAY omit it, which is simply making no payload
  claim.
- Advisory members (`event_id`, `action`, `target`, `timestamp`,
  `payload`) MAY be absent: the event hash commits to the stored line
  exactly as sealed, so omitting them is a weaker claim made honestly,
  never a malformation. Readers MUST NOT reject an event for omitting
  an advisory member, and a typed reader MUST NOT refuse to parse it —
  the members verification rules read are `seq`, `kind`, `prev_hash`,
  `hash`, and (only when the manifest binds an actor set) `actor`.
  Conformance vector: `spec/vectors/chain-rules/`
  (`minimal-event-fields`).
- `untrusted_payload_fields`: paths into `payload` naming members whose
  contents must be treated as untrusted by readers. Every entry MUST
  match the path grammar in "Untrusted content" below; writers refuse
  to emit a non-conforming entry and verifiers reject it fail-closed.
- `pith_normalized_fields`: OPTIONAL, advisory provenance. Paths in the
  same grammar as `untrusted_payload_fields`, naming top-level `payload`
  members whose narrative text was rewritten by a Pith normalizer — or
  by an author applying the discipline — before the event was hashed.
  The pre-rewrite text is NOT preserved anywhere in the capsule; this
  marker is what keeps a lossy rewrite inside the hash chain from being
  silent (see [pith.md](pith.md)). Writers MUST NOT emit an
  out-of-grammar entry (the reference builders refuse at append time,
  and record the member automatically when their normalizer changed a
  field). Readers MUST preserve the member verbatim, MUST include it in
  the canonicalization below — it is covered by the event hash like
  every other member — and MUST NOT reject an event merely because it
  is present. Unlike `untrusted_payload_fields` there is no verifier
  validation obligation in v0.7: a malformed entry weakens provenance
  detail but does not unmark unsafe content for downstream readers.
  Conformance vectors: `spec/vectors/pith-authoring/`.
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

`JCS(...)` above is defined only over I-JSON input. An event whose payload
carries a number outside the IEEE-754 exact-integer range, or a string with
an unpaired surrogate, has no canonical form: builders MUST reject it at
`appendEvent` time, and verifiers MUST report the refusal as a
canonicalization error rather than as a hash mismatch. See
[canonicalization.md](canonicalization.md).

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

### Path grammar (normative)

Each `untrusted_payload_fields` entry is a string matching:

```
path    = "payload" 1*( "." segment )
segment = 1*( ALPHA / DIGIT / "_" / "-" )
```

`"payload.summary"` and `"payload.review.notes"` are well-formed;
`"payload"` alone (no segment), `"payload..x"` (empty segment),
`"not-payload.note"` (wrong root), and any entry that is not a string
are not.

Rules:

- **Writers MUST NOT emit** an event whose `untrusted_payload_fields`
  contains a non-string entry or an entry outside the grammar; the
  reference builders reject the marking at append time, when the caller
  still has it in hand.
- **Verifiers MUST reject** such an event (a chain-area failure,
  fail-closed, in every profile). A marking a host cannot parse
  silently unmarks LLM-authored content for every downstream reader —
  the marking is inside the event hash, so this is the capsule
  malformed about its own safety claim, not a policy choice.
- The member itself remains OPTIONAL, and an empty array is legal:
  "nothing here is marked untrusted" is a claim the grammar does not
  police. Only present entries are validated.

### Resolution (the host-projection contract)

Hosts project a marking onto the payload deterministically, with no
invented semantics:

- Split the path on `"."`. Discard the leading `payload` root. Each
  remaining segment names an object member, looked up in order starting
  at the event's `payload` object.
- Only JSON **object** members are traversable. There is no array
  indexing, wildcard, or escape syntax in v0.7.
- A path that fails to resolve — a named member is absent, or an
  intermediate value is not an object — marks **nothing**. It is not an
  integrity violation (payload shapes evolve; the claim covers the
  member *if present*), and hosts MUST NOT guess at near-miss members.
- A member whose name contains characters outside the segment alphabet
  cannot be marked. Writers MUST NOT put untrusted narrative under such
  a name.

Conformance vector: `spec/vectors/chain-rules/`
(`invalid-untrusted-path` MUST fail verification).

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

## Custody hand-off event (convention)

A successor capsule declaring lineage ([lineage.md](lineage.md)) starts
a FRESH chain — the predecessor's history stays where it is signed —
and the reference builders open the successor chain, by default, with a
conventional genesis event so custody is visible to the cold LLM reader
in the chain narrative:

```json
{ "actor": "system:host", "kind": "observation",
  "action": "custody_received",
  "target": "capsule:<predecessor capsule_id>" }
```

This is a writer convention (the backstop-event posture), NOT a
verifier rule: `action` and `target` are advisory members no
verification rule reads, the `manifest.predecessors` declaration is the
binding claim under every signature, and a mandatory chain echo would
be a second surface that must agree with the first. Copying predecessor
events into a successor chain is not forbidden, but re-hashed under a
new chain context they are fresh assertions on the successor's
authority wearing old actors' names — worthless as history
([lineage.md](lineage.md) "Chain treatment").

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
8. When `untrusted_payload_fields` is present, confirm it is an array
   and every entry matches the path grammar in "Untrusted content" —
   unconditionally. An unparseable marking silently unmarks content
   for every downstream host.

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
  participant cryptographically bound to a key in v0.7).

The chain proves: *these events, in this order, with these payloads,
were the events at seal time.* Anything stronger requires an external
anchor (Rekor, RFC 3161) which is parking-lot for v0.7.
