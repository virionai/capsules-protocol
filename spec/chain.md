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
- `actor`: `human:`, `ai:`, `system:`, or `capsule:` prefix. Must appear
  in the manifest's `participants[]` *or* be the literal `system:host`
  for backstop events emitted by the host runtime.
- `kind`: one of the listed values. Readers reject unknown kinds.
- `timestamp`: ISO 8601 UTC, no fractional seconds. Advisory only;
  authoritative time-binding is the envelope's `signed_at`.
- `payload`: free-form JSON object. May contain LLM-authored text.
- `untrusted_payload_fields`: dotted paths into `payload` whose contents
  must be treated as untrusted by readers — see "Untrusted content"
  below.
- `prev_hash`: hex of the previous event's `hash`, or 64 zeroes for the
  first event.
- `hash`: see "Hashing" below.

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

## Verification

The reader walks the chain in order:

1. Recompute each event's hash from `prev_hash || JCS(event-without-hash)`.
2. Compare against the stored `hash`.
3. Confirm `prev_hash` of event N equals `hash` of event N-1.
4. Confirm event 1's `prev_hash` is 32 zero bytes (hex `000...0`).
5. Confirm `seq` is strictly monotonic from 1.
6. Confirm `actor` appears in manifest participants or is `system:host`.

A mismatch at any step fails verification. The reader reports which
event failed which check; it does not stop at the first error.

## What the chain does *not* prove

- Time of event (advisory `timestamp`; authoritative time is the
  envelope's `signed_at` at seal time).
- Truth of payload contents.
- Authority of the actor outside of `originator` (which is the only
  participant cryptographically bound to a key in v0.6).

The chain proves: *these events, in this order, with these payloads,
were the events at seal time.* Anything stronger requires an external
anchor (Rekor, RFC 3161) which is parking-lot for v0.6.
