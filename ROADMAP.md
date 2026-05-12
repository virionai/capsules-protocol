# Capsule Roadmap — v0.6 prototype to v1.0

One page. Five rows. Each milestone has a kill criterion.

## Milestones

| # | Milestone | Why it matters | Kill if |
|---|---|---|---|
| 1 | **Lock envelope at v0.6** with crypto fixes (raw-byte sign, full-envelope canonical, domain separation per role, drop AES-GCM placeholder, `capsule_id` derived from `originator_pubkey \|\| first_event_hash`, `signers[]`, self-attested `signed_at`) — plus signed test vectors | Without this, every v1.0 commitment is debt. | Two independent reviewers each find a different envelope flaw we missed. |
| 2 | **Tamper-detection demo as canonical first example** — clean PASS, payload-tampered FAIL, envelope-tampered FAIL, encrypted-blob-tampered FAIL (one screen) | The demo that earns the format its weight. | A reviewer replicates the same auditability with `git tag --sign` + a markdown file in <50 LOC and ≤2 deps. |
| 3 | **Foreign-LLM cold-read benchmark vs plain markdown** — same work, two formats, measure time-to-first-correct-action and decision-attribution accuracy in a different vendor's model | Heart of the pitch. Currently no measurement exists. | Capsule wins by less than a meaningful margin (define before testing). Reframe the format as an audit shell, not a context-transfer mechanism. |
| 4 | **One real loan-application demo, end-to-end, reviewed by a real auditor** — platform produces, regulator opens cold months later, decrypts with custodial key, asks a question, gets an auditable answer | Proves the platform-as-issuer go-to-market. | A real auditor reviews and says "this isn't how we work." |
| 5 | **Second independent implementation** (Python, Rust, or Go verifier) with bit-identical hashes against the JS SDK on signed test vectors | "Spec" vs "library." | After 90 days, no second implementer engages. The format is a JS library; sell it as such. |

## Parking lot — blocked on adoption signal

These are not roadmap items until at least three of the five above land.
They are explicitly de-prioritized so the project does not keep adding
infrastructure to a format that has not yet proven itself in use.

- Provenance ledger / envelope publication service
- RFC 3161 / Rekor temporal anchoring
- Identity registry / federation
- Recipient rotation and key revocation policy
- AES-256-GCM runtime support
- Web Bluetooth / mesh networking
- Microphone / Web Speech permission UX
- Declarative view specs (capsule grows into a UI layout language)
- Browser-safe SDK polish beyond what the demo requires
- Embedded Android WebView host validation (if WebView decrypt benchmark
  fails Milestone 3 implicitly, soften the mobile claim instead of
  pursuing parity)

## Operating principle

> Do not add infrastructure before the capsule file proves its value.

Path:

```
portable file → local verification → host-executed bridge → user-visible trust → optional hosted services
```

If any milestone above triggers its kill criterion, the project should
stop and rethink before continuing, not work around the failure.

## What is *not* on this roadmap and should not be

- Bespoke per-LLM-provider bridges (Gemma 4, OpenAI, Claude, Codex). One
  MCP server replaces all of them; if MCP cannot carry capsule
  operations for a specific reason, document the reason — do not write
  six adapters.
- "Production-Ready v1.0" examples while SDK is `0.6.x`. Any example
  claiming production status against a deprecated runtime is
  reputational liability.
- "Mobile-readability is non-negotiable" as a foundational claim until
  the encrypted-blob decrypt path on a mid-tier Android phone is
  measured and documented.
