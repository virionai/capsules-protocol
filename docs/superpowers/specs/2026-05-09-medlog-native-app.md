# medlog — Native Medical-Journal App, Design Plan

**Status:** scoping
**Target:** post-Kaggle launch (Q3 2026 target)
**Owner:** medlog application, lives alongside `examples/medical-journal/`
**Capsule format:** v0.6 (no schema changes)
**Companion site:** prescribe.chat (already shipped as static site)

## Goal

Promote the medical-journal demo from "Edge Gallery skill that proves
the format" to "first-party iOS + Android app that any patient can
install when their clinician issues a code." Same prescription model.
Same Capsule v0.6 file. Same on-device-only data. A native shell with
better UX, a custom Gemma 4 E2B finetune, and direct file/share
integration.

## Why a native app at all

The Edge Gallery skill is the right place to *prove* the format. It is
not the right place to *productize* the experience for patients.

| Concern | Edge Gallery skill | Native medlog app |
|---|---|---|
| Activation friction | Install Edge Gallery, find skill list, paste URL | Install medlog, tap prescribe.chat URL once |
| Always-on capture | Open host app → open chat → invoke skill | Lock-screen widget; side-button voice memo |
| Background | None | Background nudges, lazy-warm model, pre-cache |
| File handoff | Save / Share what the host exposes | Native Files / Storage Access Framework, Share Sheet |
| Health overlay | None | Read-only HealthKit / Health Connect into chain |
| Model lifecycle | Whatever Edge Gallery ships | Pin to a known Gemma 4 E2B + LoRAs; predictable |
| Brand legibility | Hidden inside a developer tool | Has its own home screen identity |

The Edge Gallery skill stays in the repo as the canonical reference
implementation and the demo path. medlog is the path to a v1 product.

## Why Gemma 4 E2B (not E4B)

E4B is the multimodal flagship; medlog uses E2B because:

- **Smaller surface, more devices.** E2B (effective ~2B params, multimodal) runs
  comfortably on mid-tier Pixel / iPhone 14+ class hardware. E4B is
  flagship-class. medlog's target is "any phone a patient already owns."
- **Faster cold-start, lower battery.** A journal nudges the patient
  several times a day; cold-starting a 4B model on every nudge is rude
  to the device. E2B fits a "warm-on-foreground, sleep-on-background"
  cycle.
- **Sufficient depth.** The journal use cases are: clarifying questions
  during text intake, transcribing voice memos, describing photos,
  summarizing chains for export. None require encyclopedia-class
  knowledge; a focused finetune of E2B beats a generic E4B for these.

The clinician-side tooling (the future `clinician-app`) can use E4B —
it has a different deployment story (always plugged in, fewer devices,
deeper analysis).

## Finetune strategy

Three orthogonal LoRAs trained separately and stacked at inference time.
This keeps each adapter small (tens of MB) and lets us swap one without
retraining the others.

### LoRA 1 — Domain adapter

- **Goal:** know how clinicians actually elicit a chief complaint, food
  history, exposure history. Responsible for the *content* of clarifying
  questions.
- **Data:** 5–10k synthesized intake transcripts, reviewed and corrected
  by 2–3 practicing clinicians (general practice + 1–2 specialties).
  Synthetic generation seeded from real intake forms (de-identified) and
  textbook intake protocols.
- **Eval:** held-out set of 200 transcripts; clinician panel rates
  question quality on a 1–5 rubric. Target ≥4.0 average.
- **Refresh cadence:** quarterly, or when a new specialty adapter ships.

### LoRA 2 — Style adapter

- **Goal:** enforce the journaling voice. Concise. ≤2 clarifying
  questions per turn. Never offers a diagnosis. Never editorializes.
  Pith-style normalization on prose fields.
- **Data:** 2–3k examples of "good journal turn" vs. "bad journal turn"
  pairs. Deterministic style rules baked as constraints during inference
  too (max sentence length, banned phrases like "you should", etc.) so
  the adapter and the runtime agree.
- **Eval:** automated pith metric (sentence count, mean length, presence
  of banned phrases) plus blinded clinician preference.

### LoRA 3 — Safety adapter

- **Goal:** the boundary. *Describe* what is in the photo, *do not*
  diagnose it. Refuse "is this cancer?" Refuse to recommend dosing
  changes. Detect suicidal-ideation language and surface a local
  hotline + nudge to contact clinician *now*. Defer everything else to
  the prescribing clinic.
- **Data:** 1–2k red-team examples of prompts that try to get the
  model out of the safe envelope, paired with the right refusal /
  escalation. Includes adversarial photo prompts.
- **Eval:** red-team pass rate (must be ≥99% on the held-out adversarial
  set before any release). Failures block ship.

### Per-prescription specialty adapters (post-launch)

The prescribe.chat clinic skill can carry *one* additional LoRA for the
clinic's specialty (derm, allergy, GI, mental health). It loads on top
of the three base LoRAs when that prescription is active. Same base
model, different specialty intelligence per code.

Total adapter footprint: 3 base LoRAs (~30–50 MB combined) + 1 optional
specialty LoRA per active prescription. Base Gemma 4 E2B at INT4 ships
at ~1.5 GB.

## Tech stack

### iOS

- **UI:** SwiftUI. Native, fastest to a polished surface.
- **Inference:** **MLX** (Apple's on-device ML framework, not Core ML).
  MLX has the best LoRA + multimodal story on Apple Silicon today. Core
  ML is a fallback if MLX has gaps for Gemma 4 E2B at ship time.
- **Storage:** Files app integration via UIDocumentBrowser; the
  `.capsule` file is a first-class Files document. Capsule keys live in
  Keychain (X25519 + Ed25519, both as raw bytes wrapped by Keychain).
- **Distribution:** App Store. TestFlight for beta.

### Android

- **UI:** Compose. Native, matches the iOS app in feel.
- **Inference:** **LiteRT + MediaPipe LLM Inference** (Edge Gallery's
  underpinnings). Same stack the demo skill ran on, so we get parity by
  construction.
- **Storage:** Storage Access Framework for `.capsule` handling.
  EncryptedSharedPreferences for keys.
- **Distribution:** Play Store. Internal testing → closed beta → open.

### Cross-platform shared

- **Capsule v0.6 SDK** ported to Swift and Kotlin. This is the
  single biggest engineering investment in the plan, and also the
  single biggest *strategic* win — see "Format moat" below.
- **Synthetic chain fixtures** shared between SDKs as a JSON corpus, so
  the Swift and Kotlin SDKs can be regression-tested against the
  reference JS SDK byte-for-byte.

### Why not Flutter / React Native

Considered and rejected for v1. Two reasons:

- **Model integration is the hot path.** MLX (iOS) and LiteRT (Android)
  have native APIs; bridging through a cross-platform layer adds
  latency we cannot afford on every Gemma turn.
- **Camera / mic / files.** All three are platform-specific surfaces
  where native gives the better UX. The cross-platform abstractions
  here are leaky enough that we'd write platform code anyway.

We keep the door open for v2 if a mature multimodal-on-device
abstraction (a future Expo SDK or similar) makes the trade-off shift.

## Format moat

The native ports are the second and third independent implementations
of the Capsule v0.6 spec. That is the single largest credibility signal
the format can earn. The plan should treat them as such:

- The Swift SDK and the Kotlin SDK each ship a `verifyCapsule` that
  passes the same parity-test fixtures as the JS reference.
- The fixtures live in `examples/medical-journal/parity-fixtures/` (new
  directory) and are the contract surface across implementations.
- A change to the spec requires updating the fixtures, then making all
  three SDKs pass. This is what turns "spec" into "spec with teeth."

This is independent of whether medlog ships on time. Even if the
launch slips, the multi-SDK parity is shippable as a standalone
milestone, and arguably more valuable to the format than the app.

## Privacy / regulatory posture

- **HIPAA:** medlog (the app) is not a covered entity. No PHI leaves
  the device. The clinic that issues the prescription *is* a covered
  entity, and the `.capsule` file is the patient-controlled handoff
  artifact. We document this posture in the App Store / Play Store
  data-safety forms and in the in-app first-run flow.
- **App Store / Play Store data declarations:** "no data collected,
  none transmitted." We must keep the absence of telemetry honest;
  even crash reporting goes through the platform (Apple TestFlight,
  Google Play Console) so it does not constitute a data collection by
  us.
- **Apple Health / Google Fit:** read-only, opt-in, scoped to the
  signals that matter for the journal context (HR, sleep, steps).
  Stored only in chain events the user accepts.
- **Backups:** `.capsule` files are eligible for system backup
  (iCloud / Google Drive) by default. The file remains encrypted to
  patient + clinic, so backup restoration on a new device requires the
  patient's `.pem` (the availability backup from the existing v0.1
  spec) to reopen. Documented prominently.

## Distribution / business model

- **Free.** No paid tiers, no in-app purchase. The cost of building
  this is amortized across the format adoption it earns. A future
  clinician-side product (`clinician-app` for iPad) is the obvious
  monetization surface; the patient app stays free.
- **No accounts.** A patient with a code can install. A patient
  without a code can install and self-prescribe (degraded mode, no
  recipient encryption — only the patient's own key). The
  self-prescribe path exists so the app is reviewable on app stores
  without a working clinic on the reviewer's end.
- **One default-bundled clinic for the demo:** Gemma Good Family
  Medicine (rx7q). Reviewers can run end-to-end without contacting a
  real clinic.

## Timeline

| Phase | Length | Outcome |
|---|---|---|
| 1 — SDK port + iOS shell | 4–6 weeks | Capsule v0.6 in Swift; SwiftUI shell loads bundled JS skill on Gemma 4 E2B (MLX); seal + verify offline. |
| 2 — Android shell + parity | 4–6 weeks | Capsule v0.6 in Kotlin; Compose shell on LiteRT; cross-implementation parity test green. |
| 3 — Finetune + safety | 8–10 weeks | Three base LoRAs + safety eval ≥99% on the red-team set. Clinician panel sign-off on domain adapter. |
| 4 — Polish + submit | 6–8 weeks | Lock-screen widget, voice-memo shortcut, file handler, App Store + Play Store submission, beta with 1–2 clinics. |

Total: ~6–8 months from kickoff to public launch. The Kaggle
submission is the demo and the launch event for the format. medlog is
the v1 product that earns the format its first wave of real-world use.

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | Gemma 4 E2B does not ship on iOS via MLX in time | Hold for Gemma 4 release; fall back to E4B on iPhone 15+ if E2B is delayed; or ship Android-first and add iOS in v1.1. |
| 2 | Finetune budget (clinician hours, GPU time) blows out | Start with style + safety LoRAs only (the cheap two). Domain LoRA can ship in v1.1 without breaking the journal. |
| 3 | App Store reviewer rejects "no accounts, no terms" | Add a minimal first-run consent screen + a static privacy page on prescribe.chat. Standard play. |
| 4 | LoRA + multimodal not yet supported in MediaPipe LLM Inference for Gemma 4 E2B at ship time | Land the base model first; LoRAs as a v1.1 update. Bundled JS journal skill provides text-only flow until adapters land. |
| 5 | Two SDK ports drift from the JS reference | Parity test as the contract. CI runs Swift + Kotlin + JS verifiers on the shared fixture set; PRs that break parity must update the spec deliberately. |
| 6 | Patient self-prescribe mode confuses the trust model | Mark self-prescribed capsules visibly different in the export panel ("no clinic recipient — only you can read this"); restrict that path's UI from any "send to clinic" CTA. |

## Open questions deferred to implementation

- Do we ship the patient `.pem` availability backup as a generated
  paper card (printable) or as an Apple/Google Wallet pass? Wallet
  passes are richer but tie us to platform stores.
- Does the lock-screen widget require Live Activities (iOS) /
  ongoing-notification (Android), or is a plain widget enough? This
  affects whether we need a foreground service on Android.
- Specialty LoRAs: do they ship in the clinic skill bundle (heavy:
  the bundle goes from ~4 KB to ~30 MB) or get fetched from
  prescribe.chat on first encrypt (lighter, but a network touch)?
  Prefer the heavy bundle for honesty; revisit if download size hurts.

## Definition of done for v1.0 launch

- iOS app on App Store, Android app on Play Store, both with the
  Gemma Good Family Medicine demo prescription preinstalled and
  reviewable end-to-end without external network.
- Cross-implementation parity test: Swift, Kotlin, and JS verifiers
  all pass the shared fixture set, byte-for-byte where the spec
  requires it.
- Three base LoRAs in production, with the safety adapter passing
  ≥99% on the red-team eval.
- One real prescribed clinic (besides the demo) using the app with at
  least three patients, for at least one full visit cycle.
- Public technical writeup linking back to the Kaggle submission and
  framing the app as the productization of the format the submission
  introduced.
