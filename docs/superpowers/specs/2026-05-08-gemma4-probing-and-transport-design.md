# Gemma 4 Probing + Patient-to-Doctor Transport — Design Spec

**Status:** approved (brainstorm), pending implementation plan
**Target:** Kaggle Gemma 4 Good Hackathon submission, deadline 2026-05-18
**Owner:** medical-journal example in `examples/medical-journal/`
**Capsule format:** v0.6 (no schema changes)

## Goal

Move the medical-journal example from "signed data format with Gemma stubs"
to "on-device Gemma 4 multimodal medical journal with end-to-end encrypted
patient-to-clinic delivery." Two coupled subsystems:

1. **Probing intelligence** — Gemma 4 actively probes the patient at three
   points (text intake, multimodal evidence, pre-export briefing) instead
   of passively logging whatever arrives.
2. **Transport** — multi-recipient encrypted capsules with a URL-based
   trust-establishment flow that runs through Edge Gallery's existing
   skill mechanism.

These ship together because the trust anchor (clinic's recipient pubkey)
must be on the patient device before the first encrypted export, and the
probing intelligence is what gives the demo something worth encrypting.

## Architecture

Three skills coexist on the patient device under Edge Gallery + Gemma 4,
each with one responsibility:

```
patient device (Edge Gallery + Gemma 4)
├── medical-journal     orchestrator + logger + sealer
├── clinical-probe      Gemma 4 intelligence (text + vision)
└── clinic:<rx7q>       trust anchor; installed once via prescribe.chat URL
```

```
clinician
├── reader.html         universal, zero-install, decrypts + renders
└── clinician-skill     optional Edge Gallery + Gemma 4 add-on for chain-grounded Q&A
```

`prescribe.chat` is a static site (GitHub Pages / Cloudflare Pages) hosting
per-clinic immutable JSON. One HTTP GET at install; offline forever after.

### Skill responsibilities

**medical-journal** (existing skill, refactored):
- Owns the chain (`localStorage` while in-flight, `.capsule` file as
  source of truth at rest).
- Reopens the encrypted `.capsule` using the patient's X25519 private key,
  appends new events, re-seals, writes back. The file on disk is always
  the canonical record.
- Calls `get_clinic_recipient()` from the installed `clinic:<short>` skill
  at seal time to obtain the clinic's X25519 pubkey.
- Encrypts the sealed capsule to **two recipients**: `[patient.pubkey,
  clinic.pubkey]`, using the v0.6 `key_bundles[]` mechanism.
- Bundles the `clinic:<short>` skill into the exported capsule's
  `skills/clinic-rx7q/` tree so the clinician's reader can confirm
  round-trip identity.
- Returns control to Gemma after each log; Gemma decides whether to
  invoke `clinical-probe` next based on user intent.

**clinical-probe** (new skill, the headline Gemma 4 demo):
- Three actions:
  - `intake_probe({intent, partial_fields})` — text-only. Returns 1–2
    clarifying questions Gemma asks the patient before logging. Used
    when the user's free-text doesn't supply enough to populate a
    `log_symptom` / `log_food` / `log_environment` event.
  - `multimodal_probe({media_b64, mime, lane})` ★ — Gemma 4 reads the
    bytes on-device and produces a structured finding plus 1–2
    evidence-tied follow-up questions. Two media types in v0.1:
    - **Photo** (image/jpeg, image/png, image/webp): Gemma 4 vision
      returns `{location_hint, color, texture, edge_quality, raised,
      size_estimate, confidence}` and a follow-up like "the edge looks
      raised on the upper-right; does that side itch more?"
    - **Audio** (audio/m4a, audio/wav, audio/aac, audio/webm): Gemma 4
      audio understanding returns `{transcript, classification (clear /
      wheeze / cough / hoarse / crackle / other), classification_confidence,
      duration_seconds}` and a follow-up like "I hear a wheeze on the
      out-breath; is it worse lying down or after exercise?"
    Both media bytes are persisted to the capsule's `payload/<id>.<ext>`
    tree and committed to the chain hash via `media_path`. Gemma's
    transcript / description / finding fields are flagged in
    `untrusted_payload_fields`. Video is parking-lot for v0.7+.
    This is the most multimodal-grounded call and the one that visibly
    proves Gemma 4 multimodal is running on-device.
  - `export_briefing({chain, practice_focus})` — reads the chain,
    generates a structured pre-visit summary (onset, severity trend,
    candidate triggers with co-occurrence stats, treatments tried, open
    questions). Output is plain text + structured JSON, embedded into
    the capsule's `program.md` at export.
- v0.1 implementation: `intake_probe` (text Gemma 4) and `multimodal_probe`
  (Gemma 4 vision for photos AND Gemma 4 audio for voice memos) call
  Gemma 4 on-device. `export_briefing` ships as deterministic JS
  (extending the current `correlateTriggers`) until the clinician-skill
  bridge is ready to consume a richer LLM-authored briefing in v0.7+.
- Stateless. Each Gemma-powered call is an independent inference.
- Marked `untrusted: true` for all LLM-authored fields it returns.

**clinic:<rx7q>** (new skill, generated per clinic):
- Tiny. One action: `get_clinic_recipient()` → `{name, x25519_pubkey,
  originator_allowlist, version, issued_at}`.
- All values are baked at build time into `skill.json`. No runtime
  network calls. Skill is installed via `prescribe.chat/<short>` URL.
- Schema versioned to allow future fields (e.g., revocation URL) without
  breaking existing installs.

### prescribe.chat — trust establishment

**Edge Gallery install constraint:** Edge Gallery exposes only two skill
install paths — *Load skill from URL* and *Import Local Skill*. There are
no deep links, custom URL schemes, or "tap a link → opens Edge Gallery"
intents. The patient must open Edge Gallery and paste the URL manually.
The trust-establishment design accommodates this constraint rather than
working around it.

URL pattern: `https://prescribe.chat/<short>` (e.g., `prescribe.chat/rx7q`).
4-char codes give 1.6M slots, ample for the demo and beyond. The URL is
the *install URL itself* (not a landing page) — pasted directly into Edge
Gallery's "Load skill from URL" input. It must be short enough to type
from a paper card if needed.

A separate human-readable preview is served at `prescribe.chat/about/<short>`
showing clinic name, address, pubkey fingerprint, and a copy-to-clipboard
button for the install URL. The clinic distributes either URL; the about
page is recommended for first-time patients, the bare install URL for
returning patients or text-message delivery.

Two endpoints per clinic:

| Path | Type | Purpose |
|---|---|---|
| `/about/<short>` | HTML | Human-readable preview; clinic name, address, pubkey fingerprint, copy-install-URL button |
| `/<short>` | JSON + MD bundle | The install URL pasted into Edge Gallery; `skill.json` carries the pubkey, `SKILL.md` carries the action surface |

Patient flow:
1. Patient receives `prescribe.chat/<short>` (or its `/about/` preview)
   via SMS / email / paper card / camera-scanned QR (decoded to clipboard).
2. (Optional) Patient opens the `/about/` page in a browser, reviews
   clinic name and pubkey fingerprint, taps "Copy install URL."
3. Patient opens Edge Gallery → *Load skill from URL* → pastes
   `prescribe.chat/<short>`.
4. Edge Gallery fetches the URL, displays the skill name from the
   manifest ("Riverside Dermatology — RX7Q"), patient confirms install.
5. `medical-journal` skill, on its next invocation that needs an
   encryption recipient, calls `get_clinic_recipient()` from the newly
   installed clinic skill and surfaces the clinic name + fingerprint to
   the patient one more time before any encrypt operation. First-use
   confirmation is required; subsequent uses cache the consent.

**Anti-phishing layers** (defense in depth, since there is no deep-link
auto-install dialog to do this once and trust):
- The `/about/` preview page is the recommended entry point and shows
  clinic name + address + pubkey fingerprint before any install action.
- Edge Gallery's own *Load skill from URL* dialog displays the skill
  name from the fetched manifest, derived from `clinic_name` in the
  skill JSON.
- `medical-journal`'s first-use confirmation re-surfaces the clinic
  name + fingerprint inside the skill flow, after install but before
  the first encryption.
- Short codes (`<4char>`) are issued non-sequentially and rate-limited
  on the prescribe.chat side to prevent enumeration / squatting of
  lookalike codes.

### Multi-recipient encryption (the "reopen and repackage" cycle)

The capsule file on the phone is the source of truth. localStorage holds
ephemeral working state and the patient's private keys; the chain itself
lives encrypted in the `.capsule` file.

On every log:

```
1. Read .capsule from app storage.
2. Decrypt content.enc using patient.x25519_priv (patient is recipient #0).
3. Open inner ZIP, parse chain.
4. Append new event(s), recompute hashes.
5. Re-seal: rebuild deterministic ZIP, re-sign envelope (signed_at = now).
6. Re-encrypt to [patient.pubkey, clinic.pubkey] with fresh content_key.
7. Write .capsule back.
```

The chain is append-only by hash linkage; "re-seal" creates a new envelope
signature over the extended chain. `signed_at` advances each time;
`first_event_hash` is invariant.

**Patient identity (X25519 + Ed25519):**
- Both keypairs generated on first run via Web Crypto.
- Stored as JWKs in `localStorage` under
  `capsule_medical_journal_patient_keys`.
- Exportable as a **plain `.pem`** file via the export panel — recommended
  at enrollment, mandatory before "wipe data." The export is an
  *availability backup* the patient holds until the capsule has been
  transported to the doctor, not a confidentiality wrapper. The patient
  is journaling their own life; the `.pem` ensures they don't lose
  access to that journal if localStorage is wiped. After the doctor has
  the capsule, the patient's continued ability to reopen is convenience,
  not protection.
- Importable from a `.pem` file when re-installing on a new device or
  after data clear. No passphrase prompt.
- Loss of the private key = inability to reopen own existing capsules.
  This is documented prominently in the export-key UX. The clinic still
  retains the ability to decrypt their copy of any previously-shared
  capsule, so loss is a UX problem, not a data-loss problem.

**Why this matters for the demo:** the `.capsule` file becomes the
patient's medical record artifact across sessions. After a week of
logging, there is one file on the phone, encrypted, that the clinician
opens cold months later and a new clinician — at a referral, at a second
opinion — opens with the patient's permission and a different recipient
key (added at re-export).

### Clinician side

**reader.html** (existing, extended):
- Drag-drop a `.capsule` → render lanes, correlation, audit trail (today).
- New: detect encrypted capsule (envelope `cipher: ChaCha20-Poly1305`),
  prompt for clinic private key (`.pem` file picker or paste).
- Decrypt → verify → render.
- New: render the bundled `skills/clinic-rx7q/skill.json` as the
  displayed trust anchor: "this capsule was encrypted to clinic
  <name>, fingerprint <hash>, installed by patient at <date>." If the
  clinician's local installed clinic skill matches, badge as "verified
  trust anchor"; otherwise warn.
- Static doctor-side prep card: candidate triggers, suggested questions
  drawn from a deterministic template based on practice_focus. *Not*
  LLM-generated; this keeps the universal reader zero-install.

**clinician-skill** (new, optional):
- Edge Gallery + Gemma 4 on the clinician device.
- Loads a `.capsule` (decryption flow as above), reads the chain,
  runs Gemma 4 to generate a chain-grounded pre-visit briefing
  (60-second read), structured Q&A targeting the highest-ranked
  candidate triggers, and a confidence-tagged differential.
- Architecture mirrors `clinical-probe` (stateless action surface,
  untrusted output marking, no network).
- Practice-specific specialty skills (derm, allergy/immunology, GI,
  general) are scoped as v0.7+ — clinician-skill ships as a
  general-practice baseline.

## Demo flow (the 90-second video)

1. Clinic shows `prescribe.chat/rx7q` (and an `/about/` QR) on a card.
2. Patient opens the `/about/` URL on iPhone → reviews clinic name +
   fingerprint → taps "Copy install URL" → opens Edge Gallery →
   *Load skill from URL* → pastes → Edge Gallery shows "Riverside
   Dermatology — RX7Q" → patient confirms → clinic skill installed.
3. Patient logs symptom: "my forearm is itchy again." Gemma calls
   `intake_probe` → asks "severity 1-10? where exactly?" → patient
   replies → `log_symptom` fires.
4. **Photo probe.** Patient takes photo of the patch. Gemma calls
   `multimodal_probe` with the JPEG bytes → on-device vision returns
   `{raised: true, edge: sharp, color: red, …}` and asks "the edge
   looks raised on the upper-right — does that side itch more?"
   Patient confirms → `log_photo` fires with the bytes (saved to
   `payload/<id>.jpg`) and the structured finding (in the chain event,
   `untrusted_payload_fields` populated).
5. **Audio probe.** Patient records a 12-second voice memo: "this is
   the wheeze I wanted Dr. Singh to hear." Gemma calls `multimodal_probe`
   with the audio bytes → on-device audio understanding returns
   `{transcript, classification: "wheeze", classification_confidence: 0.78}`
   and asks "is the wheeze worse lying down or after exercise?"
   Patient replies → `log_audio` fires with the bytes (saved to
   `payload/<id>.m4a`) and the structured finding.
6. Patient says "pack this for Dr. Singh." Gemma calls `export_briefing`
   → produces structured pre-visit summary → `medical-journal`
   reopens existing `.capsule` (decrypts with patient's own key),
   appends new events, re-seals, encrypts to `[patient, clinic]`,
   writes file. Export panel shows verification passing on the
   encrypted artifact and lists the bundled media files.
7. Patient AirDrops the `.capsule` to clinician's iPad.
8. Clinician opens `reader.html` → drag-drops → loads clinic private
   key → decryption succeeds → trust anchor verified → lanes render
   with photo inline + audio playable → static prep card visible.
9. (Optional) Clinician opens `clinician-skill` in Edge Gallery →
   loads same capsule → Gemma 4 generates the pre-visit briefing.

Airplane mode visible on screen throughout steps 3–9. Network only at
step 2 (one-time skill install) and step 7 (AirDrop is local-radio,
not internet).

## Scope cuts for 10-day delivery

In scope (must ship by 2026-05-18):
- ✓ medical-journal refactor (orchestration, reopen/append/re-seal cycle)
- ✓ clinical-probe skill with `intake_probe` (text Gemma 4),
  `multimodal_probe` for both photos (Gemma 4 vision) and audio
  (Gemma 4 audio understanding) wired to real on-device Gemma 4 calls
- ✓ Photo and audio bytes persisted to capsule `payload/` tree, hashed
  via `media_path`, round-tripped byte-identically through encryption
- ✓ clinic skill template + 1–2 demo clinics on prescribe.chat
- ✓ Multi-recipient encryption (patient + clinic) using existing v0.6
  format support
- ✓ Patient X25519 keypair generation, plain `.pem` export, plain `.pem`
  import. The `.pem` is an *availability backup* (so localStorage wipes
  don't strand the patient from their own past entries) — not a
  confidentiality wrapper. Password-encryption is parking-lot for v0.7+.
- ✓ reader.html decryption support + trust-anchor rendering + inline
  photo render + audio playback + static prep card
- ✓ Edge Gallery URL-install flow (no deep links): `prescribe.chat/<short>`
  install URL + `/about/<short>` preview page
- ✓ End-to-end demo recording on real devices, airplane mode
- ✓ Technical writeup + 3-min video + public repo

Out of scope (parking lot, flagged in writeup as v0.7+):
- ✗ Video probe (movement analysis, multimodal_probe for video/mp4)
- ✗ `export_briefing` as Gemma 4 call — ships as deterministic JS
  template until clinician-skill is ready
- ✗ clinician-skill — stub it as a README example; full implementation
  post-deadline
- ✗ Specialty clinician skills (derm, allergy, GI)
- ✗ Skill revocation / key rotation
- ✗ Custodial recovery for patient private keys
- ✗ Real prescribe.chat domain — start with GitHub Pages subdomain;
  domain registration if time permits
- ✗ Local-skill (`Import Local Skill`) install path as a fallback —
  v0.1 documents URL install only; sideload would let the design work
  without prescribe.chat hosting at all and is a v0.7+ resilience win

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | ~~Edge Gallery doesn't support skill-from-URL install~~ — *resolved*: Edge Gallery supports *Load skill from URL* and *Import Local Skill* only. URL flow confirmed; no deep-link auto-install dialog. Anti-phishing relies on multi-layer name+fingerprint surfacing. | Design adapted to manual-paste flow; sideload remains a v0.7 fallback if prescribe.chat hosting fails. |
| 2 | Gemma 4 vision OR audio latency on mid-tier Android too slow for live demo | Benchmark both modalities on day 2. Fallback: pre-warm the model on first invocation; use the smallest Gemma 4 multimodal variant available; record demo on a flagship if needed. Audio probe especially — transcription is more compute than expected on some chips. |
| 3 | Web Crypto doesn't ship ChaCha20-Poly1305; vendored AEAD adds bytes/risk | Use a minimal vetted JS implementation (e.g., libsodium.js subset). Same dependency as the existing roadmap parking-lot note. |
| 4 | Skill-to-skill orchestration in Edge Gallery is implicit (Gemma routes), not explicit (skill A calls skill B) | Design assumes implicit. medical-journal returns "needs probe" hints; Gemma decides. If Edge Gallery offers explicit cross-skill calls, optimize later. |
| 5 | ~~Multi-recipient encryption underspecified in v0.6 prototype SDK~~ — *resolved by audit*: the Node SDK has full `CapsuleBuilder.seal({recipients})` + `CapsuleReader.decrypt()` with tests. The actual gap is **browser-side**: `medical-journal-builder.js` runs in Edge Gallery's WebView and currently has only Ed25519+SHA-256 via Web Crypto. Browser needs X25519 ECDH (Web Crypto, modern), HKDF-SHA256 (Web Crypto), and a vendored ChaCha20-Poly1305 (not in Web Crypto). | Vendor `@noble/ciphers` (subset) for ChaCha20-Poly1305; everything else via Web Crypto. |
| 6 | "Repackaging on every log" amplifies write costs / battery drain | Acceptable for the demo. v0.7 can add lazy seal (in-memory chain, periodic flush). |
| 7 | Patient loses private key, can't reopen own capsule | Docs + UX mandate `.pem` export at enrollment. Clinic still has its copy. |
| 8 | prescribe.chat domain not owned at submission time | Use GitHub Pages subdomain (`virion-ai.github.io/prescribe`) for submission; register domain post-deadline. |

## Open questions deferred to implementation

- Exact Edge Gallery skill-install URL scheme (verify day 1).
- Whether `multimodal_probe` returns one structured finding object or a
  ranked list of candidate findings (probably one, with `confidence`).
- ~~Whether the patient's identity export `.pem` should be password-encrypted~~
  *resolved*: plain `.pem` for v0.1. The export's purpose is availability
  (the patient's own access to their journal) until the capsule is
  transported to the doctor, not confidentiality protection on the file
  itself. Password-encryption is parking-lot for v0.7+.
- ChaCha20-Poly1305 implementation choice (libsodium.js vs noble-ciphers
  vs hand-rolled).
- Whether `signed_at` should advance on every reopen-append-reseal cycle
  (yes — it represents the seal time of *this* version of the chain).

## Test plan summary

Extends `parity-test.mjs`:
- Build encrypted capsule with two recipients.
- Decrypt with patient key, verify chain.
- Decrypt with clinic key, verify chain. Assert byte-identical inner ZIP.
- Reopen-append-reseal cycle: starting from a sealed encrypted capsule,
  append three events (one symptom, one photo, one audio), re-seal,
  verify the new capsule still decrypts, chain length is original + 3,
  hash linkage holds, media payloads round-trip byte-identically.
- `multimodal_probe` integration tests (mock Gemma 4 with deterministic
  output for reproducibility):
  - Photo: JPEG bytes → `{raised, edge, color, …}` finding → `log_photo`
    event includes finding fields, `untrusted_payload_fields` covers
    LLM-authored entries, photo bytes land at `payload/<id>.jpg`.
  - Audio: WAV/M4A bytes → `{transcript, classification, confidence}`
    finding → `log_audio` event includes finding fields,
    `untrusted_payload_fields` covers transcript + classification, audio
    bytes land at `payload/<id>.<ext>`.
- Identity round-trip: export plain `.pem`, wipe localStorage, reimport,
  decrypt prior capsule successfully. (Availability backup; no passphrase.)
- Tamper tests extended: tampered ciphertext fails before decryption;
  tampered key bundle fails recipient resolution; mismatched clinic
  trust-anchor in bundled skill warns at clinician reader; tampered
  media bytes detected via chain hash mismatch on `media_path` field.

## Definition of done for the Kaggle submission

- Demo video shows: URL install via Edge Gallery's *Load skill from URL*
  → patient logs with **photo** multimodal probe (Gemma 4 vision call
  latency ≤ 5s on a Pixel 8) → patient logs with **audio** multimodal
  probe (Gemma 4 audio call latency ≤ 8s on a Pixel 8 for ≤30s clip) →
  encrypted export with both media in `payload/` → AirDrop → clinician
  decrypt → trust anchor verified → lanes + photo inline + audio
  playback + correlation + static prep card rendered.
- Repository is public, README points to the medical-journal example as
  the canonical demo, build + parity-test green (incl. audio round-trip).
- Technical writeup explains: capsule format crypto, multi-recipient
  encryption, three-skill architecture, Gemma 4 multimodal call sites
  (photo + audio), trust establishment via prescribe.chat under the
  Edge Gallery URL-install constraint, the v0.7+ parking lot.
- Airplane-mode segment of demo video runs without network and exercises
  both multimodal probes + encryption + AirDrop + decryption.
