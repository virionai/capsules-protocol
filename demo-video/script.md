# Medical Journal — Capsule v0.6 launch demo

**Submission:** Kaggle Gemma 4 Good Hackathon · 2026-05-18
**Length:** 3:00 (with 1:30 highlight-reel cut markers · cuts marked ⚡)
**Audio:** single narrator V/O, ambient device sounds, no music until 2:45

---

## 0:00–0:10 — COLD OPEN ⚡

[**Visual:** Black. A single file icon fades in, centered: `medical-journal-2026-05-08-c18ac983.capsule` · 16.8 KB. Hold three seconds. The file pulses once.]

**V/O:** This is one file.

[Cut to: same file dragged into a Mac terminal. Single line types itself: `$ capsule verify medical-journal-2026-05-08-c18ac983.capsule`. Output prints in green: `verified · originator: ed25519:74b096cc6983… · 18 events · 3 media payloads`. Cursor blinks.]

**V/O:** Encrypted. Signed. Written by an on-device LLM in airplane mode. Opened cold by a doctor with no install.

[Cut to: title card, low-key. **Capsule** · *portable, signed, verifiable AI-context records*. Smaller line: `medical-journal — Kaggle Gemma 4 Good Hackathon, 2026`.]

---

## 0:10–0:30 — THE ASK ⚡

[**Visual:** Hand-held, eye level. Patient at a kitchen table on Tuesday morning, scratching their forearm. Caption: **Tuesday, 7:42 a.m.**]

**V/O:** Most of what a clinician needs to see happens between visits.

[Patient picks up a Pixel 8. Pulls up Edge Gallery. **Airplane mode icon visible in status bar**, large enough to register. Caption appears bottom-left: ✈ *airplane mode — entire patient flow*.]

**V/O:** This patient is journaling for an allergy clinic. Their doctor prescribed it on a paper card — a single short URL.

[Quick cut: paper card on the kitchen table, large text `prescribe.chat/rx7q · Riverside Dermatology`.]

---

## 0:30–0:55 — TRUST INSTALL

[**Visual:** Phone screen recording. Patient opens `prescribe.chat/about/rx7q` in a browser. Page shows clinic name, address, pubkey fingerprint (`A7F2…1B83`), big button: *Copy install URL*.]

**V/O:** The about page shows the clinic's name, address, and key fingerprint. The patient confirms it's the right clinic before installing anything.

[Patient taps Copy. Switches to Edge Gallery. Taps *Load skill from URL*. Pastes. Edge Gallery shows confirm dialog: "Install skill **Riverside Dermatology — RX7Q**?" Patient confirms.]

**V/O:** Edge Gallery installs the clinic's trust anchor. One HTTP call, ever. After this, the patient is offline for the rest of the demo.

[Phone goes back to airplane mode confirmation, ✈ icon flashes briefly.]

---

## 0:55–1:25 — GEMMA 4 PROBES (the headline shot)

[**Visual:** Patient back in Edge Gallery chat. Types: *"my forearm is itchy again."*]

[Gemma 4 response bubbles in. Caption: **Gemma 4 · on-device · text intake probe**.]

**Gemma (text on screen):** Severity 1 to 10? Where exactly?

[Patient: *"a 7, the same patch on my left forearm."* Gemma confirms, fires `log_symptom`. Tiny chain-event toast slides in: ✓ *symptom logged · seq 14*.]

**V/O:** Gemma asks the questions a clinician would. Then it logs the answer.

[Patient taps the camera button. Snaps the rash. **Caption:** *Gemma 4 · multimodal probe · vision*.]

[Screen recording: Gemma 4's structured finding renders inline: `{raised: true, edge: sharp, color: red, size_estimate: 4cm}`. Below it, a follow-up: *"the edge looks raised on the upper-right — does that side itch more?"* ]

[Patient: *"yes, way more there."* `log_photo` fires. Toast: ✓ *photo logged · payload/p-…jpg*.]

[**Visual cut:** Patient holds phone to mouth, records 12 seconds of audio. **Caption:** *Gemma 4 · multimodal probe · audio*.]

[Screen: structured output: `{transcript: "this is the wheeze I want Dr. Singh to hear…", classification: wheeze, confidence: 0.78}`. Follow-up: *"is the wheeze worse lying down or after exercise?"*]

[Patient replies. `log_audio` fires. Toast: ✓ *audio logged · payload/a-…wav*.]

**V/O:** Vision and audio. Gemma's interpretation goes in the chain — flagged untrusted. The bytes go in the file.

---

## 1:25–1:55 — SEAL & TRANSPORT ⚡

[**Visual:** Patient: *"pack this for Dr. Singh."* Edge Gallery responds. Export panel slides up.]

[Panel shows: *Sealed and signed on-device · 18 events · 3 media files · capsule_id c18ac983… · trust anchor: Riverside Dermatology RX7Q*. Below: ✓ envelope signature ✓ capsule_id derives ✓ content index ok ✓ chain hashes contiguous. Two buttons: **Save .capsule** · **Share…**.]

**V/O:** The skill reopens its existing capsule, appends the new events, re-seals, and re-encrypts to the patient and the clinic. The file on disk is the medical record.

[Patient taps Share → AirDrop → clinician's iPad. AirDrop animation completes.]

**V/O:** Local radio, not the internet. Airplane mode still on.

---

## 1:55–2:30 — CLINICIAN SIDE

[**Visual:** Hand on iPad. Wifi off. Clinician taps the AirDropped file → opens in `reader.html` (saved as a bookmark, no install).]

[Reader prompts: *Recipient key required to decrypt.* Clinician picks `riverside-derm.pem` from Files. Decrypt succeeds. Page renders.]

[**Header strip:** ✓ verified · format 0.6 · 18 chain events · signed by originator · trust anchor: **Riverside Dermatology RX7Q** ✓ matches local install.]

**V/O:** The reader rebuilt every hash, verified the patient's signature, and confirmed the capsule was sealed to *this* clinic — not impersonated. All offline.

[**Visual:** scroll through. Three-lane layout: Symptoms · Foods · Environment. Severity sparkline. Below: a section labeled **Co-occurrences (±24h around high-severity symptoms)**:]

> **Foods** ×2 cheese pizza · ×2 Greek yogurt with honey
> **Environment** ×2 pet_dander · ×1 pollen

[Aux section: photo renders inline (the actual rash). Audio player below it (Play arrow, 12 s). Each LLM-authored field has a small orange "LLM" tag.]

**V/O:** Three lanes. Candidate triggers. Photos and voice memos the clinician can play right there. Everything Gemma authored is flagged.

[Clinician taps play on the audio. Wheeze plays. Hold for 2 seconds.]

---

## 2:30–2:50 — THE FORMAT MOAT ⚡

[**Visual:** Cut to a black terminal. Single line types itself:]

```
$ ssh verify@capsules.run < medical-journal-2026-05-08-c18ac983.capsule
```

[Output prints in green:]

```
✓ verified
  originator: ed25519:74b096cc6983…
  signed_at:  2026-05-08T17:16:55Z
  events:     18
  media:      3 files (337 B + 1644 B + 32 B)
attestation: rfc8785 · sha256(envelope) c1225fba96b5…
```

**V/O:** Same file. Verified by SSH. No client install, no Capsule keypair to bootstrap — the clinician's existing SSH key is the trust path.

[Cut: split-screen with three logos / words appearing in sequence: **JavaScript** · **Python** · **Rust**. Below: small line — *bit-identical against signed v0.6 test vectors*.]

**V/O:** Three independent implementations. One spec. The format is the bet. The journal is the proof.

---

## 2:50–3:00 — CLOSE

[**Visual:** Back to the single file icon from the cold open. Below it now:]

> **Capsule** · portable, signed, verifiable AI-context records
> capsules.run · github.com/virion-ai/capsule
> medical-journal — Kaggle Gemma 4 Good Hackathon

[Music swells once, briefly. Cut to black.]

**V/O:** One file. Patient owns it. Doctor reads it. Anyone can verify it. That's Capsule.

---

## 1:30 highlight-reel cut

Use the four ⚡-marked segments back to back, omit the install + transport detail, drop the closing card to 4 seconds:

- 0:00–0:10 cold open (10 s)
- 0:55–1:25 Gemma probes (compressed to 30 s — drop one of photo / audio depending on benchmark winner)
- 1:25–1:35 seal panel only (10 s)
- 1:55–2:15 clinician decrypt + lanes + inline media (20 s)
- 2:30–2:50 SSH verify (20 s)
- 2:50–2:54 close card (4 s)

= 1:34. Trim a beat in the seal panel and you're at 1:30.

---

## B-roll / cutaways the editor will want

- Tight macro of the rash on the patient's forearm (consent on file)
- 2-second loops of: airplane-mode icon engaging, AirDrop send animation, ✓ verified strip in reader, terminal cursor on `capsule verify`
- Slow scroll of `chain/events.jsonl` opened in a text editor — shows real JSON, untrusted_payload_fields visible
- Static still: the prescribe.chat paper card, on a clipboard, next to a stethoscope (sells the clinic-issuing-the-journal frame)
- 3-second screen capture: `cat medical-journal.capsule | xxd | head` — hex bytes scrolling, "this is just a file" reinforcer

---

## Production notes

1. **The airplane-mode chyron is non-negotiable.** Bottom-left, persistent from 0:30 to 2:00. Judges who skim need to see it without listening.
2. **Real Gemma 4 latency.** If photo+audio probes total > 8 s on the demo Pixel, cut the audio probe from the 3-minute and the 90-second versions. Audio is replaceable; photo isn't (vision is the headline multimodal claim).
3. **One take of the SSH verify.** Pre-warm the connection. The ✓ should print in under two seconds or it kills the segment.
4. **Captions throughout.** Many judges skim with the sound off. Every V/O line should appear as on-screen text within 200 ms.
5. **Don't show the clinic's private key file picker for more than half a second.** "It's a file on disk" is the read; lingering on the picker invites questions about key management we don't want to answer in the video.
6. **The closing card stays on long enough to read the URL.** Four seconds minimum. People will pause to type it.

---

## What this script does *not* show, deliberately

- The Edge Gallery chat UI in detail (don't sell the runtime, sell the format)
- Specifics of multi-recipient encryption (one V/O sentence; the writeup carries it)
- The CLI's full surface (`capsule verify` is enough; `inspect`, `seal`, `unseal` are for the docs)
- Any cloud workflow — `capsules.run` exists but the demo's clincher is that the file works *without* it. Save the runtime story for the developer launch.

The 3-minute version sells the format through the medical demo. The 90-second cut sells the format through the file. Both end on `Capsule`.
