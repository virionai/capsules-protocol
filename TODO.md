# TODO

Tactical task list across the project. `ROADMAP.md` holds the strategic
milestones with kill criteria; this file holds concrete items still
owed, grouped by area and tagged by priority relative to the Kaggle
deadline (**2026-05-18**).

Legend: **P0** must ship for the deadline · **P1** should ship · **P2**
post-deadline parking-lot.

---

## Capsule v0.6 SDKs (`sdk-swift/`, `sdk-kotlin/`)

Both SDKs are code-complete in source form but **not compile-tested in
an IDE this session**. First steps for the next instance:

- [ ] **P0** — Open `sdk-swift/` in Xcode 15+ via `swift build` and run
      `Tests/CapsuleTests/RoundTripTests.swift`. Surface and fix any
      ceremony issues (likely small: an import, a CryptoKit availability
      gate, etc.).
- [ ] **P0** — `cd sdk-kotlin && ./gradlew :core:compileKotlin
      :skills:compileKotlin :llm:compileKotlin :ui:assembleDebug` to
      shake out compile issues. Likely small.
- [ ] **P1** — Add Kotlin SDK round-trip tests parallel to the Swift
      ones (build a capsule via `:core`, run `CapsuleVerifier.verify`,
      assert pass; flip a byte, assert fail). Lives in
      `sdk-kotlin/core/src/test/kotlin/`.
- [ ] **P1** — Cross-impl byte-parity test: feed identical chain inputs
      into Node SDK + Swift SDK + Kotlin SDK and compare the produced
      `manifest_hash` and `content_index_hash`. They should match
      exactly per the spec's determinism boundary. (`sdk/`'s
      verifyCapsule already accepts what the JS reference produces;
      this widens the parity claim.)
- [ ] **P1** — `medlog-ios` and `medlog-android` currently inline the
      Capsule core. Migrate them to depend on the SDK packages
      (SwiftPM `.package(path: "../../sdk-swift")` and Gradle
      `includeBuild("../../sdk-kotlin")`). Removes ~1500 LOC of
      duplication.
- [ ] **P2** — Tag and publish: SPM tag + Maven Central artifact
      (`ai.virion.capsule:core:0.6.0-prototype.1`). Block on first
      independent code review of the crypto.
- [ ] **P2** — Multi-signer `seal()` path. The lower-level
      `Envelope.sign` already accepts `[Signer]`; the high-level
      Builder only takes the originator. Surface multi-signer when a
      caller actually needs it (e.g., notary-co-signed handoffs).
- [ ] **P2** — Encryption: X25519 + HKDF-SHA256 + ChaCha20-Poly1305
      multi-recipient. iOS gets ChaCha via `swift-crypto`; Android gets
      it via the existing BouncyCastle dependency. Ships alongside the
      patient ↔ clinic flow on `medlog`.
- [ ] **P2** — Edge Gallery `CapsuleSkillRuntime` adapter as a separate
      `CapsuleEdgeGallery` target / `:edge` module. The `WebviewSpec`
      shape already matches the Edge Gallery `webview` response field;
      adapter is ~30 LOC of bridging.

---

## medlog (`examples/medical-journal/medlog-{ios,android}/`)

- [ ] **P0** — Compile-test in Xcode and Android Studio. Same expected
      issues as the SDKs: small ceremony.
- [ ] **P1** — Live photo / audio / video capture. Chain entries already
      carry `media_id`, `media_path`, `mime`; the missing piece is
      AVFoundation + PHPickerViewController on iOS and CameraX +
      MediaRecorder on Android. The seal step packs whatever the
      MediaStore can resolve.
- [ ] **P1** — prescribe.chat code redemption inside the app (paste a
      4-char code → fetch the clinic recipient skill at
      `prescribe.chat/<code>` → first-use confirm screen showing clinic
      name + key fingerprint → store recipient pubkey). Ships once
      Capsule encryption lands.
- [ ] **P1** — Wire real Gemma-4 E2B inference. Both projects already
      declare the dependency surface (MediaPipe `tasks-genai` on
      Android; `MediaPipeTasksGenAI` pod on iOS). Swap
      `StubLocalLLM` → `MediaPipeLocalLLM` once the `.task` bundle
      ships. Cold-start latency target ≤ 5 s for text on a Pixel 8 /
      iPhone 14 Pro per the design spec.
- [ ] **P2** — Reopen-append-reseal cycle: treat the encrypted
      `.capsule` on disk as the source of truth across sessions.
      Patient's chain decrypts, gets new events appended, re-seals,
      re-encrypts to `[patient, clinic]`. Documented in the design spec.
- [ ] **P2** — `.pem` export/import for the originator key — the
      "availability backup" path so a localStorage / Keychain wipe
      doesn't strand the patient from their own past entries.

---

## prescribe.chat (`examples/medical-journal/prescribe-chat/`)

- [ ] **P0** — Pick a deploy host. Cloudflare Pages or Netlify gives
      the bare `prescribe.chat/rx7q` install URL via `_redirects`;
      GitHub Pages forces `prescribe.chat/rx7q.zip`. Demo flow tolerates
      either, but the bare form is materially nicer on the printed card.
- [ ] **P1** — Self-host the Google Fonts (EB Garamond + JetBrains
      Mono). Currently one fonts.googleapis.com fetch on first visit;
      the rest of the site is local-only. Removing it removes the only
      third-party request a privacy-minded reviewer would flag.
- [ ] **P1** — Templating for the `about/<short>.html` page. v0
      hand-authors per clinic; once 3+ clinics exist, generate from
      `clinics/<short>.json` via an extension to `build-clinic-bundle.mjs`.
- [ ] **P2** — Real prescribe.chat domain. Submission can ship as a
      Cloudflare Pages or `virion-ai.github.io/prescribe` subdomain;
      register the bare domain post-deadline.
- [ ] **P2** — iOS Edge Gallery URL placeholder. `index.html` and
      `about/rx7q.html` both link `iPhone → App Store` to
      `#ios-coming-soon`. Replace with the real URL once Google ships
      the iOS build.

---

## Demo + submission (Kaggle Gemma 4 Good Hackathon)

- [ ] **P0** — Record the 90-second demo video on real devices,
      airplane mode through steps 3–9. The flow is enumerated in
      `docs/superpowers/specs/2026-05-08-gemma4-probing-and-transport-design.md`
      §"Demo flow". Needs a Pixel 8 (Edge Gallery + medlog-Android),
      an iPhone 14 Pro+ (medlog-iOS), and an iPad (clinician reader).
- [ ] **P0** — Public repository with a clear README pointing readers
      at the medical-journal example as the canonical demo.
- [ ] **P0** — Technical writeup (≤ 3000 words) covering: Capsule
      format crypto, multi-recipient encryption, three-skill
      architecture (medical-journal + clinical-probe + clinic), Gemma 4
      multimodal call sites (photo + audio), trust establishment via
      prescribe.chat, the v0.7+ parking lot. The writeup is where the
      *format moat* gets articulated; without it the submission reads
      as "a good Kaggle app" instead of "a launch of an open standard."
- [ ] **P1** — Land at least one outside engineer to read the spec and
      author a 200-line Python or Rust capsule verifier against the
      test vectors before submission. **This is the single highest
      moat-strengthening signal**: it converts "interesting JS library
      with native ports" into "format with a fourth-language
      independent implementation by someone outside the project." Even
      a half-finished PR is worth showing in the writeup.
- [ ] **P2** — Specialty clinician skills (derm, allergy, GI). v0
      ships a general-practice baseline.
- [ ] **P2** — One real clinic willing to issue a `prescribe.chat`
      code for an actual pilot. Names a real adoption signal.

---

## Capsule v0.6 spec

- [ ] **P2** — Encryption tightening: a written test vector for the
      multi-recipient flow once both native SDKs implement it.
      Currently exercised only in the JS SDK + tamper-detection
      example.
- [ ] **P2** — RFC 3161 / Rekor temporal anchoring. Self-attested
      `signed_at` is good enough for v0.6 demos; clinical use will
      eventually want an anchor.
- [ ] **P2** — Identity registry / federation. v0.6 binds capsule
      identity to the originator key; trust is the host's allowlist.
      A registry is parking-lot until adoption signal warrants it.

---

## Notes for the next instance

- The medlog + SDK Capsule cores were authored against the JS
  reference at
  `examples/medical-journal/edge-gallery-skill/assets/medical-journal-builder.js`,
  which itself is parity-tested against the Node SDK at `sdk/`. So
  the algorithm chain is: JS reference (parity-tested) → Swift core
  (uncompiled) → Kotlin core (uncompiled). The first compile + test
  pass is the single most valuable thing to do.
- Where Swift / Kotlin behaviour diverges from JS, the JS reference
  is the source of truth — that's the test vector the Node SDK's
  `verifyCapsule()` accepts.
- Auto mode and bash + write tools have been the working environment
  here; a fresh session can pick up by reading `MEDLOG.md`,
  `sdk-swift/README.md`, `sdk-kotlin/README.md`, and this file.
