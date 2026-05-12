# Capsule Clinical — Visual Identity

## Style Prompt

Capsule is a portable, cryptographically-signed file format for AI-context records. The visual language pairs Swiss-grid clinical precision (Müller-Brockmann) with the lived authenticity of terminal output and signed envelopes — institutional gravity, never showy. Black canvas, monospace dominates technical surfaces, sans dominates UI/narrative surfaces. Verified-green appears only when something is actually verified. LLM-authored fields wear a warm amber tag — the same way Wikipedia's `{{citation needed}}` does — small, specific, never cosmetic. Generous negative space. Hairline rules instead of heavy boxes. Numbers are large and tabular. The format is the bet — make every signature, hash, and verification check feel weight-bearing.

## Colors

```
#0a0a0a   bg            near-black canvas, used everywhere
#141414   surface       panels, cards
#1f1f1f   surface-2     nested panels (decryption status, etc.)
#2a2a2a   border         hairlines, dividers
#f5f5f5   fg            primary text
#a3a3a3   muted         labels, attribution, captions
#525252   muted-2       very low priority text
#5fdb87   verified       cryptographic success only — terminal output, ✓ checks
#ff9f43   llm-amber     LLM-authored / untrusted fields
#7c9cff   brand-blue   Capsule brand moments (close card, links, info)
#dc2626   alert-red     errors only — used sparingly, NEVER decoratively
```

Tint neutrals slightly cool toward blue (Capsule brand). Pure `#000` is reserved for nothing. Headlines are `#f5f5f5`, body is `#f5f5f5` or `#a3a3a3` for secondary lines.

## Typography

- **IBM Plex Sans** — display and body. Weights: 300 (body fine print), 400 (body), 600 (labels, callouts), 700 (headlines, file IDs).
- **IBM Plex Mono** — terminal, code, file names, signatures, hex hashes, structured outputs from LLM probes. Weights: 400, 600.

Pairing rationale: same family, different mode. Sans and mono share IBM's institutional letterforms but contrast on rhythm — proportional vs monospaced. The file IS the bet, so the file's appearance (mono) earns visual weight against the narration (sans).

Treatments:
- `font-variant-numeric: tabular-nums` on every number — verifications, severity, confidence, byte counts.
- Tracking: `-0.02em` to `-0.03em` on display sizes. Mono stays at `0`.
- Headlines: 80–120px (single hero word) or 56–72px (two/three words).
- Body/narration captions: 32–40px (large enough for sound-off judges).
- Mono technical text: 28–36px.
- Mono micro-labels (file paths, hashes shown for atmosphere): 18–22px.
- Tiny attribution: 16px minimum.

## Motion

- **Eases**: `power3.out` for confident entrances (file icons, panels, terminal lines), `expo.out` for snap arrivals (✓ verifications, toast notifications), `sine.inOut` for breathing/ambient (file pulse, glow), `power2.out` for caption text, `back.out(1.4)` reserved for celebratory moments only (the close card).
- **Durations**: 0.4–0.7s for content entrances, 0.2–0.3s for accent toasts and ✓ stamps, 1.0–2.0s for the cold-open file pulse breath.
- **Stagger**: 60–120ms between siblings. Captions appear within 200ms of V/O alignment per the script's production note.
- **Cadence rule**: every scene has a build (entrances), breathe (visible content with ambient motion), resolve (transition takes the exit). No exit tweens except final scene fade.

## Transitions

- **Primary**: blur crossfade (0.5s, `power2.inOut`) — clinical, calm, says "this continues."
- **Accent (topic shifts)**: hard cut (0s) at the four ⚡-marked transitions in the script — cold open → ask, probes → seal, clinician → SSH verify. Emphasizes register change.
- **Outro**: color dip to black (0.7s, `power1.inOut`) into the close card.
- **Format note**: CSS-only. No shaders. The composition has too much fine technical text (file paths, hashes) for shader-capture artifacts.

## What NOT to Do

- **No matrix-terminal cliché.** Green text on black is fine for actual terminal output; everywhere else, use neutral fg. The verified-green is a verification color, not a theme color. Don't put green text on UI labels.
- **No glow halos around every element.** Glows are reserved for the file icon's ambient pulse and the verified ✓ moment. Adding glow to caption text or panels makes it feel like a screensaver, not a demo.
- **No gradient text.** Solid fills only. Gradient text is the AI design tell.
- **No purple-to-blue accents.** Capsule's blue is `#7c9cff`, used sparingly for brand moments — not as a default decorative color.
- **No mock chrome that looks fake.** Phone/iPad mockups are simplified geometric frames, not photorealistic Apple-product renders. Sell the file/format, not the device.
- **No shadows on flat panels.** Use border hairlines (1px `#2a2a2a`) for separation. Drop shadows on dark = murky.
- **No emoji except ✓ ✕ ✈ ⚡** — these four are semantic. Anything else is decoration.
- **No animated typing** longer than 3 seconds — the script calls for typed terminal lines, but keep them brief; long type-ons drag.

## Per-Scene Layout Cues

- **Cold open (Scene 1)**: file icon centered, breath/pulse, then terminal slides in below.
- **The Ask (Scene 2)**: kitchen-table proxy → use a stylized calendar/clock chyron and a paper-card mockup with mono URL.
- **Trust install (Scene 3)**: browser frame with prescribe.chat mockup; install confirmation panel.
- **Gemma probes (Scene 4 — HEADLINE)**: phone frame with chat bubbles. Three sub-beats: text → photo → audio. Each fires a toast. Photo and audio show structured output JSON next to the bubble.
- **Seal & transport (Scene 5)**: full-screen export panel with checklist, then AirDrop "ping" animation.
- **Clinician (Scene 6)**: iPad-shape frame with verified strip on top, three-lane reader below, co-occurrences section.
- **Format moat (Scene 7)**: SSH terminal, then three-implementation logos (JS/Python/Rust) stacked.
- **Close (Scene 8)**: file icon returns + brand block + URLs.

## Captions Policy

Per the script's production note: "Every V/O line should appear as on-screen text within 200 ms." Implementation: bottom-aligned caption strip across all scenes, IBM Plex Sans 400 at 32px, fg `#f5f5f5`, max-width 1500px, line-height 1.3. No background pill — just text on the dark canvas. Stagger by 80ms when caption changes.
