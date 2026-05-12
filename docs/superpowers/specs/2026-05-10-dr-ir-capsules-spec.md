# DR/IR Capsule Examples — Design Spec

**Status:** approved (controller-set), pending implementation
**Target:** demonstrate Capsule v0.6 as a portable, signed, verifiable preparedness artifact across three audience scopes — Town, Family, Business — for the Kaggle Gemma 4 Good Hackathon (Crisis Response / Global Resilience track plus cross-cutting tracks)
**Owner:** new examples at `examples/town-dr/`, `examples/family-dr/`, `examples/business-dr/`
**Capsule format:** v0.6 (no schema changes)

## Why these three

A disaster/incident-response capsule is the cleanest possible Crisis Response track answer for Capsule because the format's headline properties — *signed*, *portable*, *verifiable*, *offline-first* — are exactly what a DR plan needs:

- A town wants to **publish** a plan that anyone can verify came from the town's emergency-management office, that a citizen can use offline when the power and network are down.
- A family wants to **hold** a plan that doesn't depend on any cloud service to read at 2 a.m. when their phone is at 6% battery.
- A business wants to **distribute** an encrypted plan to authorized roles (owner, BCM, IT lead) without trusting a SaaS vendor with vendor contracts and employee PII.

Same format. Three audiences. One demo arc.

## How Gemma fits

On the user's phone, Gemma 4 E4B reads the capsule (or its public surface for encrypted variants), and serves three distinct modes:

1. **Prep mode** — "Walk me through filling out my family DR plan." Gemma authors structured entries via the skill's log_* actions.
2. **Drill mode** — "Quiz me. Earthquake hits — what do I do?" Gemma reads the plan's scenarios and runs interactive drills, logs the result.
3. **Incident mode** — "There's smoke. Help." Gemma identifies the most-applicable scenario and walks the user through it step-by-step, logging decisions to the chain so the after-action review is captured automatically.

For the demo, **prep mode and drill mode** are the headline interactions. Incident mode is the payoff shot.

## Existing Edge Gallery skills to compose with

Per research at `github.com/google-ai-edge/gallery/tree/main/skills` (built-in + featured):

| Existing skill | How a DR capsule uses it |
|---|---|
| `interactive-map` | Render shelters, evacuation routes, hazard zones, family meeting points |
| `query-wikipedia` | Educational content during drill mode ("what is sheltering in place?") |
| `send-email` | Notify out-of-area emergency contact, send BCP status updates |
| `qr-code` | Encode the prepare.chat install URL on a printed go-bag tag |
| `calculate-hash` | Verify a freshly-distributed plan matches the town's published fingerprint |

Each DR skill's `SKILL.md` should explicitly call out which built-in skills the LLM may chain to for richer interactions. This is what makes Gemma "load-bearing" instead of decorative — the capsule's data is referenced *across* skills the user already has.

## Shared schema (all three examples)

DR/IR capsules share a structured plan plus a chain of *operational events* (drills, incidents, decisions, status updates). The plan is "snapshot data" — entries that define the world. The operational events are "what happened" — drills run, incidents experienced, decisions made.

### Event types

All `kind: "observation" | "decision" | "mutation"` per v0.6 chain schema.

**Plan-definition events** (`kind: "mutation"`):

| `action` | Used for | Required payload fields |
|---|---|---|
| `defined_scenario` | Add a hazard scenario | `slug`, `label`, `hazard_kind`, `severity_tier`, `summary` |
| `defined_action_step` | Add a step in a scenario's plan | `scenario_slug`, `seq`, `actor`, `instruction`, `time_estimate` |
| `defined_contact` | Add a contact (person or org) | `slug`, `name`, `role`, `phone`, `when_to_call` |
| `defined_resource` | Add a resource (location, supply, service) | `slug`, `label`, `resource_kind`, `address_or_coords`, `notes` |
| `defined_role` | Bind a contact slug to a role in a scenario | `scenario_slug`, `role`, `contact_slug` |
| `defined_supply` | Inventory entry (go-bag contents, business critical inventory) | `slug`, `label`, `quantity`, `location`, `expires_at` |

**Operational events** (`kind: "observation" | "decision"`):

| `action` | Used for | Required payload fields |
|---|---|---|
| `logged_drill` | Record a drill exercise | `scenario_slug`, `drill_kind`, `outcome`, `notes` *(untrusted)* |
| `logged_incident_status` | Snapshot during an incident | `scenario_slug`, `status`, `location`, `notes` *(untrusted)* |
| `logged_decision` | Capture a choice made during an incident | `scenario_slug`, `decision`, `rationale` *(untrusted)*, `decided_by` |
| `after_action_report` | Post-incident retrospective | `scenario_slug`, `what_worked` *(untrusted)*, `what_didnt` *(untrusted)*, `corrective_actions` *(untrusted)* |
| `asked_question` | Patient-side Q&A | `question`, `answer` *(untrusted)* |

**Untrusted prose** flagging: `notes`, `rationale`, `summary`, `what_worked`, `what_didnt`, `corrective_actions`, `answer` — any field that's LLM-authored prose or could be LLM-paraphrased.

### Hazard kinds

A controlled vocabulary the LLM picks from (no free-form):

```
earthquake · flood · wildfire · house_fire · severe_weather · tornado · hurricane
power_outage · water_outage · cold_snap · heat_wave · active_threat
medical_emergency · cyber_incident · supply_disruption · pandemic
hazmat_release · evacuation_order · other
```

### Severity tiers

```
minor (drill / preparedness) · moderate (localized event) · major (community-wide) · critical (life-threatening)
```

### Resource kinds

```
shelter · hospital · pharmacy · police · fire_station · gas_station · grocery
cooling_center · warming_center · meeting_point · supply_cache · vendor
office_location · school · place_of_worship · other
```

### Drill kinds

```
tabletop · walkthrough · full_drill · evacuation_drill · communication_drill · post_incident_review
```

## Bootstrap URLs (`prepare.chat`)

All three examples share the `prepare.chat/<short>` install pattern, mirroring `prescribe.chat`. The short codes encode the audience tier in the prefix:

- **Town:** `prepare.chat/T-<TOWN-CODE>` — e.g., `prepare.chat/T-RIVERSIDE-CA`
- **Family:** `prepare.chat/F-<FAMILY-CODE>` — e.g., `prepare.chat/F-7QFP`
- **Business:** `prepare.chat/B-<BIZ-CODE>` — e.g., `prepare.chat/B-ACME-CORP`

Each prefix routes to a different about page format, but the install URL itself is what gets pasted into Edge Gallery's *Load skill from URL*.

**SMS-shareable bootstrap:** the URL is short enough for SMS. The town emergency manager texts every resident:

> Riverside emergency prep: prepare.chat/T-RIVERSIDE-CA — open in browser, then add to Edge Gallery. Works offline once installed.

## Per-example specifics

### Town DR (`examples/town-dr/`)

**Audience:** every citizen of a town.
**Encryption:** none. Town plans are public information.
**Originator:** the town's emergency management office (signs the published plan capsule).
**Patient identity:** the citizen's device generates its own Ed25519 keypair on first install; the citizen's *additions to their copy* (drill outcomes, personal incident logs) are signed by their key. The original plan is signed by the town.

**Multi-signer envelope:**
- `originator` — town emergency management Ed25519 key (published)
- (optional) `creator` — citizen's device key, added once the citizen logs anything

**Lanes / event focus:**
- `defined_scenario` × 8–12 (earthquake, flood, wildfire, severe weather, power outage, water outage, evacuation order, active threat, hazmat — region-appropriate)
- `defined_action_step` × 30–60 (steps per scenario)
- `defined_resource` × 15–25 (shelters, hospitals, cooling centers, meeting points)
- `defined_contact` × 8–15 (town manager, fire chief, police, school superintendent, public health officer, block captains)
- `logged_drill` × 0–N (citizen-side; recorded when the citizen runs prep mode)
- `logged_incident_status`, `logged_decision` × 0–N (during an actual incident)

**Skill actions:**
- `define_scenario` (admin / pre-distributed)
- `define_action_step` (admin)
- `define_contact` (admin)
- `define_resource` (admin)
- `run_drill` — interactive drill mode
- `log_incident` — incident-mode status snapshot
- `log_decision`
- `after_action`
- `get_scenarios` — list applicable scenarios
- `get_resources_near` — filter resources by geo or category (composes with `interactive-map`)
- `summarize_for_responder` — generate handoff for a first responder
- `export_capsule`
- `wipe_data` (clears citizen's local additions; preserves the published plan)

**Doctor-equivalent reader:** `examples/town-dr/responder/reader.html` — a single HTML page a first responder opens in the field (offline) to inspect a citizen's capsule for medical info, special-needs flags, and any logged incident state.

### Family DR (`examples/family-dr/`)

**Audience:** a family unit.
**Encryption:** none for v0.1 (family-internal data; the user can choose to encrypt at OS level by storing the capsule in encrypted storage). Future v0.2 may add family-internal encryption.
**Originator:** the family's primary signer (typically a parent / household head).
**Lanes / event focus:**
- `defined_scenario` × 5–8 (earthquake, house fire, severe weather, power outage, medical emergency, active threat — household-appropriate)
- `defined_member` × 2–6 (NEW family-specific event type — family members with relationship, school/work location, medical info, allergies)
- `defined_pet` × 0–4 (NEW family-specific event type)
- `defined_meeting_point` × 2 (primary + secondary, NEW family-specific event type)
- `defined_supply` × 5–15 (go-bag contents)
- `defined_contact` × 5–10 (out-of-area emergency contact is mandatory — the standard "call grandma in Phoenix" pattern; doctors; school emergency lines)
- `logged_drill` × 0–N

**Family-specific event types added to the schema:**

- `defined_member` — `slug, name, relationship, age, medical_notes (untrusted), allergies (untrusted), school_or_work, primary_contact_slug`
- `defined_pet` — `slug, name, species, breed, medical_notes (untrusted), evac_carrier_location`
- `defined_meeting_point` — `slug, tier ("primary"|"secondary"), label, address_or_coords, notes (untrusted)`

**Skill actions:** mirror Town's surface plus family-specific:
- `add_member`, `add_pet`, `add_meeting_point`
- `add_supply` (go-bag inventory)
- `run_drill`, `log_incident`, `log_decision`, `after_action`
- `get_meeting_points`
- `summarize_for_babysitter` — generate a brief for someone watching the kids
- `export_capsule`, `wipe_data`

**Reader:** `examples/family-dr/reader.html` — for the family to review what's in their plan, run drills outside Edge Gallery (e.g., on a laptop), and print a paper copy for the fridge.

### Business DR (`examples/business-dr/`)

**Audience:** small/medium business — owner, BCM, IT lead, key staff.
**Encryption:** **required**. Vendor contracts, employee emergency contacts, and customer notification templates contain PII and operationally sensitive data. The capsule is encrypted to multiple recipients (owner + BCM + IT lead by default; HR for employee PII; legal for regulatory). Uses Capsule v0.6 multi-recipient ChaCha20-Poly1305 + X25519+HKDF.
**Originator:** business owner.
**Lanes / event focus:**
- `defined_scenario` × 8–15 (cyber_incident, supply_disruption, key_person_unavailable, power_outage, fire, severe_weather, regulatory_inspection, customer_data_breach — business-appropriate)
- `defined_system` × 5–20 (NEW business-specific event type — critical IT systems with RTO/RPO)
- `defined_vendor` × 5–15 (NEW business-specific event type — vendor contacts with SLA tier, contract reference)
- `defined_regulatory_requirement` × 0–10 (NEW business-specific event type — HIPAA breach notice, GDPR, SEC 8-K, state breach laws)
- `defined_contact` × 10–25 (employees emergency contacts, insurance broker, legal counsel, IT contractor)
- `defined_resource` × 5–10 (office locations, backup work sites, supply caches)
- `logged_drill`, `logged_incident_status`, `logged_decision`, `after_action_report` × 0–N

**Business-specific event types:**
- `defined_system` — `slug, label, system_kind ("crm"|"erp"|"file_server"|"email"|"phone"|"web"|"other"), rto_hours, rpo_hours, vendor_slug, recovery_runbook_ref`
- `defined_vendor` — `slug, name, role, phone, email, sla_tier ("gold"|"silver"|"bronze"|"none"), contract_ref`
- `defined_regulatory_requirement` — `slug, jurisdiction, framework ("HIPAA"|"GDPR"|"SEC"|"State"|"PCI"|"other"), trigger ("breach"|"outage_over_X_hours"|"other"), deadline_hours, contact_slug, notification_template_ref`

**Skill actions:** Town + business-specific:
- `define_system`, `define_vendor`, `define_regulatory_requirement`
- `set_recipient` — register additional encryption recipients (e.g., HR pubkey for employee-PII visibility)
- `run_drill`, `log_incident`, `log_decision`, `after_action_report`
- `assess_regulatory_exposure` — given a scenario, list regulatory deadlines triggered
- `notify_vendor` — compose a status notification (uses built-in `send-email`)
- `export_capsule` (encrypted), `wipe_data`

**Reader:** `examples/business-dr/reader.html` — multi-recipient reader: drops a `.capsule` file, picks a recipient `.pem`, decrypts to that recipient's view (HR sees employee PII, IT sees system inventory, owner sees everything, auditor sees only regulatory + corrective-actions trail).

## Shared library

A new shared library at `examples/dr-ir-common/dr-ir-builder.js`. Three example dirs use it (each via build-time inline). This is the first Capsule example to share a builder library across examples — the medical-journal pattern was one-per-example. Acceptable because the three DR/IR examples truly share the same chain shape; only payload schemas differ per event type.

Alternative: ship per-example builders (`town-dr-builder.js`, `family-dr-builder.js`, `business-dr-builder.js`) copy-evolved from `medical-journal-builder.js`. **Choose this alternative** for the first cut. Sharing emerges later when the duplication is provably stable. Keeps each example independently shippable.

## Test strategy

Each example has its own `parity-test.mjs` mirroring the medical-journal pattern:

1. Stub `localStorage` in Node.
2. Load the example's builder into `vm.runInThisContext`.
3. Build a synthetic capsule with a realistic plan and a small operational chain.
4. Self-verify via the in-browser code path.
5. Re-verify via the SDK's `verifyCapsule` (plain) or `verifyCapsule` + decrypt-with-recipient (encrypted, business only).
6. Parse back via `parseCapsule`.
7. Confirm event count, lane counts, and any per-example analytic outputs.

## SMS-bootstrap format

The text message a town sends to residents (and equivalents for family and business):

> Riverside emergency prep is now in your phone's reach.
> Install: prepare.chat/T-RIVERSIDE-CA
> Open the link, tap Copy install URL, then in Edge Gallery: Load skill from URL. Works offline forever.
> If you have questions: 555-0123 (M–F 9–5)

Each example's README documents the exact SMS template the originator can copy-paste.

## Out of scope (parking lot for v0.7+)

- Multi-party real-time coordination (one capsule, multiple concurrent editors)
- Federation (one town's capsule referencing a neighboring town's plan)
- Public-ledger anchoring of town plans (a town signature on `tsa.capsules.run`)
- Localization (Spanish version of `prepare.chat/T-RIVERSIDE-CA`)
- Native iOS/Android apps beyond Edge Gallery
- Mesh-networking deliverability (Bluetooth-LE distribution during a network outage)
- Map-tile bundling (offline map shards in `payload/`)

## Definition of done for each example

- Skill installs into Edge Gallery via `Load skill from URL` (or `Import Local Skill` for local iteration).
- Skill exposes the documented actions; each runs without errors on a synthetic chain.
- `npm test` in the example directory exits 0 with a green PASS line including SDK verifier confirmation.
- Reader.html opens any `.capsule` produced by that example, renders the plan, lists drills/incidents/decisions, and (for business) decrypts with a recipient `.pem`.
- README documents the SMS-bootstrap template, the prepare.chat URL pattern, and the expected demo flow.
- Bus DR specifically: parity test confirms a capsule encrypted to two recipient keys decrypts correctly with either key and fails (closed) with a wrong key.
