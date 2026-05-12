# ComplianceQ × Capsule v0.6 — Integration Shape

ComplianceQ is the OSINT-agent intelligence layer. Capsule v0.6 is the
portable verifiable shell. This document describes the seam — what each
side owns, where signatures land, how the lifecycle plays out across
onboarding, periodic review, continuous monitoring, and regulator audit.

## The line between "format" and "platform"

The capsule format is **domain-agnostic by design**. Hand it a
healthcare workflow and it carries patient consent + clinician
signoffs. Hand it a loan workflow and it carries credit data + officer
signoffs. The format's job is to be the same wrapper across every
regulated workflow: portable, multi-signed, optionally encrypted,
hash-chain-audited, cold-readable by foreign LLMs.

The format has no knowledge of:

- what an OFAC SDN list is
- which adverse-media categories are "escalation-relevant"
- what a Tier 2 PEP is
- when a partial match becomes a real one
- how to disposition evidence
- which jurisdictions are high-risk this quarter
- what a SAR threshold should be

All of that is **domain intelligence**. It belongs to the platform.

ComplianceQ owns:

| Layer | Provided by ComplianceQ |
|---|---|
| **Data feeds** | Sanctions lists (OFAC, UN, EU, UK HMT, regional), PEP databases, adverse-media corpus, corporate registries (Companies House, SEC EDGAR, regional), beneficial ownership, court records, regulatory enforcement actions, watchlist monitoring streams |
| **Tools** | Each entry in `tool-contracts.json` is a ComplianceQ API: `ofac_screen`, `pep_screen`, `adverse_media_search`, `corporate_registry_lookup`, `ubo_trace`, `sanctions_multi_list_screen`, `enforcement_action_lookup`, `litigation_search`, etc. |
| **The OSINT agent** | The model that reads SKILL.md, plans queries, calls tools in parallel, synthesizes findings, identifies discrepancies, drafts adverse-media summaries, generates entity relationship maps, proposes risk classifications, surfaces evidence to the analyst |
| **Skills (rubrics)** | The `SKILL.md` files declaring how each step is performed. ComplianceQ's compliance experts author them, version them, and sign them |
| **Taxonomies** | PEP tier definitions, adverse-media category taxonomy, jurisdiction-risk lists. ComplianceQ publishes versions on a documented cadence and signs each |
| **Decision-gate definitions** | Which steps require human signoff, what the review packet must contain, what role can sign |
| **Risk model & calibration** | Threshold values, scoring weights, tier-assignment rules — derived from ComplianceQ's training data and validated under their model risk policy. Each model version ships a model card |
| **Continuous monitoring** | New adverse media surfacing post-onboarding, list-update rescreening, alert generation |

The capsule format owns:

| Layer | Provided by Capsule |
|---|---|
| Portable archive | One file, deterministic ZIP, opens on any OS |
| Multi-signer envelope | `signers[]` with role-keyed Ed25519 sigs, domain separation per role |
| Encryption | ChaCha20-Poly1305 + X25519 + HKDF, multiple recipients |
| Append-only chain | SHA-256 hash linkage, raw-byte signing, untrusted-content marking |
| Verification | L2 (no decrypt), L3 (with key), per-signer trust against host allowlist |
| Foreign-LLM cold readability | program.md + agents.md + chain projection that the regulator's model can absorb |
| Pith normalizer | Narrative fields stay terse and consistent across LLM authors |

Calibrated thresholds and screening intelligence belong to ComplianceQ.
The capsule carries them — pinned by hash, traveling with every
instance — but does not produce them.

## Signing layout under the partnership

A ComplianceQ-produced instance has at least three signers. Each one
attests to a different fact.

```
signers: [
  {
    role: "screening-platform",
    public_key: <ComplianceQ's published platform key>,
    signature: <attests: this capsule was produced through ComplianceQ's
                pipeline using template v3.2.1, model v2026-Q1, and the
                pinned taxonomies/lists declared in payload/>
  },
  {
    role: "analyst",
    public_key: <bank's named analyst, registered with bank>,
    signature: <attests: I reviewed the screening output, accepted the
                AI-proposed dispositions where valid, recommended the
                final outcome>
  },
  {
    role: "compliance-manager",
    public_key: <bank's compliance manager>,
    signature: <attests: I reviewed the analyst's recommendation,
                approved the outcome and conditions>
  }
  // + mlro signer when SAR is in scope
]
```

The trust model:

- **Regulator allowlists ComplianceQ's pubkey.** Proves "this came from
  ComplianceQ's pipeline as documented." If ComplianceQ publishes
  multiple keys (e.g. per environment or per region), each is on the
  list with its scope.
- **Regulator allowlists each bank's published officer pubkey
  registry.** Proves accountable human review at the bank.
- **A regulator audit is a one-shot offline operation.** Open the
  capsule, L2 verify against the union of allowlists, decrypt with
  the regulator's audit key, L3 verify, project to the regulator's
  LLM. No call to ComplianceQ, no call to the bank.

This is the partnership's main asset: the regulator trusts the artifact
*independently of either platform's availability*.

## Liability split

The signatures naturally partition responsibility:

- **ComplianceQ's signature** asserts the *pipeline ran as
  documented*. It does not warrant the *correctness* of every output.
  ComplianceQ's terms of service should state: "the screening was
  performed using model version X.Y on date Z; outputs are
  evidence-shaped and require human review before action."
- **The bank's analyst signature** asserts *human review of the
  outputs*, with rationale recorded as decision events.
- **The compliance-manager signature** asserts *senior review and
  approval*.
- **The MLRO signature**, when present, asserts *MLRO concurrence with
  the SAR-related outcome*.

If a screening output later proves wrong, the chain shows whether the
analyst missed the differentiator, the AI proposed a wrong disposition,
or the threshold model was miscalibrated. The capsule makes the
post-mortem possible without finger-pointing.

## What travels in the instance

A ComplianceQ-issued instance carries everything a regulator needs to
reproduce *understanding*:

```
instance.capsule (encrypted to bank vault + regulator audit key)
├── manifest.json
├── program.md                                  the AML review document
├── agents.md                                   participants, signing authority
├── chain/events.jsonl                          the decision trail
├── skills/                                     ComplianceQ's signed rubrics
│   ├── ofac-screening/SKILL.md                 (+ skill.json with version pin)
│   ├── pep-screening/SKILL.md
│   ├── adverse-media-screening/SKILL.md
│   ├── ubo-tracing/SKILL.md
│   ├── corporate-registry-lookup/SKILL.md
│   ├── enforcement-action-lookup/SKILL.md
│   ├── risk-tiering/SKILL.md
│   ├── match-disposition/SKILL.md
│   └── escalation-and-decision/SKILL.md
├── payload/
│   ├── playbook.md                             the orchestration spec
│   ├── model-card.json                         which model, when validated, perf
│   ├── decision-gates.json
│   ├── tool-contracts.json
│   ├── version-pins.json                       template-version, taxonomy-versions, list-publish-dates
│   ├── taxonomies/
│   │   ├── pep-tiers-v2026.03.json
│   │   ├── adverse-media-categories-v2026.03.json
│   │   └── jurisdiction-risk-v2026.04.json
│   └── evidence/                               raw OSINT findings
│       ├── ofac-result.json
│       ├── pep-result.json
│       ├── adverse-media-result.json
│       ├── corporate-registry.json
│       └── ubo-trace.json
└── provenance/envelope.json                    multi-signer envelope
```

The regulator opens this in 2031 — five years after seal — and can
answer:

- *Who decided?* Chain + manifest participants + envelope signers.
- *On what evidence?* `payload/evidence/` raw responses + their
  lookup_ids referenced in chain events.
- *Under which model version?* `payload/model-card.json`.
- *Under which list versions?* `payload/version-pins.json` + each
  evidence file's `list_publish_date`.
- *Under which rubric?* The signed `skills/<id>/SKILL.md` files
  carried inside this instance, byte-identical to what was used at
  decision time.

No call to ComplianceQ. No assumption that ComplianceQ still exists.
The capsule is self-contained.

## Lifecycle

### Onboarding (point-in-time investigation)

```
1. Bank's analyst opens an investigation in ComplianceQ
2. ComplianceQ loads aml-investigation-template.capsule
3. Analyst supplies subject (name, type, jurisdictions, optional aliases/dob)
4. ComplianceQ's agent walks playbook.md:
     - calls OSINT tools (the ones in tool-contracts.json)
     - applies SKILL.md rubrics
     - drafts events into the chain
5. At each decision gate, ComplianceQ surfaces a review packet in the
   analyst's queue:
     - the proposed disposition / outcome
     - the cited evidence
     - the rule that triggered the gate
6. Analyst (or analyst + manager + MLRO as required) signs each gate
7. ComplianceQ's pipeline signs as screening-platform
8. Instance encrypted to bank's vault + regulator audit key, sealed
9. Bank stores under retention policy (e.g. 7-year FinCEN, 10-year EU)
```

### Periodic rescreening

OSINT data changes daily. A subject onboarded in March may require
rescreening in June.

```
1. ComplianceQ's monitoring detects: OFAC list updated, PEP database
   refreshed, adverse media on subject newly indexed
2. Rescreening capsule produced; chain event references the original
   instance:
     {
       kind: "observation",
       action: "rescreen_performed",
       target: "<original capsule_id>",
       payload: {
         summary: "Rescreened against OFAC list 2026-06-15; no new matches",
         original_capsule_id: "<hex>",
         original_first_event_hash: "<hex>",
         delta: "no_change"
       }
     }
3. New instance sealed; references the original via lineage
4. Regulator can walk: original → rescreen-1 → rescreen-2 → ...
```

The format does not yet have first-class lineage in the manifest.
Adding `manifest.lineage = { supersedes: <capsule_id>, parents: [...] }`
is a v0.7 schema item; the partnership demand makes the case for
landing it.

### Continuous monitoring (alerts)

```
1. ComplianceQ continuously watches: lists, adverse media, related
   entities of UBOs, transaction-pattern-fed signals from bank
2. On material change, an "alert capsule" is produced:
     - small, often a single observation event
     - references the customer's current onboarding instance
     - encrypted to bank's alert queue + regulator
3. Bank's compliance team triages; if escalation needed, a full
   investigation capsule is opened that references the alert chain
```

### Regulator audit

```
1. Bank delivers requested capsules to regulator (offline, via secure
   transfer of the actual files)
2. Regulator's tooling:
     a. L2 verifies each capsule against ComplianceQ pubkey allowlist
        + bank pubkey allowlist
     b. Decrypts with the regulator's recorded audit key
     c. L3 verifies against the outer envelope
     d. Projects the chain into their regulator-trained LLM:
          "show all SAR-relevant decisions from 2026-Q3 where
           pep-tier-1 was triggered"
     e. Cross-references the model-card to confirm calibration
        documentation was current at decision time
3. Regulator can request the same capsules from ComplianceQ as a
   integrity cross-check (same bytes, same hashes, same signatures)
```

## What ComplianceQ has to publish

For the partnership to deliver verifiable artifacts to regulators,
ComplianceQ must publish (out of band, on a stable URL):

1. **Signing-key registry.** A list of currently-valid platform
   pubkeys, with rotation history. Every regulator and bank fetches
   this to populate their allowlist.
2. **Template-version index.** Which template versions are current,
   which are retired (still verifiable but no longer issued), what
   the version differences are.
3. **Model card per model version.** Methodology, training data
   provenance, validation results (precision, recall, AUC where
   applicable), known limitations, last-validated date. Required by
   model risk policy at every customer bank.
4. **Taxonomy version log.** When PEP tiers, adverse-media categories,
   or jurisdiction-risk lists were updated, with the change rationale.
5. **Tool-contract changelog.** When `tool-contracts.json` evolves,
   so banks pinning specific versions know what's stable.

All five travel in the regulator's audit toolchain. None of them require
calling ComplianceQ live.

## Per-customer overlays

Different banks have different risk appetites. A community bank may
escalate at adverse-media count ≥ 1; a private bank serving HNW clients
may escalate at ≥ 3. Both are valid; both must be auditable.

Pattern:

- ComplianceQ publishes the **base template** with default thresholds.
- A bank publishes a **bank overlay** capsule with their tuned
  thresholds, signed by their compliance officer.
- An instance pins both: `manifest.lineage.parents = [base_template_id,
  bank_overlay_id]`.
- The chain shows which overlay was applied (`overlay_applied` event).

The regulator audit reads both the base and the overlay, sees the
differences explicitly, and can challenge specific tuning if warranted.

## Multi-tenant data residency

ComplianceQ's pipeline serves many banks across jurisdictions. EU bank
customers need EU-resident processing; US banks may need US-resident.
The format already accommodates this:

- ComplianceQ runs region-segregated pipelines, each with its own
  signing-key (from the published registry).
- An EU instance is signed by ComplianceQ's EU platform key + the
  bank's officers, encrypted to the bank's EU vault + the regulator's
  EU audit key. Plaintext never leaves the region.
- Cross-border audit (e.g. US regulator auditing a EU subsidiary)
  works the same way: the regulator gets the encrypted artifact, has
  their decryption key, performs L3 locally.

## What ComplianceQ has to build (beyond what they already have)

Most of ComplianceQ's existing OSINT pipeline maps to capsule tooling
without rewrite. The new work is small:

1. **Capsule output adapter.** A library call at the end of an
   investigation that takes the existing internal records and emits
   a v0.6 capsule. ~200 lines using the SDK.
2. **Skill authoring discipline.** Compliance experts write SKILL.md
   files in the rubric format. They already write playbooks; this is
   formalizing them.
3. **Signing-key registry endpoint.** A JSON file at a stable URL
   listing current platform pubkeys.
4. **Per-instance model-card emission.** Already produced internally
   for model risk; just include in the instance payload.
5. **Per-customer overlay support.** A way for a bank to upload a
   tuned overlay capsule; the runner pins it to instances.
6. **Rescreen / lineage handling.** A v0.7 schema item; until it
   lands, lineage can travel as `manifest.metadata.lineage_pointers`
   without protocol blessing.

Total: small enough to ship without a major engineering investment.

## What banks have to do

1. **Officer signing keys.** Each named officer who can sign capsules
   gets an Ed25519 key. HSM-backed for production. The bank publishes
   the registry of *who currently holds which authority* on a stable
   URL.
2. **Vault recipient key.** The bank's compliance vault has an X25519
   key; instances are encrypted to it.
3. **Allowlist setup.** The bank's verifier tools allowlist
   ComplianceQ's published pubkey + the regulator's audit pubkey.
4. **Retention storage.** Capsules go into a 7-10 year retention
   system. The format makes this easy: each capsule is a self-contained
   file. WORM-compatible.

Optional but valuable:

5. **Bank-specific overlay capsule** with their tuned thresholds.
6. **Internal alert tooling** that consumes ComplianceQ alert capsules
   and surfaces to compliance staff.

## What the regulator gets

1. **Independent verifiability.** A regulator with the published keys
   can audit a capsule offline. No vendor lock-in.
2. **Reproducible decisions.** The chain + skills + taxonomies +
   model-card make every decision traceable to a specific rubric
   under a specific model.
3. **Fewer document requests.** Asking for "the AML file on customer
   X" returns one capsule that contains everything that produced it,
   pinned by hash.
4. **Cross-vendor comparability.** If two banks use different OSINT
   platforms, both produce capsules in the same format. The
   regulator's tooling treats them the same way at the verification
   and projection layer; only the *payload* differs.

## Threats specific to the partnership

| Risk | Mitigation in v0.6 | Open |
|---|---|---|
| ComplianceQ key compromise | Key registry rotation; instances issued before compromise remain valid via the historical key list | Revocation transparency log (parking-lot) |
| Bank officer key compromise | Per-officer keys mean blast radius is limited; bank's officer registry can be updated | Same as above |
| Skill rubric injection (someone slips a malicious SKILL.md into a capsule) | Skills are `signed` only when their hash is covered by an envelope signature; the runner refuses unsigned skills | Stricter content-policy framing for "signed" markdown |
| Model drift unnoticed | Each instance carries the model card; regulator can check validation date | Continuous validation reporting (ComplianceQ ops) |
| Stale taxonomy / list | Each instance pins versions in `version-pins.json` + `list_publish_date` | Required-freshness gate (e.g. refuse to seal if list older than N days) |
| Encrypted blob exfiltration | Encryption to multiple recipients (bank + regulator) means leaked outer is L2-only useful | Key-rotation rescreen flow |
| Cross-jurisdiction visibility | Region-segregated pipelines + region-specific recipient keys | Documented data-residency policy |

None of these are blockers for a v0.6-based partnership; all are
manageable.

## Concrete next steps for ComplianceQ partnership

1. **Replace mock tools in the runner with ComplianceQ API calls.**
   This is the smallest meaningful integration delivery.
2. **Add ComplianceQ's signing key as a `screening-platform` signer
   in the seal step.** Multi-sig already supported by v0.6.
3. **Embed a model-card template** in the AML investigation template.
   Populate from ComplianceQ's existing model-risk documentation.
4. **Author one production-grade skill** (e.g. `ofac-screening/SKILL.md`)
   with ComplianceQ's actual rubric, threshold table, and disposition
   evidence requirements. Use it as the template for the rest.
5. **Stand up the signing-key registry endpoint.** A stable JSON file.
6. **Pilot with one bank customer** producing real (test-data)
   capsules; have a regulator-side mock verifier do the L2/L3 check.
7. **Iterate on the SKILL.md format** based on what the OSINT agent
   actually needs at each step. The current shape is a starting point;
   ComplianceQ's compliance experts will refine it.

The format is ready for this. The next milestone for ComplianceQ is
not protocol changes — it's authoring the operational skills with the
fidelity that justifies the platform's signature on every instance.
