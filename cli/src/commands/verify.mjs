// `capsule verify <file> [--allowlist KEY...] [--predecessor FILE...]
//                        [--accept-versions V...] [--json]`
//
// Wraps the SDK's verifyCapsule() and applies the CLI's POLICY LAYER —
// trust policy, custody policy, version policy — on top. The split is
// deliberate: the SDK reports facts (which integrity checks passed;
// which signers are trusted under the supplied allowlist; which declared
// predecessors the supplied bytes establish; whether the observed format
// version is in the declared accepted set) and never decides policy —
// the CLI is the policy layer, because the CLI is where an operator
// expresses what they demand.
//
//   - No --allowlist:  no trust policy. The verdict covers integrity
//                      only, and the report says so explicitly.
//   - --allowlist KEY (repeatable): trust policy "at least one distinct
//                      allowlisted key must carry a valid signature".
//                      A capsule whose math checks pass but whose
//                      signers all miss the allowlist FAILS (exit 1) —
//                      `capsule verify f --allowlist $KEY && deploy`
//                      must never deploy an artifact signed by someone
//                      the operator did not trust.
//   - No --predecessor: declared lineage is reported, never a verdict
//                      input (spec/lineage.md: linkage is report-only —
//                      a host's file handling must not forge a forgery
//                      verdict against an honest successor).
//   - --predecessor FILE (repeatable): custody policy "every supplied
//                      file matches a declared entry, verifies valid
//                      under its own era, and every equality holds".
//                      `capsule verify s --predecessor p && publish`
//                      must never publish on a failed custody check the
//                      operator asked for. Declared entries left
//                      unsupplied do NOT fail the exit (an operator may
//                      hold one branch of a merge) but are reported.
//   - --accept-versions V (repeatable): version policy "the capsule's
//                      declared format version must be one of these".
//                      spec/versioning.md "Host policy": the SDK reports
//                      the verdict as a fact and MUST NOT be silent; the
//                      demand is the operator's, so an unaccepted
//                      version fails the run (exit 1) like an unmatched
//                      allowlist. Absent the flag, every known version is
//                      accepted and the fact is reported as null.
//
// Exit codes (spec/results.md "CLI reference renderer" + DECISIONS M4;
// cli/README.md; CI depends on them):
//   0  verdict VALID and every requested policy satisfied
//   1  verdict INVALID or UNSUPPORTED, or a requested policy not
//      satisfied (--allowlist matched no signer, --predecessor did not
//      establish the declared linkage, --accept-versions excludes the
//      declared version). A capsule this verifier cannot open — unknown
//      era, unsupported profile, malformed container — is a verdict
//      about the capsule/verifier pair, NOT an operator error: it is
//      rendered from the total verifier's fail-closed result and exits
//      1, the same as the Rust CLI.
//   2  usage / I-O error only (unknown flag, malformed key, malformed
//      version string, unreadable file — including an unreadable
//      --predecessor path)
//
// The plain report mirrors the Rust verifier's layout. The JSON output
// carries the same integrity fields as the Rust CLI plus `trust` and
// `version_policy` blocks; `ok` here is the OVERALL verdict (integrity
// AND every requested policy) and always matches the exit code, while
// `integrity_ok` preserves the SDK/Rust math-only verdict and `verdict`
// carries the SDK's normalized verdict (spec/results.md).

import { CapsuleReader, verifyCapsule } from "@capsule/sdk-v0.7-prototype";
import { parseArgs } from "../args.mjs";
import { CLIError, check, out, readBytes, truncHex } from "../format.mjs";

const USAGE = `usage: capsule verify <file> [--allowlist KEY...] [--predecessor FILE...]
                      [--accept-versions VERSION...] [--json]

  --allowlist KEY    Trusted Ed25519 public key (64 hex chars). Repeat
                     the flag for multiple keys. Supplying an allowlist
                     sets the trust policy: verification FAILS (exit 1)
                     unless at least one allowlisted key carries a
                     valid signature. Without it the verdict covers
                     integrity only, and the report says so.
  --predecessor FILE Sealed predecessor capsule to check the capsule's
                     manifest.predecessors declaration against. Repeat
                     the flag (merges, and one file per hop for deeper
                     lineage). Supplying one sets the custody policy:
                     verification FAILS (exit 1) unless every supplied
                     file matches a declared entry, verifies valid
                     under its own era, and every equality holds.
                     Without it, declared lineage is reported and never
                     affects the exit code.
  --accept-versions VERSION
                     Accepted capsule format version ('<major>.<minor>',
                     e.g. 0.7). Repeat for multiple. Supplying it sets
                     the version policy: a capsule whose declared
                     version is outside the set still verifies (the math
                     is unaffected) but FAILS the run (exit 1), and the
                     verdict carries version_not_accepted_by_policy.
  --json             Emit the full result as pretty-printed JSON.
                     Same exit code in either mode.
`;

// spec/results.md "Required renderer language": one rendering per
// qualifier, each containing that qualifier's normative minimum
// substring, printed in the same report as the verdict.
const QUALIFIER_LINES = {
  signer_set_unbound: () =>
    "signer set is not bound by the seal (manifest.signer_commitment absent)",
  actor_set_unbound: () =>
    "chain actors are not bound to a declared participant set (manifest.participants empty)",
  empty_chain_not_walked: () =>
    "empty chain: no events to walk; envelope anchors checked to be null instead",
  encrypted_outer_only: () =>
    "content is encrypted and was not read (L2 outer only; chain deferred to L3)",
  version_not_accepted_by_policy: (result) =>
    `format version ${result.formatVersion?.observed} is not in the declared accepted set of this host`,
  trust_not_evaluated: () => "trust not evaluated: no allowlist supplied",
  no_trusted_signer: () =>
    "allowlist provided but matched no signer; trusted=false for all signers",
  // The three lineage names (spec/lineage.md pinned phrases, which
  // spec/results.md adopts as the required minimum substrings).
  lineage_declared_unverified: () =>
    "lineage declared, not verified: no supplied predecessor established the declared linkage",
  lineage_mismatch: () =>
    "supplied predecessor is a different sealed state of the declared predecessor",
  lineage_predecessor_invalid: () =>
    "a supplied predecessor fails its own verification",
};

// A qualifier this CLI cannot name is surfaced VERBATIM (spec/results.md
// consumer rule): a later revision's name or an x- vendor entry must
// never be silently dropped, which would read as "unqualified". A lane
// adding a spec-defined qualifier adds its rendering to the table above,
// with that qualifier's required substring in the string.
function qualifierLine(name, result) {
  const render = QUALIFIER_LINES[name];
  return render ? render(result) : name;
}

// The first clause of the refusal diagnosis, for the Result line. The
// full wording — including the "limitation of the verifier" sentence the
// cross-lane needles pin — still prints in the Errors section.
function primaryDiagnosis(result) {
  const first = result.errors?.[0];
  if (typeof first !== "string" || first.length === 0) return null;
  return first.replace(/^capsule cannot be opened: /, "").split("; ")[0];
}

// spec/profiles.md §4.2: one line beside `Format version:`. The profile
// actually APPLIED, and whether the capsule declared it.
function profileLine(profile) {
  if (!profile) return "(unread)";
  switch (profile.status) {
    case "default":
    case "supported":
      return `${profile.effective}/${profile.effectiveVersion}` +
        ` (${profile.status}, ${profile.declared ? "declared" : "undeclared"})`;
    case "unsupported":
      return `${profile.observed}/${profile.observedVersion}` +
        " — declared but not supported by this verifier";
    case "mismatched":
      return "mismatched — envelope.profile does not match manifest.format.profile";
    case "invalid":
      return "invalid declaration (see Errors)";
    case "unevaluated":
      return (profile.declared ? `${profile.observed}/${profile.observedVersion} ` : "") +
        "(unevaluated — the version gate refused first)";
    default:
      return "(unread)";
  }
}

export async function verifyCmd(argv) {
  const args = parseArgs(argv, {
    booleans: ["json"],
    arrays: ["allowlist", "predecessor", "accept_versions"],
    maxPositionals: 1,
  });
  if (args.help) {
    process.stderr.write(USAGE);
    return 0;
  }
  const file = args._[0];
  if (!file) {
    process.stderr.write(USAGE);
    return 2;
  }

  // Trust configuration is validated at the argument boundary (parity
  // with the Rust CLI): an entry that is not a 32-byte Ed25519 public
  // key can never match a signer, so accepting it would only ever
  // manufacture a misleading FAIL — or, before F04, a misleading PASS.
  const allowlist = args.allowlist || [];
  for (const entry of allowlist) {
    if (!/^[0-9a-fA-F]{64}$/.test(entry)) {
      throw new CLIError(
        `--allowlist entry must be 64 hex chars (a 32-byte Ed25519 public key); got: ${entry}`,
        2,
      );
    }
  }
  // Same boundary for the version policy: a value outside the
  // '<major>.<minor>' grammar (spec/versioning.md) can never match a
  // declared version, so it would only ever manufacture a policy failure
  // the operator did not intend.
  const acceptVersionsArg = args.accept_versions || [];
  for (const entry of acceptVersionsArg) {
    if (!/^\d+\.\d+$/.test(entry)) {
      throw new CLIError(
        `--accept-versions entry must be a '<major>.<minor>' version string; got: ${entry}`,
        2,
      );
    }
  }
  // Absent flag = no declared policy at all, which is NOT the same as an
  // empty accepted set: only a declared policy is reported and decided.
  const acceptVersions = acceptVersionsArg.length > 0 ? acceptVersionsArg : null;

  const bytes = await readBytes(file);

  // The predecessor pool is read at the argument boundary too: an
  // unreadable path is a usage error, never a silently smaller pool
  // that would report the entry "declared, not verified".
  const predecessorFiles = args.predecessor || [];
  const pool = [];
  for (const path of predecessorFiles) pool.push(await readBytes(path));

  // The capsule is opened best-effort for the report header, but
  // verification always runs over a surface the total verifier accepts:
  // an unknown era or an unsupported profile is refused at open, and
  // that refusal is a VERDICT (UNSUPPORTED, exit 1), not an operator
  // error (exit 2). spec/results.md; parity with the Rust CLI, which has
  // always fed raw bytes to verify_capsule.
  let reader = null;
  try {
    reader = await CapsuleReader.fromBytes(bytes);
  } catch {
    reader = null;
  }

  const result = await verifyCapsule(reader ?? bytes, {
    allowlist,
    predecessors: pool,
    ...(acceptVersions ? { acceptVersions } : {}),
  });

  // POLICY (the CLI-level decisions the SDK deliberately never makes).
  // trustedSignerCount counts DISTINCT keys that are both valid and
  // allowlisted, so duplicate signer rows cannot satisfy the policy.
  const policy = allowlist.length > 0 ? "allowlist" : "none";
  const policySatisfied = policy === "none" ? null : result.trustedSignerCount > 0;

  // CUSTODY POLICY (spec/lineage.md "CLI exit policy"). The SDK's
  // linkage reporting is report-only in every lane; supplying
  // --predecessor is the operator asking for it to be decisive here.
  // A checked entry is one a supplied artifact was matched to, so the
  // count of them is the count of supplied files that matched
  // something: an unmatched file (a mistyped path) fails the policy,
  // and so does any checked entry that is not `verified`.
  const custody = custodyPolicy(result.lineage, predecessorFiles.length);
  // acceptedByPolicy is null whenever the policy was not declared or the
  // capsule never reached the check (a refusal); only an explicit false
  // is a failed demand.
  const versionPolicySatisfied = acceptVersions
    ? result.formatVersion?.acceptedByPolicy ?? null
    : null;
  // DECISIONS M4: every REQUESTED policy is decisive. A verdict that
  // stays VALID beside an unmet demand still exits 1 — rendering a
  // failed policy and then exiting 0 is the failure mode the rule exists
  // to prevent.
  const ok =
    result.ok &&
    policySatisfied !== false &&
    custody.satisfied !== false &&
    versionPolicySatisfied !== false;

  if (args.json) {
    out(JSON.stringify(
      {
        ok,
        integrity_ok: result.ok,
        // spec/results.md: the normalized verdict surface. `verdict` is
        // the SDK's fact about the capsule; `ok` above stays the CLI's
        // overall verdict (integrity AND every requested policy).
        verdict: result.verdict,
        verdict_reason: result.verdictReason,
        qualifiers: result.qualifiers,
        level: result.level,
        capsule_id: reader ? reader.manifest().id : null,
        signed_at: reader ? reader.envelope().signed_at : null,
        trust: {
          policy,
          allowlist_size: allowlist.length,
          trusted_signer_count: result.trustedSignerCount,
          satisfied: policySatisfied,
        },
        // spec/versioning.md "Host policy": reported by the SDK, decided
        // here. satisfied is null when no policy was declared.
        version_policy: {
          policy: acceptVersions ? "accept_versions" : "none",
          accept_versions: acceptVersions ?? [],
          satisfied: versionPolicySatisfied,
        },
        errors: result.errors,
        chain: result.chain,
        content_index: result.contentIndex,
        envelope: result.envelope,
        signer_set: result.signerSet,
        actor_set: result.actorSet,
        // spec/lineage.md reporting: the facts channel, in the spec's
        // snake_case. Report-only at the SDK level; `custody` beside it
        // carries the CLI policy this invocation asked for.
        lineage: lineageJson(result.lineage),
        custody: {
          policy: custody.policy,
          predecessors_supplied: predecessorFiles.length,
          unmatched_count: custody.unmatched,
          verified_depth: result.lineage.verifiedDepth,
          satisfied: custody.satisfied,
        },
        // spec/versioning.md: the observed format version is a reported
        // fact, next to (never inside) the integrity verdict. Member
        // names are the Rust CLI's (this JSON is the cross-CLI wire
        // surface; the SDK's camelCase stays inside the SDK).
        format_version: {
          observed: result.formatVersion.observed,
          supported: result.formatVersion.supported,
          status: result.formatVersion.status,
          suite: result.formatVersion.suite,
          accepted_by_policy: result.formatVersion.acceptedByPolicy,
        },
        // spec/profiles.md: which profile's rules were applied, and
        // whether the capsule declared one.
        profile: {
          observed: result.profile.observed,
          observed_version: result.profile.observedVersion,
          declared: result.profile.declared,
          effective: result.profile.effective,
          effective_version: result.profile.effectiveVersion,
          supported: result.profile.supported,
          status: result.profile.status,
          accepted_by_policy: result.profile.acceptedByPolicy,
        },
        // Derived at verify time from THIS invocation's allowlist —
        // never read from the capsule (spec/trust.md "Skill trust").
        skill_trust: {
          capsule_signed: result.skillTrust.capsuleSigned,
          skills: result.skillTrust.skills,
        },
        notes: result.notes,
        trusted_signer_count: result.trustedSignerCount,
      },
      null,
      2,
    ));
    return ok ? 0 : 1;
  }

  // Human report.
  // The lineage notes are rendered inside the Custody block, next to the
  // entries they describe; `custodyBlockShown` records whether that block
  // is going to appear, so the Notes section below can avoid printing the
  // same channel twice — and can still print them when it does not.
  const lineageNotes = (result.notes ?? []).filter((n) => String(n).startsWith("lineage:"));
  const custodyBlockShown =
    Boolean(reader) && (result.lineage.declared || predecessorFiles.length > 0);
  out(`File:                   ${file} (${bytes.length} bytes)`);
  if (reader) {
    const m = reader.manifest();
    const e = reader.envelope();
    out(`Capsule ID:             ${truncHex(m.id)}`);
    out(`Originator (Ed25519):   ${truncHex(m.originator.public_key)}`);
    // signed_at is asserted by the signer; the format has no external
    // time anchor, so it is labelled as attested, never verified.
    out(`Sealed at (attested):   ${e.signed_at}  — signer-supplied; no external time anchor`);
  }
  out(`Level:                  ${result.level}`);
  // spec/versioning.md: report which era's rules were applied. Suite
  // "v0.6" = Ed25519 / SHA-256 / JCS / X25519+HKDF-SHA-256+ChaCha20.
  // The observed version is reported even when the capsule was refused —
  // that is what keeps "too old a verifier" apart from "corrupt file".
  out(`Format version:         ${result.formatVersion.observed ?? "(unread)"}` +
      (result.formatVersion.suite ? `  (${result.formatVersion.suite} suite)` : "") +
      (result.formatVersion.status === "known" ? "" : `  [${result.formatVersion.status}]`));
  out(`Profile:                ${profileLine(result.profile)}`);

  if (reader) {
    out("");
    out("Checks:");
    out(`  [${check(result.contentIndex.ok)}] content_index` +
        (result.contentIndex.errors?.length ? `  (${result.contentIndex.errors.length} error(s))` : ""));
    out(`  [${check(result.chain.ok)}] chain` +
        (result.chain.errors?.length ? `  (${result.chain.errors.length} error(s))` : "") +
        (result.chain.note ? `  — ${result.chain.note}` : ""));
    out(`  [${check(result.envelope.ok)}] envelope_signature`);
    out(`  [${check(result.signerSet.ok)}] signer_set` +
        (result.signerSet.bound ? "" : "  — unbound (manifest.signer_commitment absent)"));
    // Actor-set binding: violations surface as chain errors; the line
    // fails when any chain error is an actor-rule error, and bound/unbound
    // is the honest-assurance report (mirrors signer_set).
    const actorErrors = (result.chain.errors ?? []).filter((ce) =>
      String(ce.message ?? "").includes("not in manifest.participants"));
    out(`  [${check(actorErrors.length === 0)}] actor_set` +
        (actorErrors.length ? `  (${actorErrors.length} error(s))` : "") +
        (result.actorSet.bound ? "" : "  — unbound (manifest.participants empty)"));

    // Trust is reported apart from the integrity checks: the checks above
    // are facts about the capsule; this block is the operator's policy.
    out("");
    out("Trust:");
    if (policy === "none") {
      out(`  policy:            none — no --allowlist supplied`);
      out(`  trusted signers:   0 (nothing is trusted without an allowlist)`);
      out(`  policy check:      NOT EVALUATED — signer identity not checked`);
    } else {
      out(`  policy:            allowlist (${allowlist.length} key${allowlist.length === 1 ? "" : "s"} supplied)`);
      out(`  trusted signers:   ${result.trustedSignerCount} distinct allowlisted key(s) with a valid signature`);
      out(`  policy check:      ${policySatisfied
        ? "SATISFIED"
        : "FAILED — allowlist provided but matched no signer"}`);
    }
    // Skill trust is DERIVED from this invocation's allowlist, never read
    // from the capsule (spec/trust.md "Skill trust").
    const skillTiers = Object.entries(result.skillTrust.skills);
    if (skillTiers.length > 0) {
      out(`  skills (derived):  ${skillTiers.map(([id, tier]) => `${id}=${tier}`).join(", ")}`);
    }

    // The version policy is the operator's second demand, reported like
    // the first: the SDK supplies the fact (spec/versioning.md "Host
    // policy"), this block is the decision made on it.
    if (acceptVersions) {
      out("");
      out("Version policy:");
      out(`  accepted:          ${acceptVersions.join(", ")}`);
      out(`  observed:          ${result.formatVersion.observed}`);
      out(`  policy check:      ${versionPolicySatisfied === null
        ? "NOT EVALUATED"
        : versionPolicySatisfied
          ? "SATISFIED"
          : `FAILED — format version ${result.formatVersion.observed} is not in the declared accepted set`}`);
    }

    // Custody: the lineage declaration and what this invocation could
    // establish about it. A declared predecessor is NEVER omitted from
    // output — a custody claim that quietly disappears when bytes are
    // missing is how a citation gets read as an endorsement
    // (spec/lineage.md, required human-output language). Inside the
    // opened-capsule block by refusal exclusivity: a capsule that never
    // opened has no custody facts, only its refusal diagnosis.
    if (custodyBlockShown) {
      out("");
      out("Custody (lineage):");
      const malformed = result.lineage.declared && !result.lineage.ok
        && result.lineage.entries.length === 0;
      out(`  declared:          ${!result.lineage.declared
        ? "no manifest.predecessors member — this capsule declares no predecessor"
        : malformed
          ? "manifest.predecessors is present but malformed — see Errors"
          : `${result.lineage.entries.length} predecessor entr${result.lineage.entries.length === 1 ? "y" : "ies"}`}`);
      out(`  policy:            ${custody.policy === "none"
        ? "none — no --predecessor supplied; lineage does not affect the exit code"
        : `predecessor (${predecessorFiles.length} file${predecessorFiles.length === 1 ? "" : "s"} supplied)`}`);
      if (result.lineage.declared && !malformed) {
        out(`  verified depth:    ${result.lineage.verifiedDepth}`);
        for (const e of result.lineage.entries) {
          out(`  - hop ${e.hop}  capsule ${truncHex(e.capsule_id)}  era ${e.format_version}` +
              `  status=${e.status}${e.reason ? ` (${e.reason})` : ""}` +
              (e.identityChecked ? "" : "  identity_checked=false"));
          if (e.artifact) {
            out(`      supplied artifact: ok=${e.artifact.ok}  level=${e.artifact.level}` +
                `  version=${e.artifact.observed_version}  errors=${e.artifact.error_count}`);
          }
          for (const detail of e.errors) out(`      ${detail}`);
        }
      }
      if (custody.policy !== "none") {
        out(`  policy check:      ${custody.satisfied
          ? "SATISFIED — every supplied predecessor matched a declared entry and verified"
          : `FAILED — ${custody.reason}`}`);
      }
      if (lineageNotes.length) {
        out("  notes:");
        for (const n of lineageNotes) out(`    - ${String(n).replace(/^lineage: /, "")}`);
      }
    }

    out("");
    out("Signers:");
    if (result.envelope.signers?.length) {
      for (const s of result.envelope.signers) {
        out(`  - ${(s.role + ":").padEnd(13)} ${truncHex(s.public_key)}` +
            `  valid=${s.valid}  trusted=${s.trusted}`);
      }
    } else {
      out("  (none)");
    }
  }

  if (result.errors?.length) {
    out("");
    out("Errors:");
    for (const er of result.errors) out(`  - ${er}`);
  }
  if (result.chain.errors?.length) {
    out("");
    out("Chain errors:");
    for (const ce of result.chain.errors) out(`  - seq ${ce.seq}: ${ce.message}`);
  }
  if (result.contentIndex.errors?.length) {
    out("");
    out("Content-index errors:");
    for (const ie of result.contentIndex.errors) out(`  - ${ie}`);
  }
  // Canonical note strings pass through verbatim (spec/results.md): the
  // notes are the lanes' shared wording for the same facts the
  // qualifiers name, and a renderer that drops them drops the evidence.
  // The one exception is bookkeeping, not omission: lineage notes are
  // rendered in the Custody block above, where they sit next to the
  // entries they describe, and printing them twice would make one
  // channel look like two. When there is no Custody block — a
  // pre-lineage-era capsule, or one that never opened — they fall
  // through to here rather than disappearing.
  const otherNotes = (result.notes ?? []).filter(
    (n) => !(custodyBlockShown && String(n).startsWith("lineage:")),
  );
  if (otherNotes.length) {
    out("");
    out("Notes:");
    for (const n of otherNotes) out(`  - ${n}`);
  }

  // The verdict block (spec/results.md "CLI reference renderer"). It is
  // verdict-first and enumerates every qualifier: a VALID verdict must
  // never be readable as more than what was actually checked, and a
  // qualifier the operator never sees converts an honest weaker claim by
  // the author into a false stronger claim by the tooling.
  out("");
  if (result.verdict === "unsupported") {
    const diagnosis = primaryDiagnosis(result);
    out(`Result: UNSUPPORTED (${result.verdictReason}${diagnosis ? `: ${diagnosis}` : ""})`);
  } else if (result.verdict === "invalid") {
    out("Result: INVALID");
  } else if (result.qualifiers.length === 0) {
    out(`Result: VALID (no qualifiers; ${result.trustedSignerCount} distinct trusted signer` +
        `${result.trustedSignerCount === 1 ? "" : "s"})`);
  } else {
    out("Result: VALID");
    out("  qualifiers:");
    for (const q of result.qualifiers) out(`    - ${qualifierLine(q, result)}`);
  }
  // Requested policies are the operator's demands, so their outcome
  // belongs beside the verdict: exit 1 with a VALID verdict is only
  // honest if the report says which demand went unmet. A capsule that
  // never opened has no policy outcome to report — refusal exclusivity
  // (spec/profiles.md, spec/versioning.md) keeps the diagnosis alone.
  if (policy !== "none" && reader) {
    out(`  trust policy: ${policySatisfied
      ? "SATISFIED"
      : "FAILED — allowlist provided but matched no signer"}`);
  }
  if (custody.policy !== "none" && reader) {
    out(`  custody policy: ${custody.satisfied
      ? `SATISFIED — lineage verified to depth ${result.lineage.verifiedDepth}`
      : `FAILED — ${custody.reason}`}`);
  }
  if (acceptVersions && versionPolicySatisfied !== null) {
    out(`  version policy: ${versionPolicySatisfied
      ? "SATISFIED"
      : `FAILED — format version ${result.formatVersion.observed} is not in the declared accepted set`}`);
  }
  return ok ? 0 : 1;
}

/**
 * The custody policy this invocation asked for (spec/lineage.md "CLI
 * exit policy"). Every supplied artifact the SDK matched moved exactly
 * one entry off `unverified`, so the checked entries count the supplied
 * files that found a home: the rest are unmatched (a mistyped path must
 * not exit 0). Entries left `unverified` are declared-but-unsupplied —
 * an operator may hold one branch of a merge — and never fail the exit.
 */
function custodyPolicy(lineage, suppliedCount) {
  if (suppliedCount === 0) {
    return { policy: "none", satisfied: null, unmatched: 0, reason: null };
  }
  const checked = lineage.entries.filter((e) => e.status !== "unverified");
  const unmatched = suppliedCount - checked.length;
  const notVerified = checked.filter((e) => e.status !== "verified");
  const reasons = [];
  if (unmatched > 0) {
    reasons.push(
      `${unmatched} supplied predecessor file(s) matched no declared entry`,
    );
  }
  for (const e of notVerified) {
    reasons.push(
      `hop ${e.hop} ${e.capsule_id}: ${e.status}${e.reason ? ` (${e.reason})` : ""}`,
    );
  }
  return {
    policy: "predecessor",
    satisfied: reasons.length === 0,
    unmatched,
    reason: reasons.length === 0 ? null : reasons.join("; "),
  };
}

/** The lineage facts channel in the spec's snake_case for --json. */
function lineageJson(lineage) {
  return {
    declared: lineage.declared,
    ok: lineage.ok,
    verified_depth: lineage.verifiedDepth,
    entries: lineage.entries.map((e) => ({
      capsule_id: e.capsule_id,
      format_version: e.format_version,
      originator_public_key: e.originator_public_key,
      first_event_hash: e.first_event_hash,
      entry_hash: e.entry_hash,
      manifest_hash: e.manifest_hash,
      hop: e.hop,
      identity_checked: e.identityChecked,
      status: e.status,
      reason: e.reason,
      errors: e.errors,
      artifact: e.artifact,
    })),
  };
}
