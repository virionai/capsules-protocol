// Lineage verification (spec/lineage.md): the `manifest.predecessors`
// standalone checks and the report-only supplied-bytes linkage walk.
//
// Two groups of obligations. STANDALONE checks are properties of the
// successor artifact alone and fail it closed (the caller pushes the
// problems into result.errors). LINKAGE checks depend on evidence the
// host supplied at verify time (the `predecessors` verify option) and
// are REPORT-ONLY: the successor's `ok` must remain a function of the
// capsule, never of the invocation — otherwise a third party flips a
// valid capsule's verdict by handing the verifier the wrong file.

import { parseJsonStrict } from "./canonical.js";
import { hexToBytes } from "./crypto.js";
import {
  computeCapsuleId,
  declaredAlternateProfileId,
  manifestHash,
  predecessorIdentityCheckable,
  predecessorsProblems,
} from "./manifest.js";
import { CapsuleReader } from "./reader.js";
import { classifyVersion } from "./versions.js";
import { unpackZip } from "./zip.js";

/**
 * Eras whose rule sets define lineage semantics. A hop declaring an
 * earlier era (e.g. 0.6) carries any `predecessors` member as an
 * unknown member under that era's rules — inert, never shape-checked —
 * and terminates the interpretable walk (spec/lineage.md,
 * spec/versioning.md: no retroactive interpretation of sealed eras).
 */
const LINEAGE_ERAS = new Set(["0.7"]);

/**
 * Resource limit, not a protocol rule (like the reader's file-count and
 * size caps): the walk never fetches — depth is bounded by the supplied
 * pool — and the cap bounds pathological pools.
 */
export const LINEAGE_HOP_CAP_DEFAULT = 256;

/**
 * The fail-closed / not-evaluated lineage shape. `declared: false` here
 * means "not evaluated OR no member present" — after an open-stage or
 * version-gate refusal the channel holds this default and the refusal
 * diagnosis is the only error carried (refusal exclusivity).
 */
export function defaultLineage() {
  return { declared: false, ok: false, verifiedDepth: 0, entries: [] };
}

/** One reported entry: the declared six members echoed, plus the facts. */
function makeEntry(declared, hop) {
  return {
    capsule_id: declared.capsule_id ?? null,
    format_version: declared.format_version ?? null,
    originator_public_key: declared.originator_public_key ?? null,
    first_event_hash: declared.first_event_hash ?? null,
    entry_hash: declared.entry_hash ?? null,
    manifest_hash: declared.manifest_hash ?? null,
    hop,
    identityChecked: predecessorIdentityCheckable(declared),
    status: "unverified",
    reason: null,
    errors: [],
    artifact: null,
  };
}

const HEX64_LOWER = /^[0-9a-f]{64}$/;

/**
 * Classify one supplied pool artifact. Returns a record whose `kind` is
 *   "verifiable"           — plain, known era, default profile; carries
 *                            the full own-era verification + recomputes
 *   "encrypted"            — encrypted capsule (v0.7.1 declarations
 *                            commit to plain members; never guessed at)
 *   "unsupported_version"  — declared era outside the known table
 *   "unsupported_profile"  — declares a profile this verifier does not
 *                            implement (default-profile scope, B2)
 *   "unreadable"           — not openable as a capsule at all
 * Matching for the unverifiable kinds uses the artifact's own CLAIMED
 * id (nothing can be recomputed); their status says so explicitly.
 */
async function classifyArtifact(input, verify, hostOptions) {
  const record = {
    kind: "unreadable",
    manifest: null,
    envelope: null,
    claimedId: null,
    version: null,
    recomputedId: null,
    recomputedMh: null,
    originatorKey: null,
    firstEventHash: null,
    entryHash: null,
    verification: null,
    summary: null,
    assigned: false,
    openError: null,
  };
  let files = null;
  let verifyInput = input;
  try {
    if (input instanceof CapsuleReader) {
      files = input.files_();
    } else {
      const bytes = input instanceof ArrayBuffer ? new Uint8Array(input) : input;
      verifyInput = bytes;
      files = await unpackZip(bytes);
    }
    const manifestBytes = files.get("manifest.json");
    if (!manifestBytes) throw new Error("missing manifest.json");
    record.manifest = parseJsonStrict(manifestBytes, "manifest.json");
    const envBytes = files.get("provenance/envelope.json");
    record.envelope = envBytes ? parseJsonStrict(envBytes, "provenance/envelope.json") : null;
  } catch (err) {
    record.openError = err.message;
    return record;
  }
  const id = record.manifest?.id;
  record.claimedId = typeof id === "string" && HEX64_LOWER.test(id) ? id : null;
  const versionClass = classifyVersion(record.manifest?.format?.version);
  record.version = versionClass.observed;
  if (record.envelope?.cipher !== "none" || files.has("content.enc")) {
    record.kind = "encrypted";
    return record;
  }
  if (versionClass.status !== "known") {
    record.kind = "unsupported_version";
    return record;
  }
  if (declaredAlternateProfileId(record.manifest) !== null) {
    record.kind = "unsupported_profile";
    return record;
  }
  record.kind = "verifiable";
  // Recomputed values ONLY, never the artifact's own claims: identity
  // under the artifact's declared era's domain string, manifest hash
  // from the stored manifest document.
  try {
    record.recomputedId = computeCapsuleId(
      hexToBytes(record.manifest.originator?.public_key ?? ""),
      record.manifest.first_event_hash ?? null,
      record.version,
    );
  } catch {
    record.recomputedId = null;
  }
  try {
    record.recomputedMh = manifestHash(record.manifest);
  } catch {
    record.recomputedMh = null;
  }
  record.originatorKey =
    typeof record.manifest.originator?.public_key === "string"
      ? record.manifest.originator.public_key.toLowerCase()
      : null;
  record.firstEventHash = record.manifest.first_event_hash ?? null;
  record.entryHash = record.envelope?.entry_hash ?? null;
  // The predecessor is verified fully as a capsule under ITS declared
  // version's rules, with the same host options as the main
  // verification (allowlist, version policy) — never the pool, which
  // belongs to this walk.
  record.verification = await verify(verifyInput, {
    allowlist: hostOptions?.allowlist,
    acceptVersions: hostOptions?.acceptVersions,
  });
  record.summary = {
    ok: record.verification.ok,
    observed_version: record.verification.formatVersion?.observed ?? record.version,
    level: record.verification.level,
    error_count: record.verification.errors.length,
  };
  return record;
}

/**
 * The six equalities of spec/lineage.md linkage. Returns member-precise
 * difference strings (empty = the supplied artifact IS the declared
 * sealed state). Wording never uses tamper/corruption vocabulary: the
 * supplied file being a different genuine seal is the common honest
 * cause, and "wrong file supplied" versus "successor lied" is genuinely
 * indistinguishable here — the verifier reports the precise fact and
 * never decides.
 */
function equalityDiffs(entry, record) {
  const pairs = [
    ["format_version", entry.format_version, record.version],
    ["capsule_id", entry.capsule_id, record.recomputedId],
    ["originator_public_key", entry.originator_public_key, record.originatorKey],
    ["first_event_hash", entry.first_event_hash, record.firstEventHash],
    ["entry_hash", entry.entry_hash, record.entryHash],
    ["manifest_hash", entry.manifest_hash, record.recomputedMh],
  ];
  const diffs = [];
  for (const [name, declared, supplied] of pairs) {
    if ((declared ?? null) !== (supplied ?? null)) {
      diffs.push(
        `${name}: declared ${declared ?? "null"}, supplied artifact has ${supplied ?? "null"}`,
      );
    }
  }
  return diffs;
}

/**
 * Evaluate the lineage area for one manifest. Standalone problems are
 * pushed into `errors` (fail-closed, overall verdict); linkage facts
 * live only in the returned area and `notes` (report-only).
 *
 * `verify` is the caller's verifyCapsule (passed in, not imported, to
 * keep the module graph acyclic).
 */
export async function evaluateLineage({ manifest, options = {}, verify, errors, notes }) {
  const lineage = defaultLineage();
  const declared =
    manifest != null && typeof manifest === "object" && "predecessors" in manifest;
  if (!declared) {
    // No claim, nothing checked. ok=true: unchecked is not failed.
    lineage.ok = true;
    return lineage;
  }
  lineage.declared = true;

  // Standalone checks 1–3, fail-closed (spec/lineage.md).
  const problems = predecessorsProblems(manifest.predecessors);
  if (problems.length > 0) {
    for (const p of problems) errors.push(`manifest.${p}`);
    lineage.ok = false;
    return lineage;
  }

  // Pinned phrase: no report may imply a consent bit exists before the
  // v0.8+ countersignature artifact.
  notes.push(
    "lineage: manifest.predecessors is the successor's one-way declaration; " +
      "the predecessor's originator has not countersigned it",
  );

  lineage.entries = manifest.predecessors.map((e) => makeEntry(e, 1));

  // Linkage (report-only) over the supplied pool.
  const pool = Array.isArray(options.predecessors) ? options.predecessors : [];
  const hopCap = options.lineageHopCap ?? LINEAGE_HOP_CAP_DEFAULT;
  const records = [];
  for (const input of pool) {
    records.push(await classifyArtifact(input, verify, options));
  }

  // Seen-set on recomputed manifest_hash bounds pathological pools (a
  // true commitment cycle is a hash fixpoint and cannot verify).
  const walked = new Set();
  const openEntry = (predicate) =>
    lineage.entries.find((e) => e.status === "unverified" && predicate(e));

  let changed = true;
  while (changed) {
    changed = false;
    for (const record of records) {
      if (record.assigned || record.kind === "unreadable") continue;

      if (record.kind !== "verifiable") {
        // Bytes in hand but rules unavailable: match by the artifact's
        // claimed id (status says explicitly that nothing was verified).
        const entry =
          record.claimedId === null ? undefined : openEntry((e) => e.capsule_id === record.claimedId);
        if (!entry) continue;
        record.assigned = true;
        changed = true;
        entry.status = "predecessor_unverifiable";
        entry.reason =
          record.kind === "encrypted" ? "encrypted_predecessor" : record.kind;
        if (record.kind === "encrypted") {
          notes.push(
            `lineage: supplied predecessor for capsule ${entry.capsule_id} is an ` +
              `encrypted capsule; v0.7.1 lineage declarations commit to a plain ` +
              `capsule's members — decrypt the inner capsule and supply it instead. ` +
              `The entry stays declared, not verified`,
          );
        } else if (record.kind === "unsupported_version") {
          notes.push(
            `lineage: supplied predecessor for capsule ${entry.capsule_id} declares ` +
              `format version '${record.version}', which this verifier does not ` +
              `support — a limitation of the verifier, not a defect of either ` +
              `capsule. The entry stays declared, not verified`,
          );
        } else {
          notes.push(
            `lineage: supplied predecessor for capsule ${entry.capsule_id} declares ` +
              `profile '${declaredAlternateProfileId(record.manifest)}', which this ` +
              `verifier does not implement (v0.7.1 lineage declarations commit to ` +
              `default-profile predecessors) — a limitation of the verifier, not a ` +
              `defect of either capsule. The entry stays declared, not verified`,
          );
        }
        continue;
      }

      // Matching uses recomputed values only. Pair match first; an
      // id-only match is a different sealed state of the same identity.
      let entry =
        record.recomputedId === null || record.recomputedMh === null
          ? undefined
          : openEntry(
              (e) =>
                e.capsule_id === record.recomputedId &&
                e.manifest_hash === record.recomputedMh,
            );
      if (!entry && record.recomputedId !== null) {
        entry = openEntry((e) => e.capsule_id === record.recomputedId);
      }
      if (!entry) continue;
      record.assigned = true;
      changed = true;
      entry.artifact = record.summary;
      const diffs = equalityDiffs(entry, record);

      if (!record.verification.ok) {
        // Two facts, never collapsed: "is this the declared artifact"
        // vs "does it verify internally". Takes precedence over
        // mismatch; the equalities are still reported informatively.
        entry.status = "predecessor_invalid";
        entry.errors.push(
          `supplied predecessor fails its own verification under era ` +
            `${record.version} (${record.verification.errors.length} error(s)); ` +
            `this is a property of the supplied artifact, not of the successor's declaration`,
        );
        entry.errors.push(...diffs);
      } else if (diffs.length > 0) {
        entry.status = "mismatch";
        entry.errors.push(
          `supplied artifact is a different sealed state of the declared predecessor ` +
            `(same capsule identity, different seal) — not evidence of tampering; ` +
            `re-seals of a growing line legitimately share a capsule_id`,
        );
        entry.errors.push(...diffs);
      } else {
        entry.status = "verified";
      }

      // Recursive walk: a hop whose manifest matches the declared
      // manifest_hash contributes ITS OWN first-person declaration to
      // the frontier — even when its event chain is broken (the
      // commitment chain authenticates the declaration bytes). A
      // mismatched artifact is NOT the declared artifact and never
      // contributes.
      if (
        record.recomputedMh !== null &&
        entry.manifest_hash === record.recomputedMh &&
        !walked.has(record.recomputedMh)
      ) {
        walked.add(record.recomputedMh);
        const childDeclared = record.manifest?.predecessors;
        if (childDeclared !== undefined) {
          if (!LINEAGE_ERAS.has(record.version)) {
            notes.push(
              `lineage: predecessor ${entry.capsule_id} declares era ${record.version}, ` +
                `whose rule set defines no lineage semantics; its predecessors member ` +
                `is an unknown member under that era and terminates the walk`,
            );
          } else if (predecessorsProblems(childDeclared).length === 0) {
            // A malformed hop declaration is diagnosed by that hop's own
            // verification (predecessor_invalid); nothing to walk.
            if (entry.hop + 1 <= hopCap) {
              for (const d of childDeclared) {
                lineage.entries.push(makeEntry(d, entry.hop + 1));
              }
            } else {
              notes.push(
                `lineage: hop cap ${hopCap} reached; deeper declarations were not walked`,
              );
            }
          }
        }
      }
    }
  }

  // Unmatched supplied artifacts are named, never silently ignored — a
  // mistyped path must be visible.
  records.forEach((record, i) => {
    if (record.assigned) return;
    if (record.kind === "unreadable") {
      notes.push(
        `lineage: supplied predecessor artifact #${i + 1} could not be read as a ` +
          `capsule (${record.openError}); it matched no declared entry`,
      );
    } else {
      const label = record.claimedId ?? record.recomputedId ?? "(unknown id)";
      notes.push(
        `lineage: supplied predecessor artifact #${i + 1} (capsule ${label}) ` +
          `matched no declared entry`,
      );
    }
  });

  // Pinned phrase: a custody claim must never quietly disappear when
  // bytes are missing — that is how a citation gets read as an
  // endorsement.
  for (const entry of lineage.entries) {
    if (entry.status === "unverified" || entry.status === "predecessor_unverifiable") {
      notes.push(
        `lineage: predecessor ${entry.capsule_id} (hop ${entry.hop}): declared, not verified`,
      );
    }
  }

  // verified_depth: the largest N such that every declared entry within
  // N hops has status "verified".
  let depth = 0;
  for (let hop = 1; ; hop++) {
    if (!lineage.entries.some((e) => e.hop === hop)) break;
    if (!lineage.entries.filter((e) => e.hop <= hop).every((e) => e.status === "verified")) {
      break;
    }
    depth = hop;
  }
  lineage.verifiedDepth = depth;
  if (depth >= 1) {
    const parents = lineage.entries
      .filter((e) => e.hop === 1)
      .map((e) => e.capsule_id)
      .join(", ");
    // Two distinct identities, always: the successor is never presented
    // as BEING the predecessor or as its endorsed continuation.
    notes.push(`lineage: successor of capsule ${parents}; lineage verified to depth ${depth}`);
  }

  // Area verdict: standalone passed (or we returned above) AND nothing
  // checked contradicts. Unchecked is not failed.
  lineage.ok = !lineage.entries.some(
    (e) => e.status === "mismatch" || e.status === "predecessor_invalid",
  );
  return lineage;
}
