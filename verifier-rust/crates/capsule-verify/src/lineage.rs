//! Lineage verification (spec/lineage.md): the `manifest.predecessors`
//! standalone checks and the report-only supplied-bytes linkage walk.
//! Mirrors `evaluateLineage` in `sdk-js/src/lineage.js`.
//!
//! Two groups of obligations. STANDALONE checks are properties of the
//! successor artifact alone and fail it closed (the caller pushes the
//! problems into `VerifyResult::errors` under
//! [`TopErrorCategory::Lineage`]). LINKAGE checks depend on evidence the
//! host supplied at verify time (the `predecessors` verify option) and
//! are REPORT-ONLY: the successor's `ok` must remain a function of the
//! capsule, never of the invocation — otherwise a third party flips a
//! valid capsule's verdict by handing the verifier the wrong file.
//!
//! The declaration is read from the PRESERVED `serde_json::Value` the
//! manifest parsed into ([`crate::schemas::Manifest::predecessors`] keeps
//! it raw): every shape reaches the checks, so a malformed declaration
//! gets the cross-lane `predecessors[i].<member>` diagnosis instead of a
//! lane-specific manifest parse crash.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::hex_to_bytes;
use crate::manifest::{compute_capsule_id, manifest_hash};
use crate::schemas::{Envelope, Manifest};
use crate::verifier::{verify_capsule, VerifyOptions, VerifyResult};
use crate::versions::{classify_version, VersionStatus};
use crate::zip_reader::unpack_zip;

/// The six spec-defined members of one predecessor entry, all REQUIRED
/// when the entry is present (nullability only on the two anchors).
pub const PREDECESSOR_ENTRY_MEMBERS: &[&str] = &[
    "capsule_id",
    "format_version",
    "originator_public_key",
    "first_event_hash",
    "entry_hash",
    "manifest_hash",
];

/// The era default profile id (spec/lineage.md "Scope"), frozen forever.
/// A v0.7.1 declaration commits to a predecessor verified under it; a
/// supplied artifact declaring any other profile is reported
/// `predecessor_unverifiable` / `unsupported_profile` — a verifier/scope
/// limitation, never `mismatch` and never `predecessor_invalid`.
pub const DEFAULT_PROFILE_ID: &str = "v0.6-suite";

/// Eras whose rule sets define lineage semantics. `predecessors` is a
/// CLAIM member, not a rule selector, so it follows per-era rule sets:
/// inside a capsule declaring an earlier era it stays an unknown member
/// even to a v0.7.1 reader — preserved, hashed, never shape-checked
/// (spec/versioning.md "In-era tightening and cross-era force";
/// spec/lineage.md "No retroactive interpretation of sealed eras"). The
/// gate is the SAME whether the capsule is the verification subject or a
/// hop reached through the walk — one artifact, one rule set.
const LINEAGE_ERAS: &[&str] = &["0.7"];

/// Whether an observed `<major>.<minor>` era interprets `predecessors`.
/// An unknown era never reaches here (the version gate fails closed
/// first), so `false` means "known era, pre-lineage rules".
pub(crate) fn era_defines_lineage(version: &str) -> bool {
    LINEAGE_ERAS.contains(&version)
}

/// Resource limit, not a protocol rule — the sibling of this lane's
/// [`crate::zip_reader::MAX_ENTRIES`] / [`crate::zip_reader::MAX_TOTAL_BYTES`]
/// reader caps. The walk never fetches (depth is bounded by the supplied
/// pool); the cap bounds pathological pools.
pub const LINEAGE_HOP_CAP: usize = 256;

/// How many problems a verify result actually diagnosed.
///
/// [`VerifyResult::errors`] carries the cross-cutting diagnoses only —
/// area failures live in their own channels (a tampered payload is a
/// `content_index` error, a broken link a `chain` error, a forged
/// signature an invalid signer row) — so counting the top-level vector
/// alone reports a failing capsule as having zero errors. Every report
/// that says "N error(s)" about someone else's artifact uses this count.
pub fn verification_error_count(result: &VerifyResult) -> usize {
    let invalid_signatures = result.envelope.signers.iter().filter(|s| !s.valid).count();
    result.errors.len()
        + result.content_index.errors.len()
        + result.chain.errors.len()
        + invalid_signatures
}

/// The lineage fact channel (spec/lineage.md "Reporting").
///
/// The derived `Default` — `declared: false, ok: false` — is the
/// fail-closed NOT-EVALUATED shape: after an open-stage or version-gate
/// refusal the channel holds it and the refusal diagnosis is the only
/// error carried (refusal exclusivity), so `declared: false` there means
/// "not evaluated", not "absent". A capsule that reached the check and
/// declares nothing reports `declared: false, ok: true` — unchecked is
/// not failed.
///
/// `ok` is true iff the standalone checks passed AND no CHECKED entry is
/// `mismatch` or `predecessor_invalid`. A standalone failure also fails
/// the capsule; a linkage failure never does.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LineageCheck {
    pub declared: bool,
    pub ok: bool,
    pub verified_depth: usize,
    pub entries: Vec<LineageEntry>,
}

/// One reported entry: the declared six members echoed (so hosts apply
/// key policy without re-parsing the manifest) plus the facts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEntry {
    pub capsule_id: Option<String>,
    pub format_version: Option<String>,
    pub originator_public_key: Option<String>,
    pub first_event_hash: Option<String>,
    pub entry_hash: Option<String>,
    pub manifest_hash: Option<String>,
    /// 1 for an immediate parent; N for a declaration recovered from a
    /// verified hop's own first-person declaration.
    pub hop: usize,
    /// Whether standalone check 3 (identity coherence) actually ran —
    /// false when the declared era is outside this verifier's known
    /// table, which is REPORTED, never failed.
    pub identity_checked: bool,
    /// Closed vocabulary: "unverified" | "verified" | "mismatch" |
    /// "predecessor_invalid" | "predecessor_unverifiable".
    pub status: String,
    /// Closed vocabulary, `Some` only with status
    /// "predecessor_unverifiable": "unsupported_version" |
    /// "encrypted_predecessor" | "unsupported_profile" |
    /// "unsupported_capability".
    pub reason: Option<String>,
    pub errors: Vec<String>,
    /// Slim summary of the supplied predecessor's OWN verification;
    /// `None` when nothing was checked. Host trust over predecessor
    /// originators derives from that verification's per-signer results —
    /// the lineage area does not duplicate host policy.
    pub artifact: Option<PredecessorArtifact>,
}

/// The supplied predecessor's own verify result, slimmed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredecessorArtifact {
    pub ok: bool,
    pub observed_version: Option<String>,
    pub level: String,
    pub error_count: usize,
}

fn is_hex64_lower(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex64_lower_of(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|s| is_hex64_lower(s))
}

/// The declared profile id when the manifest declares an ALTERNATE
/// profile, `None` for the era default (declared explicitly or by
/// absence). A present-but-uninterpretable declaration returns a
/// placeholder: the caller treats it as non-default, and the profile
/// machinery (spec/profiles.md) owns its full diagnosis.
pub fn declared_alternate_profile_id(manifest: &Value) -> Option<String> {
    let profile = manifest.get("format")?.get("profile")?;
    if profile.is_null() {
        return None;
    }
    match profile.get("id").and_then(Value::as_str) {
        Some(DEFAULT_PROFILE_ID) => None,
        Some(id) if !id.is_empty() => Some(id.to_string()),
        _ => Some("(uninterpretable profile declaration)".to_string()),
    }
}

/// True when the declared era's identity rule is available to this
/// implementation, i.e. standalone check 3 actually ran for the entry.
pub fn predecessor_identity_checkable(entry: &Value) -> bool {
    let declared = entry.get("format_version").and_then(Value::as_str).unwrap_or("");
    classify_version(declared) == VersionStatus::Known
}

/// Validate a stored `predecessors` value (spec/lineage.md, standalone
/// checks 1–3). Returns problem strings; empty means well-formed. Every
/// problem names its member as `predecessors[i].<member>` — the shared
/// cross-lane diagnosis strings.
///
///   1. Shape and grammar — an array of entry objects; the six members
///      present with the required types; lowercase hex REQUIRED, not
///      normalized (the claim is bound by its stored bytes); a
///      present-but-EMPTY array is malformed ("no claim" has exactly one
///      spelling: absence); two entries sharing a `manifest_hash` are
///      malformed (the same sealed artifact cited twice). Two entries
///      sharing a `capsule_id` with DIFFERENT manifest hashes stay legal
///      — a merge of two snapshots of one line. Vendor extensions inside
///      an entry use the `x-` prefix; any other unrecognized member is
///      malformed.
///   2. Null coherence — `first_event_hash` and `entry_hash` both null
///      (zero-event predecessor) or both 64-hex; a mixed declaration
///      describes a predecessor that cannot exist.
///   3. Identity coherence — under a KNOWN declared era, the declared
///      `capsule_id` must equal the recompute under THAT era's identity
///      rule. An unknown declared era SKIPS the check (versioning.md
///      forbids applying one era's formula to another era's claim);
///      callers report `identity_checked: false`, never a failure.
pub fn predecessors_problems(predecessors: &Value) -> Vec<String> {
    let Some(list) = predecessors.as_array() else {
        return vec!["predecessors must be an array of predecessor entry objects".to_string()];
    };
    if list.is_empty() {
        return vec![
            "predecessors must not be empty when present (\"no claim\" has exactly one spelling: absence)"
                .to_string(),
        ];
    }
    let mut problems = Vec::new();
    for (i, entry) in list.iter().enumerate() {
        let Some(obj) = entry.as_object() else {
            problems.push(format!("predecessors[{i}] must be an entry object"));
            continue;
        };
        for key in obj.keys() {
            if !PREDECESSOR_ENTRY_MEMBERS.contains(&key.as_str()) && !key.starts_with("x-") {
                problems.push(format!(
                    "predecessors[{i}].{key} is not a spec-defined entry member \
                     (vendor extensions must use the x- prefix)"
                ));
            }
        }
        for key in ["capsule_id", "originator_public_key", "manifest_hash"] {
            if hex64_lower_of(obj.get(key)).is_none() {
                problems.push(format!("predecessors[{i}].{key} must be lowercase 64-hex"));
            }
        }
        for key in ["first_event_hash", "entry_hash"] {
            let anchor_ok = match obj.get(key) {
                None => false,
                Some(Value::Null) => true,
                Some(v) => v.as_str().is_some_and(is_hex64_lower),
            };
            if !anchor_ok {
                problems.push(format!(
                    "predecessors[{i}].{key} must be lowercase 64-hex or null"
                ));
            }
        }
        let declared_version = obj.get("format_version").and_then(Value::as_str).unwrap_or("");
        let version_status = classify_version(declared_version);
        if version_status == VersionStatus::Invalid {
            problems.push(format!(
                "predecessors[{i}].format_version must be a '<major>.<minor>' version string, got {}",
                obj.get("format_version").unwrap_or(&Value::Null)
            ));
        }
        // Null coherence (check 2) — only meaningful once both anchors typed.
        let feh = obj.get("first_event_hash");
        let eh = obj.get("entry_hash");
        let feh_null = matches!(feh, Some(Value::Null));
        let eh_null = matches!(eh, Some(Value::Null));
        let feh_ok = feh_null || hex64_lower_of(feh).is_some();
        let eh_ok = eh_null || hex64_lower_of(eh).is_some();
        if feh_ok && eh_ok && feh_null != eh_null {
            problems.push(format!(
                "predecessors[{i}].first_event_hash and predecessors[{i}].entry_hash must be \
                 both null (zero-event predecessor) or both 64-hex — a mixed declaration \
                 describes a predecessor that cannot exist"
            ));
        }
        // Identity coherence (check 3) — known declared eras only.
        let coherent_so_far =
            version_status == VersionStatus::Known && feh_ok && eh_ok && feh_null == eh_null;
        if let (true, Some(id), Some(key)) = (
            coherent_so_far,
            hex64_lower_of(obj.get("capsule_id")),
            hex64_lower_of(obj.get("originator_public_key")),
        ) {
            let derived = hex_to_bytes(key).ok().and_then(|raw| {
                compute_capsule_id(&raw, hex64_lower_of(feh), declared_version).ok()
            });
            if derived.as_deref() != Some(id) {
                problems.push(format!(
                    "predecessors[{i}].capsule_id does not derive from the declared originator \
                     key and first event hash under era {declared_version} — the declaration \
                     contradicts its own members"
                ));
            }
        }
    }
    // Duplicate manifest_hash across entries (the same artifact cited twice).
    let mut seen: Vec<(&str, usize)> = Vec::new();
    for (i, entry) in list.iter().enumerate() {
        let Some(mh) = hex64_lower_of(entry.get("manifest_hash")) else {
            continue;
        };
        match seen.iter().find(|(seen_mh, _)| *seen_mh == mh) {
            Some((_, first)) => problems.push(format!(
                "predecessors[{i}].manifest_hash duplicates predecessors[{first}].manifest_hash \
                 (the same sealed artifact cited twice)"
            )),
            None => seen.push((mh, i)),
        }
    }
    problems
}

/// One reported entry, built from a declared entry object.
fn entry_from_declared(declared: &Value, hop: usize) -> LineageEntry {
    let member = |key: &str| {
        declared
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    LineageEntry {
        capsule_id: member("capsule_id"),
        format_version: member("format_version"),
        originator_public_key: member("originator_public_key"),
        first_event_hash: member("first_event_hash"),
        entry_hash: member("entry_hash"),
        manifest_hash: member("manifest_hash"),
        hop,
        identity_checked: predecessor_identity_checkable(declared),
        status: "unverified".to_string(),
        reason: None,
        errors: Vec::new(),
        artifact: None,
    }
}

/// How a supplied pool artifact can be read by THIS verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    /// Plain, known era, default profile: fully verifiable, with the
    /// identity and manifest hash RECOMPUTED for matching.
    Verifiable,
    /// An encrypted capsule. v0.7.1 declarations commit to a plain
    /// capsule's members, so the mapping is never guessed at.
    Encrypted,
    /// Declared era outside this verifier's known table.
    UnsupportedVersion,
    /// Declares a profile this verifier does not implement.
    UnsupportedProfile,
    /// Not openable as a capsule at all.
    Unreadable,
}

impl ArtifactKind {
    /// The `predecessor_unverifiable` reason, for the kinds that report
    /// one. `None` for the two kinds that never reach that status: a
    /// verifiable artifact is checked, and an unreadable one is not a
    /// predecessor at all (it is named in `notes` as unmatched).
    fn reason(self) -> Option<&'static str> {
        match self {
            ArtifactKind::Encrypted => Some("encrypted_predecessor"),
            ArtifactKind::UnsupportedVersion => Some("unsupported_version"),
            ArtifactKind::UnsupportedProfile => Some("unsupported_profile"),
            ArtifactKind::Verifiable | ArtifactKind::Unreadable => None,
        }
    }
}

/// One classified pool artifact.
struct ArtifactRecord {
    kind: ArtifactKind,
    /// The artifact's OWN claimed id — used to match only for the kinds
    /// where nothing can be recomputed; their status says so explicitly.
    claimed_id: Option<String>,
    version: Option<String>,
    profile_id: Option<String>,
    recomputed_id: Option<String>,
    recomputed_manifest_hash: Option<String>,
    originator_key: Option<String>,
    first_event_hash: Option<String>,
    entry_hash: Option<String>,
    /// The artifact's own first-person lineage declaration, raw.
    declared_predecessors: Option<Value>,
    verification: Option<VerifyResult>,
    assigned: bool,
    open_error: Option<String>,
}

impl ArtifactRecord {
    fn new(kind: ArtifactKind, open_error: Option<String>) -> Self {
        ArtifactRecord {
            kind,
            claimed_id: None,
            version: None,
            profile_id: None,
            recomputed_id: None,
            recomputed_manifest_hash: None,
            originator_key: None,
            first_event_hash: None,
            entry_hash: None,
            declared_predecessors: None,
            verification: None,
            assigned: false,
            open_error,
        }
    }

    fn unreadable(message: String) -> Self {
        ArtifactRecord::new(ArtifactKind::Unreadable, Some(message))
    }

    fn summary(&self) -> Option<PredecessorArtifact> {
        let v = self.verification.as_ref()?;
        Some(PredecessorArtifact {
            ok: v.ok,
            observed_version: v.format_version.observed.clone().or_else(|| self.version.clone()),
            level: v.level.clone(),
            error_count: verification_error_count(v),
        })
    }
}

/// Classify one supplied pool artifact, verifying it fully under ITS
/// declared version's rules when this verifier can (the same host options
/// as the main verification — never the pool, which belongs to this walk).
fn classify_artifact(bytes: &[u8], options: &VerifyOptions) -> ArtifactRecord {
    let files = match unpack_zip(bytes) {
        Ok(f) => f,
        Err(e) => return ArtifactRecord::unreadable(e.to_string()),
    };
    let Some(manifest_bytes) = files.get("manifest.json") else {
        return ArtifactRecord::unreadable("missing manifest.json".to_string());
    };
    let manifest_value: Value = match crate::jcs::parse_json_strict(manifest_bytes) {
        Ok(v) => v,
        Err(e) => return ArtifactRecord::unreadable(format!("failed to parse manifest.json: {e}")),
    };
    let manifest: Manifest = match serde_json::from_value(manifest_value.clone()) {
        Ok(m) => m,
        Err(e) => return ArtifactRecord::unreadable(format!("failed to parse manifest.json: {e}")),
    };
    let envelope: Option<Envelope> = match files.get("provenance/envelope.json") {
        None => None,
        Some(b) => match crate::jcs::parse_json_strict(b)
            .and_then(|v: Value| serde_json::from_value::<Envelope>(v))
        {
            Ok(e) => Some(e),
            Err(e) => {
                return ArtifactRecord::unreadable(format!(
                    "failed to parse provenance/envelope.json: {e}"
                ))
            }
        },
    };

    // An artifact with no readable plain envelope is treated as encrypted
    // rather than guessed at, matching the JS reference's classification.
    let cipher_is_none = envelope.as_ref().is_some_and(|e| e.cipher == "none");
    let alternate_profile = declared_alternate_profile_id(&manifest_value);
    let kind = if !cipher_is_none || files.contains_key("content.enc") {
        ArtifactKind::Encrypted
    } else if classify_version(&manifest.format.version) != VersionStatus::Known {
        ArtifactKind::UnsupportedVersion
    } else if alternate_profile.is_some() {
        ArtifactKind::UnsupportedProfile
    } else {
        ArtifactKind::Verifiable
    };

    let mut record = ArtifactRecord::new(kind, None);
    record.claimed_id = Some(manifest.id.clone()).filter(|id| is_hex64_lower(id));
    record.version = Some(manifest.format.version.clone());
    record.declared_predecessors = manifest.predecessors.clone();
    record.profile_id = alternate_profile;
    if kind != ArtifactKind::Verifiable {
        return record;
    }

    // Recomputed values ONLY, never the artifact's own claims: identity
    // under the artifact's declared era's domain string, manifest hash
    // from the stored manifest document.
    record.recomputed_id = hex_to_bytes(&manifest.originator.public_key)
        .ok()
        .and_then(|pk| {
            compute_capsule_id(
                &pk,
                manifest.first_event_hash.as_deref(),
                &manifest.format.version,
            )
            .ok()
        });
    record.recomputed_manifest_hash = Some(manifest_hash(&manifest_value));
    record.originator_key = Some(manifest.originator.public_key.to_lowercase());
    record.first_event_hash = manifest.first_event_hash.clone();
    record.entry_hash = envelope.and_then(|e| e.entry_hash);
    record.verification = Some(verify_capsule(
        bytes,
        &VerifyOptions {
            allowlist: options.allowlist.clone(),
            recipient_private_key: None,
            accept_versions: options.accept_versions.clone(),
            predecessors: Vec::new(),
        },
    ));
    record
}

/// The six equalities of spec/lineage.md linkage. Returns member-precise
/// difference strings (empty = the supplied artifact IS the declared
/// sealed state). The wording never uses tamper/corruption vocabulary:
/// the supplied file being a different genuine seal is the common honest
/// cause, and "wrong file supplied" versus "successor lied" is genuinely
/// indistinguishable here.
fn equality_diffs(entry: &LineageEntry, record: &ArtifactRecord) -> Vec<String> {
    let pairs: [(&str, Option<&str>, Option<&str>); 6] = [
        ("format_version", entry.format_version.as_deref(), record.version.as_deref()),
        ("capsule_id", entry.capsule_id.as_deref(), record.recomputed_id.as_deref()),
        (
            "originator_public_key",
            entry.originator_public_key.as_deref(),
            record.originator_key.as_deref(),
        ),
        (
            "first_event_hash",
            entry.first_event_hash.as_deref(),
            record.first_event_hash.as_deref(),
        ),
        ("entry_hash", entry.entry_hash.as_deref(), record.entry_hash.as_deref()),
        (
            "manifest_hash",
            entry.manifest_hash.as_deref(),
            record.recomputed_manifest_hash.as_deref(),
        ),
    ];
    pairs
        .iter()
        .filter(|(_, declared, supplied)| declared != supplied)
        .map(|(name, declared, supplied)| {
            format!(
                "{name}: declared {}, supplied artifact has {}",
                declared.unwrap_or("null"),
                supplied.unwrap_or("null")
            )
        })
        .collect()
}

/// Index of the first entry still open (status "unverified") satisfying
/// `predicate`. An artifact is assigned to at most one entry, and an
/// entry receives at most one artifact.
fn open_entry(
    entries: &[LineageEntry],
    predicate: impl Fn(&LineageEntry) -> bool,
) -> Option<usize> {
    entries
        .iter()
        .position(|e| e.status == "unverified" && predicate(e))
}

/// Evaluate the lineage area for one manifest. Standalone problems are
/// pushed into `problems` (fail-closed, the caller categorizes them);
/// linkage facts live only in the returned area and `notes`
/// (report-only).
pub(crate) fn evaluate_lineage(
    manifest: &Manifest,
    options: &VerifyOptions,
    problems: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> LineageCheck {
    let mut lineage = LineageCheck::default();
    let Some(declared) = manifest.predecessors.as_ref() else {
        // No claim, nothing checked. ok=true: unchecked is not failed.
        lineage.ok = true;
        return lineage;
    };
    if !era_defines_lineage(&manifest.format.version) {
        // Present, but this capsule's era defines no lineage semantics:
        // the member is an unknown member under those rules — preserved
        // and hashed, never shape-checked. Interpreting it would
        // retroactively rewrite a sealed era's verdict.
        notes.push(format!(
            "lineage: this capsule declares era {}, whose rule set defines no lineage \
             semantics; its predecessors member is an unknown member under that era \
             and was not interpreted",
            manifest.format.version
        ));
        lineage.ok = true;
        return lineage;
    }
    lineage.declared = true;

    // Standalone checks 1–3, fail-closed.
    let standalone = predecessors_problems(declared);
    if !standalone.is_empty() {
        problems.extend(standalone);
        return lineage;
    }

    // Pinned phrase: no report may imply a consent bit exists before the
    // v0.8+ countersignature artifact.
    notes.push(
        "lineage: manifest.predecessors is the successor's one-way declaration; \
         the predecessor's originator has not countersigned it"
            .to_string(),
    );

    let declared_entries = declared.as_array().expect("checked as an array above");
    lineage.entries = declared_entries
        .iter()
        .map(|e| entry_from_declared(e, 1))
        .collect();

    // Linkage (report-only) over the supplied pool.
    let mut records: Vec<ArtifactRecord> = options
        .predecessors
        .iter()
        .map(|bytes| classify_artifact(bytes, options))
        .collect();

    // Seen-set on the recomputed manifest hash bounds pathological pools
    // (a true commitment cycle is a hash fixpoint and cannot verify).
    let mut walked: BTreeSet<String> = BTreeSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        for record in &mut records {
            if record.assigned || record.kind == ArtifactKind::Unreadable {
                continue;
            }

            if let Some(reason) = record.kind.reason() {
                // Bytes in hand but rules unavailable: match by the
                // artifact's claimed id (nothing can be recomputed).
                let Some(claimed) = record.claimed_id.clone() else {
                    continue;
                };
                let Some(ei) = open_entry(&lineage.entries, |e| {
                    e.capsule_id.as_deref() == Some(claimed.as_str())
                }) else {
                    continue;
                };
                record.assigned = true;
                changed = true;
                lineage.entries[ei].status = "predecessor_unverifiable".to_string();
                lineage.entries[ei].reason = Some(reason.to_string());
                let entry_id = lineage.entries[ei].capsule_id.clone().unwrap_or_default();
                notes.push(match record.kind {
                    ArtifactKind::Encrypted => format!(
                        "lineage: supplied predecessor for capsule {entry_id} is an encrypted \
                         capsule; v0.7.1 lineage declarations commit to a plain capsule's \
                         members — decrypt the inner capsule and supply it instead. The entry \
                         stays declared, not verified"
                    ),
                    ArtifactKind::UnsupportedVersion => format!(
                        "lineage: supplied predecessor for capsule {entry_id} declares format \
                         version '{}', which this verifier does not support — a limitation of \
                         the verifier, not a defect of either capsule. The entry stays declared, \
                         not verified",
                        record.version.as_deref().unwrap_or("(none)")
                    ),
                    _ => format!(
                        "lineage: supplied predecessor for capsule {entry_id} declares profile \
                         '{}', which this verifier does not implement (v0.7.1 lineage \
                         declarations commit to default-profile predecessors) — a limitation of \
                         the verifier, not a defect of either capsule. The entry stays declared, \
                         not verified",
                        record.profile_id.as_deref().unwrap_or("(none)")
                    ),
                });
                continue;
            }

            // Matching uses recomputed values only. The pair match comes
            // first; an id-only match is a different sealed state of the
            // same identity.
            let recomputed_id = record.recomputed_id.clone();
            let recomputed_mh = record.recomputed_manifest_hash.clone();
            let mut found = match (&recomputed_id, &recomputed_mh) {
                (Some(id), Some(mh)) => open_entry(&lineage.entries, |e| {
                    e.capsule_id.as_deref() == Some(id.as_str())
                        && e.manifest_hash.as_deref() == Some(mh.as_str())
                }),
                _ => None,
            };
            if found.is_none() {
                if let Some(id) = &recomputed_id {
                    found = open_entry(&lineage.entries, |e| {
                        e.capsule_id.as_deref() == Some(id.as_str())
                    });
                }
            }
            let Some(ei) = found else { continue };
            record.assigned = true;
            changed = true;

            let diffs = equality_diffs(&lineage.entries[ei], record);
            let verification_ok = record
                .verification
                .as_ref()
                .is_some_and(|v| v.ok);
            lineage.entries[ei].artifact = record.summary();
            if !verification_ok {
                // Two facts, never collapsed: "is this the declared
                // artifact" vs "does it verify internally". Takes
                // precedence over mismatch; the equalities are still
                // reported informatively.
                let error_count = record
                    .verification
                    .as_ref()
                    .map_or(0, verification_error_count);
                lineage.entries[ei].status = "predecessor_invalid".to_string();
                lineage.entries[ei].errors.push(format!(
                    "supplied predecessor fails its own verification under era {} \
                     ({error_count} error(s)); this is a property of the supplied artifact, \
                     not of the successor's declaration",
                    record.version.as_deref().unwrap_or("(none)")
                ));
                lineage.entries[ei].errors.extend(diffs);
            } else if !diffs.is_empty() {
                lineage.entries[ei].status = "mismatch".to_string();
                lineage.entries[ei].errors.push(
                    "supplied artifact is a different sealed state of the declared predecessor \
                     (same capsule identity, different seal) — not evidence of tampering; \
                     re-seals of a growing line legitimately share a capsule_id"
                        .to_string(),
                );
                lineage.entries[ei].errors.extend(diffs);
            } else {
                lineage.entries[ei].status = "verified".to_string();
            }

            // Recursive walk: a hop whose manifest matches the declared
            // manifest_hash contributes ITS OWN first-person declaration
            // to the frontier — even when its event chain is broken (the
            // commitment chain authenticates the declaration bytes). A
            // mismatched artifact is NOT the declared artifact and never
            // contributes.
            let Some(mh) = recomputed_mh else { continue };
            if lineage.entries[ei].manifest_hash.as_deref() != Some(mh.as_str())
                || !walked.insert(mh)
            {
                continue;
            }
            let Some(child) = record.declared_predecessors.clone() else {
                continue;
            };
            let hop = lineage.entries[ei].hop;
            let entry_id = lineage.entries[ei].capsule_id.clone().unwrap_or_default();
            let era = record.version.clone().unwrap_or_default();
            if !LINEAGE_ERAS.contains(&era.as_str()) {
                notes.push(format!(
                    "lineage: predecessor {entry_id} declares era {era}, whose rule set defines \
                     no lineage semantics; its predecessors member is an unknown member under \
                     that era and terminates the walk"
                ));
                continue;
            }
            // A malformed hop declaration is diagnosed by that hop's own
            // verification (predecessor_invalid); nothing to walk.
            if !predecessors_problems(&child).is_empty() {
                continue;
            }
            if hop + 1 > LINEAGE_HOP_CAP {
                notes.push(format!(
                    "lineage: hop cap {LINEAGE_HOP_CAP} reached; deeper declarations were not walked"
                ));
                continue;
            }
            for declared_child in child.as_array().into_iter().flatten() {
                lineage.entries.push(entry_from_declared(declared_child, hop + 1));
            }
        }
    }

    // Unmatched supplied artifacts are named, never silently ignored — a
    // mistyped path must be visible.
    for (i, record) in records.iter().enumerate() {
        if record.assigned {
            continue;
        }
        if record.kind == ArtifactKind::Unreadable {
            notes.push(format!(
                "lineage: supplied predecessor artifact #{} could not be read as a capsule ({}); \
                 it matched no declared entry",
                i + 1,
                record.open_error.as_deref().unwrap_or("unknown error")
            ));
        } else {
            let label = record
                .claimed_id
                .as_deref()
                .or(record.recomputed_id.as_deref())
                .unwrap_or("(unknown id)");
            notes.push(format!(
                "lineage: supplied predecessor artifact #{} (capsule {label}) matched no \
                 declared entry",
                i + 1
            ));
        }
    }

    // Pinned phrase: a custody claim must never quietly disappear when
    // bytes are missing — that is how a citation gets read as an
    // endorsement.
    for entry in &lineage.entries {
        if entry.status == "unverified" || entry.status == "predecessor_unverifiable" {
            notes.push(format!(
                "lineage: predecessor {} (hop {}): declared, not verified",
                entry.capsule_id.as_deref().unwrap_or("(none)"),
                entry.hop
            ));
        }
    }

    // verified_depth: the largest N such that every declared entry within
    // N hops has status "verified".
    let mut depth = 0;
    for hop in 1.. {
        if !lineage.entries.iter().any(|e| e.hop == hop) {
            break;
        }
        if !lineage
            .entries
            .iter()
            .filter(|e| e.hop <= hop)
            .all(|e| e.status == "verified")
        {
            break;
        }
        depth = hop;
    }
    lineage.verified_depth = depth;
    if depth >= 1 {
        // Two distinct identities, always: the successor is never
        // presented as BEING the predecessor or as its endorsed
        // continuation.
        let parents = lineage
            .entries
            .iter()
            .filter(|e| e.hop == 1)
            .map(|e| e.capsule_id.clone().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(", ");
        notes.push(format!(
            "lineage: successor of capsule {parents}; lineage verified to depth {depth}"
        ));
    }

    // Area verdict: standalone passed (or we returned above) AND nothing
    // checked contradicts. Unchecked is not failed.
    lineage.ok = !lineage
        .entries
        .iter()
        .any(|e| e.status == "mismatch" || e.status == "predecessor_invalid");
    lineage
}

/// The three EMITTED lineage verdict qualifiers (spec/lineage.md
/// "Reporting"): bare strings, non-empty only on a VALID verdict —
/// "valid verdict, custody claim not clean" is exactly what a renderer
/// must not hide. Payload-carrying facts (`verified_depth`, per-entry
/// statuses and reasons) live in the lineage area, never on the
/// bare-string array.
pub(crate) fn lineage_qualifiers(ok: bool, lineage: &LineageCheck) -> Vec<String> {
    let mut qualifiers = Vec::new();
    if !ok || !lineage.declared {
        return qualifiers;
    }
    let any = |status: &str| lineage.entries.iter().any(|e| e.status == status);
    if any("unverified") || any("predecessor_unverifiable") {
        qualifiers.push("lineage_declared_unverified".to_string());
    }
    if any("mismatch") {
        qualifiers.push("lineage_mismatch".to_string());
    }
    if any("predecessor_invalid") {
        qualifiers.push("lineage_predecessor_invalid".to_string());
    }
    qualifiers
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A well-formed single-entry declaration derived from a real
    /// keypair: id recomputed under the declared era's domain string.
    fn coherent_entry() -> Value {
        let key = [7u8; 32];
        let feh = "a".repeat(64);
        let id = compute_capsule_id(&key, Some(&feh), "0.7").unwrap();
        json!({
            "capsule_id": id,
            "format_version": "0.7",
            "originator_public_key": crate::crypto::bytes_to_hex(&key),
            "first_event_hash": feh,
            "entry_hash": "b".repeat(64),
            "manifest_hash": "c".repeat(64),
        })
    }

    #[test]
    fn well_formed_declaration_has_no_problems() {
        let problems = predecessors_problems(&json!([coherent_entry()]));
        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
    }

    #[test]
    fn shape_and_grammar_problems_name_their_member() {
        assert!(predecessors_problems(&json!("nope"))[0].contains("must be an array"));
        assert!(predecessors_problems(&json!([]))[0].contains("must not be empty"));

        let mut entry = coherent_entry();
        entry["capsule_id"] = json!("A".repeat(64));
        let problems = predecessors_problems(&json!([entry]));
        assert!(
            problems.iter().any(|p| p.contains("predecessors[0].capsule_id")),
            "uppercase hex must be refused, not normalized: {problems:?}"
        );

        let mut entry = coherent_entry();
        entry.as_object_mut().unwrap().remove("manifest_hash");
        assert!(predecessors_problems(&json!([entry]))
            .iter()
            .any(|p| p.contains("predecessors[0].manifest_hash")));

        let mut entry = coherent_entry();
        entry["label"] = json!("official continuation");
        assert!(predecessors_problems(&json!([entry]))
            .iter()
            .any(|p| p.contains("not a spec-defined entry member")));

        // Vendor extensions ride the x- prefix and stay legal.
        let mut entry = coherent_entry();
        entry["x-acme-note"] = json!("internal");
        assert!(predecessors_problems(&json!([entry])).is_empty());
    }

    /// Two entries citing the same sealed artifact are malformed; two
    /// snapshots of one line (same id, different manifest hash) are a
    /// coherent merge claim.
    #[test]
    fn duplicate_manifest_hash_is_malformed_but_shared_ids_are_legal() {
        let entry = coherent_entry();
        let problems = predecessors_problems(&json!([entry.clone(), entry.clone()]));
        assert!(problems.iter().any(|p| p.contains("cited twice")), "{problems:?}");

        let mut second = entry.clone();
        second["manifest_hash"] = json!("d".repeat(64));
        assert!(predecessors_problems(&json!([entry, second])).is_empty());
    }

    #[test]
    fn null_coherence_rejects_a_predecessor_that_cannot_exist() {
        let mut entry = coherent_entry();
        entry["first_event_hash"] = Value::Null;
        let problems = predecessors_problems(&json!([entry]));
        assert!(problems.iter().any(|p| p.contains("cannot exist")), "{problems:?}");
    }

    /// A zero-event predecessor declares both anchors null and derives
    /// its id with 32 zero bytes standing in for the first event hash.
    #[test]
    fn zero_event_predecessor_is_coherent() {
        let key = [9u8; 32];
        let entry = json!({
            "capsule_id": compute_capsule_id(&key, None, "0.7").unwrap(),
            "format_version": "0.7",
            "originator_public_key": crate::crypto::bytes_to_hex(&key),
            "first_event_hash": Value::Null,
            "entry_hash": Value::Null,
            "manifest_hash": "c".repeat(64),
        });
        assert!(predecessors_problems(&json!([entry])).is_empty());
    }

    #[test]
    fn identity_coherence_fails_closed_under_a_known_era() {
        let mut entry = coherent_entry();
        entry["capsule_id"] = json!("f".repeat(64));
        let problems = predecessors_problems(&json!([entry]));
        assert!(problems.iter().any(|p| p.contains("does not derive")), "{problems:?}");
    }

    /// versioning.md forbids applying one era's identity formula to
    /// another era's claim: an unknown declared era SKIPS check 3 and is
    /// reported, never failed — the verifier's age must not convict a
    /// capsule.
    #[test]
    fn unknown_declared_era_skips_identity_coherence() {
        let mut entry = coherent_entry();
        entry["format_version"] = json!("0.9");
        assert!(
            predecessors_problems(&json!([entry.clone()])).is_empty(),
            "an unknown era must not fail the declaration"
        );
        assert!(!predecessor_identity_checkable(&entry));
        assert!(predecessor_identity_checkable(&coherent_entry()));
    }

    #[test]
    fn version_grammar_is_checked_before_era_support() {
        let mut entry = coherent_entry();
        entry["format_version"] = json!("v0.7");
        let problems = predecessors_problems(&json!([entry]));
        assert!(
            problems.iter().any(|p| p.contains("predecessors[0].format_version")),
            "{problems:?}"
        );
    }

    #[test]
    fn alternate_profile_declarations_are_named() {
        assert_eq!(declared_alternate_profile_id(&json!({"format": {}})), None);
        assert_eq!(
            declared_alternate_profile_id(&json!({"format": {"profile": {"id": DEFAULT_PROFILE_ID}}})),
            None
        );
        assert_eq!(
            declared_alternate_profile_id(&json!({"format": {"profile": {"id": "acme-pq"}}})),
            Some("acme-pq".to_string())
        );
        assert_eq!(
            declared_alternate_profile_id(&json!({"format": {"profile": 42}})),
            Some("(uninterpretable profile declaration)".to_string())
        );
    }
}
