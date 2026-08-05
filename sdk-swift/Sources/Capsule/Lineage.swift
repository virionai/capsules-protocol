// Lineage verification (spec/lineage.md): the `manifest.predecessors`
// standalone checks and the report-only supplied-bytes linkage walk.
// Mirrors sdk-js/src/lineage.js.
//
// Two groups of obligations. STANDALONE checks are properties of the
// successor artifact alone and fail it closed (the verifier records them
// as a failing `lineage` check). LINKAGE checks depend on evidence the
// host supplied at verify time (the `predecessors:` verify parameter)
// and are REPORT-ONLY: the successor's `ok` must remain a function of
// the capsule, never of the invocation — otherwise a third party flips a
// valid capsule's verdict by handing the verifier the wrong file.

import Foundation

/// Machine-readable lineage facts on a verify result (spec/lineage.md
/// "Reporting"). The wire member is `manifest.predecessors`; the result
/// area is `lineage` — the `signer_commitment`/`signerSetBound` naming
/// precedent.
public struct LineageReport {
    /// Slim summary of a supplied predecessor's OWN verification. Host
    /// trust over predecessor originators derives from that verification's
    /// per-signer results; the lineage area does not duplicate host policy.
    public struct ArtifactSummary: Equatable {
        public let ok: Bool
        public let observedVersion: String?
        public let level: String
        /// Failing checks in this lane's verify result (the lane-local
        /// spelling of the reference lane's error count).
        public let errorCount: Int
        public init(ok: Bool, observedVersion: String?, level: String, errorCount: Int) {
            self.ok = ok; self.observedVersion = observedVersion
            self.level = level; self.errorCount = errorCount
        }
    }

    /// One reported entry: the declared six members echoed (so hosts apply
    /// key policy without re-parsing the manifest) plus the facts.
    public struct Entry {
        public let capsuleId: String?
        public let formatVersion: String?
        public let originatorPublicKey: String?
        public let firstEventHash: String?
        public let entryHash: String?
        public let manifestHash: String?
        /// 1 = an immediate parent; deeper hops are reached only through
        /// supplied bytes (no hop is hearsay).
        public let hop: Int
        /// Whether standalone check 3 (identity coherence) actually ran:
        /// false when the declared era is outside this verifier's known
        /// table — skipped and REPORTED, never failed.
        public let identityChecked: Bool
        /// Closed vocabulary, identical strings in every lane:
        /// "unverified" | "verified" | "mismatch" | "predecessor_invalid"
        /// | "predecessor_unverifiable".
        public let status: String
        /// For "predecessor_unverifiable": "unsupported_version" |
        /// "encrypted_predecessor" | "unsupported_profile" |
        /// "unsupported_capability".
        public let reason: String?
        public let errors: [String]
        public let artifact: ArtifactSummary?

        public init(capsuleId: String?, formatVersion: String?, originatorPublicKey: String?,
                    firstEventHash: String?, entryHash: String?, manifestHash: String?,
                    hop: Int, identityChecked: Bool, status: String, reason: String?,
                    errors: [String], artifact: ArtifactSummary?) {
            self.capsuleId = capsuleId; self.formatVersion = formatVersion
            self.originatorPublicKey = originatorPublicKey
            self.firstEventHash = firstEventHash; self.entryHash = entryHash
            self.manifestHash = manifestHash; self.hop = hop
            self.identityChecked = identityChecked; self.status = status
            self.reason = reason; self.errors = errors; self.artifact = artifact
        }
    }

    /// `true` when the manifest carries a `predecessors` member. After an
    /// open-stage or version-gate refusal this is the not-evaluated
    /// default, where `false` means "not evaluated", not "absent"
    /// (refusal exclusivity: the refusal diagnosis is the only error such
    /// a result carries).
    public let declared: Bool
    /// Area verdict: the standalone checks passed AND nothing CHECKED
    /// contradicts. Unchecked is not failed — `unverified` and
    /// `predecessor_unverifiable` entries never falsify it. A `mismatch`
    /// or `predecessor_invalid` entry falsifies the AREA only; the
    /// capsule's own `ok` is never a function of the supplied pool.
    public let ok: Bool
    /// The largest N such that every declared entry within N hops has
    /// status "verified".
    public let verifiedDepth: Int
    public let entries: [Entry]

    public init(declared: Bool, ok: Bool, verifiedDepth: Int, entries: [Entry]) {
        self.declared = declared; self.ok = ok
        self.verifiedDepth = verifiedDepth; self.entries = entries
    }

    /// The fail-closed / not-evaluated shape, used before the lineage
    /// stage runs and after any open-stage refusal.
    public static let notEvaluated = LineageReport(
        declared: false, ok: false, verifiedDepth: 0, entries: []
    )
}

public enum Lineage {
    /// The six spec-defined members of one predecessor entry, all
    /// REQUIRED when an entry is present (nullability only where marked).
    public static let ENTRY_MEMBERS: [String] = [
        "capsule_id",
        "format_version",
        "originator_public_key",
        "first_event_hash",
        "entry_hash",
        "manifest_hash",
    ]

    /// The era default profile id (spec/lineage.md "Scope"), frozen
    /// forever. v0.7.1 declarations commit to DEFAULT-PROFILE
    /// predecessors: the entry grammar presumes the era-default identity
    /// derivation and key encoding.
    public static let DEFAULT_PROFILE_ID = "v0.6-suite"

    /// Eras whose rule sets define lineage semantics. `predecessors` is a
    /// CLAIM member, not a rule selector, so it follows per-era rule
    /// sets: inside a capsule declaring an earlier era (e.g. 0.6) it
    /// stays an unknown member even to a v0.7.1 reader — preserved,
    /// hashed, never shape-checked (spec/versioning.md "In-era tightening
    /// and cross-era force"; spec/lineage.md "No retroactive
    /// interpretation of sealed eras"). The gate is the SAME whether the
    /// capsule is the verification subject or a hop reached through the
    /// walk — one artifact, one rule set.
    static let LINEAGE_ERAS: Set<String> = ["0.7"]

    /// Whether an observed `<major>.<minor>` era interprets
    /// `predecessors`. An unknown era never reaches here (the version
    /// gate refuses the capsule first), so `false` means "known era,
    /// pre-lineage rules".
    static func eraDefinesLineage(_ version: String) -> Bool {
        LINEAGE_ERAS.contains(version)
    }

    /// Resource limit, not a protocol rule (like the reader's file-count
    /// and size caps): the walk never fetches — depth is bounded by the
    /// supplied pool — and the cap bounds pathological pools.
    public static let HOP_CAP = 256

    private static let ZERO_HASH = String(repeating: "0", count: 64)

    // MARK: - Standalone checks (fail-closed)

    /// Validate a stored `predecessors` value (spec/lineage.md standalone
    /// checks 1–3). Returns problem strings; empty means well-formed.
    /// Every problem names its member as `predecessors[i].<member>` — the
    /// shared cross-lane diagnosis strings, never a lane-specific parse
    /// crash: the member is parsed leniently and diagnosed here.
    public static func predecessorsProblems(_ value: JCSValue) -> [String] {
        guard case .array(let entries) = value else {
            return ["predecessors must be an array of predecessor entry objects"]
        }
        if entries.isEmpty {
            return [
                "predecessors must not be empty when present "
                    + "(\"no claim\" has exactly one spelling: absence)"
            ]
        }
        var problems: [String] = []
        var firstIndexByManifestHash: [String: Int] = [:]
        for (i, entry) in entries.enumerated() {
            guard case .object(let fields) = entry else {
                problems.append("predecessors[\(i)] must be an entry object")
                continue
            }
            func member(_ key: String) -> JCSValue? {
                fields.first(where: { $0.0 == key })?.1
            }
            // Vendor extensions inside an entry use the x- prefix; any
            // other unrecognized member is malformed (the
            // signer_commitment exact-members precedent). No advisory
            // members: the spec does not lend a verified-adjacent slot to
            // unverifiable reputation text about someone else's work.
            for (key, _) in fields where !ENTRY_MEMBERS.contains(key) && !key.hasPrefix("x-") {
                problems.append(
                    "predecessors[\(i)].\(key) is not a spec-defined entry member "
                        + "(vendor extensions must use the x- prefix)")
            }
            // Lowercase hex is REQUIRED, not normalized: the claim is
            // bound by its stored bytes, and case-variant spellings of one
            // claim are a cross-lane comparison differential.
            for key in ["capsule_id", "originator_public_key", "manifest_hash"] {
                guard case .some(.string(let hex)) = member(key), CapsuleReader.isHex64(hex) else {
                    problems.append("predecessors[\(i)].\(key) must be lowercase 64-hex")
                    continue
                }
            }
            let first = nullableHex(member("first_event_hash"))
            let entryHash = nullableHex(member("entry_hash"))
            if case .malformed = first {
                problems.append("predecessors[\(i)].first_event_hash must be lowercase 64-hex or null")
            }
            if case .malformed = entryHash {
                problems.append("predecessors[\(i)].entry_hash must be lowercase 64-hex or null")
            }
            var declaredVersion: String? = nil
            if case .some(.string(let v)) = member("format_version") { declaredVersion = v }
            let versionStatus = CapsuleVersions.classify(declaredVersion)
            if versionStatus == .invalid {
                problems.append(
                    "predecessors[\(i)].format_version must be a '<major>.<minor>' version "
                        + "string, got \(Chain.debugQuoted(declaredVersion))")
            }
            // Check 2 — null coherence. Both null (a zero-event
            // predecessor; a template hand-off is legitimate) or both
            // 64-hex; a mixed declaration describes a predecessor that
            // cannot exist.
            if first.isWellFormed, entryHash.isWellFormed, first.isNull != entryHash.isNull {
                problems.append(
                    "predecessors[\(i)].first_event_hash and predecessors[\(i)].entry_hash must "
                        + "be both null (zero-event predecessor) or both 64-hex — a mixed "
                        + "declaration describes a predecessor that cannot exist")
            }
            // Check 3 — identity coherence, under KNOWN declared eras
            // only. An unknown declared era SKIPS the check
            // (spec/versioning.md forbids applying one era's formula to
            // another era's claim); the entry reports
            // identityChecked=false, never a failure — the rule must not
            // punish a capsule for the verifier's age.
            if versionStatus == .known,
               let era = declaredVersion,
               case .some(.string(let declaredId)) = member("capsule_id"),
               CapsuleReader.isHex64(declaredId),
               case .some(.string(let originatorKey)) = member("originator_public_key"),
               CapsuleReader.isHex64(originatorKey),
               first.isWellFormed, entryHash.isWellFormed, first.isNull == entryHash.isNull,
               let originatorBytes = try? Bytes.fromHexThrowing(originatorKey),
               originatorBytes.count == 32
            {
                let derived = Manifest.computeCapsuleId(
                    originatorPub: originatorBytes,
                    firstEventHashHex: first.hex ?? ZERO_HASH,
                    version: era
                )
                if derived != declaredId {
                    problems.append(
                        "predecessors[\(i)].capsule_id does not derive from the declared "
                            + "originator key and first event hash under era \(era) — the "
                            + "declaration contradicts its own members")
                }
            }
            // Two entries sharing a manifest_hash cite the same sealed
            // artifact twice — no legitimate producer (the
            // duplicate-signer precedent). Two entries sharing capsule_id
            // with DIFFERENT manifest_hash values stay legal: a merge of
            // two snapshots of one line is a coherent claim.
            if case .some(.string(let mh)) = member("manifest_hash"), CapsuleReader.isHex64(mh) {
                if let seen = firstIndexByManifestHash[mh] {
                    problems.append(
                        "predecessors[\(i)].manifest_hash duplicates "
                            + "predecessors[\(seen)].manifest_hash "
                            + "(the same sealed artifact cited twice)")
                } else {
                    firstIndexByManifestHash[mh] = i
                }
            }
        }
        return problems
    }

    /// The declared alternate profile id, or nil for the era default
    /// (declared explicitly or by absence). A present-but-uninterpretable
    /// declaration returns a placeholder — the caller treats it as
    /// non-default; the profile machinery owns its full diagnosis.
    static func declaredAlternateProfileId(_ manifest: JCSValue) -> String? {
        guard case .object(let pairs) = manifest,
              let format = pairs.first(where: { $0.0 == "format" })?.1,
              case .object(let formatPairs) = format,
              let profile = formatPairs.first(where: { $0.0 == "profile" })?.1
        else { return nil }
        if case .null = profile { return nil }
        guard case .object(let profilePairs) = profile,
              case .some(.string(let id)) = profilePairs.first(where: { $0.0 == "id" })?.1,
              !id.isEmpty
        else { return "(uninterpretable profile declaration)" }
        return id == DEFAULT_PROFILE_ID ? nil : id
    }

    // MARK: - Evaluation

    /// The lineage stage's output: the reported area, the standalone
    /// problems (fail-closed, the caller records them), and the notes the
    /// caller appends to the verify result.
    struct Evaluation {
        let report: LineageReport
        let standaloneProblems: [String]
        let notes: [String]
    }

    /// Evaluate the lineage area for one manifest. `pool` is the supplied
    /// predecessor artifacts (report-only). `outerManifest` is the outer
    /// manifest when verifying an encrypted capsule's inner package, for
    /// the L3 inner/outer equality (standalone check 4).
    static func evaluate(manifest: JCSValue,
                         version: String,
                         pool: [Data],
                         allowlist: Set<String>,
                         acceptVersions: Set<String>?) -> Evaluation
    {
        guard case .object(let manifestPairs) = manifest,
              let declaredValue = manifestPairs.first(where: { $0.0 == "predecessors" })?.1
        else {
            // No claim, nothing checked. ok=true: unchecked is not failed.
            return Evaluation(
                report: LineageReport(declared: false, ok: true, verifiedDepth: 0, entries: []),
                standaloneProblems: [], notes: []
            )
        }
        guard eraDefinesLineage(version) else {
            // Present, but this capsule's era defines no lineage
            // semantics: the member is an unknown member under those
            // rules — preserved and hashed, never shape-checked.
            // Interpreting it would retroactively rewrite a sealed era's
            // verdict.
            return Evaluation(
                report: LineageReport(declared: false, ok: true, verifiedDepth: 0, entries: []),
                standaloneProblems: [],
                notes: ["lineage: this capsule declares era \(version), whose rule set "
                        + "defines no lineage semantics; its predecessors member is an "
                        + "unknown member under that era and was not interpreted"]
            )
        }

        // Standalone checks 1–3, fail-closed.
        let problems = predecessorsProblems(declaredValue)
        guard problems.isEmpty, case .array(let declaredEntries) = declaredValue else {
            return Evaluation(
                report: LineageReport(declared: true, ok: false, verifiedDepth: 0, entries: []),
                standaloneProblems: problems, notes: []
            )
        }

        // Pinned phrase: no report may imply a consent bit exists before
        // the v0.8+ countersignature artifact.
        var notes = [
            "lineage: manifest.predecessors is the successor's one-way declaration; "
                + "the predecessor's originator has not countersigned it"
        ]
        var entries = declaredEntries.map { WorkEntry($0, hop: 1) }
        var records = pool.map {
            classifyArtifact($0, allowlist: allowlist, acceptVersions: acceptVersions)
        }

        // Seen-set on recomputed manifest_hash bounds pathological pools
        // (a true commitment cycle is a hash fixpoint and cannot verify).
        var walked = Set<String>()
        func openEntry(_ predicate: (WorkEntry) -> Bool) -> Int? {
            entries.firstIndex { $0.status == "unverified" && predicate($0) }
        }

        var changed = true
        while changed {
            changed = false
            for i in records.indices {
                if records[i].assigned || records[i].kind == .unreadable { continue }

                if records[i].kind != .verifiable {
                    // Bytes in hand but rules unavailable: match by the
                    // artifact's CLAIMED id (nothing can be recomputed);
                    // the status says explicitly that nothing was verified.
                    guard let claimedId = records[i].claimedId,
                          let e = openEntry({ $0.capsuleId == claimedId })
                    else { continue }
                    records[i].assigned = true
                    changed = true
                    entries[e].status = "predecessor_unverifiable"
                    let id = entries[e].capsuleId ?? claimedId
                    switch records[i].kind {
                    case .encrypted:
                        entries[e].reason = "encrypted_predecessor"
                        notes.append(
                            "lineage: supplied predecessor for capsule \(id) is an encrypted "
                                + "capsule; v0.7.1 lineage declarations commit to a plain "
                                + "capsule's members — decrypt the inner capsule and supply it "
                                + "instead. The entry stays declared, not verified")
                    case .unsupportedVersion:
                        entries[e].reason = "unsupported_version"
                        notes.append(
                            "lineage: supplied predecessor for capsule \(id) declares format "
                                + "version '\(records[i].version ?? "null")', which this verifier "
                                + "does not support — a limitation of the verifier, not a defect "
                                + "of either capsule. The entry stays declared, not verified")
                    case .unsupportedProfile:
                        entries[e].reason = "unsupported_profile"
                        notes.append(
                            "lineage: supplied predecessor for capsule \(id) declares profile "
                                + "'\(records[i].profileId ?? "null")', which this verifier does "
                                + "not implement (v0.7.1 lineage declarations commit to "
                                + "default-profile predecessors) — a limitation of the verifier, "
                                + "not a defect of either capsule. The entry stays declared, not "
                                + "verified")
                    case .verifiable, .unreadable:
                        break  // filtered above
                    }
                    continue
                }

                // Matching uses RECOMPUTED values only, never the
                // artifact's own claims. Pair match first; an id-only
                // match is a different sealed state of the same identity.
                var match: Int? = nil
                if let id = records[i].recomputedId, let mh = records[i].recomputedManifestHash {
                    match = openEntry { $0.capsuleId == id && $0.manifestHash == mh }
                }
                if match == nil, let id = records[i].recomputedId {
                    match = openEntry { $0.capsuleId == id }
                }
                guard let e = match else { continue }
                records[i].assigned = true
                changed = true
                entries[e].artifact = records[i].summary
                let diffs = equalityDiffs(entries[e], records[i])

                if records[i].verificationOk == false {
                    // Two facts, never collapsed: "is this the declared
                    // artifact" vs "does it verify internally". Takes
                    // precedence over mismatch; the equalities are still
                    // reported informatively.
                    entries[e].status = "predecessor_invalid"
                    entries[e].errors.append(
                        "supplied predecessor fails its own verification under era "
                            + "\(records[i].version ?? "null") (\(records[i].failingCount) "
                            + "error(s)); this is a property of the supplied artifact, not of "
                            + "the successor's declaration")
                    entries[e].errors.append(contentsOf: diffs)
                } else if !diffs.isEmpty {
                    entries[e].status = "mismatch"
                    entries[e].errors.append(
                        "supplied artifact is a different sealed state of the declared "
                            + "predecessor (same capsule identity, different seal) — not "
                            + "evidence of tampering; re-seals of a growing line legitimately "
                            + "share a capsule_id")
                    entries[e].errors.append(contentsOf: diffs)
                } else {
                    entries[e].status = "verified"
                }

                // Recursive walk: a hop whose manifest matches the
                // declared manifest_hash contributes ITS OWN first-person
                // declaration to the frontier — even when its event chain
                // is broken (the commitment chain authenticates the
                // declaration bytes). A mismatched artifact is NOT the
                // declared artifact and never contributes.
                guard let recomputedMh = records[i].recomputedManifestHash,
                      entries[e].manifestHash == recomputedMh,
                      !walked.contains(recomputedMh),
                      let childManifest = records[i].manifest,
                      case .object(let childPairs) = childManifest,
                      let childDeclared = childPairs.first(where: { $0.0 == "predecessors" })?.1
                else { continue }
                walked.insert(recomputedMh)
                let hopVersion = records[i].version ?? ""
                if !LINEAGE_ERAS.contains(hopVersion) {
                    notes.append(
                        "lineage: predecessor \(entries[e].capsuleId ?? "(unknown id)") declares "
                            + "era \(hopVersion), whose rule set defines no lineage semantics; "
                            + "its predecessors member is an unknown member under that era and "
                            + "terminates the walk")
                    continue
                }
                // A malformed hop declaration is diagnosed by that hop's
                // own verification (predecessor_invalid); nothing to walk.
                guard predecessorsProblems(childDeclared).isEmpty,
                      case .array(let childEntries) = childDeclared
                else { continue }
                let nextHop = entries[e].hop + 1
                if nextHop > HOP_CAP {
                    notes.append(
                        "lineage: hop cap \(HOP_CAP) reached; deeper declarations were not walked")
                    continue
                }
                for child in childEntries {
                    entries.append(WorkEntry(child, hop: nextHop))
                }
            }
        }

        // Unmatched supplied artifacts are named, never silently ignored
        // — a mistyped path must be visible.
        for (i, record) in records.enumerated() where !record.assigned {
            if record.kind == .unreadable {
                notes.append(
                    "lineage: supplied predecessor artifact #\(i + 1) could not be read as a "
                        + "capsule (\(record.openError ?? "unknown error")); it matched no "
                        + "declared entry")
            } else {
                let label = record.claimedId ?? record.recomputedId ?? "(unknown id)"
                notes.append(
                    "lineage: supplied predecessor artifact #\(i + 1) (capsule \(label)) "
                        + "matched no declared entry")
            }
        }

        // Pinned phrase: a custody claim must never quietly disappear when
        // bytes are missing — that is how a citation gets read as an
        // endorsement.
        for entry in entries
        where entry.status == "unverified" || entry.status == "predecessor_unverifiable" {
            notes.append(
                "lineage: predecessor \(entry.capsuleId ?? "(unknown id)") "
                    + "(hop \(entry.hop)): declared, not verified")
        }

        // verified_depth: the largest N such that every declared entry
        // within N hops has status "verified".
        var depth = 0
        var hop = 1
        while entries.contains(where: { $0.hop == hop }) {
            if !entries.filter({ $0.hop <= hop }).allSatisfy({ $0.status == "verified" }) { break }
            depth = hop
            hop += 1
        }
        if depth >= 1 {
            // Two distinct identities, always: the successor is never
            // presented as BEING the predecessor or as its endorsed
            // continuation.
            let parents = entries
                .filter { $0.hop == 1 }
                .map { $0.capsuleId ?? "(unknown id)" }
                .joined(separator: ", ")
            notes.append(
                "lineage: successor of capsule \(parents); lineage verified to depth \(depth)")
        }

        let areaOk = !entries.contains {
            $0.status == "mismatch" || $0.status == "predecessor_invalid"
        }
        return Evaluation(
            report: LineageReport(
                declared: true, ok: areaOk, verifiedDepth: depth,
                entries: entries.map { $0.frozen }
            ),
            standaloneProblems: [], notes: notes
        )
    }

    /// Standalone check 4 (encrypted successors, at L3): when BOTH
    /// manifests carry the member they MUST be equal (JCS byte equality).
    /// Single-layer presence is legal — a private or a public-only
    /// citation is each a weaker claim made honestly — but a capsule
    /// asserting one origin to the world and another to its recipients is
    /// lying about itself across layers. Returns nil when the rule does
    /// not apply or holds.
    static func innerOuterProblem(inner: JCSValue, outer: JCSValue?) -> String? {
        guard let outer,
              case .object(let innerPairs) = inner,
              case .object(let outerPairs) = outer,
              let innerDeclared = innerPairs.first(where: { $0.0 == "predecessors" })?.1,
              let outerDeclared = outerPairs.first(where: { $0.0 == "predecessors" })?.1
        else { return nil }
        let innerBytes = try? JCS.bytes(innerDeclared)
        let outerBytes = try? JCS.bytes(outerDeclared)
        if let innerBytes, let outerBytes, innerBytes == outerBytes { return nil }
        return "L3: manifest.predecessors differs between the inner and outer manifests — "
            + "the capsule asserts one origin to the world and another to its recipients"
    }

    // MARK: - Internals

    /// A declared entry under construction: the six members are fixed by
    /// the manifest, the facts accumulate through the walk.
    private struct WorkEntry {
        let capsuleId: String?
        let formatVersion: String?
        let originatorPublicKey: String?
        let firstEventHash: String?
        let entryHash: String?
        let manifestHash: String?
        let hop: Int
        let identityChecked: Bool
        var status = "unverified"
        var reason: String? = nil
        var errors: [String] = []
        var artifact: LineageReport.ArtifactSummary? = nil

        init(_ declared: JCSValue, hop: Int) {
            func member(_ key: String) -> String? {
                guard case .object(let pairs) = declared,
                      case .some(.string(let s)) = pairs.first(where: { $0.0 == key })?.1
                else { return nil }
                return s
            }
            capsuleId = member("capsule_id")
            formatVersion = member("format_version")
            originatorPublicKey = member("originator_public_key")
            firstEventHash = member("first_event_hash")
            entryHash = member("entry_hash")
            manifestHash = member("manifest_hash")
            self.hop = hop
            identityChecked = CapsuleVersions.classify(formatVersion) == .known
        }

        var frozen: LineageReport.Entry {
            LineageReport.Entry(
                capsuleId: capsuleId, formatVersion: formatVersion,
                originatorPublicKey: originatorPublicKey, firstEventHash: firstEventHash,
                entryHash: entryHash, manifestHash: manifestHash, hop: hop,
                identityChecked: identityChecked, status: status, reason: reason,
                errors: errors, artifact: artifact
            )
        }
    }

    /// One classified pool artifact.
    private struct PoolRecord {
        enum Kind {
            /// Plain, known era, default profile: fully verified under its
            /// own era's rules, with the identity and manifest hash
            /// recomputed.
            case verifiable
            /// v0.7.1 declarations commit to a plain capsule's members;
            /// never guessed at.
            case encrypted
            case unsupportedVersion
            case unsupportedProfile
            /// Not openable as a capsule at all.
            case unreadable
        }
        var kind: Kind = .unreadable
        var manifest: JCSValue? = nil
        var claimedId: String? = nil
        var version: String? = nil
        var profileId: String? = nil
        var recomputedId: String? = nil
        var recomputedManifestHash: String? = nil
        var originatorKey: String? = nil
        var firstEventHash: String? = nil
        var entryHash: String? = nil
        var summary: LineageReport.ArtifactSummary? = nil
        var verificationOk: Bool? = nil
        var failingCount = 0
        var assigned = false
        var openError: String? = nil
    }

    private static func classifyArtifact(_ bytes: Data,
                                         allowlist: Set<String>,
                                         acceptVersions: Set<String>?) -> PoolRecord
    {
        var record = PoolRecord()
        let manifest: JCSValue
        var envelope: JCSValue? = nil
        var files: [String: Data] = [:]
        do {
            for (path, data) in try CapsuleZip.unpack(bytes) { files[path] = data }
            guard let manifestBytes = files["manifest.json"] else {
                throw CapsuleError.malformed("missing manifest.json")
            }
            manifest = try CapsuleReader.parseJSONFile(manifestBytes, name: "manifest.json")
            if let envelopeBytes = files["provenance/envelope.json"] {
                envelope = try CapsuleReader.parseJSONFile(
                    envelopeBytes, name: "provenance/envelope.json")
            }
        } catch {
            record.openError = "\(error)"
            return record
        }
        record.manifest = manifest
        if let id = lookupString(manifest, ["id"]), CapsuleReader.isHex64(id) {
            record.claimedId = id
        }
        record.version = lookupString(manifest, ["format", "version"])

        let cipher = envelope.flatMap { lookupString($0, ["cipher"]) }
        if cipher != "none" || files["content.enc"] != nil {
            record.kind = .encrypted
            return record
        }
        if CapsuleVersions.classify(record.version) != .known {
            record.kind = .unsupportedVersion
            return record
        }
        if let profileId = declaredAlternateProfileId(manifest) {
            record.kind = .unsupportedProfile
            record.profileId = profileId
            return record
        }
        record.kind = .verifiable

        // Recomputed values ONLY, never the artifact's own claims:
        // identity under the artifact's declared era's domain string,
        // manifest hash from the stored manifest document.
        if let era = record.version,
           let keyHex = lookupString(manifest, ["originator", "public_key"]),
           CapsuleReader.isHex64(keyHex),
           let keyBytes = try? Bytes.fromHexThrowing(keyHex),
           keyBytes.count == 32
        {
            let first = lookupString(manifest, ["first_event_hash"])
            if first == nil || CapsuleReader.isHex64(first!) {
                record.recomputedId = Manifest.computeCapsuleId(
                    originatorPub: keyBytes,
                    firstEventHashHex: first ?? ZERO_HASH,
                    version: era
                )
            }
            record.originatorKey = keyHex.lowercased()
        }
        record.recomputedManifestHash = try? Manifest.hash(manifest)
        record.firstEventHash = lookupString(manifest, ["first_event_hash"])
        record.entryHash = envelope.flatMap { lookupString($0, ["entry_hash"]) }

        // The predecessor is verified fully as a capsule under ITS
        // declared version's rules, with the same host options as the main
        // verification (allowlist, version policy) — never the pool, which
        // belongs to this walk.
        let verification = CapsuleVerifier.verify(
            bytes, allowlist: allowlist, acceptVersions: acceptVersions)
        record.verificationOk = verification.ok
        record.failingCount = verification.checks.filter { !$0.ok }.count
        record.summary = LineageReport.ArtifactSummary(
            ok: verification.ok,
            observedVersion: verification.formatVersion.observed ?? record.version,
            level: verification.level,
            errorCount: record.failingCount
        )
        return record
    }

    /// The six equalities of spec/lineage.md linkage. Returns
    /// member-precise difference strings (empty = the supplied artifact IS
    /// the declared sealed state). Wording never uses tamper/corruption
    /// vocabulary: the supplied file being a different genuine seal is the
    /// common honest cause, and "wrong file supplied" versus "successor
    /// lied" is genuinely indistinguishable here — the verifier reports
    /// the precise fact and never decides.
    private static func equalityDiffs(_ entry: WorkEntry, _ record: PoolRecord) -> [String] {
        let pairs: [(String, String?, String?)] = [
            ("format_version", entry.formatVersion, record.version),
            ("capsule_id", entry.capsuleId, record.recomputedId),
            ("originator_public_key", entry.originatorPublicKey, record.originatorKey),
            ("first_event_hash", entry.firstEventHash, record.firstEventHash),
            ("entry_hash", entry.entryHash, record.entryHash),
            ("manifest_hash", entry.manifestHash, record.recomputedManifestHash),
        ]
        return pairs.compactMap { (name, declared, supplied) in
            declared == supplied
                ? nil
                : "\(name): declared \(declared ?? "null"), supplied artifact has "
                    + "\(supplied ?? "null")"
        }
    }

    /// A nullable hash member's classification.
    private enum NullableHex {
        case hex(String)
        case null
        case malformed

        var isWellFormed: Bool { if case .malformed = self { return false }; return true }
        var isNull: Bool { if case .null = self { return true }; return false }
        var hex: String? { if case .hex(let s) = self { return s }; return nil }
    }

    private static func nullableHex(_ value: JCSValue?) -> NullableHex {
        switch value {
        case .some(.null): return .null
        case .some(.string(let s)) where CapsuleReader.isHex64(s): return .hex(s)
        default: return .malformed
        }
    }

    private static func lookupString(_ v: JCSValue, _ path: [String]) -> String? {
        var cur = v
        for key in path {
            guard case .object(let pairs) = cur,
                  let next = pairs.first(where: { $0.0 == key })?.1 else { return nil }
            cur = next
        }
        if case .string(let s) = cur { return s }
        return nil
    }
}
