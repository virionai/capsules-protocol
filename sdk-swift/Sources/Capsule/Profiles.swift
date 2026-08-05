// Profile declaration policy (spec/profiles.md). Mirrors
// sdk-js/src/profiles.js.
//
// A capsule may DECLARE the verification profile that governs it —
// `manifest.format.profile` and `envelope.profile`, mirroring the
// `format.version` / `envelope.version` dyad. A verifier keeps a table
// of the profiles it implements (keyed selection, exactly like the
// known-version table) and:
//
//   - Treats ABSENCE of a declaration in a 0.6/0.7 capsule as the
//     default profile `v0.6-suite` version `1.0`, permanently — the
//     mirror of the algorithm-suite pin in spec/versioning.md.
//   - Requires the two documents' NORMALIZED declarations (absence =
//     default) to agree; a capsule whose pairs differ is ambiguous
//     about which rules bind it and fails closed BEFORE any profile's
//     rules are applied (`profile_mismatch` — a defect of the capsule).
//   - FAILS CLOSED on a declared (id, version) pair outside the table,
//     with a diagnosis distinct from both tampering and malformation:
//     `unsupported_profile` is a limitation of the verifier, never a
//     defect of the capsule.
//   - Treats a present declaration that violates the closed object
//     shape or the identifier grammar as a MALFORMED document
//     (invalid_manifest_shape), not a support gap.
//
// The gate runs at OPEN stage, after the version gate and before
// anything else: a reader that cannot establish its governing rules
// cannot meaningfully construct at all, and applying the wrong
// profile's rules would manufacture mismatch errors indistinguishable
// from tampering — versioning.md's confusion, reproduced on the
// profile axis.

import Foundation

public enum CapsuleProfiles {

    /// One row of the profile table: an (id, version) pair, matched
    /// EXACTLY — no ranges, no compatibility semantics.
    public struct Ref: Equatable {
        public let id: String
        public let version: String
        public init(id: String, version: String) {
            self.id = id
            self.version = version
        }
    }

    /// The default profile: the envelope.md verification/encryption
    /// procedure of the capsule's declared era with the v0.6 algorithm
    /// suite of versioning.md. The id deliberately matches the suite
    /// fact (`v0.6`) verifiers already report. Frozen forever — the
    /// absence rule makes this spelling permanent.
    public static let defaultProfile = Ref(id: "v0.6-suite", version: "1.0")

    /// Every (id, version) profile row this implementation applies. A
    /// profile once supported is supported forever (the archival rule
    /// applied to profiles), and the default row of every known era is
    /// always present.
    public static let supportedProfiles: [Ref] = [defaultProfile]

    /// Closed classification vocabulary for a declaration dyad.
    public enum Status: String {
        /// No declaration, or the explicit era default: default rules
        /// apply (explicit default is exactly equivalent to absence —
        /// a redundant claim made honestly).
        case `default`
        /// Declared alternate profile this reader implements
        /// (unreachable in-era: the reference table holds one row).
        case supported
        /// Declared alternate the reader does not implement: a
        /// limitation of the verifier, not a defect of the capsule.
        case unsupported
        /// Normalized declarations disagree: the capsule is ambiguous
        /// about which rules bind it (a defect).
        case mismatched
        /// A present member violates the closed shape or the grammar:
        /// a malformed document.
        case invalid
        /// Read but not classified: the version gate refused first.
        case unevaluated
        /// Could not be read at all: the fail-closed default.
        case unread
    }

    /// The outcome of classifying a (manifest, envelope) declaration
    /// dyad against this implementation's table.
    public struct Classification {
        public let status: Status
        public let observed: String?
        public let observedVersion: String?
        public let declared: Bool
        public let effective: String?
        public let effectiveVersion: String?
        public let supported: Bool
        /// Field-path-prefixed shape problems (status `.invalid` only).
        public let problems: [String]
        /// Both NORMALIZED pairs (status `.mismatched` only), for the
        /// diagnosis wording.
        public let normalizedManifest: Ref?
        public let normalizedEnvelope: Ref?
    }

    // profile-id = lowletter *63( lowletter / DIGIT / "-" / "." )
    // 1..64 bytes, lowercase-only, no trailing "-" or "." (no leading
    // one by construction: the first byte is a letter).
    /// True iff `id` satisfies the spec/profiles.md identifier grammar.
    public static func isValidProfileId(_ id: String) -> Bool {
        let bytes = Array(id.utf8)
        guard (1...64).contains(bytes.count) else { return false }
        func isLower(_ b: UInt8) -> Bool { b >= 0x61 && b <= 0x7A }
        func isDigit(_ b: UInt8) -> Bool { b >= 0x30 && b <= 0x39 }
        guard isLower(bytes[0]) else { return false }
        for b in bytes.dropFirst() where !(isLower(b) || isDigit(b) || b == 0x2D || b == 0x2E) {
            return false
        }
        if id.hasSuffix("-") || id.hasSuffix(".") { return false }
        // The vendor fence: an id beginning `x-` MUST be vendor-scoped
        // `x-<vendor>-<name>`; ids not beginning `x-` are reserved to
        // the spec, exactly like non-`x-` member keys.
        if id.hasPrefix("x-") {
            let rest = id.dropFirst(2)
            guard let separator = rest.firstIndex(of: "-") else { return false }
            guard separator != rest.startIndex, rest.index(after: separator) != rest.endIndex
            else { return false }
        }
        return true
    }

    /// True iff `version` satisfies the profile-version grammar — the
    /// SAME grammar as format versions (spec/versioning.md).
    public static func isValidProfileVersion(_ version: String) -> Bool {
        CapsuleVersions.parse(version) != nil
    }

    /// Shape problems for ONE document's present profile declaration.
    /// Returns [] for a well-formed declaration; every message is
    /// prefixed with the offending field path (the
    /// invalid_manifest_shape idiom). `envelope: true` applies the
    /// envelope-copy rules (no `params`: params are single-sourced in
    /// the manifest so no second copy can diverge).
    public static func declarationProblems(_ value: JCSValue,
                                           path: String,
                                           envelope: Bool = false) -> [String]
    {
        let shape = envelope ? "{ id, version }" : "{ id, version, params? }"
        if value == .null {
            // null is NOT a declaration: the honest way to not declare
            // is to omit, and a second spelling of absence is a known
            // typed-decoder divergence across lanes.
            return ["\(path) must be an object \(shape); null is not a declaration "
                    + "— omit the member to not declare"]
        }
        guard case .object(let pairs) = value else {
            return ["\(path) must be an object \(shape), got \(describe(value))"]
        }
        var problems: [String] = []
        // The object is CLOSED: an uninterpretable member in the rule
        // SELECTOR is the capsule asserting something meaningless about
        // what governs it. Vendor freight rides in manifest params or
        // x- members.
        let allowed = envelope ? ["id", "version"] : ["id", "version", "params"]
        for (key, _) in pairs where !allowed.contains(key) {
            problems.append(
                key == "params" && envelope
                    ? "\(path).params is not allowed: params are single-sourced in manifest.format.profile"
                    : "\(path).\(key) is not a member of the closed profile object "
                      + "(exactly: \(allowed.joined(separator: ", ")))"
            )
        }
        let idValue = pairs.first(where: { $0.0 == "id" })?.1
        if !(stringOf(idValue).map { isValidProfileId($0) } ?? false) {
            problems.append(
                "\(path).id must be a profile identifier (1-64 bytes, lowercase letter first, "
                + "then lowercase letters, digits, '-' or '.'; 'x-' ids vendor-scoped as "
                + "x-<vendor>-<name>), got \(describe(idValue))"
            )
        }
        let versionValue = pairs.first(where: { $0.0 == "version" })?.1
        if !(stringOf(versionValue).map { isValidProfileVersion($0) } ?? false) {
            problems.append(
                "\(path).version must be a '<major>.<minor>' version string, got \(describe(versionValue))"
            )
        }
        if !envelope, let params = pairs.first(where: { $0.0 == "params" })?.1 {
            if case .object = params {} else {
                problems.append("\(path).params must be a JSON object, got \(describe(params))")
            }
        }
        return problems
    }

    /// Classify the (manifest, envelope) declaration dyad against this
    /// implementation's table. Pass the raw member values (`nil` when
    /// ABSENT — note that a present JSON null is `.some(.null)`, which
    /// is malformed, not absence). Pure and total; never throws.
    ///
    /// The caller is responsible for gate ORDER: classify only after
    /// both documents pass the version gate (the absence rule is
    /// era-keyed).
    public static func classify(manifestDeclaration: JCSValue?,
                                envelopeDeclaration: JCSValue?) -> Classification
    {
        let declared = manifestDeclaration != nil || envelopeDeclaration != nil
        // The declared id/version as read — reported even on refusal
        // and even when invalid (the observed fact). On a dyad mismatch
        // these are the manifest values; when the manifest is silent,
        // the envelope's.
        let source = manifestDeclaration ?? envelopeDeclaration
        var observed: String? = nil
        var observedVersion: String? = nil
        if case .object(let pairs)? = source {
            observed = stringOf(pairs.first(where: { $0.0 == "id" })?.1)
            observedVersion = stringOf(pairs.first(where: { $0.0 == "version" })?.1)
        }
        func base(_ status: Status,
                  observed: String? = observed,
                  observedVersion: String? = observedVersion,
                  problems: [String] = [],
                  normalizedManifest: Ref? = nil,
                  normalizedEnvelope: Ref? = nil) -> Classification
        {
            Classification(
                status: status, observed: observed, observedVersion: observedVersion,
                declared: declared, effective: nil, effectiveVersion: nil, supported: false,
                problems: problems,
                normalizedManifest: normalizedManifest, normalizedEnvelope: normalizedEnvelope
            )
        }

        var problems: [String] = []
        if let m = manifestDeclaration {
            problems += declarationProblems(m, path: "manifest.format.profile")
        }
        if let e = envelopeDeclaration {
            problems += declarationProblems(e, path: "envelope.profile", envelope: true)
        }
        if !problems.isEmpty { return base(.invalid, problems: problems) }

        // Normalized dyad equality: absence means the era default, so
        // the default declared in exactly one document is coherent
        // (both readings mean the default) — refusing it would punish a
        // truthful statement.
        func normalize(_ declaration: JCSValue?) -> Ref {
            guard case .object(let pairs)? = declaration,
                  let id = stringOf(pairs.first(where: { $0.0 == "id" })?.1),
                  let version = stringOf(pairs.first(where: { $0.0 == "version" })?.1)
            else { return defaultProfile }
            return Ref(id: id, version: version)
        }
        let m = normalize(manifestDeclaration)
        let e = normalize(envelopeDeclaration)
        if m != e {
            // Mismatch BEFORE table lookup: the effective declaration
            // does not exist until the documents agree, and reporting a
            // mismatched capsule as "unsupported" would hand the
            // auditor a false remediation ("find a better verifier" for
            // a defective capsule).
            return base(.mismatched, normalizedManifest: m, normalizedEnvelope: e)
        }
        guard supportedProfiles.contains(m) else {
            return base(.unsupported, observed: m.id, observedVersion: m.version)
        }
        return Classification(
            status: m == defaultProfile ? .default : .supported,
            observed: observed, observedVersion: observedVersion, declared: declared,
            effective: m.id, effectiveVersion: m.version, supported: true,
            problems: [], normalizedManifest: nil, normalizedEnvelope: nil
        )
    }

    /// Cross-lane refusal wording (spec/profiles.md, spec/results.md).
    public static func unsupportedMessage(id: String?, version: String?) -> String {
        "profile '\(id ?? "null")' version '\(version ?? "null")' is not supported by this verifier "
        + "(supported: \(supportedProfiles.map { "\($0.id)/\($0.version)" }.joined(separator: ", "))); "
        + "this is a limitation of the verifier, not corruption of the capsule "
        + "— verify it with an implementation of that profile"
    }

    /// Cross-lane mismatch wording: both NORMALIZED pairs quoted.
    public static func mismatchMessage(manifest: Ref, envelope: Ref) -> String {
        func fmt(_ r: Ref) -> String { "'\(r.id)' version '\(r.version)'" }
        return "envelope.profile does not match manifest.format.profile: "
            + "manifest normalizes to \(fmt(manifest)), envelope normalizes to \(fmt(envelope)) "
            + "(absence means the era default \(defaultProfile.id)/\(defaultProfile.version)); "
            + "the capsule is ambiguous about which rules bind it"
    }

    /// The diagnosis a refusing classification carries; `nil` when the
    /// classification is not a refusal. Three different facts, three
    /// different remediations, kept distinguishable by wording as well
    /// as by status.
    public static func refusalMessage(for cls: Classification) -> String? {
        switch cls.status {
        case .invalid:
            // Field-path-prefixed shape wording (the
            // invalid_manifest_shape idiom) — never the word
            // "unsupported": malformed is a defect of the capsule,
            // unsupported a limitation of the verifier.
            return cls.problems.joined(separator: "; ")
        case .mismatched:
            return mismatchMessage(manifest: cls.normalizedManifest ?? defaultProfile,
                                   envelope: cls.normalizedEnvelope ?? defaultProfile)
        case .unsupported:
            return unsupportedMessage(id: cls.observed, version: cls.observedVersion)
        default:
            return nil
        }
    }

    /// The open-stage profile gate. Call AFTER both documents pass the
    /// version gate. Throws `CapsuleError.profileRefused` carrying the
    /// classification (so a fail-closed verify result can populate its
    /// profile channel from the error alone); returns the
    /// classification when the effective profile is one this
    /// implementation applies.
    @discardableResult
    public static func requireSupported(manifest: JCSValue,
                                        envelope: JCSValue) throws -> Classification
    {
        let cls = classify(
            manifestDeclaration: member(manifest, "format", "profile"),
            envelopeDeclaration: member(envelope, "profile")
        )
        guard let message = refusalMessage(for: cls) else { return cls }
        throw CapsuleError.profileRefused(
            status: cls.status.rawValue, observed: cls.observed,
            observedVersion: cls.observedVersion, declared: cls.declared, message: message
        )
    }

    /// The raw declaration member of one document (`nil` when absent).
    /// Reading the value tree — never a typed projection — is what
    /// keeps an unknown member inside `format` from being dropped.
    public static func member(_ value: JCSValue, _ path: String...) -> JCSValue? {
        var cur = value
        for key in path {
            guard case .object(let pairs) = cur,
                  let next = pairs.first(where: { $0.0 == key })?.1 else { return nil }
            cur = next
        }
        return cur
    }

    private static func stringOf(_ value: JCSValue?) -> String? {
        if case .string(let s)? = value { return s }
        return nil
    }

    /// Compact rendering of an offending value for shape diagnostics.
    private static func describe(_ value: JCSValue?) -> String {
        switch value {
        case nil: return "undefined"
        case .some(.null): return "null"
        case .some(.bool(let b)): return b ? "true" : "false"
        case .some(.integer(let n)): return String(n)
        case .some(.decimal(let d)): return String(d)
        case .some(.string(let s)): return Chain.debugQuoted(s)
        case .some(.array): return "an array"
        case .some(.object): return "an object"
        }
    }
}
