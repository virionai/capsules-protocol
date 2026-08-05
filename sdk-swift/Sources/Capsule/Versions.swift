// Version-compatibility policy (spec/versioning.md). Mirrors
// sdk-js/src/versions.js.
//
// A capsule DECLARES its format era (manifest.format.version and
// envelope.version), and every domain-separation string embeds that
// version. This is the known-version table and the version-keyed
// selectors:
//   - any KNOWN version opens and verifies under that era's rules and
//     constants, forever (the archival profile), with the observed
//     version reported as a fact on the verify result;
//   - an UNKNOWN version fails closed with a diagnosis distinct from
//     tamper detection ("this verifier is too old" is not "this capsule
//     is corrupt");
//   - a version string violating the <major>.<minor> grammar is a
//     malformed document, not a support gap.

import Foundation

public enum CapsuleVersions {
    // Backing storage for the version table. Mutated ONLY by
    // `simulatingBump` (test-only): production code reads the computed
    // `known` / `current` and must never write these.
    private static var knownStorage: [String] = ["0.6", "0.7"]
    private static var currentStorage: String = "0.7"

    /// Every format version this implementation knows, oldest → newest.
    /// A version is never removed (spec/versioning.md: dropping a
    /// version a verifier once knew is a conformance violation).
    public static var known: [String] { knownStorage }

    /// The version this implementation SEALS at. Every version literal
    /// the seal path emits or keys on (manifest.format.version,
    /// envelope.version, the encryption AAD's version member, the
    /// key-wrap HKDF info) MUST derive from this one value, so a future
    /// bump has a single source of truth and cannot leave the encrypted
    /// seal path keyed to a stale era.
    public static var current: String { currentStorage }

    /// TEST-ONLY: run `body` with the version table replaced, restoring
    /// it afterwards. This simulates a future version bump in-process —
    /// the regression class it exists for is a seal path that silently
    /// keeps an old version in a domain string after `current` moves,
    /// which produces capsules that VERIFY but cannot be decrypted.
    static func simulatingBump<R>(
        known newKnown: [String], current newCurrent: String, _ body: () throws -> R
    ) rethrows -> R {
        precondition(newKnown.contains(newCurrent),
                     "current must be a member of the known table")
        let savedKnown = knownStorage
        let savedCurrent = currentStorage
        knownStorage = newKnown
        currentStorage = newCurrent
        defer {
            knownStorage = savedKnown
            currentStorage = savedCurrent
        }
        return try body()
    }

    /// Per-era algorithm-suite identifier (spec/versioning.md "Algorithm
    /// suites"): a v0.6 capsule names no algorithm anywhere in its
    /// bytes; absence means the v0.6 suite (Ed25519 / SHA-256 / JCS
    /// RFC 8785 / X25519 + HKDF-SHA-256 + ChaCha20-Poly1305). v0.7
    /// introduces no algorithm changes and no agility: absence in a
    /// 0.7 capsule means the SAME v0.6 suite — the identifier names
    /// the algorithm set by the era that introduced it.
    public static func suite(for version: String) -> String? {
        switch version {
        case "0.6", "0.7": return "v0.6"
        default: return nil
        }
    }

    /// Closed classification vocabulary for a declared version.
    public enum Status: String {
        case known
        case unknownNewer = "unknown_newer"
        case unknownOlder = "unknown_older"
        case invalid
    }

    /// Parse `<major>.<minor>` (decimal, no leading zeros).
    static func parse(_ v: String) -> (UInt64, UInt64)? {
        let parts = v.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        func component(_ s: Substring) -> UInt64? {
            guard !s.isEmpty, s.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
            if s.count > 1 && s.hasPrefix("0") { return nil } // no leading zeros
            return UInt64(s)
        }
        guard let major = component(parts[0]), let minor = component(parts[1]) else { return nil }
        return (major, minor)
    }

    /// Classify a declared version against the known-version table.
    public static func classify(_ v: String?) -> Status {
        guard let v, let parsed = parse(v) else { return .invalid }
        if known.contains(v) { return .known }
        let newest = parse(known.last!)!
        return parsed > newest ? .unknownNewer : .unknownOlder
    }

    /// Standard diagnosis wording. The needles
    /// "newer than this verifier supports" and
    /// "older than any version this verifier supports" are the
    /// cross-lane conformance contract (spec/vectors/version-compat/).
    public static func unsupportedMessage(field: String, observed: String,
                                          status: Status) -> String
    {
        if status == .unknownNewer {
            return "\(field) '\(observed)' is newer than this verifier supports "
                + "(newest known: \(known.last!)); this is a limitation of the verifier, "
                + "not corruption of the capsule — verify it with a newer implementation"
        }
        return "\(field) '\(observed)' is older than any version this verifier supports "
            + "(oldest known: \(known.first!)); this is not evidence of tampering — "
            + "verify it with an implementation that retains the \(observed) rules"
    }

    /// Reader gate: return the version when known; throw otherwise.
    /// Grammar violations throw a field-path-prefixed `.malformed`
    /// (mapping to the registry's invalid_manifest_shape reason);
    /// well-formed unknown versions throw `.unsupportedVersion` with the
    /// standard, distinguishable diagnosis.
    @discardableResult
    static func requireKnown(field: String, _ v: String?) throws -> String {
        switch classify(v) {
        case .known:
            return v!
        case .invalid:
            throw CapsuleError.malformed(
                "\(field): not a '<major>.<minor>' version string, got \(Chain.debugQuoted(v))")
        case let status:
            throw CapsuleError.unsupportedVersion(
                observed: v,
                status: status.rawValue,
                message: unsupportedMessage(field: field, observed: v!, status: status)
            )
        }
    }

    // -----------------------------------------------------------------
    // Version-keyed domain-separation strings. A verifier that accepts
    // a v0.6 capsule must retain the v0.6 strings forever, selected by
    // the capsule's DECLARED version — never a single current constant.
    // -----------------------------------------------------------------

    /// `capsule-id-v<version>\0` — the capsule_id hash domain.
    public static func idDomain(_ version: String) -> Data {
        Data("capsule-id-v\(version)\0".utf8)
    }

    /// `capsule-provenance-v<version>:<role>\0` — the signing domain.
    public static func provenanceDomain(_ version: String, role: String) -> Data {
        Data("capsule-provenance-v\(version):\(role)\0".utf8)
    }

    /// `capsule-key-wrap-v<version>` — the HKDF info for key wrap.
    public static func keyWrapInfo(_ version: String) -> Data {
        Data("capsule-key-wrap-v\(version)".utf8)
    }
}
