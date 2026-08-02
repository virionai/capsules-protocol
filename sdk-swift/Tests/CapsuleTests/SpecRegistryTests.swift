// Registry-driven conformance against spec/vectors.
//
// Mirrors sdk-py/tests/test_spec_registry.py and
// verifier-rust/tests/spec_registry.rs: this lane reads the
// language-neutral outcome registries directly, so Swift tracks the same
// normative expectations as the JS reference lane without hand-copied
// assertions:
//
//   - tamper-detection/vectors.json   (verify-stage outcomes)
//   - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
//   - malformed-shape/vectors.json    (manifest/chain document shape rules)
//   - unknown-fields/vectors.json     (unknown-member preservation outcomes)
//   - signer-set/vectors.json         (signer-set binding outcomes)
//   - chain-binding/vectors.json      (empty-chain anchors + stored-line hashing)
//   - chain-rules/vectors.json        (per-event actor + kind field rules)
//   - jcs-key-order.json              (RFC 8785 §3.2.3 member ordering)
//   - ijson-acceptance.json           (the I-JSON canonicalization input domain)
//   - unicode-boundary/vectors.json   (Pith-truncated astral text verifies)
//
// signing-input.json is consumed by SigningInputVectorTests, and
// jcs-numbers.json / ed25519-key-validation.json by their own test files.
//
// The registry's `reason` categories are normative; the substring table
// below maps each category onto this lane's error messages.

import Foundation
import XCTest
@testable import Capsule

final class SpecRegistryTests: XCTestCase {

    /// Walks up from this file to the repo root, matching ParityTests.
    private static let vectorsDir: URL = {
        URL(fileURLWithPath: #file)
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
            .appendingPathComponent("spec/vectors")
    }()

    // MARK: - Registry plumbing

    private func loadJSON(_ url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            XCTFail("not a JSON object: \(url.path)")
            throw CocoaError(.fileReadCorruptFile)
        }
        return obj
    }

    /// Resolve the collection's allowlist: an inline hex key, or the
    /// originator key in a referenced keys.json.
    private func allowlist(_ doc: [String: Any], base: URL) throws -> Set<String> {
        if let k = doc["originator_public_key_hex"] as? String { return [k] }
        if let kf = doc["keys_file"] as? String {
            let keys = try loadJSON(base.appendingPathComponent(kf).standardizedFileURL)
            if let pk = (keys["originator"] as? [String: Any])?["publicKey"] as? String {
                return [pk]
            }
        }
        return []
    }

    /// Per-lane mapping of the registry's normative open-stage reason
    /// categories onto this lane's `CapsuleError.malformed` messages.
    private func openReasonNeedles(_ reason: String) -> [String] {
        switch reason {
        case "missing_required_file":
            return ["missing manifest.json", "missing provenance/envelope.json"]
        case "invalid_json":
            return ["failed to parse manifest.json"]
        case "invalid_manifest_shape":
            // Every manifest shape error from CapsuleReader's validation is
            // prefixed with the offending field path (or names manifest.json
            // itself), mirroring the JS reference's validateManifestShape.
            return ["manifest."]
        case "duplicate_entry":
            return ["duplicate entry"]
        case "unsafe_path":
            return ["zip path traversal", "zip path: absolute"]
        case "unsupported_compression":
            return ["only STORED supported"]
        case "symlink_entry":
            return ["symlink"]
        case "directory_marker_shape":
            return ["directory attribute on non-directory name",
                    "directory marker with nonzero size"]
        case "local_central_name_mismatch":
            return ["local/central name mismatch"]
        default:
            XCTFail("unknown open-stage reason \(reason)")
            return []
        }
    }

    /// Registry `failing` area → this lane's check name.
    private static let areaCheck: [String: String] = [
        "content_index": "content_index_hash",
        "chain": "chain",
        "envelope": "envelope_signature",
        "encrypted_blob": "encrypted_blob_hash",
        "signer_set": "signer_commitment",
        "originator_binding": "originator_binding",
    ]

    /// Verify-stage vectors that THIS lane legitimately rejects at OPEN:
    /// `CapsuleReader.parse` requires chain/events.jsonl and program.md
    /// before it hands back a ParsedCapsule, so a capsule with a missing or
    /// unparseable chain never reaches the per-area checks. Refusing earlier
    /// is strictly stronger than the registry's ok=false requirement. Pinned
    /// by name so a lane that starts *accepting* one of these fails here.
    private static let openRejectedVerifyVectors: Set<String> = [
        "missing-chain",
        "invalid-chain-json",
    ]

    private func haystack(_ v: CapsuleVerification) -> String {
        v.checks.map { "\($0.name) \($0.detail)" }.joined(separator: " ")
    }

    private func assertVerifyOutcome(_ name: String,
                                     _ expected: [String: Any],
                                     _ v: CapsuleVerification) {
        let expectedOk = (expected["ok"] as? Bool) ?? true
        XCTAssertEqual(
            v.ok, expectedOk,
            "\(name): expected ok=\(expectedOk); failing checks: " +
            v.checks.filter { !$0.ok }.map { "\($0.name):\($0.detail)" }.joined(separator: ", ")
        )
        for area in (expected["failing"] as? [String]) ?? [] {
            guard let checkName = Self.areaCheck[area] else {
                XCTFail("\(name): unknown failing area \(area)")
                continue
            }
            let c = v.checks.first(where: { $0.name == checkName })
            XCTAssertNotNil(c, "\(name): expected a \(checkName) check entry")
            XCTAssertEqual(
                c?.ok, false,
                "\(name): expected \(checkName) to fail; got \(haystack(v))"
            )
        }
        if let needle = expected["error_includes"] as? String {
            XCTAssertTrue(
                haystack(v).contains(needle),
                "\(name): expected an error containing \(needle); got \(haystack(v))"
            )
        }
        if let bound = expected["signer_set_bound"] as? Bool {
            XCTAssertEqual(
                v.signerSetBound, bound,
                "\(name): expected signerSetBound=\(bound)"
            )
        }
        // Actor-set binding (chain.md step 6) follows the signer-set
        // contract: a non-empty manifest.participants[] binds the chain's
        // actors; an empty one must be REPORTED as unbound, never
        // rejected.
        if let bound = expected["actor_set_bound"] as? Bool {
            XCTAssertEqual(
                v.actorSetBound, bound,
                "\(name): expected actorSetBound=\(bound)"
            )
        }
        // Honest-reporting pin: some rules require the verifier to REPORT
        // a weaker claim machine-readably, not just to pass/fail.
        if let needle = expected["notes_includes"] as? String {
            XCTAssertTrue(
                v.notes.contains(where: { $0.contains(needle) }),
                "\(name): expected a note containing \(needle); got \(v.notes)"
            )
        }
    }

    // MARK: - tamper-detection/vectors.json

    func testTamperRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("tamper-detection/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "tamper-detection registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - unicode-boundary/vectors.json

    /// A JS-built capsule carrying Pith-truncated astral text must verify
    /// here. A failure means this lane's canonicalization disagrees on
    /// well-formed astral text — not that the capsule was tampered with.
    func testUnicodeBoundaryRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("unicode-boundary/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "unicode-boundary registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - signer-set/vectors.json

    /// Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS
    /// (spec/manifest.md "signer_commitment", spec/envelope.md "Signer set
    /// binding"). A present manifest.signer_commitment must equal the
    /// normalized envelope signer set exactly — strip / add / role-swap /
    /// unsorted all fail closed; an absent one verifies with
    /// signerSetBound=false. Duplicate (role, public_key) signers are
    /// malformed, and the manifest originator must have a valid
    /// role-"originator" signature.
    func testSignerSetRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("signer-set/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "signer-set registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - chain-rules/vectors.json

    /// chain.md per-event field rules (verification steps 6 and 7). The
    /// actor rule is conditional on the manifest's own claim: a non-empty
    /// participants[] binds every event actor to the declared set or
    /// system:host (fail-closed); an empty one verifies with
    /// actorSetBound=false plus a note — absence is a weaker claim made
    /// honestly. The kind enum is closed in every tier. All three
    /// fixtures are cryptographically well-formed, so only these rules
    /// decide them.
    func testChainRulesRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("chain-rules/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "chain-rules registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - malformed-layout/vectors.json

    func testMalformedRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("malformed-layout/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "malformed-layout registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))

            let isOpenStage = (expected["stage"] as? String) == "open"
                || Self.openRejectedVerifyVectors.contains(name)
            if isOpenStage {
                let reason = (expected["stage"] as? String) == "open"
                    ? try XCTUnwrap(expected["reason"] as? String, "\(name): reason")
                    : nil
                var thrown: Error?
                do { _ = try CapsuleReader.parse(bytes) } catch { thrown = error }
                let err = try XCTUnwrap(thrown, "\(name): reader must refuse this container")
                if let reason {
                    let needles = openReasonNeedles(reason)
                    XCTAssertTrue(
                        needles.contains(where: { "\(err)".contains($0) }),
                        "\(name): expected reason \(reason) (any of \(needles)); got \(err)"
                    )
                }
                // Fail-closed at the verifier surface too.
                XCTAssertFalse(CapsuleVerifier.verify(bytes, allowlist: keys).ok,
                               "\(name): open-stage fixture must not verify")
                continue
            }
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - malformed-shape/vectors.json

    /// Verify-stage vectors in malformed-shape that THIS lane legitimately
    /// refuses at parse: Foundation's JSON parser rejects the hostile
    /// number literal (1e999) before a manifest hash can be recomputed,
    /// which spec/canonicalization.md blesses explicitly ("rejection may
    /// happen at JSON parse time or at the canonicalization gate; both are
    /// conforming"). Pinned by name so a lane that starts ACCEPTING the
    /// value fails here.
    private static let shapeParseRejectedVectors: Set<String> = [
        "manifest-hostile-number",
    ]

    /// Manifest / chain document shape rules (spec/manifest.md field rules,
    /// spec/chain.md). Open-stage vectors must be refused by the reader for
    /// the named reason; verify-stage ones open but fail the pinned areas.
    func testMalformedShapeRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("malformed-shape/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "malformed-shape registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))

            if Self.shapeParseRejectedVectors.contains(name) {
                var thrown: Error?
                do { _ = try CapsuleReader.parse(bytes) } catch { thrown = error }
                XCTAssertNotNil(thrown, "\(name): reader must refuse this container")
                XCTAssertFalse(CapsuleVerifier.verify(bytes, allowlist: keys).ok,
                               "\(name): fixture must not verify")
                continue
            }
            if (expected["stage"] as? String) == "open" {
                let reason = try XCTUnwrap(expected["reason"] as? String, "\(name): reason")
                var thrown: Error?
                do { _ = try CapsuleReader.parse(bytes) } catch { thrown = error }
                let err = try XCTUnwrap(thrown, "\(name): reader must refuse this container")
                let needles = openReasonNeedles(reason)
                XCTAssertTrue(
                    needles.contains(where: { "\(err)".contains($0) }),
                    "\(name): expected reason \(reason) (any of \(needles)); got \(err)"
                )
                XCTAssertFalse(CapsuleVerifier.verify(bytes, allowlist: keys).ok,
                               "\(name): open-stage fixture must not verify")
                continue
            }
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - chain-binding/vectors.json

    /// Empty-chain anchor rule + stored-line hashing (spec/chain.md "Empty
    /// chains"). A chain with zero events is legal — the weakest honest
    /// shape — and then manifest.first_event_hash, envelope.first_event_hash
    /// and envelope.entry_hash MUST all be null (claiming an anchor over
    /// zero events fails closed; those anchors are the only envelope-to-
    /// chain binding in a plain capsule). The verifier must REPORT that no
    /// events were walked (notes pin). And an event whose stored bytes omit
    /// the optional untrusted_payload_fields member must verify: the hash
    /// preimage is the stored line, never a typed-struct round-trip.
    func testChainBindingRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("chain-binding/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "chain-binding registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - unknown-fields/vectors.json

    /// Unknown members in the hashed documents MUST be preserved and hashed
    /// (spec/manifest.md "Unknown members", spec/envelope.md, spec/chain.md).
    /// The positive vector carries x- extension members in manifest.json,
    /// provenance/envelope.json, and a chain event, all covered by the seal;
    /// it must verify ok=true. The tampered variants mutate an unknown
    /// member post-seal and must fail in the pinned area — proving the
    /// members are inside the integrity envelope, not decoration.
    func testUnknownFieldsRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("unknown-fields/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "unknown-fields registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - jcs-key-order.json

    /// RFC 8785 §3.2.3: object members sort on their UTF-16 code-unit
    /// sequences.
    ///
    /// Swift's `String <` is NOT that order, twice over: it compares
    /// canonically-equivalent, normalization-aware sequences of Unicode
    /// scalars, so a supplementary-plane key (>= U+10000, UTF-16 lead
    /// surrogate 0xD800..0xDBFF) sorts *above* U+E000..U+FFFF instead of
    /// below it, and canonically equivalent keys ("e" + U+0301 vs
    /// precomposed U+00E9) compare *equal*, leaving their relative order to
    /// the sort's unspecified stability. Both are negative witnesses in the
    /// vector file: a lane using `String <` emits different canonical
    /// bytes, a different hash, and fails to verify an honest capsule built
    /// by any other lane.
    func testJcsKeyOrderRegistry() throws {
        let path = Self.vectorsDir.appendingPathComponent("jcs-key-order.json")
        let doc = try loadJSON(path)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "jcs-key-order registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let keys = try XCTUnwrap(vector["keys"] as? [String], "\(name): keys")
            let pairs = keys.enumerated().map { (i, key) in (key, JCSValue.integer(Int64(i))) }
            let canonical = try JCS.bytes(.object(pairs))
            XCTAssertEqual(
                Bytes.toHex(canonical),
                try XCTUnwrap(vector["canonical_utf8_hex"] as? String),
                name
            )
            XCTAssertEqual(
                Hash.sha256Hex(canonical),
                try XCTUnwrap(vector["sha256_hex"] as? String),
                name
            )
        }
    }

    // MARK: - ijson-acceptance.json

    /// Normative reject-reason vocabulary from `ijson-acceptance.json`.
    private static let ijsonReasons: Set<String> = ["integer_out_of_range", "unpaired_surrogate"]

    /// spec/canonicalization.md: the acceptance boundary is identical in
    /// every lane. A reject vector is satisfied by refusal at parse time OR
    /// at the canonicalization gate — whichever this lane reaches first.
    /// Foundation refuses lone-surrogate escapes at parse; `assertAcceptable`
    /// (applied inside `parseJSON`) refuses out-of-range integer literals.
    func testIJsonAcceptanceRegistry() throws {
        let path = Self.vectorsDir.appendingPathComponent("ijson-acceptance.json")
        let doc = try loadJSON(path)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "ijson-acceptance registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let text = try XCTUnwrap(vector["input_json"] as? String, "\(name): input_json")
            let expect = try XCTUnwrap(vector["expect"] as? String, "\(name): expect")
            let data = Data(text.utf8)
            if expect == "accept" {
                let value = try CapsuleReader.parseJSON(data)
                XCTAssertEqual(
                    try JCS.canonical(value),
                    try XCTUnwrap(vector["canonical"] as? String),
                    name
                )
                continue
            }
            XCTAssertEqual(expect, "reject", "\(name): expect must be accept or reject")
            let reason = try XCTUnwrap(vector["reason"] as? String, "\(name): reason")
            XCTAssertTrue(Self.ijsonReasons.contains(reason), "\(name): unknown reason \(reason)")
            XCTAssertThrowsError(
                try CapsuleReader.parseJSON(data),
                "\(name): the value must never reach a hash"
            )
        }
    }

    /// The comparator claim itself, independent of the vector file: the two
    /// cases Swift's `String <` gets wrong.
    func testUtf16LessDisagreesWithSwiftStringOrdering() {
        // U+1F600 is D83D DE00, so it precedes U+E000 in UTF-16 order even
        // though its scalar value is far larger.
        XCTAssertTrue(JCS.utf16Less("\u{1F600}", "\u{E000}"))
        XCTAssertFalse(JCS.utf16Less("\u{E000}", "\u{1F600}"))
        XCTAssertTrue("\u{E000}" < "\u{1F600}", "Swift's String < is scalar order, not UTF-16")
        // Canonically equivalent keys are distinct and strictly ordered.
        XCTAssertTrue(JCS.utf16Less("e\u{0301}", "\u{00E9}"))
        XCTAssertFalse(JCS.utf16Less("\u{00E9}", "e\u{0301}"))
        XCTAssertEqual("e\u{0301}", "\u{00E9}", "Swift's String == is canonical equivalence")
    }
}
