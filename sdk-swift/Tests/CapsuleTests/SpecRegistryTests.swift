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
//   - version-compat/vectors.json     (version gates: known opens and
//                                      reports; unknown fails closed with
//                                      a non-tamper diagnosis)
//   - jcs-key-order.json              (RFC 8785 §3.2.3 member ordering)
//   - ijson-acceptance.json           (the I-JSON canonicalization input domain)
//   - unicode-boundary/vectors.json   (Pith-truncated astral text verifies)
//   - pith-authoring/vectors.json     (verbatim technical prose + the
//                                      pith_normalized_fields marker verify)
//   - lineage/vectors.json            (manifest.predecessors: fail-closed
//                                      standalone checks + REPORT-ONLY
//                                      supplied-bytes linkage)
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
        // spec/versioning.md: unknown versions fail closed with a
        // diagnosis DISTINCT from malformation or tampering.
        case "unsupported_version_newer":
            return ["newer than this verifier supports"]
        case "unsupported_version_older":
            return ["older than any version this verifier supports"]
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
        "lineage": "lineage",
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

    /// All diagnostic text a vector's `error_includes` may pin. Lineage
    /// entry errors join it because linkage diagnoses are REPORT-ONLY —
    /// they never fail a check, but their wording is pinned (e.g.
    /// "different sealed state of the declared predecessor").
    private func haystack(_ v: CapsuleVerification) -> String {
        (v.checks.map { "\($0.name) \($0.detail)" }
            + v.lineage.entries.flatMap { $0.errors }).joined(separator: " ")
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
        // a weaker claim machine-readably, not just to pass/fail. A string
        // pins one substring; an array pins several (e.g. the lineage
        // phrases "declared, not verified" AND "not countersigned").
        let noteNeedles = (expected["notes_includes"] as? [String])
            ?? (expected["notes_includes"] as? String).map { [$0] }
            ?? []
        for needle in noteNeedles {
            XCTAssertTrue(
                v.notes.contains(where: { $0.contains(needle) }),
                "\(name): expected a note containing \(needle); got \(v.notes)"
            )
        }
        // Skill-trust derivation (spec/trust.md "Skill trust"): the tier
        // MUST come from the verify result — capsuleSigned plus the exact
        // per-id map — never from any skill_trust member in the capsule.
        if let want = expected["skill_trust"] as? [String: Any] {
            let wantSigned = want["capsule_signed"] as? Bool ?? false
            XCTAssertEqual(
                v.skillTrust.capsuleSigned, wantSigned,
                "\(name): expected skillTrust.capsuleSigned=\(wantSigned)"
            )
            let wantSkills = (want["skills"] as? [String: String]) ?? [:]
            XCTAssertEqual(
                v.skillTrust.skills, wantSkills,
                "\(name): skillTrust.skills mismatch"
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

    // MARK: - pith-authoring/vectors.json

    /// Pith is opt-in authoring (spec/pith.md); its marker is an ordinary
    /// member. technical-prose-verbatim: a default-built capsule whose
    /// summary holds dots inside an identifier and decimals, stored
    /// byte-identical, no marker. pith-normalized-marker: a pith-enabled
    /// capsule whose event carries pith_normalized_fields (spec/chain.md),
    /// covered by the event hash like any other member. Both MUST verify
    /// ok:true; a failure means this lane rejects or re-projects an
    /// optional event member — not tampering.
    func testPithAuthoringRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("pith-authoring/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "pith-authoring registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            assertVerifyOutcome(name, expected, CapsuleVerifier.verify(bytes, allowlist: keys))
        }
    }

    // MARK: - lineage/vectors.json

    /// `expected.lineage` pins the reported area (spec/lineage.md
    /// "Reporting"). Every member is ignore-if-absent, per the shared
    /// outcome-schema contract.
    private func assertLineage(_ name: String, _ want: [String: Any], _ got: LineageReport) {
        let shape = got.entries
            .map { "hop \($0.hop) \($0.status)\($0.reason.map { r in " (\(r))" } ?? "")" }
            .joined(separator: ", ")
        if let declared = want["declared"] as? Bool {
            XCTAssertEqual(got.declared, declared, "\(name): expected lineage.declared=\(declared)")
        }
        if let ok = want["ok"] as? Bool {
            XCTAssertEqual(got.ok, ok, "\(name): expected lineage.ok=\(ok); entries: \(shape)")
        }
        if let depth = want["verified_depth"] as? Int {
            XCTAssertEqual(
                got.verifiedDepth, depth,
                "\(name): expected lineage.verified_depth=\(depth); entries: \(shape)"
            )
        }
        guard let wantEntries = want["entries"] as? [[String: Any]] else { return }
        XCTAssertEqual(
            got.entries.count, wantEntries.count,
            "\(name): expected \(wantEntries.count) lineage entries; got \(shape)"
        )
        guard got.entries.count == wantEntries.count else { return }
        for (i, wantEntry) in wantEntries.enumerated() {
            let entry = got.entries[i]
            let at = "\(name): lineage.entries[\(i)]"
            if let status = wantEntry["status"] as? String {
                XCTAssertEqual(entry.status, status,
                               "\(at).status; errors: \(entry.errors.joined(separator: "; "))")
            }
            if let hop = wantEntry["hop"] as? Int {
                XCTAssertEqual(entry.hop, hop, "\(at).hop")
            }
            if let reason = wantEntry["reason"] as? String {
                XCTAssertEqual(entry.reason, reason, "\(at).reason")
            }
            if let capsuleId = wantEntry["capsule_id"] as? String {
                XCTAssertEqual(entry.capsuleId, capsuleId, "\(at).capsule_id")
            }
            if let checked = wantEntry["identity_checked"] as? Bool {
                XCTAssertEqual(entry.identityChecked, checked, "\(at).identity_checked")
            }
            if let version = wantEntry["artifact_observed_version"] as? String {
                XCTAssertEqual(entry.artifact?.observedVersion, version,
                               "\(at).artifact.observed_version")
            }
            // A FLOOR, not an equality: the count is lane-local (this
            // lane counts failing checks), so only the honesty invariant
            // is pinned — an artifact reported as failing never also
            // reports zero errors.
            if let floor = wantEntry["artifact_error_count_min"] as? Int {
                XCTAssertGreaterThanOrEqual(entry.artifact?.errorCount ?? 0, floor,
                                            "\(at).artifact.error_count")
            }
        }
    }

    /// The capsule's own declared identity — a reported fact some vectors
    /// pin (the same-id-zero-event-rewrap and unendorsed-successor ids).
    private func declaredCapsuleId(_ bytes: Data) throws -> String? {
        let parsed = try CapsuleReader.parse(bytes)
        guard case .object(let pairs) = parsed.manifest,
              case .some(.string(let id)) = pairs.first(where: { $0.0 == "id" })?.1
        else { return nil }
        return id
    }

    /// The lineage declaration (spec/lineage.md, `manifest.predecessors`).
    /// PRESENCE BINDS, ABSENCE REPORTS: an absent member is "no claim"; a
    /// PRESENT malformed declaration is the capsule asserting something
    /// meaningless about its own origin and fails closed with the shared
    /// `predecessors[i].<member>` diagnoses. Identity coherence is
    /// era-keyed and SKIPPED (identity_checked=false, never failed) for
    /// unknown declared eras.
    ///
    /// Linkage against the per-vector `predecessors` pool is REPORT-ONLY:
    /// the ok-true-under-mismatch vectors are normative — a lane that
    /// fails the capsule when a host supplies the wrong (or a hostile)
    /// file lets a third party flip a valid capsule's verdict. The
    /// verified/mismatch/predecessor_invalid/predecessor_unverifiable
    /// vocabulary and the pinned phrases ("declared, not verified", "not
    /// countersigned", "different sealed state") are the cross-lane
    /// contract.
    func testLineageRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("lineage/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let keysDoc = try loadJSON(
            base.appendingPathComponent(try XCTUnwrap(doc["keys_file"] as? String))
                .standardizedFileURL
        )
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "lineage registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            for req in (vector["requires"] as? [String]) ?? [] {
                XCTAssertTrue(Self.knownRequirements.contains(req),
                              "\(name): unknown requirement \(req)")
            }
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            // The pool paths are relative to the collection file; supplying
            // them is the host's evidence, not the capsule's claim.
            var pool: [Data] = []
            for rel in (vector["predecessors"] as? [String]) ?? [] {
                pool.append(try Data(contentsOf: base.appendingPathComponent(rel)))
            }
            let v = CapsuleVerifier.verify(bytes, allowlist: keys, predecessors: pool)
            assertVerifyOutcome(name, expected, v)
            if let wantId = expected["capsule_id"] as? String {
                XCTAssertEqual(try declaredCapsuleId(bytes), wantId,
                               "\(name): expected capsule_id \(wantId)")
            }
            if let wantLineage = expected["lineage"] as? [String: Any] {
                assertLineage(name, wantLineage, v.lineage)
            }
            // Verdict qualifiers: the exact array after stripping x-
            // vendor entries. Non-empty only on a valid verdict, and
            // payload-carrying facts never ride the bare strings.
            if let wantQualifiers = expected["qualifiers"] as? [String] {
                XCTAssertEqual(
                    v.qualifiers.filter { !$0.hasPrefix("x-") }, wantQualifiers,
                    "\(name): expected qualifiers \(wantQualifiers); got \(v.qualifiers)"
                )
            }
            // `inner_ok` pins an L3 fail-closed outcome — the inner/outer
            // declaration equality of an encrypted successor. This lane's
            // L3 surface is one composite result over the outer and inner
            // halves, so the inner refusal shows up as the composite `ok`.
            guard let keyName = expected["decryptable_with"] as? String else { continue }
            let pair = try XCTUnwrap(keysDoc[keyName] as? [String: Any],
                                     "\(name): keys_file has no keypair \(keyName)")
            let pub = Bytes.fromHex(try XCTUnwrap(pair["publicKey"] as? String))
            let priv = Bytes.fromHex(try XCTUnwrap(pair["privateKey"] as? String))
            let l3 = CapsuleVerifier.verify(
                bytes, recipientPrivateKey: priv, recipientPublicKey: pub,
                allowlist: keys, predecessors: pool
            )
            XCTAssertEqual(l3.level, "L3", "\(name): level must be L3")
            let wantInnerOk = (expected["inner_ok"] as? Bool) ?? true
            XCTAssertEqual(
                l3.ok, wantInnerOk,
                "\(name): expected L3 ok=\(wantInnerOk); failing checks: "
                + l3.checks.filter { !$0.ok }.map { "\($0.name):\($0.detail)" }
                    .joined(separator: ", ")
            )
            if let needle = expected["inner_error_includes"] as? String {
                XCTAssertTrue(
                    haystack(l3).contains(needle),
                    "\(name): expected an L3 error containing \(needle); got \(haystack(l3))"
                )
            }
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

    // MARK: - skill-trust/vectors.json

    /// Skill trust is DERIVED from the verify result, never read from the
    /// capsule (spec/trust.md "Skill trust"). The same capsule bytes
    /// classify differently at hosts with different allowlists, so each
    /// vector pins its own trust configuration: the per-vector `allowlist`
    /// names keypairs in keys_file ([] = verify with no allowlist). A lane
    /// that surfaces the fixture's own `skill_trust` manifest member as
    /// trust hands prompt-injection text to a host LLM as trusted
    /// instructions — the defect (A01) this collection keeps closed.
    func testSkillTrustRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("skill-trust/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keysDoc = try loadJSON(
            base.appendingPathComponent(try XCTUnwrap(doc["keys_file"] as? String))
                .standardizedFileURL
        )
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "skill-trust registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let names = try XCTUnwrap(vector["allowlist"] as? [String], "\(name): allowlist")
            var keys: Set<String> = []
            for keyName in names {
                let pk = (keysDoc[keyName] as? [String: Any])?["publicKey"] as? String
                keys.insert(try XCTUnwrap(pk, "\(name): allowlist entry \(keyName) not in keys_file"))
            }
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

    // MARK: - semantic-binding/vectors.json

    /// Per-lane mapping of the registry's normative verify-stage reason
    /// categories onto this SDK's check details.
    private static let verifyReasonNeedles: [String: String] = [
        "first_event_hash_binding": "manifest.first_event_hash mismatch",
        "encryption_shape": "manifest.encryption must be",
        "encryption_metadata_path": "manifest.encryption.metadata_path",
        "cipher_without_blob": "plain capsule must have cipher='none'",
        "blob_without_cipher": "encrypted blob present but envelope.",
    ]

    /// Optional lane capabilities a semantic-binding vector may declare in
    /// requires[]. This SDK implements all of them, so nothing is skipped;
    /// the set exists so an unknown requirement fails loudly instead of
    /// silently skipping a vector.
    private static let knownRequirements: Set<String> = ["encryption"]

    /// Manifest claims must agree with the signed envelope, the chain, and
    /// the files. Every fixture is well-formed and correctly signed; only
    /// its semantics are wrong, so nothing but an explicit cross-check
    /// catches it. `decryptable_with` pins that L3 decryption resolves the
    /// metadata through manifest.encryption.metadata_path, never a
    /// hardcoded path.
    func testSemanticBindingRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("semantic-binding/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let keysDoc = try loadJSON(
            base.appendingPathComponent(try XCTUnwrap(doc["keys_file"] as? String))
                .standardizedFileURL
        )
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "semantic-binding registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            for req in (vector["requires"] as? [String]) ?? [] {
                XCTAssertTrue(Self.knownRequirements.contains(req),
                              "\(name): unknown requirement \(req)")
            }
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            let v = CapsuleVerifier.verify(bytes, allowlist: keys)
            assertVerifyOutcome(name, expected, v)

            if let reason = expected["reason"] as? String {
                let needle = Self.verifyReasonNeedles[reason]
                XCTAssertNotNil(needle, "\(name): unknown verify-stage reason \(reason)")
                XCTAssertTrue(haystack(v).contains(needle ?? "\u{0}"),
                              "\(name): expected reason \(reason); got \(haystack(v))")
            }

            if let keyName = expected["decryptable_with"] as? String {
                let pair = try XCTUnwrap(keysDoc[keyName] as? [String: Any],
                                         "\(name): keys_file has no keypair \(keyName)")
                let pub = Bytes.fromHex(try XCTUnwrap(pair["publicKey"] as? String))
                let priv = Bytes.fromHex(try XCTUnwrap(pair["privateKey"] as? String))
                let l3 = CapsuleVerifier.verify(
                    bytes,
                    recipientPrivateKey: priv,
                    recipientPublicKey: pub,
                    allowlist: keys
                )
                XCTAssertTrue(
                    l3.ok,
                    "\(name): L3 must follow manifest.encryption.metadata_path; failing: "
                    + l3.checks.filter { !$0.ok }.map { "\($0.name):\($0.detail)" }
                        .joined(separator: ", ")
                )
                XCTAssertEqual(l3.level, "L3", "\(name): level must be L3")
            }
        }
    }

    // MARK: - version-compat/vectors.json

    /// spec/versioning.md: a capsule declaring a KNOWN format version
    /// verifies under that era's rules with the observed version REPORTED
    /// machine-readably; a well-formed unknown version is refused at open
    /// with a diagnosis distinct from tamper detection (verifier-too-old
    /// vs unknown-older), a grammar-violating one as malformed. The
    /// unknown-version fixtures are internally coherent under their
    /// declared version's domain strings, so only the version gate
    /// refuses them. Even on refusal, the verify result still reports
    /// the observed version (expected.observed_version pin).
    func testVersionCompatRegistryOutcomes() throws {
        let path = Self.vectorsDir.appendingPathComponent("version-compat/vectors.json")
        let doc = try loadJSON(path)
        let base = path.deletingLastPathComponent()
        let keys = try allowlist(doc, base: base)
        let vectors = (doc["vectors"] as? [[String: Any]]) ?? []
        XCTAssertFalse(vectors.isEmpty, "version-compat registry is empty")
        for vector in vectors {
            let name = vector["name"] as? String ?? "<unnamed>"
            let file = try XCTUnwrap(vector["capsule_file"] as? String, "\(name): capsule_file")
            let expected = try XCTUnwrap(vector["expected"] as? [String: Any], "\(name): expected")
            let bytes = try Data(contentsOf: base.appendingPathComponent(file))
            let v = CapsuleVerifier.verify(bytes, allowlist: keys)

            if (expected["stage"] as? String) == "open" {
                let reason = try XCTUnwrap(expected["reason"] as? String, "\(name): reason")
                var thrown: Error?
                do { _ = try CapsuleReader.parse(bytes) } catch { thrown = error }
                let err = try XCTUnwrap(thrown, "\(name): reader must refuse this capsule")
                let needles = openReasonNeedles(reason)
                XCTAssertTrue(
                    needles.contains(where: { "\(err)".contains($0) }),
                    "\(name): expected reason \(reason) (any of \(needles)); got \(err)"
                )
                XCTAssertFalse(v.ok, "\(name): open-stage fixture must not verify")
            } else {
                assertVerifyOutcome(name, expected, v)
            }
            if let observed = expected["observed_version"] as? String {
                // The observed version is a REPORTED fact even when the
                // capsule is refused — what lets an auditor tell "this
                // verifier is too old" apart from "corrupt".
                XCTAssertEqual(
                    v.formatVersion.observed, observed,
                    "\(name): expected formatVersion.observed=\(observed)"
                )
            }
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
    private static let ijsonReasons: Set<String> = ["integer_out_of_range", "unpaired_surrogate", "duplicate_member"]

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
