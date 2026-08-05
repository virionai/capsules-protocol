// Lineage declaration (manifest.predecessors) — spec/lineage.md.
//
// Mirrors sdk-js/test/lineage.test.js at the unit level; the cross-lane
// fixture outcomes live in SpecRegistryTests (lineage collection). Rules
// exercised here: PRESENCE BINDS, ABSENCE REPORTS; the member is parsed
// leniently and diagnosed at CHECK time (never a parse crash); identity
// coherence is era-keyed and SKIPPED for unknown declared eras; supplied
// predecessor bytes are REPORT-ONLY.

import Foundation
import XCTest
@testable import Capsule

final class LineageTests: XCTestCase {

    private static let vectorsDir: URL = {
        URL(fileURLWithPath: #file)
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
            .appendingPathComponent("spec/vectors")
    }()

    private func fixture(_ relative: String) throws -> Data {
        try Data(contentsOf: Self.vectorsDir.appendingPathComponent(relative))
    }

    private let hashA = String(repeating: "a", count: 64)
    private let hashB = String(repeating: "b", count: 64)

    /// A coherent entry: `capsule_id` derived from the declared key and
    /// first event hash under the declared era, exactly as a writer that
    /// derives from predecessor bytes produces it.
    private func coherentEntry(
        keyHex: String,
        firstEventHash: String?,
        entryHash: String?,
        manifestHash: String,
        version: String = "0.7",
        extra: [(String, JCSValue)] = []
    ) -> JCSValue {
        let id = Manifest.computeCapsuleId(
            originatorPub: Bytes.fromHex(keyHex),
            firstEventHashHex: firstEventHash ?? String(repeating: "0", count: 64),
            version: version
        )
        return .object([
            ("capsule_id", .string(id)),
            ("format_version", .string(version)),
            ("originator_public_key", .string(keyHex)),
            ("first_event_hash", firstEventHash.map { JCSValue.string($0) } ?? .null),
            ("entry_hash", entryHash.map { JCSValue.string($0) } ?? .null),
            ("manifest_hash", .string(manifestHash)),
        ] + extra)
    }

    private func keyHex() -> String { Ed25519KeyPair.generate().publicKeyHex }

    // MARK: - The reader must not refuse the new OPTIONAL member

    /// A capsule declaring `predecessors` opens like any other: the member
    /// is ordinary manifest content, preserved verbatim and covered by
    /// manifest_hash. A lane whose reader refused it would make an honest
    /// v0.7.1 capsule unopenable.
    func testReaderOpensACapsuleDeclaringPredecessors() throws {
        let parsed = try CapsuleReader.parse(try fixture("lineage/output/bob.capsule"))
        guard case .object(let pairs) = parsed.manifest,
              case .some(.array(let declared)) = pairs.first(where: { $0.0 == "predecessors" })?.1
        else {
            XCTFail("manifest.predecessors must survive parsing verbatim")
            return
        }
        XCTAssertEqual(declared.count, 1)
    }

    /// The malformation is diagnosed at CHECK time, not by a parse crash:
    /// the reader hands back the capsule and the verifier fails it closed
    /// with the shared `predecessors` diagnosis. A lane that threw at
    /// parse would report a different failure class than every other lane
    /// for the same bytes.
    func testMalformedDeclarationIsDiagnosedAtCheckTimeNotAtParse() throws {
        let bytes = try fixture("lineage/output/member-not-array.capsule")
        XCTAssertNoThrow(try CapsuleReader.parse(bytes),
                         "a malformed predecessors member is a check failure, not a parse refusal")
        let v = CapsuleVerifier.verify(bytes)
        XCTAssertFalse(v.ok)
        let check = v.checks.first(where: { $0.name == "lineage" })
        XCTAssertEqual(check?.ok, false, "the lineage check must carry the diagnosis")
        XCTAssertTrue(check?.detail.contains("predecessors must be an array") ?? false,
                      "got \(check?.detail ?? "(no lineage check)")")
    }

    // MARK: - Standalone checks (fail-closed)

    func testWellFormedDeclarationHasNoProblems() {
        let entry = coherentEntry(keyHex: keyHex(), firstEventHash: hashA,
                                  entryHash: hashB, manifestHash: hashA)
        XCTAssertEqual(Lineage.predecessorsProblems(.array([entry])), [])
    }

    /// "No claim" has exactly one spelling: absence (the present-but-empty
    /// signer_commitment precedent).
    func testMemberShapeRules() {
        XCTAssertTrue(
            Lineage.predecessorsProblems(.object([])).joined().contains("must be an array"))
        XCTAssertTrue(
            Lineage.predecessorsProblems(.array([])).joined().contains("must not be empty"))
        XCTAssertTrue(
            Lineage.predecessorsProblems(.array([.string("capsule:abc")])).joined()
                .contains("predecessors[0] must be an entry object"))
    }

    /// All six members are REQUIRED — there is no weaker declaration made
    /// honestly INSIDE an entry — and hex is lowercase by rule, not by
    /// normalization: the claim is bound by its stored bytes.
    func testEntryMemberGrammar() {
        let key = keyHex()
        let full = coherentEntry(keyHex: key, firstEventHash: hashA,
                                 entryHash: hashB, manifestHash: hashA)
        guard case .object(let members) = full else { return XCTFail("entry shape") }
        for required in Lineage.ENTRY_MEMBERS {
            let stripped = JCSValue.object(members.filter { $0.0 != required })
            XCTAssertTrue(
                Lineage.predecessorsProblems(.array([stripped])).joined()
                    .contains("predecessors[0].\(required)"),
                "removing \(required) must be diagnosed by member name"
            )
        }
        let uppercase = JCSValue.object(members.map { (name, value) in
            name == "manifest_hash" ? (name, .string(self.hashA.uppercased())) : (name, value)
        })
        XCTAssertTrue(
            Lineage.predecessorsProblems(.array([uppercase])).joined()
                .contains("predecessors[0].manifest_hash must be lowercase 64-hex"))
    }

    /// Vendor extensions inside an entry use the x- prefix; any other
    /// unrecognized member is malformed. The spec lends no
    /// verified-adjacent slot to unverifiable text about someone else's
    /// work — no `label`, `note`, or `relation`.
    func testUnrecognizedEntryMembers() {
        let key = keyHex()
        let vendor = coherentEntry(
            keyHex: key, firstEventHash: hashA, entryHash: hashB, manifestHash: hashA,
            extra: [("x-acme-note", .string("continued during migration"))]
        )
        XCTAssertEqual(Lineage.predecessorsProblems(.array([vendor])), [])
        let advisory = coherentEntry(
            keyHex: key, firstEventHash: hashA, entryHash: hashB, manifestHash: hashA,
            extra: [("label", .string("the official continuation"))]
        )
        XCTAssertTrue(
            Lineage.predecessorsProblems(.array([advisory])).joined()
                .contains("predecessors[0].label is not a spec-defined entry member"))
    }

    /// A zero-event predecessor declares both nullable members null (a
    /// template hand-off is legitimate); a mixed declaration describes a
    /// predecessor that cannot exist.
    func testNullCoherence() {
        let key = keyHex()
        let zeroEvent = coherentEntry(keyHex: key, firstEventHash: nil,
                                      entryHash: nil, manifestHash: hashA)
        XCTAssertEqual(Lineage.predecessorsProblems(.array([zeroEvent])), [])

        guard case .object(let members) = zeroEvent else { return XCTFail("entry shape") }
        let mixed = JCSValue.object(members.map { (name, value) in
            name == "entry_hash" ? (name, .string(self.hashB)) : (name, value)
        })
        XCTAssertTrue(
            Lineage.predecessorsProblems(.array([mixed])).joined().contains("cannot exist"))
    }

    /// Identity coherence under a KNOWN declared era: the declared
    /// capsule_id must equal the recompute under that era's identity rule.
    /// No external evidence is involved — this is self-assertion, not
    /// linkage, so it fails closed.
    func testIdentityCoherenceUnderKnownEras() {
        let key = keyHex()
        let coherent = coherentEntry(keyHex: key, firstEventHash: hashA,
                                     entryHash: hashB, manifestHash: hashA)
        guard case .object(let members) = coherent else { return XCTFail("entry shape") }
        let fabricated = JCSValue.object(members.map { (name, value) in
            name == "capsule_id" ? (name, .string(self.hashB)) : (name, value)
        })
        XCTAssertTrue(
            Lineage.predecessorsProblems(.array([fabricated])).joined().contains("does not derive"))

        // Cross-era citation is a feature: the recompute is keyed to the
        // PREDECESSOR's era, so the v0.7 id of the same key/genesis is a
        // lie about a v0.6 predecessor.
        let v06 = coherentEntry(keyHex: key, firstEventHash: hashA, entryHash: hashB,
                                manifestHash: hashA, version: "0.6")
        XCTAssertEqual(Lineage.predecessorsProblems(.array([v06])), [])
        guard case .object(let v06Members) = v06 else { return XCTFail("entry shape") }
        let eraSwapped = JCSValue.object(v06Members.map { (name, value) in
            name == "format_version" ? (name, .string("0.7")) : (name, value)
        })
        XCTAssertTrue(
            Lineage.predecessorsProblems(.array([eraSwapped])).joined().contains("does not derive"))
    }

    /// The unknown-era skip is the rule's release valve: versioning.md
    /// forbids applying one era's formula to another era's claim, so an
    /// id that derives under no era this verifier knows is REPORTED
    /// unchecked, never failed. The successor is not lying; this verifier
    /// is too old for the declared predecessor's era.
    func testIdentityCoherenceIsSkippedForUnknownEras() {
        let entry = JCSValue.object([
            ("capsule_id", .string(hashA)),
            ("format_version", .string("0.9")),
            ("originator_public_key", .string(keyHex())),
            ("first_event_hash", .string(hashA)),
            ("entry_hash", .string(hashB)),
            ("manifest_hash", .string(hashB)),
        ])
        XCTAssertEqual(Lineage.predecessorsProblems(.array([entry])), [])
        // A grammar violation is a malformed declaration, not an unknown
        // era.
        guard case .object(let members) = entry else { return XCTFail("entry shape") }
        let badGrammar = JCSValue.object(members.map { (name, value) in
            name == "format_version" ? (name, .string("v0.7")) : (name, value)
        })
        XCTAssertTrue(
            Lineage.predecessorsProblems(.array([badGrammar])).joined()
                .contains("predecessors[0].format_version"))
    }

    /// Two entries citing the SAME sealed artifact have no legitimate
    /// producer (the duplicate-signer precedent); two snapshots of one
    /// line — same capsule_id, different manifest_hash — are a coherent
    /// merge claim.
    func testDuplicateEntries() {
        let key = keyHex()
        let first = coherentEntry(keyHex: key, firstEventHash: hashA,
                                  entryHash: hashB, manifestHash: hashA)
        XCTAssertTrue(
            Lineage.predecessorsProblems(.array([first, first])).joined().contains("cited twice"))

        let sameIdLaterSeal = coherentEntry(keyHex: key, firstEventHash: hashA,
                                            entryHash: hashA, manifestHash: hashB)
        XCTAssertEqual(Lineage.predecessorsProblems(.array([first, sameIdLaterSeal])), [])
    }

    // MARK: - Reporting

    /// Absence is a weaker claim made honestly: nothing is checked and the
    /// area reports `declared=false` at full assurance.
    func testAbsentMemberReportsNoClaim() throws {
        let v = CapsuleVerifier.verify(try fixture("lineage/output/alice.capsule"))
        XCTAssertTrue(v.ok)
        XCTAssertFalse(v.lineage.declared)
        XCTAssertTrue(v.lineage.ok)
        XCTAssertTrue(v.lineage.entries.isEmpty)
        // The merged surface (spec/results.md) carries the base
        // vocabulary too — this fixture is verified with no allowlist —
        // but an ABSENT declaration contributes no lineage name.
        XCTAssertEqual(v.qualifiers, ["trust_not_evaluated"])
        XCTAssertFalse(v.qualifiers.contains { $0.hasPrefix("lineage_") },
                       "absence is never a lineage qualifier")
        let check = v.checks.first(where: { $0.name == "lineage" })
        XCTAssertEqual(check?.ok, true)
        XCTAssertEqual(check?.detail, "absent (no lineage declared)")
    }

    /// No retroactive interpretation of sealed eras: the SAME malformed
    /// value that fails a 0.7 capsule closed (`empty-array`) is an inert
    /// unknown member inside a 0.6 one. `predecessors` is a claim
    /// member, so it follows per-era rule sets — and the gate applies to
    /// the SUBJECT capsule, not only to hops reached through the walk.
    func testPredecessorsInAPreLineageEraCapsuleIsInert() throws {
        let v07 = CapsuleVerifier.verify(try fixture("lineage/output/empty-array.capsule"))
        XCTAssertFalse(v07.ok, "a 0.7 capsule's malformed declaration still fails closed")

        let v06 = CapsuleVerifier.verify(
            try fixture("lineage/output/predecessors-in-v06-capsule.capsule"))
        XCTAssertTrue(v06.ok, "\(v06.checks.filter { !$0.ok })")
        XCTAssertEqual(v06.formatVersion.observed, "0.6")
        XCTAssertFalse(v06.lineage.declared)
        XCTAssertTrue(v06.lineage.ok)
        XCTAssertTrue(v06.lineage.entries.isEmpty)
        XCTAssertFalse(v06.qualifiers.contains { $0.hasPrefix("lineage_") },
                       "an uninterpreted member is never a lineage qualifier")
        XCTAssertEqual(v06.qualifiers, ["trust_not_evaluated"])
        XCTAssertTrue(v06.notes.contains { $0.contains("unknown member under that era") },
                      "the uninterpreted member is reported: \(v06.notes)")
    }

    /// Refusal exclusivity: after an open-stage refusal the lineage
    /// channel holds its not-evaluated default — `declared=false` there
    /// means "not evaluated", not "absent" — and the refusal diagnosis is
    /// the only error carried.
    func testLineageChannelIsNotEvaluatedAfterAnOpenRefusal() throws {
        let v = CapsuleVerifier.verify(
            try fixture("version-compat/output/unknown-newer-version.capsule"))
        XCTAssertFalse(v.ok)
        XCTAssertFalse(v.lineage.declared)
        XCTAssertFalse(v.lineage.ok)
        XCTAssertTrue(v.lineage.entries.isEmpty)
        XCTAssertEqual(v.checks.count, 1, "the refusal is the only diagnosis: \(v.checks)")
    }

    /// THE anti-framing rule: linkage is REPORT-ONLY. A host supplying a
    /// different genuine seal of the declared line falsifies the lineage
    /// AREA and nothing else — the successor's own verdict must remain a
    /// function of the capsule, never of the invocation, or a third party
    /// flips a valid capsule's verdict by handing over the wrong file.
    func testSuppliedBytesNeverFlipTheCapsulesOwnVerdict() throws {
        let successor = try fixture("lineage/output/bob.capsule")
        let laterSeal = try fixture("lineage/output/alice-later-seal.capsule")
        let v = CapsuleVerifier.verify(successor, predecessors: [laterSeal])
        XCTAssertTrue(v.ok, "\(v.checks.filter { !$0.ok })")
        XCTAssertFalse(v.lineage.ok)
        XCTAssertEqual(v.lineage.entries.first?.status, "mismatch")
        XCTAssertEqual(v.lineage.verifiedDepth, 0)
        // A valid verdict with an unclean custody claim: the qualifier is
        // what keeps a renderer from hiding it. The array is the merged
        // spec-defined order — the base names (entries 1–7) first, the
        // lineage names (8–10) after.
        XCTAssertEqual(v.qualifiers, ["trust_not_evaluated", "lineage_mismatch"])
        // The wording names the honest cause and never reads as tampering.
        let errors = v.lineage.entries.flatMap { $0.errors }.joined(separator: " ")
        XCTAssertTrue(errors.contains("different sealed state of the declared predecessor"))
        XCTAssertTrue(errors.contains("manifest_hash: declared"),
                      "every differing member is named: \(errors)")
    }
}
