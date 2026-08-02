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
        case "duplicate_entry":
            return ["duplicate entry"]
        case "unsafe_path":
            return ["zip path traversal", "zip path: absolute"]
        case "unsupported_compression":
            return ["only STORED supported"]
        case "symlink_entry":
            return ["symlink"]
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
}
