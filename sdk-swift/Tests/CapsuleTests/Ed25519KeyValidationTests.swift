// Vector-driven check that Ed25519 verification refuses small-order and
// non-canonically encoded public keys and non-reduced signature S values,
// per spec/vectors/ed25519-key-validation.json.
//
// Mirrors the JS reference lane (tools/check-spec-vectors.mjs), the Python
// test_ed25519_key_validation_registry, the Rust
// ed25519_key_validation_registry, and the Kotlin
// Ed25519KeyValidationVectorTest.

import Foundation
import XCTest
@testable import Capsule

final class Ed25519KeyValidationTests: XCTestCase {

    private struct Vector: Decodable {
        struct Expected: Decodable { let valid: Bool }
        let name: String
        let public_key_hex: String
        let message_hex: String
        let signature_hex: String
        let expected: Expected
        let reason: String
    }

    private struct VectorFile: Decodable {
        let vectors: [Vector]
    }

    /// Walks up from this file to the repo root, matching ParityTests.
    private static let vectorsURL: URL = {
        let testFile = URL(fileURLWithPath: #file)
        return testFile
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
            .appendingPathComponent("spec/vectors/ed25519-key-validation.json")
    }()

    func testKeyValidationMatchesSpecVectors() throws {
        let data = try Data(contentsOf: Self.vectorsURL)
        let file = try JSONDecoder().decode(VectorFile.self, from: data)
        XCTAssertFalse(file.vectors.isEmpty, "vector file is empty")
        for vector in file.vectors {
            let got = Ed25519.verify(
                publicKey: Bytes.fromHex(vector.public_key_hex),
                message: Bytes.fromHex(vector.message_hex),
                signature: Bytes.fromHex(vector.signature_hex)
            )
            XCTAssertEqual(
                got,
                vector.expected.valid,
                "\(vector.name): expected valid=\(vector.expected.valid) (\(vector.reason))"
            )
        }
    }
}
