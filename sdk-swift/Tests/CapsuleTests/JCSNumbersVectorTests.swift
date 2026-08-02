// Vector-driven check that number serialization matches the normative
// JCS vectors in spec/vectors/jcs-numbers.json (Node JSON.stringify is
// the oracle). Inputs are IEEE-754 bit patterns so no JSON parser sits
// between the vector and the value under test.
//
// Mirrors sdk-js/test/jcs-numbers.test.js, the Python
// test_jcs_numbers_match_spec_vectors, the Kotlin
// JcsNumbersVectorTest, and the Rust jcs::vector_tests.

import Foundation
import XCTest
@testable import Capsule

final class JCSNumbersVectorTests: XCTestCase {

    private struct Vector: Decodable {
        let ieee_hex: String
        let expected: String
        /// Absent means accepted. `false` marks a bit pattern outside the
        /// I-JSON acceptance boundary (spec/canonicalization.md): `expected`
        /// documents the Number::toString layout, but the value must be
        /// refused before it can be canonicalized.
        let accepted: Bool?
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
            .appendingPathComponent("spec/vectors/jcs-numbers.json")
    }()

    func testNumbersMatchSpecVectors() throws {
        let data = try Data(contentsOf: Self.vectorsURL)
        let file = try JSONDecoder().decode(VectorFile.self, from: data)
        XCTAssertFalse(file.vectors.isEmpty, "vector file is empty")
        for vector in file.vectors {
            guard let bits = UInt64(vector.ieee_hex, radix: 16) else {
                XCTFail("bad ieee_hex \(vector.ieee_hex)")
                continue
            }
            let value = Double(bitPattern: bits)
            if vector.accepted == false {
                XCTAssertThrowsError(
                    try JCS.assertAcceptable(.decimal(value)),
                    "bits \(vector.ieee_hex) (would serialize as \(vector.expected)) must be rejected"
                )
                continue
            }
            XCTAssertEqual(
                try JCS.canonical(.decimal(value)),
                vector.expected,
                "bits \(vector.ieee_hex)"
            )
        }
    }
}
