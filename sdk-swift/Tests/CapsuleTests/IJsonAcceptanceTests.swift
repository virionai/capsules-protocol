// I-JSON acceptance boundary (spec/canonicalization.md).
//
// Swift's String is a Unicode-scalar sequence and JSONSerialization refuses
// lone-surrogate escapes at parse time, so this lane's exposure is the
// number rule: JCS.canonical would lay 1e19 out as the plain literal
// 10000000000000000000, which no native-integer parser reads back the same.

import Foundation
import XCTest
@testable import Capsule

final class IJsonAcceptanceTests: XCTestCase {

    func testRejectsPlainIntegerLiteralOutsideExactRange() {
        // Date.now() * 1e6 — a nanosecond timestamp.
        XCTAssertThrowsError(try JCS.assertAcceptable(.decimal(1.7e18)))
        XCTAssertThrowsError(try JCS.assertAcceptable(.decimal(1e19)))
        // 2^53 itself is one past the exact range.
        XCTAssertThrowsError(try JCS.assertAcceptable(.decimal(9007199254740992)))
        XCTAssertThrowsError(try JCS.assertAcceptable(.integer(9007199254740992)))
        // canonical() is the backstop: it must refuse the same value even if
        // a caller skipped the gate.
        XCTAssertThrowsError(try JCS.canonical(.decimal(1e19)))
    }

    func testAcceptsExactRangeBoundaryAndExponentForm() throws {
        try JCS.assertAcceptable(.integer(9007199254740991))
        try JCS.assertAcceptable(.decimal(9007199254740991))
        // >= 1e21 serializes in exponent form and round-trips everywhere.
        try JCS.assertAcceptable(.decimal(1e21))
        XCTAssertEqual(try JCS.canonical(.decimal(1e21)), "1e+21")
        try JCS.assertAcceptable(.decimal(1.5))
    }

    func testMessageNamesTheOffendingPath() {
        let value = jobj(("payload", jobj(("ts_ns", .decimal(1.7e18)))))
        XCTAssertThrowsError(try JCS.assertAcceptable(value)) { error in
            XCTAssertTrue(
                "\(error)".contains("$.payload.ts_ns"),
                "message must name the path: \(error)"
            )
        }
    }

    func testParseJSONRefusesAnOutOfRangeIntegerLiteral() {
        let data = Data(#"{"payload":{"ts":10000000000000000000}}"#.utf8)
        XCTAssertThrowsError(try CapsuleReader.parseJSON(data))
    }

    func testParseJSONRefusesALoneSurrogateEscape() {
        // Foundation refuses this at parse; the capsule never reaches a hash.
        let data = Data(##"{"s":"x\ud83d"}"##.utf8)
        XCTAssertThrowsError(try CapsuleReader.parseJSON(data))
    }

    func testParseJSONAcceptsAWellFormedAstralPair() throws {
        let data = Data(##"{"s":"x🙂"}"##.utf8)
        let value = try CapsuleReader.parseJSON(data)
        XCTAssertEqual(try JCS.canonical(value), "{\"s\":\"x\u{1F642}\"}")
    }

    func testSealRefusesAPayloadOutsideTheBoundary() throws {
        let keys = Ed25519KeyPair.generate()
        let builder = CapsuleBuilder(originator: .init(keyPair: keys, label: "T"),
                                     createdAt: "2026-05-07T12:00:00Z")
        builder.setParticipants([.init(actorId: "human:a", role: "originator", label: "A")])
        builder.appendEvent(
            actor: "human:a", kind: "observation", action: "note", target: "capsule",
            timestamp: "2026-05-07T12:00:00Z",
            payload: jobj(("ts_ns", .decimal(1.7e18)))
        )
        XCTAssertThrowsError(try builder.seal(signedAt: "2026-05-07T12:00:00Z")) { error in
            XCTAssertTrue(
                "\(error)".contains("integer outside IEEE-754 exact range"),
                "unexpected: \(error)"
            )
        }
    }
}
