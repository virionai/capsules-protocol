// JCS canonicalization must never kill the process on attacker bytes.
//
// `CapsuleVerifier.verify` canonicalizes the manifest (Manifest.hash),
// every chain event (verifyChain), and the envelope minus its signers
// (Envelope.signingInput) — all attacker-controlled. A `precondition`
// inside `JCS.canonical` (integers outside ±(2^53 − 1), non-finite
// doubles) is a `fatalError` no `do`/`catch` can contain, so a manifest
// containing {"id":9007199254740993} would take the host process down.
// These tests pin the contract that canonicalization THROWS
// `CapsuleError.malformed` and verification reports ok=false — matching
// the catchable ValueError / IllegalArgumentException in sdk-py and
// sdk-kotlin.
//
// A regression here does not show up as a failing assertion; it shows up
// as the test bundle crashing with "Precondition failed: JCS: integer
// outside IEEE-754 exact range".
//
// Since the I-JSON acceptance boundary landed (spec/canonicalization.md),
// the refusal happens at the reader's parse boundary rather than at the
// individual manifest/chain/envelope hash steps — "at parse time or at the
// canonicalization gate, whichever the implementation reaches first; both
// are conforming". These tests therefore pin the `parse` check plus the
// message, which is what the operator sees. `ok == false` is unchanged.

import Foundation
import XCTest
@testable import Capsule

final class JCSRobustnessTests: XCTestCase {

    private static let unsafeInt = #"{"id":9007199254740993}"#  // 2^53 + 1

    func testOutOfRangeIntegerThrowsInsteadOfTrapping() {
        XCTAssertThrowsError(try JCS.canonical(.integer(9_007_199_254_740_993))) { err in
            guard case CapsuleError.malformed(let m) = err else {
                return XCTFail("expected CapsuleError.malformed, got \(err)")
            }
            XCTAssertTrue(m.contains("2^53"), "got \(m)")
        }
        XCTAssertThrowsError(try JCS.canonical(.integer(-9_007_199_254_740_993)))
        // Boundary values stay canonicalizable.
        XCTAssertEqual(try JCS.canonical(.integer(9_007_199_254_740_991)),
                       "9007199254740991")
        XCTAssertEqual(try JCS.canonical(.integer(-9_007_199_254_740_991)),
                       "-9007199254740991")
    }

    func testNonFiniteDoubleThrowsInsteadOfTrapping() {
        XCTAssertThrowsError(try JCS.canonical(.decimal(.infinity)))
        XCTAssertThrowsError(try JCS.canonical(.decimal(.nan)))
    }

    func testManifestWithOutOfRangeIntegerFailsVerificationWithoutTrapping() {
        let bytes = CapsuleZip.pack([
            (path: "manifest.json", data: Data(Self.unsafeInt.utf8)),
            (path: "provenance/envelope.json", data: Data("{}".utf8)),
            (path: "chain/events.jsonl", data: Data()),
            (path: "program.md", data: Data("# hi\n".utf8)),
        ])
        let v = CapsuleVerifier.verify(bytes)
        XCTAssertFalse(v.ok, "manifest with 2^53+1 integer must not verify")
        Self.assertAcceptanceRefusal(v, naming: "manifest.json")
    }

    /// The refusal must be reported as a canonicalization error naming the
    /// offending document — never as a hash mismatch, and never as a JSON
    /// syntax error, since the bytes parse perfectly well.
    private static func assertAcceptanceRefusal(_ v: CapsuleVerification, naming file: String) {
        let parse = v.checks.first(where: { $0.name == "parse" })
        XCTAssertEqual(parse?.ok, false,
                       "must fail closed at parse; got \(String(describing: parse))")
        let detail = parse?.detail ?? ""
        XCTAssertTrue(detail.contains("2^53"),
                      "detail must name the acceptance rule; got \(detail)")
        XCTAssertTrue(detail.contains(file),
                      "detail must name the offending document; got \(detail)")
        XCTAssertFalse(detail.contains("failed to parse"),
                       "the JSON parsed fine; this is not a syntax error: \(detail)")
    }

    func testChainEventWithOutOfRangeIntegerFailsVerificationWithoutTrapping() {
        // prev_hash must be the genesis value so verifyChain reaches the
        // canonicalization step instead of bailing on the linkage check.
        // The manifest and envelope must be SHAPE-valid (the reader now
        // validates both at the parse boundary), so the refusal under test
        // is attributable to the chain document.
        let genesis = String(repeating: "0", count: 64)
        let hex64 = String(repeating: "a", count: 64)
        let event = #"{"seq":9007199254740993,"prev_hash":""# + genesis + #"","hash":"y"}"#
        let manifest = #"{"format":{"version":"0.6"},"id":""# + hex64
            + #"","originator":{"public_key":""# + hex64
            + #""},"first_event_hash":null,"content_index":{"index_hash":""# + hex64
            + #"","files":[]}}"#
        let envelope = #"{"version":"0.6","capsule_id":""# + hex64
            + #"","signers":[{"role":"originator","public_key":""# + hex64
            + #"","signature":"00"}]}"#
        let bytes = CapsuleZip.pack([
            (path: "manifest.json", data: Data(manifest.utf8)),
            (path: "provenance/envelope.json", data: Data(envelope.utf8)),
            (path: "chain/events.jsonl", data: Data((event + "\n").utf8)),
            (path: "program.md", data: Data("# hi\n".utf8)),
        ])
        let v = CapsuleVerifier.verify(bytes)
        XCTAssertFalse(v.ok, "chain event with 2^53+1 integer must not verify")
        Self.assertAcceptanceRefusal(v, naming: "chain/events.jsonl")
    }

    func testEnvelopeWithOutOfRangeIntegerFailsVerificationWithoutTrapping() {
        // The envelope carries a signer entry so verifySignatures reaches
        // signingInput, which canonicalizes the envelope minus signers —
        // including the hostile integer field.
        let envelope = #"{"version":"0.6","cipher":"none","evil":9007199254740993,"# +
            #""signers":[{"role":"originator","public_key":"ab","signature":"cd"}]}"#
        let bytes = CapsuleZip.pack([
            (path: "manifest.json", data: Data(#"{"id":"x"}"#.utf8)),
            (path: "provenance/envelope.json", data: Data(envelope.utf8)),
            (path: "chain/events.jsonl", data: Data()),
            (path: "program.md", data: Data("# hi\n".utf8)),
        ])
        let v = CapsuleVerifier.verify(bytes)
        XCTAssertFalse(v.ok, "envelope with 2^53+1 integer must not verify")
        Self.assertAcceptanceRefusal(v, naming: "provenance/envelope.json")
    }
}
