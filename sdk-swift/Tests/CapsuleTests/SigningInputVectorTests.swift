// Byte-level signing-input registry (spec/vectors/signing-input.json).
//
// Mirrors sdk-py/tests/test_spec_registry.py::test_signing_input_pins and
// verifier-rust/tests/spec_registry.rs::signing_input_pins: every canonical
// byte string and hash pinned by the vector must be reproducible from the
// embedded capsule it references (spec/vectors/plain-basic.json, via
// meta.capsule_ref), and each pinned signature must verify over the
// reconstructed signing input. A failure here means this lane's
// canonicalization, hashing, or domain separation disagrees with the other
// four lanes at the byte level.

import Foundation
import XCTest
@testable import Capsule

final class SigningInputVectorTests: XCTestCase {

    private static let vectorsDir: URL = {
        URL(fileURLWithPath: #file)
            .deletingLastPathComponent()  // CapsuleTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // sdk-swift/
            .deletingLastPathComponent()  // <repo-root>/
            .appendingPathComponent("spec/vectors")
    }()

    private func loadJSON(_ url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            XCTFail("not a JSON object: \(url.path)")
            throw CocoaError(.fileReadCorruptFile)
        }
        return obj
    }

    private func lookup(_ v: JCSValue, _ path: [String]) -> JCSValue? {
        var cur = v
        for k in path {
            guard case .object(let pairs) = cur,
                  let next = pairs.first(where: { $0.0 == k })?.1 else { return nil }
            cur = next
        }
        return cur
    }

    private func str(_ v: JCSValue?, _ label: String) throws -> String {
        guard case .string(let s)? = v else {
            XCTFail("\(label): expected a string")
            throw CocoaError(.coderValueNotFound)
        }
        return s
    }

    func testSigningInputPins() throws {
        let path = Self.vectorsDir.appendingPathComponent("signing-input.json")
        let doc = try loadJSON(path)
        let meta = try XCTUnwrap(doc["meta"] as? [String: Any], "meta")
        let capsuleRef = try XCTUnwrap(meta["capsule_ref"] as? String, "meta.capsule_ref")
        let refDoc = try loadJSON(Self.vectorsDir.appendingPathComponent(capsuleRef))
        let b64 = try XCTUnwrap(refDoc["capsule_bytes_b64"] as? String, "capsule_bytes_b64")
        let capsuleBytes = try XCTUnwrap(Data(base64Encoded: b64), "base64 decode")
        let parsed = try CapsuleReader.parse(capsuleBytes)

        // capsule_id = SHA-256(domain || originator_pub_raw || first_event_hash_raw)
        let cid = try XCTUnwrap(doc["capsule_id"] as? [String: Any], "capsule_id")
        let domainHex = try XCTUnwrap(cid["domain_hex"] as? String)
        let domainUtf8 = try XCTUnwrap(cid["domain_utf8"] as? String)
        XCTAssertEqual(Bytes.toHex(Data(domainUtf8.utf8)), domainHex,
                       "capsule_id domain_utf8 / domain_hex disagree")
        let origPubHex = try XCTUnwrap(cid["originator_public_key_hex"] as? String)
        let firstHashHex = try XCTUnwrap(cid["first_event_hash_hex"] as? String)
        let preimage = Bytes.concat(
            try Bytes.fromHexThrowing(domainHex),
            try Bytes.fromHexThrowing(origPubHex),
            try Bytes.fromHexThrowing(firstHashHex)
        )
        let derived = Hash.sha256Hex(preimage)
        XCTAssertEqual(derived, try XCTUnwrap(cid["capsule_id_hex"] as? String))
        XCTAssertEqual(derived, try str(lookup(parsed.manifest, ["id"]), "manifest.id"))
        XCTAssertEqual(origPubHex,
                       try str(lookup(parsed.manifest, ["originator", "public_key"]),
                               "manifest.originator.public_key"))
        XCTAssertEqual(firstHashHex,
                       try str(lookup(parsed.manifest, ["first_event_hash"]),
                               "manifest.first_event_hash"))

        // events: hash = SHA-256(prev_hash_raw || JCS(event minus hash))
        let pins = try XCTUnwrap(doc["events"] as? [[String: Any]], "events")
        XCTAssertEqual(pins.count, parsed.events.count, "event count mismatch")
        for (pin, event) in zip(pins, parsed.events) {
            guard case .object(let pairs) = event else {
                XCTFail("event is not an object"); continue
            }
            let storedHash = try str(pairs.first(where: { $0.0 == "hash" })?.1, "event.hash")
            let withoutHash = pairs.filter { $0.0 != "hash" }
            let canon = try JCS.bytes(.object(withoutHash))
            XCTAssertEqual(Bytes.toHex(canon),
                           try XCTUnwrap(pin["canonical_bytes_hex"] as? String),
                           "event canonical bytes mismatch")
            let prevHex = try XCTUnwrap(pin["prev_hash_hex"] as? String)
            XCTAssertEqual(try str(pairs.first(where: { $0.0 == "prev_hash" })?.1, "prev_hash"),
                           prevHex)
            let recomputed = Hash.sha256Hex(
                Bytes.concat(try Bytes.fromHexThrowing(prevHex), canon)
            )
            XCTAssertEqual(recomputed, try XCTUnwrap(pin["hash_hex"] as? String))
            XCTAssertEqual(recomputed, storedHash, "hash_hex != stored event hash")
        }

        // manifest_hash = SHA-256(JCS(manifest))
        let manifestPin = try XCTUnwrap(doc["manifest"] as? [String: Any], "manifest")
        let manifestCanon = try JCS.bytes(parsed.manifest)
        XCTAssertEqual(Bytes.toHex(manifestCanon),
                       try XCTUnwrap(manifestPin["canonical_bytes_hex"] as? String))
        let manifestSha = Hash.sha256Hex(manifestCanon)
        XCTAssertEqual(manifestSha, try XCTUnwrap(manifestPin["sha256_hex"] as? String))
        XCTAssertEqual(manifestSha,
                       try str(lookup(parsed.envelope, ["manifest_hash"]),
                               "envelope.manifest_hash"))

        // content_index_hash = SHA-256(JCS(content_index.files))
        let indexPin = try XCTUnwrap(doc["content_index"] as? [String: Any], "content_index")
        let filesValue = try XCTUnwrap(lookup(parsed.manifest, ["content_index", "files"]),
                                       "manifest.content_index.files")
        let indexCanon = try JCS.bytes(filesValue)
        XCTAssertEqual(Bytes.toHex(indexCanon),
                       try XCTUnwrap(indexPin["canonical_bytes_hex"] as? String))
        let indexSha = Hash.sha256Hex(indexCanon)
        XCTAssertEqual(indexSha, try XCTUnwrap(indexPin["sha256_hex"] as? String))
        XCTAssertEqual(indexSha,
                       try str(lookup(parsed.envelope, ["content_index_hash"]),
                               "envelope.content_index_hash"))

        // envelope canonical payload + per-role signing input + signature
        let envPin = try XCTUnwrap(doc["envelope"] as? [String: Any], "envelope")
        let envCanon = try Envelope.canonicalPayload(parsed.envelope)
        let canonicalPayloadHex = try XCTUnwrap(envPin["canonical_payload_hex"] as? String)
        XCTAssertEqual(Bytes.toHex(envCanon), canonicalPayloadHex)
        XCTAssertEqual(Hash.sha256Hex(envCanon),
                       try XCTUnwrap(envPin["canonical_payload_sha256"] as? String))

        let signerPins = try XCTUnwrap(envPin["signers"] as? [[String: Any]], "envelope.signers")
        guard case .object(let envPairs) = parsed.envelope,
              case .array(let storedSigners)? = envPairs.first(where: { $0.0 == "signers" })?.1
        else {
            XCTFail("envelope.signers missing"); return
        }
        XCTAssertEqual(signerPins.count, storedSigners.count, "signer count mismatch")
        for (pin, stored) in zip(signerPins, storedSigners) {
            guard case .object(let sp) = stored else { XCTFail("signer not an object"); continue }
            let role = try XCTUnwrap(pin["role"] as? String)
            XCTAssertEqual(role, try str(sp.first(where: { $0.0 == "role" })?.1, "signer.role"))
            let pkHex = try XCTUnwrap(pin["public_key_hex"] as? String)
            XCTAssertEqual(pkHex,
                           try str(sp.first(where: { $0.0 == "public_key" })?.1,
                                   "signer.public_key"))
            let sigHex = try XCTUnwrap(pin["signature_hex"] as? String)
            XCTAssertEqual(sigHex,
                           try str(sp.first(where: { $0.0 == "signature" })?.1,
                                   "signer.signature"))
            let pinDomainHex = try XCTUnwrap(pin["domain_hex"] as? String)
            let pinDomainUtf8 = try XCTUnwrap(pin["domain_utf8"] as? String)
            XCTAssertEqual(Bytes.toHex(Data(pinDomainUtf8.utf8)), pinDomainHex,
                           "signer domain_utf8 / domain_hex disagree")
            let input = try Envelope.signingInput(parsed.envelope, role: role)
            let domain = try Bytes.fromHexThrowing(pinDomainHex)
            XCTAssertEqual(Bytes.toHex(input.prefix(domain.count)), pinDomainHex,
                           "signing input does not start with domain bytes")
            XCTAssertEqual(Bytes.toHex(input.dropFirst(domain.count)), canonicalPayloadHex,
                           "signing input does not end with canonical payload")
            XCTAssertEqual(Hash.sha256Hex(input),
                           try XCTUnwrap(pin["signing_input_sha256"] as? String))
            XCTAssertTrue(
                Ed25519.verify(publicKey: try Bytes.fromHexThrowing(pkHex),
                               message: input,
                               signature: try Bytes.fromHexThrowing(sigHex)),
                "pinned signature must verify over reconstructed signing input"
            )
        }
    }
}
