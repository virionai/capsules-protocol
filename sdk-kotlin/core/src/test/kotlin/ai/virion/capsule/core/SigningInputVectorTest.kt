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

package ai.virion.capsule.core

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SigningInputVectorTest {

    private fun lookup(v: JCSValue, path: List<String>): JCSValue? {
        var cur: JCSValue = v
        for (k in path) {
            val obj = cur as? JCSValue.Obj ?: return null
            cur = obj.pairs.firstOrNull { it.first == k }?.second ?: return null
        }
        return cur
    }

    private fun str(v: JCSValue?, label: String): String =
        (v as? JCSValue.Str)?.v ?: error("$label: expected a string")

    @Test
    fun signingInputPins() {
        val file = File(vectorsDir(), "signing-input.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val capsuleRef = doc.getAsJsonObject("meta").get("capsule_ref").asString
        val refDoc = JsonParser
            .parseString(File(vectorsDir(), capsuleRef).readText()).asJsonObject
        val capsuleBytes = Base64.getDecoder().decode(refDoc.get("capsule_bytes_b64").asString)
        val parsed = CapsuleReader.parse(capsuleBytes)

        // capsule_id = SHA-256(domain || originator_pub_raw || first_event_hash_raw)
        val cid = doc.getAsJsonObject("capsule_id")
        val domainHex = cid.get("domain_hex").asString
        assertEquals(
            domainHex,
            CapsuleCrypto.bytesToHex(cid.get("domain_utf8").asString.toByteArray(Charsets.UTF_8)),
            "capsule_id domain_utf8 / domain_hex disagree",
        )
        val derived = CapsuleCrypto.sha256Hex(
            CapsuleCrypto.concat(
                CapsuleCrypto.hexToBytes(domainHex),
                CapsuleCrypto.hexToBytes(cid.get("originator_public_key_hex").asString),
                CapsuleCrypto.hexToBytes(cid.get("first_event_hash_hex").asString),
            ),
        )
        assertEquals(cid.get("capsule_id_hex").asString, derived)
        assertEquals(str(lookup(parsed.manifest, listOf("id")), "manifest.id"), derived)
        assertEquals(
            cid.get("originator_public_key_hex").asString,
            str(
                lookup(parsed.manifest, listOf("originator", "public_key")),
                "manifest.originator.public_key",
            ),
        )
        assertEquals(
            cid.get("first_event_hash_hex").asString,
            str(lookup(parsed.manifest, listOf("first_event_hash")), "manifest.first_event_hash"),
        )

        // events: hash = SHA-256(prev_hash_raw || JCS(event minus hash))
        val pins = doc.getAsJsonArray("events")
        assertEquals(pins.size(), parsed.events.size, "event count mismatch")
        for ((pinEl, event) in pins.zip(parsed.events)) {
            val pin = pinEl.asJsonObject
            val pairs = (event as JCSValue.Obj).pairs
            val storedHash = str(pairs.firstOrNull { it.first == "hash" }?.second, "event.hash")
            val withoutHash = pairs.filter { it.first != "hash" }
            val canon = JCS.bytes(JCSValue.Obj(withoutHash))
            assertEquals(
                pin.get("canonical_bytes_hex").asString,
                CapsuleCrypto.bytesToHex(canon),
                "event ${pin.get("seq")} canonical bytes mismatch",
            )
            val prevHex = pin.get("prev_hash_hex").asString
            assertEquals(
                prevHex,
                str(pairs.firstOrNull { it.first == "prev_hash" }?.second, "event.prev_hash"),
            )
            val recomputed = CapsuleCrypto.sha256Hex(
                CapsuleCrypto.concat(CapsuleCrypto.hexToBytes(prevHex), canon),
            )
            assertEquals(pin.get("hash_hex").asString, recomputed)
            assertEquals(storedHash, recomputed, "hash_hex != stored event hash")
        }

        // manifest_hash = SHA-256(JCS(manifest))
        val manifestPin = doc.getAsJsonObject("manifest")
        val manifestCanon = JCS.bytes(parsed.manifest)
        assertEquals(
            manifestPin.get("canonical_bytes_hex").asString,
            CapsuleCrypto.bytesToHex(manifestCanon),
        )
        val manifestSha = CapsuleCrypto.sha256Hex(manifestCanon)
        assertEquals(manifestPin.get("sha256_hex").asString, manifestSha)
        assertEquals(
            manifestSha,
            str(lookup(parsed.envelope, listOf("manifest_hash")), "envelope.manifest_hash"),
        )

        // content_index_hash = SHA-256(JCS(content_index.files))
        val indexPin = doc.getAsJsonObject("content_index")
        val filesValue = lookup(parsed.manifest, listOf("content_index", "files"))
            ?: error("manifest.content_index.files missing")
        val indexCanon = JCS.bytes(filesValue)
        assertEquals(
            indexPin.get("canonical_bytes_hex").asString,
            CapsuleCrypto.bytesToHex(indexCanon),
        )
        val indexSha = CapsuleCrypto.sha256Hex(indexCanon)
        assertEquals(indexPin.get("sha256_hex").asString, indexSha)
        assertEquals(
            indexSha,
            str(
                lookup(parsed.envelope, listOf("content_index_hash")),
                "envelope.content_index_hash",
            ),
        )

        // envelope canonical payload = JCS(envelope minus signers); signing
        // input per role = domain_sep_bytes || canonical_payload_bytes.
        val envPin = doc.getAsJsonObject("envelope")
        val envPairs = (parsed.envelope as JCSValue.Obj).pairs
        val envCanon = JCS.bytes(JCSValue.Obj(envPairs.filter { it.first != "signers" }))
        val canonicalPayloadHex = envPin.get("canonical_payload_hex").asString
        assertEquals(canonicalPayloadHex, CapsuleCrypto.bytesToHex(envCanon))
        assertEquals(
            envPin.get("canonical_payload_sha256").asString,
            CapsuleCrypto.sha256Hex(envCanon),
        )

        val signerPins = envPin.getAsJsonArray("signers")
        val storedSigners = (envPairs.firstOrNull { it.first == "signers" }?.second
            as? JCSValue.Arr)?.items ?: error("envelope.signers missing")
        assertEquals(signerPins.size(), storedSigners.size, "signer count mismatch")
        for ((pinEl, stored) in signerPins.zip(storedSigners)) {
            val pin: JsonObject = pinEl.asJsonObject
            val sp = (stored as JCSValue.Obj).pairs
            val role = pin.get("role").asString
            assertEquals(role, str(sp.firstOrNull { it.first == "role" }?.second, "signer.role"))
            val pkHex = pin.get("public_key_hex").asString
            assertEquals(
                pkHex,
                str(sp.firstOrNull { it.first == "public_key" }?.second, "signer.public_key"),
            )
            val sigHex = pin.get("signature_hex").asString
            assertEquals(
                sigHex,
                str(sp.firstOrNull { it.first == "signature" }?.second, "signer.signature"),
            )
            val pinDomainHex = pin.get("domain_hex").asString
            assertEquals(
                pinDomainHex,
                CapsuleCrypto.bytesToHex(
                    pin.get("domain_utf8").asString.toByteArray(Charsets.UTF_8),
                ),
                "signer domain_utf8 / domain_hex disagree",
            )
            val input = Envelope.signingInput(parsed.envelope, role)
            val domain = CapsuleCrypto.hexToBytes(pinDomainHex)
            assertEquals(
                pinDomainHex,
                CapsuleCrypto.bytesToHex(input.sliceArray(0 until domain.size)),
                "signing input does not start with domain bytes",
            )
            assertEquals(
                canonicalPayloadHex,
                CapsuleCrypto.bytesToHex(input.sliceArray(domain.size until input.size)),
                "signing input does not end with canonical payload",
            )
            assertEquals(pin.get("signing_input_sha256").asString, CapsuleCrypto.sha256Hex(input))
            assertTrue(
                CapsuleCrypto.ed25519Verify(
                    CapsuleCrypto.hexToBytes(pkHex),
                    input,
                    CapsuleCrypto.hexToBytes(sigHex),
                ),
                "pinned signature must verify over reconstructed signing input",
            )
        }
    }

    companion object {
        /** Walk up from the gradle module dir until we find spec/vectors. */
        private fun repoRoot(): File {
            var p: File? = File(System.getProperty("user.dir")).absoluteFile
            while (p != null) {
                if (File(p, "spec/vectors/signing-input.json").exists()) return p
                p = p.parentFile
            }
            error(
                "could not locate repo root containing spec/vectors/signing-input.json " +
                    "starting from ${System.getProperty("user.dir")}",
            )
        }

        private fun vectorsDir(): File = File(repoRoot(), "spec/vectors")
    }
}
