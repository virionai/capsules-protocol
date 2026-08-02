// Vector-driven check that Ed25519 verification refuses small-order and
// non-canonically encoded public keys and non-reduced signature S values,
// per spec/vectors/ed25519-key-validation.json.
//
// BouncyCastle's Ed25519.implVerify already applies checkPointFullVar to
// the public key (rejecting y = 0, y = 1, y >= p, and the order-8 points)
// and Scalar25519.checkVar to S (requiring S < L), so this lane needs no
// guard of its own — this test pins that behaviour so a provider or
// version change cannot silently reopen the hole.
//
// Mirrors the JS reference lane (tools/check-spec-vectors.mjs), the Python
// test_ed25519_key_validation_registry, the Rust
// ed25519_key_validation_registry, and the Swift Ed25519KeyValidationTests.

package ai.virion.capsule.core

import com.google.gson.JsonParser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Ed25519KeyValidationVectorTest {

    @Test
    fun keyValidationMatchesSpecVectors() {
        val doc = JsonParser.parseString(vectorsFile().readText()).asJsonObject
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "vector file is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val reason = v.get("reason").asString
            val expected = v.getAsJsonObject("expected").get("valid").asBoolean
            val got = CapsuleCrypto.ed25519Verify(
                CapsuleCrypto.hexToBytes(v.get("public_key_hex").asString),
                CapsuleCrypto.hexToBytes(v.get("message_hex").asString),
                CapsuleCrypto.hexToBytes(v.get("signature_hex").asString),
            )
            assertEquals(expected, got, "$name: expected valid=$expected ($reason)")
        }
    }

    private fun vectorsFile(): File {
        var p: File? = File(System.getProperty("user.dir")).absoluteFile
        while (p != null) {
            val f = File(p, "spec/vectors/ed25519-key-validation.json")
            if (f.exists()) return f
            p = p.parentFile
        }
        error(
            "spec/vectors/ed25519-key-validation.json not found above " +
                System.getProperty("user.dir")
        )
    }
}
