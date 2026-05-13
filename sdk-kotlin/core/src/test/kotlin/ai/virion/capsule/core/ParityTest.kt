// Cross-implementation parity tests against the JS reference's
// tamper-detection corpus.
//
// Mirrors sdk-py/tests/test_parity_jssdk.py. The JS SDK's
// examples/tamper-detection/build.mjs produces six fixtures; this file
// drives the Kotlin verifier against the four plain ones plus the
// encrypted tamper case.
//
// These are the tests that catch cross-SDK divergence — exactly the
// class of bug the historical Envelope.kt domain-separator issue was
// (Kotlin signed with a space while JS signed with NUL, so any
// JS-produced capsule would have silently failed Kotlin verification).
// `jsCleanCapsuleVerifiesUnderKotlin` is the canonical regression
// catcher for that class of bug.
//
// Fixtures live at examples/tamper-detection/output/ at the repo root —
// authoritative there so every SDK shares one source of truth. They
// are committed; if they go missing, regenerate via:
//   cd examples/tamper-detection && npm install && npm run build

package ai.virion.capsule.core

import com.google.gson.JsonParser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ParityTest {

    @Test
    fun fixturesDirExists() {
        val dir = fixturesDir()
        val clean = File(dir, "clean.capsule")
        val keys = File(dir, "keys.json")
        assertTrue(
            clean.exists() && keys.exists(),
            "Tamper-detection fixtures missing at ${dir.absolutePath}. " +
                "Regenerate with: cd examples/tamper-detection && npm install && npm run build",
        )
    }

    @Test
    fun jsCleanCapsuleVerifiesUnderKotlin() {
        val bytes = File(fixturesDir(), "clean.capsule").readBytes()
        val pub = originatorPubkey()

        val v = CapsuleVerifier.verify(bytes = bytes, allowlist = setOf(pub))

        assertTrue(
            v.ok,
            "JS-produced clean capsule failed Kotlin verification: " +
                v.checks.filter { !it.ok }.joinToString { "${it.name}: ${it.detail}" },
        )
        assertEquals(1, v.trustedSignerCount, "expected one trusted signer")
        assertEquals(1, v.signers.size, "expected one signer entry")
        assertEquals("originator", v.signers.first().role, "expected originator role")
    }

    @Test
    fun jsTamperedPayloadCapsuleFailsUnderKotlin() {
        assertJsTamperedCapsuleFails("tampered-payload.capsule")
    }

    @Test
    fun jsTamperedChainCapsuleFailsUnderKotlin() {
        assertJsTamperedCapsuleFails("tampered-chain.capsule")
    }

    @Test
    fun jsTamperedEnvelopeCapsuleFailsUnderKotlin() {
        assertJsTamperedCapsuleFails("tampered-envelope.capsule")
    }

    @Test
    fun jsTamperedBlobCapsuleFailsUnderKotlin() {
        // tampered-blob.capsule is an encrypted-tamper fixture. The
        // Kotlin reader rejects encrypted capsules outright via
        // CapsuleException("encrypted capsule; v0 reader supports plain
        // only"). Either an exception OR ok=false counts as "not
        // verified", which is the spec-correct outcome for this case.
        assertJsTamperedCapsuleFails("tampered-blob.capsule")
    }

    private fun assertJsTamperedCapsuleFails(fixture: String) {
        val bytes = File(fixturesDir(), fixture).readBytes()
        val pub = originatorPubkey()

        // Tampered bytes can either yield ok=false (verifier parsed
        // successfully and detected the mismatch) or surface as an
        // exception (the tamper landed in a field the verifier eagerly
        // hex-decodes, or the capsule is encrypted and the reader
        // refuses it). Both signal "not verified".
        val verifiedOk = try {
            CapsuleVerifier.verify(bytes = bytes, allowlist = setOf(pub)).ok
        } catch (_: Throwable) {
            false
        }
        assertFalse(verifiedOk, "$fixture unexpectedly verified ok under Kotlin")
    }

    companion object {

        /** Walk up from the gradle module dir until we find the fixtures dir. */
        private fun repoRoot(): File {
            var p: File? = File(System.getProperty("user.dir")).absoluteFile
            while (p != null) {
                if (File(p, "examples/tamper-detection/output/keys.json").exists()) return p
                p = p.parentFile
            }
            error(
                "could not locate repo root containing " +
                    "examples/tamper-detection/output/keys.json " +
                    "starting from ${System.getProperty("user.dir")}",
            )
        }

        private fun fixturesDir(): File = File(repoRoot(), "examples/tamper-detection/output")

        private fun originatorPubkey(): String {
            val keysJson = File(fixturesDir(), "keys.json").readText(Charsets.UTF_8)
            val root = JsonParser.parseString(keysJson).asJsonObject
            return root.getAsJsonObject("originator").get("publicKey").asString
        }
    }
}
