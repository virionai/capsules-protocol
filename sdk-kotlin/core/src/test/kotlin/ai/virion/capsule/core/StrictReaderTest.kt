// Reader strictness against the normative container rules:
//   - spec/manifest.md: a signed PLAIN capsule may not smuggle an
//     unaccounted-for content.enc past the content index
//   - spec/format.md: duplicate entry names are rejected on the RAW stored
//     central-directory name, before any map collapse picks a winner
//   - spec/format.md: symlink entries are rejected
//
// The fixtures are the shared conformance corpus under spec/vectors/, so
// this lane refuses exactly what the JS/Python/Rust lanes refuse.

package ai.virion.capsule.core

import com.google.gson.JsonParser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StrictReaderTest {

    @Test
    fun plainCapsuleWithStrayContentEncFailsContentIndex() {
        val bytes = File(
            vectorsDir(),
            "tamper-detection/output/plain-stray-content-enc.capsule",
        ).readBytes()
        val v = CapsuleVerifier.verify(bytes = bytes, allowlist = setOf(originatorPubkey()))
        assertFalse(v.ok, "a signed plain capsule with a stray content.enc must not verify")
        val ci = v.checks.firstOrNull { it.name == "content_index_hash" }
        assertEquals(false, ci?.ok, "content_index_hash must fail; got $ci")
        assertTrue(
            ci!!.detail.contains("content.enc"),
            "content_index detail should name the stray blob; got ${ci.detail}",
        )
        // The signature itself is untouched — an attacker cannot re-sign.
        assertEquals(
            true, v.checks.firstOrNull { it.name == "envelope_signature" }?.ok,
            "envelope signature should still be valid",
        )
    }

    @Test
    fun duplicateEntryNameIsRejected() {
        val bytes = File(vectorsDir(), "malformed-layout/output/duplicate-entry.capsule").readBytes()
        val e = assertFailsWith<IllegalArgumentException> { CapsuleZip.unpack(bytes) }
        assertTrue(
            e.message!!.contains("duplicate entry"),
            "expected a duplicate-entry rejection; got ${e.message}",
        )
        assertFalse(
            CapsuleVerifier.verify(bytes).ok,
            "duplicate-entry.capsule must not verify",
        )
    }

    @Test
    fun symlinkEntryIsRejected() {
        val bytes = File(vectorsDir(), "malformed-layout/output/symlink-entry.capsule").readBytes()
        val e = assertFailsWith<IllegalArgumentException> { CapsuleZip.unpack(bytes) }
        assertTrue(
            e.message!!.contains("symlink"),
            "expected a symlink rejection; got ${e.message}",
        )
        assertFalse(
            CapsuleVerifier.verify(bytes).ok,
            "symlink-entry.capsule must not verify",
        )
    }

    companion object {

        /** Walk up from the gradle module dir until we find spec/vectors. */
        private fun repoRoot(): File {
            var p: File? = File(System.getProperty("user.dir")).absoluteFile
            while (p != null) {
                if (File(p, "spec/vectors/tamper-detection/output/keys.json").exists()) return p
                p = p.parentFile
            }
            error(
                "could not locate repo root containing " +
                    "spec/vectors/tamper-detection/output/keys.json " +
                    "starting from ${System.getProperty("user.dir")}",
            )
        }

        private fun vectorsDir(): File = File(repoRoot(), "spec/vectors")

        private fun originatorPubkey(): String {
            val keysJson = File(vectorsDir(), "tamper-detection/output/keys.json")
                .readText(Charsets.UTF_8)
            val root = JsonParser.parseString(keysJson).asJsonObject
            return root.getAsJsonObject("originator").get("publicKey").asString
        }
    }
}
