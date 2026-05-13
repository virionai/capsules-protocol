// Regression tests for the envelope signing-input domain separator.
//
// Per spec/envelope.md, the domain separator MUST be:
//     utf8("capsule-provenance-v0.6:" + role + "\x00")
// where "\x00" is a literal NUL byte (0x00), NOT a space.
//
// Interop with the JS, Python, Swift, and Rust implementations depends on
// this byte being exactly 0x00. A bug in this SDK (using a space instead of
// NUL) would make Kotlin-signed envelopes unverifiable elsewhere.

package ai.virion.capsule.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EnvelopeTest {
    private val hex64 = "0".repeat(64)

    private fun minimalEnvelope(): JCSValue = JCSValue.Obj(listOf(
        "version" to JCSValue.Str("0.6"),
        "capsule_id" to JCSValue.Str(hex64),
        "first_event_hash" to JCSValue.Str(hex64),
        "entry_hash" to JCSValue.Str(hex64),
        "manifest_hash" to JCSValue.Str(hex64),
        "content_index_hash" to JCSValue.Str(hex64),
        "encrypted_blob_hash" to JCSValue.Null,
        "cipher" to JCSValue.Str("none"),
        "signed_at" to JCSValue.Str("2026-05-07T12:00:00Z"),
        "signers" to JCSValue.Arr(emptyList()),
    ))

    @Test
    fun signingInputPrefixMatchesSpecDomainSeparator() {
        val envelope = minimalEnvelope()
        val input = Envelope.signingInput(envelope, role = "originator")

        // Spec: utf8("capsule-provenance-v0.6:" + role + "\x00")
        val expectedPrefix = "capsule-provenance-v0.6:originator\u0000".toByteArray(Charsets.UTF_8)

        assertTrue(
            input.size >= expectedPrefix.size,
            "signing input shorter than domain separator prefix: ${input.size} < ${expectedPrefix.size}",
        )
        val actualPrefix = input.sliceArray(0 until expectedPrefix.size)
        assertEquals(
            expectedPrefix.toList(),
            actualPrefix.toList(),
            "domain separator prefix does not match spec",
        )
    }

    @Test
    fun byteAfterRoleIsNulNotSpace() {
        // "capsule-provenance-v0.6:" is 24 bytes; "originator" is 10 bytes.
        // The byte at index 34 is the terminator that follows the role.
        // Spec requires 0x00 (NUL). The historical bug used 0x20 (SPACE).
        val envelope = minimalEnvelope()
        val input = Envelope.signingInput(envelope, role = "originator")

        assertTrue(input.size > 34, "signing input too short to contain terminator byte")
        assertEquals(
            0x00.toByte(),
            input[34],
            "byte after role must be NUL (0x00), not 0x${"%02x".format(input[34].toInt() and 0xff)}",
        )
    }
}
