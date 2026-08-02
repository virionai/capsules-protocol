package ai.virion.capsule.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * I-JSON acceptance boundary (spec/canonicalization.md).
 *
 * This lane's exposure is the worst of the five: a Java String can hold an
 * unpaired surrogate, and toByteArray(UTF_8) replaces it with '?' rather
 * than throwing, so the capsule hashed different bytes with no error at all.
 */
class IJsonAcceptanceTest {

    @Test
    fun rejectsPlainIntegerLiteralOutsideExactRange() {
        // A nanosecond timestamp: plausible payload, 19 digits.
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Decimal(1.7e18))
        }
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Decimal(1e19))
        }
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Integer(9007199254740992L))
        }
        // canonical() is the backstop: it must refuse the same value even if
        // a caller skipped the gate.
        assertFailsWith<IllegalArgumentException> {
            JCS.canonical(JCSValue.Decimal(1e19))
        }
    }

    @Test
    fun acceptsExactRangeBoundaryAndExponentForm() {
        JCS.assertAcceptable(JCSValue.Integer(9007199254740991L))
        JCS.assertAcceptable(JCSValue.Decimal(9007199254740991.0))
        JCS.assertAcceptable(JCSValue.Decimal(1e21))
        assertEquals("1e+21", JCS.canonical(JCSValue.Decimal(1e21)))
        JCS.assertAcceptable(JCSValue.Decimal(1.5))
    }

    @Test
    fun messageNamesTheOffendingPath() {
        val value = jobj("payload" to jobj("ts_ns" to JCSValue.Decimal(1.7e18)))
        val error = assertFailsWith<IllegalArgumentException> { JCS.assertAcceptable(value) }
        assertTrue(
            error.message!!.contains("\$.payload.ts_ns"),
            "message must name the path: ${error.message}",
        )
    }

    @Test
    fun rejectsUnpairedSurrogatesInValuesAndKeys() {
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Str("a\uD83D"))
        }
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(JCSValue.Str("\uDC00b"))
        }
        assertFailsWith<IllegalArgumentException> {
            JCS.assertAcceptable(jobj("k\uD800" to JCSValue.Integer(1L)))
        }
    }

    @Test
    fun canonicalRefusesRatherThanSubstitutingAQuestionMark() {
        // Without the guard this produced {"s":"a?"} — a different hash and
        // no error whatsoever.
        assertFailsWith<IllegalArgumentException> {
            JCS.bytes(jobj("s" to JCSValue.Str("a\uD83D")))
        }
    }

    @Test
    fun acceptsWellFormedAstralPair() {
        val bytes = JCS.bytes(jobj("s" to JCSValue.Str("a🙂")))
        assertEquals("{\"s\":\"a🙂\"}", String(bytes, Charsets.UTF_8))
    }

    @Test
    fun parseJsonRefusesAnOutOfRangeIntegerLiteral() {
        val text = """{"payload":{"ts":10000000000000000000}}"""
        assertFailsWith<IllegalArgumentException> {
            CapsuleReader.parseJson(text.toByteArray(Charsets.UTF_8))
        }
    }

    @Test
    fun parseJsonRefusesALoneSurrogateEscape() {
        // Gson accepts the escape and hands back a lone surrogate; the gate
        // is what stops it reaching a hash.
        val text = """{"s":"x\ud83d"}"""
        assertFailsWith<IllegalArgumentException> {
            CapsuleReader.parseJson(text.toByteArray(Charsets.UTF_8))
        }
    }
}
