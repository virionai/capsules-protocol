package ai.virion.capsule.core

import com.google.gson.JsonParser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Vector-driven check that number serialization matches the normative
 * JCS vectors in spec/vectors/jcs-numbers.json (Node JSON.stringify is
 * the oracle). Inputs are IEEE-754 bit patterns so no JSON parser sits
 * between the vector and the value under test.
 */
class JcsNumbersVectorTest {

    @Test
    fun numbersMatchSpecVectors() {
        val doc = JsonParser.parseString(vectorsFile().readText()).asJsonObject
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "vector file is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val hex = v.get("ieee_hex").asString
            val expected = v.get("expected").asString
            val bits = java.lang.Long.parseUnsignedLong(hex, 16)
            val value = java.lang.Double.longBitsToDouble(bits)
            if (v.has("accepted") && !v.get("accepted").asBoolean) {
                // Outside the I-JSON acceptance boundary
                // (spec/canonicalization.md): "expected" documents the
                // Number::toString layout, but the value must be refused.
                assertFailsWith<IllegalArgumentException>(
                    "bits $hex (would serialize as $expected) must be rejected"
                ) { JCS.assertAcceptable(JCSValue.Decimal(value)) }
                continue
            }
            assertEquals(expected, JCS.canonical(JCSValue.Decimal(value)), "bits $hex")
        }
    }

    private fun vectorsFile(): File {
        var p: File? = File(System.getProperty("user.dir")).absoluteFile
        while (p != null) {
            val f = File(p, "spec/vectors/jcs-numbers.json")
            if (f.exists()) return f
            p = p.parentFile
        }
        error("spec/vectors/jcs-numbers.json not found above ${System.getProperty("user.dir")}")
    }
}
