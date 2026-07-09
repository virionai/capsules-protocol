// JCS — RFC 8785 canonicalization. Mirrors the JavaScript reference SDK.
//
// Object keys sorted by code-unit order. Numbers via shortest-roundtrip,
// rejecting NaN/Infinity. Strings escape RFC 8259 mandatory chars and
// U+0000..U+001F. Arrays preserve insertion order.

package ai.virion.capsule.core

import java.math.BigDecimal
import java.math.BigInteger
import java.math.MathContext
import java.math.RoundingMode

sealed class JCSValue {
    object Null : JCSValue()
    data class Bool(val v: Boolean) : JCSValue()
    data class Integer(val v: Long) : JCSValue()
    data class Decimal(val v: Double) : JCSValue()
    data class Str(val v: String) : JCSValue()
    data class Arr(val items: List<JCSValue>) : JCSValue()
    /** Pairs preserved in insertion order; sorted by key at serialize time. */
    data class Obj(val pairs: List<Pair<String, JCSValue>>) : JCSValue()
}

object JCS {
    fun canonical(v: JCSValue): String = when (v) {
        is JCSValue.Null -> "null"
        is JCSValue.Bool -> if (v.v) "true" else "false"
        is JCSValue.Integer -> {
            require(Math.abs(v.v) <= MAX_SAFE_INTEGER) {
                "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1); " +
                    "not representable identically across implementations"
            }
            v.v.toString()
        }
        is JCSValue.Decimal -> {
            require(v.v.isFinite()) { "JCS: non-finite number" }
            serializeNumber(v.v)
        }
        is JCSValue.Str -> encodeString(v.v)
        is JCSValue.Arr -> v.items.joinToString(",", "[", "]") { canonical(it) }
        is JCSValue.Obj -> v.pairs
            .sortedBy { it.first }
            .joinToString(",", "{", "}") {
                encodeString(it.first) + ":" + canonical(it.second)
            }
    }

    fun bytes(v: JCSValue): ByteArray = canonical(v).toByteArray(Charsets.UTF_8)

    private const val MAX_SAFE_INTEGER = (1L shl 53) - 1

    /**
     * RFC 8785 §3.2.2.3: serialize per ECMAScript Number::toString
     * (ECMA-262 §7.1.12.1).
     *
     * Deliberately does NOT use Double.toString(): its digit selection
     * differs across runtimes (pre-JDK-19 JVMs and Android ART do not
     * produce ECMAScript's shortest-round-trip digits, and emit
     * uppercase-E scientific notation at different thresholds). Digits
     * are instead derived runtime-independently from the IEEE-754 bits
     * via exact BigDecimal arithmetic: the shortest digit string whose
     * parsed value round-trips to the same double, with ECMAScript's
     * closest-then-even tie-break.
     */
    internal fun serializeNumber(v: Double): String {
        if (v == 0.0) return "0" // covers -0.0: JCS serializes negative zero as "0"
        val negative = v < 0
        val (digits, pointPos) = shortestDigits(Math.abs(v))
        val k = digits.length
        val out = when {
            pointPos in k..21 -> digits + "0".repeat(pointPos - k)
            pointPos in 1..21 -> digits.substring(0, pointPos) + "." + digits.substring(pointPos)
            pointPos in -5..0 -> "0." + "0".repeat(-pointPos) + digits
            else -> {
                val e = pointPos - 1
                val head = if (k > 1) digits[0] + "." + digits.substring(1) else digits
                head + "e" + (if (e >= 0) "+" else "-") + Math.abs(e)
            }
        }
        return if (negative) "-$out" else out
    }

    /**
     * Shortest significant digits d1..dk and n such that
     * value == 0.d1..dk × 10^n, per ECMAScript digit selection: the
     * digit string must lie strictly inside the double's rounding
     * interval (inclusive when the mantissa is even, matching
     * round-half-even parsing); among equally short candidates prefer
     * the closest to the exact value, then the even final digit.
     */
    private fun shortestDigits(v: Double): Pair<String, Int> {
        val bits = java.lang.Double.doubleToLongBits(v)
        val biasedExp = ((bits ushr 52) and 0x7FF).toInt()
        val m52 = bits and 0xFFFFFFFFFFFFFL
        val f: Long
        val e: Int
        if (biasedExp == 0) { // subnormal
            f = m52
            e = -1074
        } else {
            f = m52 or (1L shl 52)
            e = biasedExp - 1075
        }

        // Exact value of mant × 2^exp as a BigDecimal (powers of two
        // always terminate in decimal, so division below is exact).
        fun exact(mant: BigInteger, exp: Int): BigDecimal =
            if (exp >= 0) BigDecimal(mant.shiftLeft(exp))
            else BigDecimal(mant).divide(BigDecimal(BigInteger.ONE.shiftLeft(-exp)))

        val x = exact(BigInteger.valueOf(f), e)
        // Half-gap to the successor is 2^(e-1); same to the predecessor,
        // except at a power-of-two boundary where the gap below halves.
        val highDelta = exact(BigInteger.ONE, e - 1)
        val lowDelta =
            if (m52 == 0L && biasedExp > 1) exact(BigInteger.ONE, e - 2) else highDelta
        val low = x.subtract(lowDelta)
        val high = x.add(highDelta)
        val inclusive = (f and 1L) == 0L

        fun inInterval(c: BigDecimal): Boolean =
            if (inclusive) c >= low && c <= high else c > low && c < high

        for (p in 1..17) {
            // The only p-digit decimals that can sit inside the rounding
            // interval are the two bracketing x.
            val floor = x.round(MathContext(p, RoundingMode.FLOOR))
            val ceil = x.round(MathContext(p, RoundingMode.CEILING))
            val valid = listOf(floor, ceil).distinct().filter { inInterval(it) }
            if (valid.isEmpty()) continue
            val chosen = if (valid.size == 1) valid[0] else {
                val dFloor = x.subtract(valid[0]).abs()
                val dCeil = valid[1].subtract(x).abs()
                val cmp = dFloor.compareTo(dCeil)
                when {
                    cmp < 0 -> valid[0]
                    cmp > 0 -> valid[1]
                    else -> if (lastSignificantDigitEven(valid[0])) valid[0] else valid[1]
                }
            }
            val stripped = chosen.stripTrailingZeros()
            val digits = stripped.unscaledValue().abs().toString()
            return Pair(digits, digits.length - stripped.scale())
        }
        throw IllegalStateException("JCS: no round-trip digits within 17 significant digits")
    }

    private fun lastSignificantDigitEven(c: BigDecimal): Boolean {
        val digits = c.stripTrailingZeros().unscaledValue().abs().toString()
        return (digits.last() - '0') % 2 == 0
    }

    private fun encodeString(s: String): String {
        val out = StringBuilder(s.length + 2)
        out.append('"')
        for (c in s) {
            when (val code = c.code) {
                0x22 -> out.append("\\\"")
                0x5C -> out.append("\\\\")
                0x08 -> out.append("\\b")
                0x0C -> out.append("\\f")
                0x0A -> out.append("\\n")
                0x0D -> out.append("\\r")
                0x09 -> out.append("\\t")
                in 0..0x1F -> out.append("\\u").append(String.format("%04x", code))
                else -> out.append(c)
            }
        }
        out.append('"')
        return out.toString()
    }
}

// Convenience builders
fun jobj(vararg pairs: Pair<String, JCSValue>) = JCSValue.Obj(pairs.toList())
fun jarr(vararg items: JCSValue) = JCSValue.Arr(items.toList())
fun jarr(items: List<JCSValue>) = JCSValue.Arr(items)
fun jstr(s: String?) = if (s == null) JCSValue.Null else JCSValue.Str(s)
fun jint(i: Long?) = if (i == null) JCSValue.Null else JCSValue.Integer(i)
fun jint(i: Int?) = if (i == null) JCSValue.Null else JCSValue.Integer(i.toLong())
fun jnum(d: Double?) = if (d == null) JCSValue.Null else JCSValue.Decimal(d)
fun jbool(b: Boolean?) = if (b == null) JCSValue.Null else JCSValue.Bool(b)
