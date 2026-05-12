// JCS — RFC 8785 canonicalization. Mirrors medical-journal-builder.js.
//
// Object keys sorted by code-unit order. Numbers via shortest-roundtrip,
// rejecting NaN/Infinity. Strings escape RFC 8259 mandatory chars and
// U+0000..U+001F. Arrays preserve insertion order.

package ai.virion.capsule.core

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
        is JCSValue.Integer -> v.v.toString()
        is JCSValue.Decimal -> {
            require(v.v.isFinite()) { "JCS: non-finite number" }
            when {
                v.v == 0.0 -> "0"
                v.v % 1.0 == 0.0 && Math.abs(v.v) < (1L shl 53) -> v.v.toLong().toString()
                else -> v.v.toString()
            }
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
