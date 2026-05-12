// CapsuleReader — open a sealed plain capsule, parse manifest/envelope/
// chain/program.md/agents.md, and surface its files map. Verification
// lives in CapsuleVerifier; reader is just structured access.

package ai.virion.capsule.core

import com.google.gson.JsonElement
import com.google.gson.JsonParser

data class ParsedCapsule(
    val manifest: JCSValue,
    val envelope: JCSValue,
    val events: List<JCSValue>,
    val programMd: String,
    val agentsMd: String?,
    val files: Map<String, ByteArray>,
)

data class VerifyCheck(val name: String, val ok: Boolean, val detail: String = "")

object CapsuleReader {

    fun parse(bytes: ByteArray): ParsedCapsule {
        val entries = CapsuleZip.unpack(bytes)
        val files = entries.toMap()
        val manifestBytes = files["manifest.json"]
            ?: throw CapsuleException("missing manifest.json")
        val envelopeBytes = files["provenance/envelope.json"]
            ?: throw CapsuleException("missing envelope")
        val eventsBytes = files["chain/events.jsonl"]
            ?: throw CapsuleException("missing chain")
        val programBytes = files["program.md"]
            ?: throw CapsuleException("missing program.md")

        val manifest = parseJson(manifestBytes)
        val envelope = parseJson(envelopeBytes)
        val events = String(eventsBytes, Charsets.UTF_8)
            .split('\n').filter { it.isNotEmpty() }
            .map { parseJson(it.toByteArray(Charsets.UTF_8)) }
        val programMd = String(programBytes, Charsets.UTF_8)
        val agentsMd = files["agents.md"]?.let { String(it, Charsets.UTF_8) }

        val encryption = (manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "encryption" }?.second
        if (encryption != null && encryption != JCSValue.Null) {
            throw CapsuleException("encrypted capsule; v0 reader supports plain only")
        }
        return ParsedCapsule(manifest, envelope, events, programMd, agentsMd, files)
    }

    /// Walk a JCSValue object tree by string keys; returns the leaf
    /// string if the path resolves to a `.string`, else null.
    fun lookupString(v: JCSValue, path: List<String>): String? {
        var cur: JCSValue = v
        for (k in path) {
            val obj = cur as? JCSValue.Obj ?: return null
            cur = obj.pairs.firstOrNull { it.first == k }?.second ?: return null
        }
        return (cur as? JCSValue.Str)?.v
    }

    /** Parse JSON bytes via Gson, then convert to JCSValue keeping insertion order. */
    fun parseJson(bytes: ByteArray): JCSValue =
        convert(JsonParser.parseString(String(bytes, Charsets.UTF_8)))

    private fun convert(e: JsonElement): JCSValue {
        if (e.isJsonNull) return JCSValue.Null
        if (e.isJsonPrimitive) {
            val p = e.asJsonPrimitive
            return when {
                p.isBoolean -> JCSValue.Bool(p.asBoolean)
                p.isString -> JCSValue.Str(p.asString)
                p.isNumber -> {
                    val n = p.asNumber.toString()
                    if (n.contains('.') || n.contains('e') || n.contains('E'))
                        JCSValue.Decimal(p.asDouble)
                    else JCSValue.Integer(p.asLong)
                }
                else -> JCSValue.Null
            }
        }
        if (e.isJsonArray) return JCSValue.Arr(e.asJsonArray.map { convert(it) })
        if (e.isJsonObject) {
            return JCSValue.Obj(e.asJsonObject.entrySet().map { it.key to convert(it.value) })
        }
        return JCSValue.Null
    }
}
