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
            ?: throw CapsuleException("missing provenance/envelope.json")

        val manifest = parseJsonFile(manifestBytes, "manifest.json")
        val envelope = parseJsonFile(envelopeBytes, "provenance/envelope.json")

        // Refuse encrypted capsules BEFORE demanding the plain-capsule
        // layout: the chain and program live inside the ciphertext, so
        // requiring them first would misattribute the refusal as
        // "missing chain".
        val encryption = (manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "encryption" }?.second
        if (encryption != null && encryption != JCSValue.Null) {
            throw CapsuleException("encrypted capsule; v0 reader supports plain only")
        }

        val eventsBytes = files["chain/events.jsonl"]
            ?: throw CapsuleException("missing chain")
        val programBytes = files["program.md"]
            ?: throw CapsuleException("missing program.md")
        val events = String(eventsBytes, Charsets.UTF_8)
            .split('\n').filter { it.isNotEmpty() }
            .map { parseJsonFile(it.toByteArray(Charsets.UTF_8), "chain/events.jsonl") }
        val programMd = String(programBytes, Charsets.UTF_8)
        val agentsMd = files["agents.md"]?.let { String(it, Charsets.UTF_8) }

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

    /** Collect `manifest.participants[].actor_id` into a lookup set. */
    fun participantActorIds(manifest: JCSValue): Set<String> {
        val obj = manifest as? JCSValue.Obj ?: return emptySet()
        val ps = obj.pairs.firstOrNull { it.first == "participants" }?.second
        val arr = ps as? JCSValue.Arr ?: return emptySet()
        val out = mutableSetOf<String>()
        for (item in arr.items) {
            val fields = (item as? JCSValue.Obj)?.pairs ?: continue
            val id = (fields.firstOrNull { it.first == "actor_id" }?.second as? JCSValue.Str)?.v
            if (id != null) out += id
        }
        return out
    }

    /**
     * [parseJson] with the offending file named in the error, so a reader
     * rejection can be attributed to a specific document (mirrors the Rust
     * verifier's "failed to parse manifest.json").
     */
    fun parseJsonFile(bytes: ByteArray, name: String): JCSValue {
        val value = try {
            convert(JsonParser.parseString(String(bytes, Charsets.UTF_8)))
        } catch (_: Exception) {
            throw CapsuleException("failed to parse $name")
        }
        // I-JSON acceptance boundary (spec/canonicalization.md). Reported in
        // its own words, NOT as "failed to parse": the JSON is syntactically
        // fine, it is the value that lies outside the canonicalization input
        // domain, and the operator must be able to tell that apart from both
        // a syntax error and a hash mismatch.
        try {
            JCS.assertAcceptable(value)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("$name: ${e.message}", e)
        }
        return value
    }

    /** Parse JSON bytes via Gson, then convert to JCSValue keeping insertion order. */
    fun parseJson(bytes: ByteArray): JCSValue {
        val value = convert(JsonParser.parseString(String(bytes, Charsets.UTF_8)))
        // I-JSON acceptance boundary (spec/canonicalization.md). Gson accepts
        // lone-surrogate escapes and oversized integer literals; neither has
        // a canonical form, so refuse before anything is hashed.
        JCS.assertAcceptable(value)
        return value
    }

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
