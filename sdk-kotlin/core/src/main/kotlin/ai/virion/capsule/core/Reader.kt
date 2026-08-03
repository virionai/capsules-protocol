// CapsuleReader — open a sealed plain capsule, parse manifest/envelope/
// chain/program.md/agents.md, and surface its files map. Verification
// lives in CapsuleVerifier; reader is just structured access.

package ai.virion.capsule.core

import com.google.gson.JsonElement
import com.google.gson.JsonParser
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.StringReader

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
        // Shape check at the parse boundary (mirrors the JS reference's
        // validateManifestShape / validateEnvelopeShape): full integrity is
        // the verifier's job, but a caller reading manifest fields without
        // verifying first can rely on the basic shapes, and verification
        // stays total over whatever the reader hands back.
        validateManifestShape(manifest)
        validateEnvelopeShape(envelope)

        // Refuse encrypted capsules BEFORE demanding the plain-capsule
        // layout: the chain and program live inside the ciphertext, so
        // requiring them first would misattribute the refusal as
        // "missing chain". Detection keys off the SIGNED envelope.cipher
        // plus the presence of content.enc — never the manifest's own
        // encryption claim. A manifest that merely claims encryption on a
        // cipher="none" capsule must still be read (and then rejected by
        // CapsuleVerifier), not waved through as "encrypted, nothing here
        // to check".
        val cipher = lookupString(envelope, listOf("cipher"))
        if (cipher != null && cipher != "none" && files.containsKey("content.enc")) {
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

    /** Lowercase 64-hex predicate, per the spec's canonical-hex rule. */
    fun isHex64(s: String): Boolean =
        s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }

    /**
     * Lightweight shape check on the manifest (spec/manifest.md field
     * rules). Error messages carry the offending field path, prefixed
     * `manifest.`, mirroring the JS reference's validateManifestShape —
     * the registry's `invalid_manifest_shape` reason maps onto that
     * prefix in this lane.
     */
    fun validateManifestShape(manifest: JCSValue) {
        val pairs = (manifest as? JCSValue.Obj)?.pairs
            ?: throw CapsuleException("manifest.json is not a JSON object")
        fun member(key: String): JCSValue? = pairs.firstOrNull { it.first == key }?.second
        val version = ((member("format") as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "version" }?.second as? JCSValue.Str)?.v
        // Any KNOWN version opens (spec/versioning.md): a v0.6 capsule
        // stays openable by every future reader, forever. Unknown
        // versions fail closed with a diagnosis distinct from
        // malformation or tampering.
        CapsuleVersions.requireKnown("manifest.format.version", version)
        val id = (member("id") as? JCSValue.Str)?.v
        if (id == null || !isHex64(id)) {
            throw CapsuleException("manifest.id is not a 64-char lowercase hex string")
        }
        val origPub = ((member("originator") as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "public_key" }?.second as? JCSValue.Str)?.v
        if (origPub == null || !isHex64(origPub)) {
            throw CapsuleException(
                "manifest.originator.public_key must be a 64-char lowercase hex string")
        }
        // null is the legal empty-chain shape (spec/chain.md "Empty
        // chains"): a zero-event capsule has no first event to hash. The
        // verifier enforces the null-anchor / event-count consistency; the
        // reader only rejects values that are neither null nor hex.
        when (val feh = member("first_event_hash")) {
            null, JCSValue.Null -> Unit
            is JCSValue.Str -> if (!isHex64(feh.v)) {
                throw CapsuleException(
                    "manifest.first_event_hash must be a 64-char lowercase hex string or null")
            }
            else -> throw CapsuleException(
                "manifest.first_event_hash must be a 64-char lowercase hex string or null")
        }
        validateContentIndexShape(member("content_index"))
    }

    private fun validateContentIndexShape(index: JCSValue?) {
        val pairs = (index as? JCSValue.Obj)?.pairs
            ?: throw CapsuleException("manifest.content_index must be a JSON object")
        val indexHash = (pairs.firstOrNull { it.first == "index_hash" }?.second as? JCSValue.Str)?.v
        if (indexHash == null || !isHex64(indexHash)) {
            throw CapsuleException(
                "manifest.content_index.index_hash must be a 64-char lowercase hex string")
        }
        val files = (pairs.firstOrNull { it.first == "files" }?.second as? JCSValue.Arr)?.items
            ?: throw CapsuleException("manifest.content_index.files must be an array")
        files.forEachIndexed { i, f ->
            val cols = (f as? JCSValue.Obj)?.pairs
                ?: throw CapsuleException("manifest.content_index.files[$i] must be a JSON object")
            val path = (cols.firstOrNull { it.first == "path" }?.second as? JCSValue.Str)?.v
            if (path.isNullOrEmpty()) {
                throw CapsuleException(
                    "manifest.content_index.files[$i].path must be a non-empty string")
            }
            val sha = (cols.firstOrNull { it.first == "sha256" }?.second as? JCSValue.Str)?.v
            if (sha == null || !isHex64(sha)) {
                throw CapsuleException(
                    "manifest.content_index.files[$i].sha256 must be a 64-char lowercase hex string")
            }
        }
    }

    fun validateEnvelopeShape(envelope: JCSValue) {
        val pairs = (envelope as? JCSValue.Obj)?.pairs
            ?: throw CapsuleException("envelope.json is not a JSON object")
        val version = (pairs.firstOrNull { it.first == "version" }?.second as? JCSValue.Str)?.v
        CapsuleVersions.requireKnown("envelope.version", version)
        val capsuleId = (pairs.firstOrNull { it.first == "capsule_id" }?.second as? JCSValue.Str)?.v
        if (capsuleId == null || !isHex64(capsuleId)) {
            throw CapsuleException("envelope.capsule_id must be a 64-char lowercase hex string")
        }
        val signers = (pairs.firstOrNull { it.first == "signers" }?.second as? JCSValue.Arr)?.items
        if (signers.isNullOrEmpty()) {
            throw CapsuleException("envelope.signers must be a non-empty array")
        }
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
     * Validate `manifest.participants[]` against the actor-id namespace
     * grammar (spec/manifest.md field rules, finding A06). Returns
     * problem strings prefixed `participants[i]` (empty = well-formed).
     * Unlike [participantActorIds], entries that cannot be interpreted
     * are FLAGGED, not skipped: a declared set that cannot be
     * interpreted is not a weaker claim, it is a malformed one.
     */
    fun participantActorIdProblems(manifest: JCSValue): List<String> {
        val obj = manifest as? JCSValue.Obj ?: return emptyList()
        val ps = obj.pairs.firstOrNull { it.first == "participants" }?.second
        val arr = ps as? JCSValue.Arr ?: return emptyList()
        val grammar = "(human:, ai:, system:, capsule:)"
        val problems = mutableListOf<String>()
        for ((i, item) in arr.items.withIndex()) {
            val id = when (item) {
                is JCSValue.Str -> item.v
                is JCSValue.Obj ->
                    (item.pairs.firstOrNull { it.first == "actor_id" }?.second as? JCSValue.Str)?.v
                else -> null
            }
            if (id == null) {
                problems += "participants[$i].actor_id must be a string in an allowed namespace $grammar"
            } else if (!Chain.isValidActorId(id)) {
                problems += "participants[$i].actor_id ${Chain.debugQuoted(id)} " +
                    "does not match an allowed namespace $grammar"
            }
        }
        return problems
    }

    /**
     * [parseJson] with the offending file named in the error, so a reader
     * rejection can be attributed to a specific document (mirrors the Rust
     * verifier's "failed to parse manifest.json").
     */
    fun parseJsonFile(bytes: ByteArray, name: String): JCSValue {
        val text = String(bytes, Charsets.UTF_8)
        val value = try {
            convert(JsonParser.parseString(text))
        } catch (_: Exception) {
            throw CapsuleException("failed to parse $name")
        }
        // Duplicate-member gate over the raw text (spec/canonicalization.md
        // "Objects"): Gson silently keeps the last duplicate, so the rule
        // must be checked during a streaming re-scan, before the value is
        // handed to anything that hashes. Reported in its own words, like
        // the I-JSON gate below.
        try {
            assertNoDuplicateMembers(text)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("$name: ${e.message}", e)
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
        val text = String(bytes, Charsets.UTF_8)
        val value = convert(JsonParser.parseString(text))
        // Duplicate-member gate over the raw text; see parseJsonFile.
        assertNoDuplicateMembers(text)
        // I-JSON acceptance boundary (spec/canonicalization.md). Gson accepts
        // lone-surrogate escapes and oversized integer literals; neither has
        // a canonical form, so refuse before anything is hashed.
        JCS.assertAcceptable(value)
        return value
    }

    /**
     * Reject JSON text carrying duplicate object member names, at any
     * depth (spec/canonicalization.md "Objects"; RFC 7493 2.3). Names
     * compare AFTER escape processing ("a" and "\u0061" are the same
     * name): Gson's streaming [JsonReader.nextName] hands back decoded
     * names, which is exactly the comparison the rule requires. Lenient
     * mode matches [JsonParser.parseString]'s acceptance, so this gate
     * only ever ADDS the duplicate refusal, never a syntax disagreement.
     */
    fun assertNoDuplicateMembers(text: String) {
        val reader = JsonReader(StringReader(text))
        reader.isLenient = true
        fun walk() {
            when (reader.peek()) {
                JsonToken.BEGIN_OBJECT -> {
                    reader.beginObject()
                    val seen = HashSet<String>()
                    while (reader.hasNext()) {
                        val member = reader.nextName()
                        require(seen.add(member)) {
                            "duplicate object member ${Chain.debugQuoted(member)}"
                        }
                        walk()
                    }
                    reader.endObject()
                }
                JsonToken.BEGIN_ARRAY -> {
                    reader.beginArray()
                    while (reader.hasNext()) walk()
                    reader.endArray()
                }
                else -> reader.skipValue()
            }
        }
        walk()
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
