// Append-only signed event chain. prev_hash + JCS(event) over raw bytes.

package ai.virion.capsule.core

data class BareEvent(
    val actor: String,
    val kind: String,
    val action: String,
    val target: String,
    val timestamp: String,
    val payload: JCSValue,
    val untrustedPayloadFields: List<String> = emptyList(),
)

data class BuiltEvent(
    val seq: Int,
    val eventId: String,
    val actor: String,
    val kind: String,
    val action: String,
    val target: String,
    val timestamp: String,
    val payload: JCSValue,
    val untrustedPayloadFields: List<String>,
    val prevHash: String,
    val hash: String,
    val jsonLine: ByteArray,
)

object Chain {
    val GENESIS_PREV: ByteArray = ByteArray(32)

    /**
     * The closed `kind` enum from spec/chain.md "Field rules". Readers
     * reject unknown kinds and the builder refuses to append them — in
     * every tier, because a custom kind is not a weaker claim, it is
     * unreadable to the foreign LLM reader the format serves.
     */
    val EVENT_KINDS: List<String> =
        listOf("decision", "observation", "mutation", "session", "checkpoint")

    /**
     * The one actor a chain event may always name without a matching
     * manifest participant — backstop events emitted by the host runtime.
     */
    const val HOST_ACTOR: String = "system:host"

    /** True when [kind] is one of the five values spec/chain.md allows. */
    fun isValidEventKind(kind: String?): Boolean = kind != null && kind in EVENT_KINDS

    /**
     * The normative `untrusted_payload_fields` path grammar from
     * spec/chain.md "Untrusted content":
     *
     *     path    = "payload" 1*( "." segment )
     *     segment = 1*( ALPHA / DIGIT / "_" / "-" )
     *
     * A marking outside the grammar has no defined resolution — a host
     * cannot tell which payload member the author marked untrusted — so
     * writers refuse to emit it and verifiers reject it fail-closed
     * (vector chain-rules/invalid-untrusted-path).
     */
    fun isValidUntrustedPayloadPath(path: String): Boolean {
        val segments = path.split('.')
        if (segments.size < 2 || segments[0] != "payload") return false
        for (seg in segments.drop(1)) {
            if (seg.isEmpty()) return false
            if (!seg.all { it in '0'..'9' || it in 'a'..'z' || it in 'A'..'Z' || it == '_' || it == '-' }) {
                return false
            }
        }
        return true
    }

    /**
     * Render a string the way Rust's `{:?}` renders a `String` (and JS's
     * `JSON.stringify` a plain-ASCII one), so all five lanes emit
     * byte-identical verifier messages. `null` renders as `null` (a
     * missing field).
     */
    fun debugQuoted(s: String?): String {
        if (s == null) return "null"
        val sb = StringBuilder("\"")
        for (ch in s) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                else -> sb.append(ch)
            }
        }
        return sb.append('"').toString()
    }

    fun build(bare: List<BareEvent>): List<BuiltEvent> {
        var prev = GENESIS_PREV
        val out = mutableListOf<BuiltEvent>()
        bare.forEachIndexed { i, b ->
            val seq = i + 1
            val eventId = "evt_" + String.format("%03d", seq)
            val prevHex = CapsuleCrypto.bytesToHex(prev)
            val pairs = listOf(
                "seq" to JCSValue.Integer(seq.toLong()),
                "event_id" to JCSValue.Str(eventId),
                "actor" to JCSValue.Str(b.actor),
                "kind" to JCSValue.Str(b.kind),
                "action" to JCSValue.Str(b.action),
                "target" to JCSValue.Str(b.target),
                "timestamp" to JCSValue.Str(b.timestamp),
                "payload" to b.payload,
                "untrusted_payload_fields" to
                    JCSValue.Arr(b.untrustedPayloadFields.map { JCSValue.Str(it) }),
                "prev_hash" to JCSValue.Str(prevHex),
            )
            val canonical = JCS.bytes(JCSValue.Obj(pairs))
            val hashBytes = CapsuleCrypto.sha256(CapsuleCrypto.concat(prev, canonical))
            val hashHex = CapsuleCrypto.bytesToHex(hashBytes)
            val withHash = JCSValue.Obj(pairs + ("hash" to JCSValue.Str(hashHex)))
            out += BuiltEvent(
                seq = seq, eventId = eventId,
                actor = b.actor, kind = b.kind, action = b.action, target = b.target,
                timestamp = b.timestamp, payload = b.payload,
                untrustedPayloadFields = b.untrustedPayloadFields,
                prevHash = prevHex, hash = hashHex,
                jsonLine = JCS.bytes(withHash),
            )
            prev = hashBytes
        }
        return out
    }

    fun eventsToJsonl(events: List<BuiltEvent>): ByteArray {
        var n = 0
        for (e in events) n += e.jsonLine.size + 1
        val out = ByteArray(n)
        var off = 0
        for (e in events) {
            System.arraycopy(e.jsonLine, 0, out, off, e.jsonLine.size)
            off += e.jsonLine.size
            out[off++] = '\n'.code.toByte()
        }
        return out
    }
}
