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
