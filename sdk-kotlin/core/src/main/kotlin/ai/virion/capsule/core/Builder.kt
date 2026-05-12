// CapsuleBuilder — general-purpose, mirrors sdk/src/builder.js.
//
// Host apps construct a builder, set program.md / agents.md, append
// chain events with full control over actor/kind/action/target/payload,
// optionally add skills and arbitrary payload files, then seal to bytes.
//
// No domain knowledge is baked in.

package ai.virion.capsule.core

import java.time.Instant
import java.time.format.DateTimeFormatter

class CapsuleBuilder(
    private val originator: Originator,
    createdAt: String? = null,
) {
    data class Originator(
        val keyPair: CapsuleCrypto.Ed25519KeyPair,
        val label: String = "",
    )

    data class Participant(
        val actorId: String,
        val role: String,
        val label: String,
    )

    data class PayloadFile(val path: String, val bytes: ByteArray) {
        init { require(path.startsWith("payload/")) {
            "payload path must start with 'payload/': $path"
        } }
    }

    data class BuildResult(
        val bytes: ByteArray,
        val capsuleId: String,
        val firstEventHash: String,
        val entryHash: String,
        val manifestHash: String,
        val contentIndexHash: String,
        val originatorPublicKey: String,
        val signedAt: String,
        val fileCount: Int,
        val byteCount: Int,
    )

    private val createdAt: String = createdAt ?: isoNow()
    private var programMd: String = "# Program\n"
    private var agentsMd: String? = null
    private var participants: List<Participant> = emptyList()
    private val bareEvents = mutableListOf<BareEvent>()
    private val skills = linkedMapOf<String, Triple<ByteArray?, String?, Boolean>>() // id → (json, md, signed)
    private val payload = linkedMapOf<String, ByteArray>()

    fun setProgram(md: String) = apply { this.programMd = md }
    fun setAgents(md: String) = apply { this.agentsMd = md }
    fun setParticipants(ps: List<Participant>) = apply { this.participants = ps }

    fun appendEvent(
        actor: String, kind: String, action: String, target: String,
        timestamp: String? = null,
        payload: JCSValue = JCSValue.Obj(emptyList()),
        untrustedPayloadFields: List<String> = emptyList(),
    ) = apply {
        bareEvents += BareEvent(
            actor = actor, kind = kind, action = action, target = target,
            timestamp = timestamp ?: createdAt,
            payload = payload,
            untrustedPayloadFields = untrustedPayloadFields,
        )
    }

    fun addSkill(id: String, json: ByteArray? = null, markdown: String? = null,
                 signed: Boolean = false) = apply {
        require(Regex("^[A-Za-z0-9_-]+$").matches(id)) { "invalid skill id: $id" }
        require(id != "decryption") { "'decryption' is reserved for encryption metadata" }
        skills[id] = Triple(json, markdown, signed)
    }

    fun addPayload(file: PayloadFile) = apply {
        payload[file.path] = file.bytes
    }

    fun seal(signedAt: String? = null): BuildResult {
        val sealedAt = signedAt ?: isoNow()
        val bare = if (bareEvents.isEmpty()) listOf(BareEvent(
            actor = "system:host", kind = "observation",
            action = "session_ended", target = "capsule",
            timestamp = sealedAt,
            payload = JCSValue.Obj(listOf(
                "note" to JCSValue.Str("host emitted backstop event before seal")
            )),
        )) else bareEvents
        val events = Chain.build(bare)
        val firstHash = events.first().hash
        val entryHash = events.last().hash
        val eventsJsonl = Chain.eventsToJsonl(events)

        val innerFiles = mutableListOf<Pair<String, ByteArray>>(
            "program.md" to programMd.toByteArray(Charsets.UTF_8),
            "chain/events.jsonl" to eventsJsonl,
        )
        agentsMd?.let { innerFiles += "agents.md" to it.toByteArray(Charsets.UTF_8) }
        val skillTrust = mutableListOf<Pair<String, String>>()
        for ((id, sk) in skills) {
            sk.first?.let { innerFiles += "skills/$id/skill.json" to it }
            sk.second?.let { innerFiles += "skills/$id/SKILL.md" to it.toByteArray(Charsets.UTF_8) }
            skillTrust += id to (if (sk.third) "signed" else "unsigned")
        }
        for ((path, bytes) in payload) innerFiles += path to bytes

        val capsuleId = Manifest.computeCapsuleId(originator.keyPair.publicKeyBytes, firstHash)
        val ci = Manifest.buildContentIndex(innerFiles)
        val manifest = Manifest.build(
            originator = Manifest.Originator(originator.keyPair.publicKeyHex, originator.label),
            participants = participants.map {
                Manifest.Participant(it.actorId, it.role, it.label)
            },
            contentIndex = ci,
            firstEventHash = firstHash,
            skillTrust = skillTrust,
            createdAt = createdAt,
            capsuleId = capsuleId,
        )
        val mfHash = Manifest.hash(manifest)

        val envelope = Envelope.sign(
            Envelope.build(
                capsuleId = capsuleId,
                firstEventHash = firstHash,
                entryHash = entryHash,
                manifestHash = mfHash,
                contentIndexHash = ci.indexHash,
                cipher = "none",
                signedAt = sealedAt,
            ),
            listOf(Envelope.Signer(role = "originator", keyPair = originator.keyPair))
        )

        val allFiles = innerFiles.toMutableList()
        allFiles += "manifest.json" to Manifest.bytes(manifest)
        allFiles += "provenance/envelope.json" to JCS.bytes(envelope)
        val zipBytes = CapsuleZip.pack(allFiles)

        return BuildResult(
            bytes = zipBytes,
            capsuleId = capsuleId,
            firstEventHash = firstHash,
            entryHash = entryHash,
            manifestHash = mfHash,
            contentIndexHash = ci.indexHash,
            originatorPublicKey = originator.keyPair.publicKeyHex,
            signedAt = sealedAt,
            fileCount = allFiles.size,
            byteCount = zipBytes.size,
        )
    }

    companion object {
        fun isoNow(): String =
            DateTimeFormatter.ISO_INSTANT.format(Instant.now())
                .replace(Regex("\\.\\d+Z$"), "Z")
    }
}
