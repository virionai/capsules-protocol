// CapsuleSkill — typed access to the `skills/<id>/` subtree of a capsule.
// A skill is two files: `skill.json` (typed metadata) and `SKILL.md`
// (instructions, in one of two trust tiers per spec/trust.md).

package ai.virion.capsule.skills

import ai.virion.capsule.core.CapsuleReader
import ai.virion.capsule.core.JCSValue
import ai.virion.capsule.core.ParsedCapsule

data class CapsuleSkill(
    val id: String,
    val json: ByteArray?,
    val markdown: String?,
    /** "signed" or "unsigned" per manifest.skill_trust. */
    val trust: TrustTier,
) {
    enum class TrustTier { SIGNED, UNSIGNED;
        companion object {
            fun fromString(s: String): TrustTier? = when (s.lowercase()) {
                "signed" -> SIGNED
                "unsigned" -> UNSIGNED
                else -> null
            }
        }
    }

    /** Decoded `skill.json` as a JCSValue object, or null if absent or unparseable. */
    fun metadata(): JCSValue? =
        json?.let { runCatching { CapsuleReader.parseJson(it) }.getOrNull() }
}

/** All skills contained in a parsed capsule, indexed by id. */
fun ParsedCapsule.skills(): List<CapsuleSkill> {
    data class Files(var json: ByteArray? = null, var md: String? = null)
    val byId = linkedMapOf<String, Files>()
    for ((path, data) in files) {
        if (!path.startsWith("skills/")) continue
        val parts = path.split('/')
        if (parts.size != 3 || parts[0] != "skills") continue
        val id = parts[1]
        if (id == "decryption") continue
        val files = byId.getOrPut(id) { Files() }
        when (parts[2]) {
            "skill.json" -> files.json = data
            "SKILL.md"   -> files.md = String(data, Charsets.UTF_8)
        }
    }
    val trustMap = mutableMapOf<String, CapsuleSkill.TrustTier>()
    val skillTrust = (manifest as? JCSValue.Obj)?.pairs
        ?.firstOrNull { it.first == "skill_trust" }?.second as? JCSValue.Obj
    skillTrust?.pairs?.forEach { (k, v) ->
        if (v is JCSValue.Str) {
            CapsuleSkill.TrustTier.fromString(v.v)?.let { trustMap[k] = it }
        }
    }
    return byId.map { (id, f) ->
        CapsuleSkill(
            id = id, json = f.json, markdown = f.md,
            trust = trustMap[id] ?: CapsuleSkill.TrustTier.UNSIGNED,
        )
    }.sortedBy { it.id }
}
