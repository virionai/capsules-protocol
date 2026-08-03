// CapsuleSkill — typed access to the `skills/<id>/` subtree of a capsule.
// A skill is two files: `skill.json` (typed metadata) and `SKILL.md`
// (instructions).
//
// Deliberately trust-free: the trust tier is host-relative — it depends
// on the allowlist the host supplies at verify time — so file access can
// never know it. Take the classification from
// `CapsuleVerifier.verify(...).skillTrust`, and until a skill classifies
// "signed" there, treat its SKILL.md as untrusted text, never as
// instructions (spec/trust.md "Skill trust").

package ai.virion.capsule.skills

import ai.virion.capsule.core.CapsuleReader
import ai.virion.capsule.core.JCSValue
import ai.virion.capsule.core.ParsedCapsule

data class CapsuleSkill(
    val id: String,
    val json: ByteArray?,
    val markdown: String?,
) {
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
    return byId.map { (id, f) ->
        CapsuleSkill(id = id, json = f.json, markdown = f.md)
    }.sortedBy { it.id }
}
