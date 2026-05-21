// In-process skill runtime: registered handlers run as suspending Kotlin
// functions. Hosts that bridge to external skill runtimes implement
// CapsuleSkillRuntime themselves, mapping action ids to whatever bridge
// primitive their runtime exposes.

package ai.virion.capsule.llm

import ai.virion.capsule.core.ParsedCapsule
import ai.virion.capsule.skills.CapsuleSkill
import ai.virion.capsule.skills.skills

class InProcessSkillRuntime(private val parsed: ParsedCapsule? = null) : CapsuleSkillRuntime {
    fun interface Handler {
        suspend operator fun invoke(input: ByteArray): SkillInvocationResult
    }

    private val handlers = mutableMapOf<String, Handler>()
    private val specs = mutableMapOf<String, SkillToolSpec>()

    fun register(
        skillId: String,
        actionName: String,
        summary: String,
        inputSchema: ByteArray? = null,
        outputSchema: ByteArray? = null,
        handler: Handler,
    ) {
        val id = "$skillId.$actionName"
        handlers[id] = handler
        specs[id] = SkillToolSpec(
            id = id, skillId = skillId, actionName = actionName,
            summary = summary,
            inputSchemaJSON = inputSchema, outputSchemaJSON = outputSchema,
        )
    }

    override fun availableSkills(): List<CapsuleSkill> = parsed?.skills() ?: emptyList()
    override fun availableActions(): List<SkillToolSpec> =
        specs.values.toList().sortedBy { it.id }

    override suspend fun invoke(actionId: String, input: ByteArray): SkillInvocationResult {
        val h = handlers[actionId] ?: throw SkillRuntimeException("unknown action: $actionId")
        return try { h(input) }
        catch (t: Throwable) {
            throw SkillRuntimeException("action $actionId failed: ${t.message}")
        }
    }
}
