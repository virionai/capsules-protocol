// CapsuleLLM — the harness contract.
//
// A host app that wants Capsule support typically already has a model or
// tool runtime ("the harness"). CapsuleLLM defines two small interfaces
// the host implements so capsule-bundled skills can be surfaced to that
// runtime in a uniform way.

package ai.virion.capsule.llm

import ai.virion.capsule.skills.CapsuleSkill

// ─── LLM contract ────────────────────────────────────────

interface CapsuleLocalLLM {
    suspend fun generate(prompt: String, tools: List<SkillToolSpec> = emptyList()): LLMResponse
    suspend fun describeImage(data: ByteArray, mime: String, hint: String? = null): String =
        throw UnsupportedOperationException("LLM does not support modality: image")
    suspend fun transcribeAudio(data: ByteArray, mime: String, hint: String? = null): String =
        throw UnsupportedOperationException("LLM does not support modality: audio")
}

data class LLMResponse(
    val text: String?,
    val toolCalls: List<ToolCall> = emptyList(),
)

data class ToolCall(
    val id: String,            // "<skill_id>.<action_name>"
    val inputJSON: ByteArray,
)

// ─── Skill runtime contract ──────────────────────────────

interface CapsuleSkillRuntime {
    fun availableSkills(): List<CapsuleSkill>
    fun availableActions(): List<SkillToolSpec>
    suspend fun invoke(actionId: String, input: ByteArray): SkillInvocationResult
}

data class SkillToolSpec(
    val id: String,                    // "<skill_id>.<action_name>"
    val skillId: String,
    val actionName: String,
    val summary: String,
    val inputSchemaJSON: ByteArray? = null,
    val outputSchemaJSON: ByteArray? = null,
)

data class SkillInvocationResult(
    val result: String?,
    val data: ByteArray? = null,
    val webview: WebviewSpec? = null,
)

data class WebviewSpec(
    val url: String,
    val aspectRatio: Double? = null,
)

class SkillRuntimeException(message: String) : Exception(message)
