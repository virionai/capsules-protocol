// CapsuleLLM — the harness contract.
//
// A host app that wants Capsule support typically already has an LLM
// runtime ("the harness") — Gemma via MediaPipe, Apple Intelligence,
// the Anthropic API, OpenAI Responses, anything. CapsuleLLM defines two
// small protocols the host implements so capsule-bundled skills can be
// surfaced to that LLM in a uniform way:
//
//   - CapsuleLocalLLM  — generate text / describe image / transcribe
//                        audio. Optional tool-use hook for skill
//                        function-calls.
//   - CapsuleSkillRuntime — discover skills bundled in an opened
//                        capsule, expose their actions as tool specs,
//                        route invocations to the right action.
//
// The standard tool-use loop is the same on every backend; what changes
// is which model fills CapsuleLocalLLM and how the host wires the
// runtime's tool specs into its model's tool-call format. CapsuleLLM
// stays agnostic.
//
// This file is the documentation surface; CapsuleSkillRuntime+InProcess
// supplies a default in-process runtime that any host can use as a
// starting point.

import Foundation
import Capsule
import CapsuleSkills

// MARK: - LLM contract

/// The minimum surface a host harness exposes for capsule integration.
/// Implementations may add more; capsule-aware UI components only require
/// these methods.
public protocol CapsuleLocalLLM {
    /// Generate text from a prompt. If `tools` is non-empty, the model
    /// SHOULD be invoked with tool-use enabled and may emit `toolCalls`.
    /// If the model has no tool-use, return text only.
    func generate(prompt: String, tools: [SkillToolSpec]) async throws -> LLMResponse

    /// Optional multimodal hooks. Default implementations throw
    /// `LLMUnsupported.modalityNotSupported`.
    func describeImage(_ data: Data, mime: String, hint: String?) async throws -> String
    func transcribeAudio(_ data: Data, mime: String, hint: String?) async throws -> String
}

public extension CapsuleLocalLLM {
    func describeImage(_ data: Data, mime: String, hint: String?) async throws -> String {
        throw LLMUnsupported.modalityNotSupported("image")
    }
    func transcribeAudio(_ data: Data, mime: String, hint: String?) async throws -> String {
        throw LLMUnsupported.modalityNotSupported("audio")
    }
}

public enum LLMUnsupported: Error, CustomStringConvertible {
    case modalityNotSupported(String)
    public var description: String {
        switch self {
        case .modalityNotSupported(let m): return "LLM does not support modality: \(m)"
        }
    }
}

public struct LLMResponse: Equatable {
    public let text: String?
    public let toolCalls: [ToolCall]
    public init(text: String?, toolCalls: [ToolCall] = []) {
        self.text = text; self.toolCalls = toolCalls
    }
}

public struct ToolCall: Equatable {
    public let id: String       // "<skill_id>.<action_name>"
    public let inputJSON: Data  // input as JSON; runtime parses
    public init(id: String, inputJSON: Data) {
        self.id = id; self.inputJSON = inputJSON
    }
}

// MARK: - Skill runtime contract

/// A capsule-aware skill runtime: discovers skills, surfaces their actions
/// as tool specs, executes invocations.
public protocol CapsuleSkillRuntime {
    func availableSkills() -> [CapsuleSkill]
    func availableActions() -> [SkillToolSpec]
    func invoke(actionId: String, input: Data) async throws -> SkillInvocationResult
}

public struct SkillToolSpec: Equatable {
    public let id: String              // "<skill_id>.<action_name>"
    public let skillId: String
    public let actionName: String
    public let summary: String
    public let inputSchemaJSON: Data?  // JSON Schema for input
    public let outputSchemaJSON: Data?
    public init(id: String, skillId: String, actionName: String,
                summary: String, inputSchemaJSON: Data?, outputSchemaJSON: Data?) {
        self.id = id; self.skillId = skillId; self.actionName = actionName
        self.summary = summary
        self.inputSchemaJSON = inputSchemaJSON; self.outputSchemaJSON = outputSchemaJSON
    }
}

public struct SkillInvocationResult: Equatable {
    /// Plain-text result the LLM reads back into the conversation.
    public let result: String?
    /// Optional structured side-channel data. Hosts may render or pass on.
    public let data: Data?
    /// Optional webview spec for hosts that support it (Edge Gallery
    /// passes this back as `webview`).
    public let webview: WebviewSpec?
    public init(result: String?, data: Data? = nil, webview: WebviewSpec? = nil) {
        self.result = result; self.data = data; self.webview = webview
    }
}

public struct WebviewSpec: Equatable {
    public let url: String
    public let aspectRatio: Double?
    public init(url: String, aspectRatio: Double? = nil) {
        self.url = url; self.aspectRatio = aspectRatio
    }
}

public enum SkillRuntimeError: Error, CustomStringConvertible {
    case unknownAction(String)
    case actionFailed(id: String, message: String)
    public var description: String {
        switch self {
        case .unknownAction(let id): return "unknown action: \(id)"
        case .actionFailed(let id, let m): return "action \(id) failed: \(m)"
        }
    }
}
