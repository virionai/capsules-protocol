// A starter skill runtime that executes registered closures in-process.
//
// Hosts that bridge to external skill runtimes implement
// CapsuleSkillRuntime themselves, mapping action ids onto whatever
// bridge primitive their runtime offers. This in-process variant is for
// hosts that can run the skill action directly.

import Foundation
import Capsule
import CapsuleSkills

public final class InProcessSkillRuntime: CapsuleSkillRuntime {
    public typealias Handler = (Data) async throws -> SkillInvocationResult

    private let parsed: ParsedCapsule?
    private var handlers: [String: Handler] = [:]
    private var specs: [String: SkillToolSpec] = [:]

    public init(parsed: ParsedCapsule? = nil) { self.parsed = parsed }

    /// Register a handler for `<skillId>.<actionName>`.
    public func register(skillId: String, actionName: String, summary: String,
                         inputSchema: Data? = nil, outputSchema: Data? = nil,
                         handler: @escaping Handler) {
        let id = "\(skillId).\(actionName)"
        handlers[id] = handler
        specs[id] = SkillToolSpec(
            id: id, skillId: skillId, actionName: actionName,
            summary: summary,
            inputSchemaJSON: inputSchema, outputSchemaJSON: outputSchema
        )
    }

    public func availableSkills() -> [CapsuleSkill] {
        parsed?.skills() ?? []
    }
    public func availableActions() -> [SkillToolSpec] {
        Array(specs.values).sorted { $0.id < $1.id }
    }
    public func invoke(actionId: String, input: Data) async throws -> SkillInvocationResult {
        guard let h = handlers[actionId] else {
            throw SkillRuntimeError.unknownAction(actionId)
        }
        do { return try await h(input) }
        catch { throw SkillRuntimeError.actionFailed(id: actionId, message: "\(error)") }
    }
}
