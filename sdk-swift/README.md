# Capsule SDK (Swift)

Native Swift Package for Capsule v0.6: a portable, signed, verifiable
container for AI work product. Build, read, verify, and sign capsules
on iOS or macOS; embed skills; expose them to your app's LLM through a
small documented contract.

This is one of three implementations of Capsule v0.6 — the JS SDK (Node)
is the reference; this Swift SDK and the sibling [Kotlin SDK](../sdk-kotlin)
make the format real on phones.

## Status

`v0.6.0-prototype.1` — `swift build` succeeds on macOS and iOS with
zero warnings, and the package's 25 tests pass (round-trip, encryption
primitives + end-to-end, and cross-implementation parity against
fixtures produced by the JS SDK). Encryption (X25519 + HKDF-SHA256 +
ChaCha20-Poly1305 multi-recipient) ships in this prototype.

## Install

In Xcode: **File → Add Package Dependencies →**
`https://github.com/virion-ai/capsule` (path: `new-design/sdk-swift`).

Or in `Package.swift`:

```swift
.package(url: "https://github.com/virion-ai/capsule", from: "0.6.0-prototype.1"),
```

Pick the targets you need:

```swift
.product(name: "Capsule",        package: "capsule"),  // core: required
.product(name: "CapsuleSkills",  package: "capsule"),  // optional: skills/
.product(name: "CapsuleLLM",     package: "capsule"),  // optional: harness contract
.product(name: "CapsuleUI",      package: "capsule"),  // optional: SwiftUI primitives
```

`Capsule` is zero-dep and pure CryptoKit. The other targets layer on top.

## Quick start — build a capsule

```swift
import Capsule

let kp = Ed25519KeyPair.generate()    // or load from Keychain
let builder = CapsuleBuilder(originator: .init(keyPair: kp, label: "My App"))

builder
    .setProgram("# What this capsule is\n\n…\n")
    .setAgents("# Agents\n\n- human:user\n- ai:my-on-device-llm\n")
    .setParticipants([
        .init(actorId: "human:user", role: "originator", label: "User"),
    ])
    .appendEvent(
        actor: "human:user", kind: "observation",
        action: "noted_something", target: "program.md",
        payload: jobj(("note", "the patient said the rash is itchy")),
        untrustedPayloadFields: ["payload.note"]
    )

let result = try builder.seal()
// result.bytes is a sealed .capsule file. Save / share / ship.
```

## Quick start — open + verify a capsule

```swift
import Capsule

let bytes = try Data(contentsOf: capsuleURL)
let parsed = try CapsuleReader.parse(bytes)

// Verifier returns per-check booleans + per-signer trust attribution.
let allowlist: Set<String> = [knownPatientPublicKey.lowercased()]
let v = CapsuleVerifier.verify(bytes, allowlist: allowlist)
guard v.ok else {
    for c in v.checks where !c.ok { print("✗ \(c.name): \(c.detail)") }
    return
}
print("Signers: \(v.signers.map { "\($0.role) trusted=\($0.trusted)" })")
print("Program:\n\(parsed.programMd)")
```

## Quick start — seal + open an encrypted capsule

```swift
import Capsule

// Recipients hand you their X25519 public keys (32 raw bytes each).
let alice = X25519KeyPair.generate()   // recipient — in practice you'd
                                       // receive only the public bytes
let result = try builder.seal(
    recipients: [.init(publicKey: alice.publicKeyBytes)]
)
// result.bytes is an encrypted-outer capsule. The chain, program.md,
// and any payloads live inside a ChaCha20-Poly1305 blob; the outer
// envelope is still signed and L2-verifiable without any key.

let outer = try CapsuleReader.parse(result.bytes)
let inner = try CapsuleReader.openInner(
    outer,
    recipientPrivateKey: alice.privateKeyBytes,
    recipientPublicKey: alice.publicKeyBytes
)
print(inner.programMd)

// L3 verifies outer envelope, decrypts, verifies inner envelope, and
// cross-checks capsule_id / first_event_hash / entry_hash.
let l3 = CapsuleVerifier.verify(
    result.bytes,
    recipientPrivateKey: alice.privateKeyBytes,
    recipientPublicKey: alice.publicKeyBytes,
    allowlist: [kp.publicKeyHex]   // kp from the build example above
)
```

Multiple `recipients:` are supported; each gets an independent key
bundle and can decrypt without coordination.

## Quick start — drop in "+ Capsule" UI

```swift
import SwiftUI
import Capsule
import CapsuleUI

struct ContentView: View {
    @State var opened: ParsedCapsule?
    var body: some View {
        VStack {
            AddCapsuleButton(allowlist: ["abc..."]) { parsed, verify, url in
                opened = parsed
                // host renders the parsed capsule however it wants
            }
            if let p = opened {
                Text(p.programMd)
            }
        }
    }
}
```

For sharing a sealed capsule:

```swift
ExportCapsuleButton(result: builderResult)   // verify badge + share sheet
```

## The harness contract — wiring an LLM

Your app probably already has an LLM (Gemma via MediaPipe, Apple
Intelligence, the Anthropic API, OpenAI). The `CapsuleLLM` target
defines two protocols that let capsule-bundled skills be surfaced to
that LLM in a uniform way:

```swift
import CapsuleLLM

// Implement against your model:
final class MyHarnessLLM: CapsuleLocalLLM {
    func generate(prompt: String, tools: [SkillToolSpec]) async throws -> LLMResponse {
        // call your LLM with the tool specs; return text + any tool calls
    }
    func describeImage(_ data: Data, mime: String, hint: String?) async throws -> String { … }
}

// Use the in-process skill runtime to expose actions to your LLM:
let runtime = InProcessSkillRuntime(parsed: openedCapsule)
runtime.register(skillId: "my-skill", actionName: "do_thing",
                 summary: "Does a thing.") { input in
    SkillInvocationResult(result: "ok")
}

// Standard tool-use loop:
let response = try await llm.generate(
    prompt: "User said: \(text)",
    tools: runtime.availableActions()
)
for call in response.toolCalls {
    let result = try await runtime.invoke(actionId: call.id, input: call.inputJSON)
    // feed `result.result` back to the LLM as a tool-call result message
}
```

The protocol lives in `Sources/CapsuleLLM/CapsuleLLM.swift` — read the
inline comments for the exact contract.

### Edge Gallery adapter

For hosts that bridge to Edge Gallery's `run_js` skills (the JS
reference), a `CapsuleSkillRuntime` adapter would wrap the Edge Gallery
bridge: each `invoke(actionId:input:)` packages the input JSON,
dispatches it via the bridge, and returns the JSON the skill emits
(including the optional `webview` field, which `WebviewSpec` mirrors
exactly). The SDK doesn't bundle this adapter (Edge Gallery's bridge
isn't a Swift API), but the `WebviewSpec` shape is intentionally
identical to the Edge Gallery response shape so adapters are a thin
mapping.

## What ships in v0.6.0-prototype.1

- `Capsule`: JCS, Crypto (CryptoKit) — SHA-256, Ed25519, `X25519KeyPair`,
  `HKDF`, `ChaCha20Poly1305`, `Random` — Zip (deterministic STORED),
  Chain, Manifest, Envelope, Builder (plain + multi-recipient encrypted
  `seal(recipients:)`), Reader (`parse` + `openInner`), Verifier (L2
  outer-only + L3 decrypted-content), JCSValue value type with
  literal-syntax sugar (`jobj`, `jarr`).
- `CapsuleSkills`: `CapsuleSkill` model, `ParsedCapsule.skills()`
  extension, trust-tier semantics.
- `CapsuleLLM`: `CapsuleLocalLLM` + `CapsuleSkillRuntime` protocols,
  `InProcessSkillRuntime`, `SkillToolSpec`, `WebviewSpec`,
  `LLMResponse` / `ToolCall` value types.
- `CapsuleUI`: `AddCapsuleButton`, `VerifyBadge`, `ExportCapsuleButton`.

## What's deferred

- **Compile + ship to SPM registry**: source-tree consumption works
  today; tagged release after first audit.
- **Multi-signer sealing path**: `Envelope.sign` accepts a `[Signer]`
  but `CapsuleBuilder.seal` currently signs only with the originator.
  The lower-level `Envelope` API is callable for hosts that need it.

## License

Apache-2.0 — same as the JS SDK.
