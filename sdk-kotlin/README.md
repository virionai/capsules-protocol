# Capsule SDK (Kotlin)

Native Kotlin library for Capsule v0.6: a portable, signed, verifiable
container for AI work product. Build, read, verify, and sign capsules
on Android (or any JVM); embed skills; expose them to your app's LLM
through a small documented contract.

This is one of three implementations of Capsule v0.6 — the JS SDK (Node)
is the reference; this Kotlin SDK and the sibling [Swift SDK](../sdk-swift)
make the format real on phones.

## Status

`0.6.0-prototype.1` — code-complete, untested in a Gradle build in this
session.

## Modules

| Module | Purpose | Type |
|---|---|---|
| `:core`    | JCS, Crypto, Zip, Chain, Manifest, Envelope, Builder, Reader, Verifier | Pure Kotlin/JVM library |
| `:skills`  | `CapsuleSkill` + `ParsedCapsule.skills()` extension; trust-tier semantics | Pure Kotlin/JVM |
| `:llm`     | `CapsuleLocalLLM` + `CapsuleSkillRuntime` interfaces; `InProcessSkillRuntime` | Pure Kotlin/JVM |
| `:ui`      | `AddCapsuleButton`, `VerifyBadge`, `ExportCapsuleButton` | Android library + Compose |

`:core` has only two transitive deps (BouncyCastle for Ed25519 + Gson
for JSON parsing). `:ui` adds AndroidX + Compose.

## Install

In `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories { mavenCentral() }
}
```

In `app/build.gradle.kts`:

```kotlin
dependencies {
    implementation("ai.virion.capsule:core:0.6.0-prototype.1")
    implementation("ai.virion.capsule:skills:0.6.0-prototype.1")
    implementation("ai.virion.capsule:llm:0.6.0-prototype.1")
    implementation("ai.virion.capsule:ui:0.6.0-prototype.1")
}
```

(Maven Central publish is pending — for now, consume as a path
dependency with `includeBuild("path/to/sdk-kotlin")` in your
`settings.gradle.kts`.)

## Quick start — build a capsule

```kotlin
import ai.virion.capsule.core.*

val kp = CapsuleCrypto.generateEd25519()  // or load from EncryptedSharedPreferences
val builder = CapsuleBuilder(
    originator = CapsuleBuilder.Originator(kp, label = "My App")
)

builder
    .setProgram("# What this capsule is\n\n…\n")
    .setAgents("# Agents\n\n- human:user\n- ai:my-on-device-llm\n")
    .setParticipants(listOf(
        CapsuleBuilder.Participant("human:user", "originator", "User"),
    ))
    .appendEvent(
        actor = "human:user", kind = "observation",
        action = "noted_something", target = "program.md",
        payload = jobj("note" to JCSValue.Str("the patient said the rash is itchy")),
        untrustedPayloadFields = listOf("payload.note"),
    )

val result = builder.seal()
// result.bytes is a sealed .capsule file. Save / share / ship.
```

## Quick start — open + verify a capsule

```kotlin
import ai.virion.capsule.core.CapsuleReader
import ai.virion.capsule.core.CapsuleVerifier

val bytes = file.readBytes()
val parsed = CapsuleReader.parse(bytes)
val v = CapsuleVerifier.verify(
    bytes,
    allowlist = setOf(knownPatientPublicKey.lowercase()),
)
require(v.ok) { v.checks.filterNot { it.ok }.joinToString { "${it.name}: ${it.detail}" } }
println("Signers: ${v.signers.map { "${it.role} trusted=${it.trusted}" }}")
println("Program:\n${parsed.programMd}")
```

## Quick start — drop in "+ Capsule" UI

```kotlin
import androidx.compose.runtime.*
import ai.virion.capsule.core.ParsedCapsule
import ai.virion.capsule.ui.AddCapsuleButton

@Composable
fun MyScreen() {
    var opened by remember { mutableStateOf<ParsedCapsule?>(null) }
    AddCapsuleButton(allowlist = setOf("abc...")) { parsed, verify, uri ->
        opened = parsed
    }
    opened?.let { Text(it.programMd) }
}
```

For sharing a sealed capsule:

```kotlin
ExportCapsuleButton(
    result = builderResult,
    fileProviderAuthority = "${ctx.packageName}.fileprovider",
)
```

## The harness contract — wiring an LLM

Your app probably already has an LLM (MediaPipe Gemma, Edge Gallery,
the Anthropic API, OpenAI). The `:llm` module defines two interfaces
that let capsule-bundled skills be surfaced to that LLM:

```kotlin
import ai.virion.capsule.llm.*

class MyHarnessLLM : CapsuleLocalLLM {
    override suspend fun generate(prompt: String, tools: List<SkillToolSpec>): LLMResponse {
        // call your LLM with the tool specs; return text + any tool calls
    }
}

val runtime = InProcessSkillRuntime(parsed = openedCapsule)
runtime.register(
    skillId = "my-skill", actionName = "do_thing",
    summary = "Does a thing.",
) { input ->
    SkillInvocationResult(result = "ok")
}

// Standard tool-use loop:
val response = llm.generate(
    prompt = "User said: $text",
    tools = runtime.availableActions(),
)
for (call in response.toolCalls) {
    val result = runtime.invoke(call.id, call.inputJSON)
    // feed `result.result` back to the LLM as a tool-call result
}
```

The interfaces live in `llm/src/main/kotlin/ai/virion/capsule/llm/CapsuleLLM.kt`.

### Edge Gallery adapter

For hosts that bridge to Edge Gallery's `run_js` skills, a
`CapsuleSkillRuntime` adapter wraps Edge Gallery's bridge: each
`invoke(actionId, input)` packages the JSON, dispatches via the bridge,
and returns the JSON the skill emits — including the optional
`webview` field that `WebviewSpec` mirrors exactly. The SDK doesn't
bundle this adapter (Edge Gallery's bridge isn't a Kotlin API), but
the `WebviewSpec` shape is intentionally identical to the Edge Gallery
response shape so an adapter is a thin mapping.

## What ships in 0.6.0-prototype.1

- `:core`: full Capsule v0.6 builder, reader, verifier, envelope
  sign/verify, JCS canonicalization, deterministic ZIP STORED.
- `:skills`: `CapsuleSkill` model, `ParsedCapsule.skills()` extension,
  trust-tier semantics.
- `:llm`: `CapsuleLocalLLM` + `CapsuleSkillRuntime` interfaces,
  `InProcessSkillRuntime`, `SkillToolSpec`, `WebviewSpec`,
  `LLMResponse` / `ToolCall`.
- `:ui`: `AddCapsuleButton`, `VerifyBadge`, `ExportCapsuleButton`
  Compose composables.

## What's deferred

- **Encryption** (X25519-HKDF + ChaCha20-Poly1305 multi-recipient):
  parking-lot per format spec.
- **Maven Central publishing**: tagged release after first compile-test
  + audit.
- **Multi-signer sealing path**: `Envelope.sign` accepts a `List<Signer>`
  but `CapsuleBuilder.seal` currently signs only with the originator.
  The lower-level `Envelope` API is callable.

## License

Apache-2.0 — same as the JS SDK.
