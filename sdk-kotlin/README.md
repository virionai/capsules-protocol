# Capsule SDK (Kotlin)

Native Kotlin library for Capsule v0.7: a portable, signed, verifiable
container for AI work product. Build, read, verify, and sign **plain
(unencrypted) capsules** on Android (or any JVM); embed skills; expose
them to your app's LLM through a small documented contract.

The JS SDK (Node) is the reference implementation; this Kotlin SDK and
the sibling [Swift SDK](../sdk-swift) make the format real on phones.

**Scope: plain-capsule (L2) only.** This SDK implements JCS, SHA-256
hashing, Ed25519 signing/verification, the event chain, and the
envelope — but not the encryption profile. There is no X25519 key
agreement, HKDF, or ChaCha20-Poly1305 here, so encrypted capsules are
rejected (fail closed) rather than decrypted. Use the JS, Python,
Swift, or Rust implementations for encrypted (L3) capsules until the
Kotlin encryption path lands.

## Status

`0.7.0-prototype.1` — the `:core` module compiles and its tests
(round-trip, JS-fixture parity, JCS number vectors) run in CI on every
push; see the `conformance-kotlin` lane in
[.github/workflows/conformance.yml](../.github/workflows/conformance.yml).
The Android modules (`:skills`, `:llm`, `:ui`) are not yet
compile-tested in CI.

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
    implementation("ai.virion.capsule:core:0.7.0-prototype.1")
    implementation("ai.virion.capsule:skills:0.7.0-prototype.1")
    implementation("ai.virion.capsule:llm:0.7.0-prototype.1")
    implementation("ai.virion.capsule:ui:0.7.0-prototype.1")
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

Every result also carries the normalized verdict surface of
[spec/results.md](../spec/results.md): `v.verdict`
(`valid | invalid | unsupported`, with `ok == (verdict == "valid")`),
`v.verdictReason` (non-null only for `unsupported` — an unknown format
version, a declared profile this verifier does not implement, or an
encrypted capsule this lane cannot process: a limitation of the
verifier, never a claim the capsule is corrupt), and `v.qualifiers` —
the weaker claims a *valid* capsule made honestly (unbound signer set,
unbound actor set, unwalked empty chain, no allowlist consulted, a
declared lineage nobody supplied bytes for, and so on). **If you render
a verdict, render the qualifiers beside it:** showing a bare "verified"
for a capsule that carries qualifiers is the report lying by omission,
and results.md names it non-conforming.

```kotlin
when (v.verdict) {
    "valid" -> render("verified", qualifiers = v.qualifiers)
    "unsupported" -> render("cannot verify here: ${v.verdictReason}")
    else -> render("verification failed")
}
```

`trust_not_evaluated` keys off the *effective* allowlist: an entry that
is not 64-char hex is dropped with an `ignored invalid allowlist entry`
note, so a typo cannot masquerade as a consulted policy.

`v.profile` reports the declared verification profile
([spec/profiles.md](../spec/profiles.md)) — `status` `default` for the
capsules every mainstream reader verifies, `effective` naming the rule
set actually applied. `CapsuleVerifier.verify` also accepts the
report-only host policies `acceptVersions` and `acceptProfiles`. Gate
order is version → profile → everything else; on a refusal at either
gate the diagnosis is the only error the result carries, `v.lineage`
holds its not-evaluated default, and `v.qualifiers` is empty.

## Quick start — check a lineage declaration

A successor capsule declares the exact sealed artifact(s) it continues
from in `manifest.predecessors` ([spec/lineage.md](../spec/lineage.md)).
The standalone checks always run and fail closed; supplying predecessor
bytes is REPORT-ONLY — it can falsify `lineage.ok`, never `v.ok`, so a
third party cannot flip a valid capsule's verdict by handing this
verifier the wrong file.

```kotlin
val v = CapsuleVerifier.verify(
    successorBytes,
    predecessors = listOf(predecessorFile.readBytes()),  // optional pool
)
if (v.lineage.declared) {
    for (e in v.lineage.entries) {
        // status: unverified | verified | mismatch |
        //         predecessor_invalid | predecessor_unverifiable
        println("hop ${e.hop} ${e.capsuleId}: ${e.status} ${e.reason ?: ""}")
    }
    println("verified to depth ${v.lineage.verifiedDepth}")
}
```

A declaration is the successor's **one-way** claim: the predecessor's
originator has not countersigned it, and an unchecked entry is
"declared, not verified". Both statements are in `v.notes`, and a
host UI must not drop them — that is how a citation gets read as an
endorsement. `v.qualifiers` carries the same weaker-claim facts as bare
strings (`lineage_declared_unverified`, `lineage_mismatch`,
`lineage_predecessor_invalid` — entries 8–10 of the spec-defined order,
after the seven base names), non-empty only on a valid verdict. The
payload-carrying facts — `verifiedDepth`, the per-entry statuses and
reasons — stay in `v.lineage`, never on the bare-string array.

v0.7.1 declarations commit to plain, default-profile predecessors: an
encrypted or alternate-profile supply is reported
`predecessor_unverifiable` with a reason, never guessed at and never
branded a defect. Writing a declaration (rewrap / `continueFrom`) is a
declared fast-follow in this lane — use the JS or Python SDK to seal a
successor, then verify it anywhere.

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

Your app probably already has a model or tool runtime. The `:llm`
module defines two interfaces that let capsule-bundled skills be
surfaced to that runtime:

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

### External bridge adapter

For hosts that bridge to external skill runtimes, a
`CapsuleSkillRuntime` adapter packages each `invoke(actionId, input)`
request as JSON, dispatches it through the host bridge, and returns the
JSON the skill emits — including the optional `webview` field that
`WebviewSpec` models. The SDK does not bundle host-specific adapters;
the shared interface keeps those adapters thin.

## What ships in 0.7.0-prototype.1

- `:core`: full Capsule v0.7 builder, reader, verifier, envelope
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
  not implemented — encrypted capsules are rejected, not decrypted.
  The JS, Python, Swift, and Rust implementations cover the full
  encrypted L2/L3 profile; Kotlin parity is open work.
- **Maven Central publishing**: tagged release after first compile-test
  + audit.
- **Multi-signer sealing path**: `Envelope.sign` accepts a `List<Signer>`
  but `CapsuleBuilder.seal` currently signs only with the originator.
  The lower-level `Envelope` API is callable.
- **Lineage writer surface** (`continueFrom` / `declarePredecessor` /
  rewrap): verify-side lineage ships in full, but sealing a successor
  is a declared fast-follow here, as it is in the Swift lane. The
  asymmetry is recorded in `spec/vectors/registry.json` beside the
  lineage collection, never left silent.

## License

MIT — same as the JS SDK and the repository [LICENSE](../LICENSE).
