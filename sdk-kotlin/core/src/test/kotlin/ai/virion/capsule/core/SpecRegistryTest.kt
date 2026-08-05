// Registry-driven conformance against spec/vectors.
//
// Mirrors sdk-py/tests/test_spec_registry.py and
// verifier-rust/tests/spec_registry.rs: this lane reads the
// language-neutral outcome registries directly, so Kotlin tracks the same
// normative expectations as the JS reference lane without hand-copied
// assertions:
//
//   - tamper-detection/vectors.json   (verify-stage outcomes)
//   - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
//   - malformed-shape/vectors.json    (manifest/chain document shape rules)
//   - unknown-fields/vectors.json     (unknown-member preservation outcomes)
//   - signer-set/vectors.json         (signer-set binding outcomes)
//   - chain-binding/vectors.json      (empty-chain anchors + stored-line hashing)
//   - chain-rules/vectors.json        (per-event actor + kind field rules)
//   - semantic-binding/vectors.json   (manifest claims vs envelope/chain/files)
//   - jcs-key-order.json              (RFC 8785 §3.2.3 member ordering)
//   - ijson-acceptance.json           (the I-JSON canonicalization input domain)
//   - unicode-boundary/vectors.json   (Pith-truncated astral text verifies)
//   - pith-authoring/vectors.json     (verbatim technical prose + the
//                                      pith_normalized_fields marker verify)
//   - version-compat/vectors.json     (version gates: known opens and
//                                      reports; unknown fails closed with
//                                      a non-tamper diagnosis)
//   - profile-declaration/vectors.json (the profile gate: absence means
//                                      the era default; unsupported /
//                                      mismatched / malformed kept
//                                      distinguishable)
//   - result-vocabulary/vectors.json  (the normalized verdict surface:
//                                      verdict, verdict_reason, and the
//                                      exact qualifier array)
//
// signing-input.json is consumed by SigningInputVectorTest, and
// jcs-numbers.json / ed25519-key-validation.json by their own test files.
//
// The registry's `reason` categories are normative; the substring table
// below maps each category onto this lane's error messages.

package ai.virion.capsule.core

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SpecRegistryTest {

    @Test
    fun tamperRegistryOutcomes() {
        val file = File(vectorsDir(), "tamper-detection/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "tamper-detection registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            if (name in ENCRYPTED_VECTORS) {
                assertEncryptedRefused(name, bytes)
                continue
            }
            assertVerifyOutcome(name, v.getAsJsonObject("expected"), verify(bytes, allowlist))
        }
    }

    /**
     * Skill trust is DERIVED from the verify result, never read from the
     * capsule (spec/trust.md "Skill trust"). The same capsule bytes
     * classify differently at hosts with different allowlists, so each
     * vector in skill-trust/vectors.json pins its own trust
     * configuration: the per-vector `allowlist` names keypairs in
     * keys_file ([] = verify with no allowlist). A lane that surfaces the
     * fixture's own `skill_trust` manifest member as trust hands
     * prompt-injection text to a host LLM as trusted instructions — the
     * defect (A01) this collection keeps closed.
     */
    @Test
    fun skillTrustRegistryOutcomes() {
        val file = File(vectorsDir(), "skill-trust/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val keys = JsonParser.parseString(
            File(base, doc.get("keys_file").asString).readText()
        ).asJsonObject
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "skill-trust registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val allowlist = v.getAsJsonArray("allowlist").map { keyName ->
                keys.getAsJsonObject(keyName.asString)?.get("publicKey")?.asString
                    ?: error("$name: allowlist entry ${keyName.asString} not in keys_file")
            }.toSet()
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            assertVerifyOutcome(name, v.getAsJsonObject("expected"), verify(bytes, allowlist))
        }
    }

    /**
     * A JS-built capsule carrying Pith-truncated astral text must verify
     * here. A failure means this lane's canonicalization disagrees on
     * well-formed astral text — not that the capsule was tampered with
     * (spec/canonicalization.md, spec/pith.md).
     */
    @Test
    fun unicodeBoundaryRegistryOutcomes() {
        val file = File(vectorsDir(), "unicode-boundary/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "unicode-boundary registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            assertVerifyOutcome(name, v.getAsJsonObject("expected"), verify(bytes, allowlist))
        }
    }

    /**
     * Pith is opt-in authoring (spec/pith.md); its marker is an ordinary
     * member. technical-prose-verbatim: a default-built capsule whose
     * summary holds dots inside an identifier and decimals, stored
     * byte-identical, no marker. pith-normalized-marker: a pith-enabled
     * capsule whose event carries pith_normalized_fields (spec/chain.md),
     * covered by the event hash like any other member. Both MUST verify
     * ok:true; a failure means this lane rejects or re-projects an
     * optional event member — not tampering.
     */
    @Test
    fun pithAuthoringRegistryOutcomes() {
        val file = File(vectorsDir(), "pith-authoring/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "pith-authoring registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            assertVerifyOutcome(name, v.getAsJsonObject("expected"), verify(bytes, allowlist))
        }
    }

    /**
     * Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS
     * (spec/manifest.md "signer_commitment", spec/envelope.md "Signer set
     * binding"). A present manifest.signer_commitment must equal the
     * normalized envelope signer set exactly — strip / add / role-swap /
     * unsorted all fail closed; an absent one verifies with
     * signerSetBound=false. Duplicate (role, public_key) signers are
     * malformed, and the manifest originator must have a valid
     * role-"originator" signature.
     */
    @Test
    fun signerSetRegistryOutcomes() {
        val file = File(vectorsDir(), "signer-set/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "signer-set registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            assertVerifyOutcome(name, v.getAsJsonObject("expected"), verify(bytes, allowlist))
        }
    }

    /**
     * chain.md per-event field rules (verification steps 6 and 7). The
     * actor rule is conditional on the manifest's own claim: a non-empty
     * participants[] binds every event actor to the declared set or
     * system:host (fail-closed); an empty one verifies with
     * actorSetBound=false plus a note — absence is a weaker claim made
     * honestly. The kind enum is closed in every tier. All three
     * fixtures are cryptographically well-formed, so only these rules
     * decide them.
     */
    @Test
    fun chainRulesRegistryOutcomes() {
        val file = File(vectorsDir(), "chain-rules/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "chain-rules registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            assertVerifyOutcome(name, v.getAsJsonObject("expected"), verify(bytes, allowlist))
        }
    }

    /**
     * Unknown members in the hashed documents MUST be preserved and hashed
     * (spec/manifest.md "Unknown members", spec/envelope.md, spec/chain.md).
     * The positive vector carries x- extension members in manifest.json,
     * provenance/envelope.json, and a chain event, all covered by the
     * seal; the tampered variants mutate an unknown member post-seal and
     * must fail in the pinned area.
     */
    @Test
    fun unknownFieldsRegistryOutcomes() {
        val file = File(vectorsDir(), "unknown-fields/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "unknown-fields registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            assertVerifyOutcome(name, v.getAsJsonObject("expected"), verify(bytes, allowlist))
        }
    }

    /**
     * Empty-chain anchor rule + stored-line hashing (spec/chain.md "Empty
     * chains"). A chain with zero events is legal — the weakest honest
     * shape — and then manifest.first_event_hash, envelope.first_event_hash
     * and envelope.entry_hash MUST all be null (claiming an anchor over
     * zero events fails closed). The verifier must REPORT that no events
     * were walked (notes pin). An event whose stored bytes omit the
     * optional untrusted_payload_fields member must verify: the hash
     * preimage is the stored line, never a typed-struct round-trip.
     */
    @Test
    fun chainBindingRegistryOutcomes() {
        val file = File(vectorsDir(), "chain-binding/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "chain-binding registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            assertVerifyOutcome(name, v.getAsJsonObject("expected"), verify(bytes, allowlist))
        }
    }

    /**
     * Manifest claims must agree with the signed envelope, the chain, and
     * the files (spec/manifest.md, spec/envelope.md). Every fixture is
     * well-formed and correctly signed; only its semantics are wrong, so
     * nothing but an explicit cross-check catches it. The core module is
     * a plain-capsule (L2) verifier with no X25519/ChaCha20 path, so
     * vectors tagged `"requires": ["encryption"]` are skipped here, as
     * the registry's notes allow; unknown requirements fail loudly.
     */
    @Test
    fun semanticBindingRegistryOutcomes() {
        val file = File(vectorsDir(), "semantic-binding/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "semantic-binding registry is empty")
        var evaluated = 0
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            if (requiresUnimplementedCapability(v)) continue
            evaluated += 1
            val expected = v.getAsJsonObject("expected")
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            val result = verify(bytes, allowlist)
            assertVerifyOutcome(name, expected, result)
            if (expected.has("reason")) {
                val reason = expected.get("reason").asString
                val needle = VERIFY_REASON_NEEDLES[reason]
                    ?: error("$name: unknown verify-stage reason $reason")
                val haystack = result.checks.joinToString(" ") { "${it.name} ${it.detail}" }
                assertTrue(
                    haystack.contains(needle),
                    "$name: expected an error for reason $reason; got $haystack",
                )
            }
        }
        assertTrue(evaluated > 0, "every semantic-binding vector was skipped")
    }

    /**
     * Registry `requires` handling: vectors that need the "encryption"
     * capability are skipped by this plain-only lane. Any OTHER
     * requirement is unknown and fails loudly, so a new capability cannot
     * be silently skipped.
     */
    private fun requiresUnimplementedCapability(vector: JsonObject): Boolean {
        val requires = vector.getAsJsonArray("requires") ?: return false
        var skip = false
        for (req in requires) {
            when (val r = req.asString) {
                "encryption" -> skip = true
                else -> error("unknown requirement $r")
            }
        }
        return skip
    }

    /**
     * Manifest / chain document shape rules (spec/manifest.md field rules,
     * spec/chain.md). Open-stage vectors must be refused by the reader for
     * the named reason; verify-stage ones open but fail the pinned areas.
     * manifest-hostile-number is pinned by name: Gson parses 1e999 to a
     * non-finite double and JCS.assertAcceptable refuses it at the parse
     * gate, which spec/canonicalization.md blesses ("rejection may happen
     * at JSON parse time or at the canonicalization gate; both are
     * conforming") — so the canonicalization-gate wording pinned in
     * error_includes is asserted as a parse refusal here instead.
     */
    @Test
    fun malformedShapeRegistryOutcomes() {
        val file = File(vectorsDir(), "malformed-shape/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "malformed-shape registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val expected = v.getAsJsonObject("expected")
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            if (name in SHAPE_PARSE_REJECTED_VECTORS) {
                val result = verify(bytes, allowlist)
                assertFalse(result.ok, "$name: fixture must not verify")
                val parse = result.checks.firstOrNull { it.name == "parse" }
                assertEquals(false, parse?.ok, "$name: reader must refuse this container")
                continue
            }
            val declaredOpen = expected.has("stage") && expected.get("stage").asString == "open"
            if (declaredOpen) {
                val result = verify(bytes, allowlist)
                assertFalse(result.ok, "$name: open-stage fixture must not verify")
                val parse = result.checks.firstOrNull { it.name == "parse" }
                assertEquals(false, parse?.ok, "$name: reader must refuse this container; got ${result.checks}")
                val reason = expected.get("reason").asString
                val needles = openReasonNeedles(reason)
                assertTrue(
                    needles.any { parse!!.detail.contains(it) },
                    "$name: expected reason $reason (any of $needles); got ${parse!!.detail}",
                )
                continue
            }
            assertVerifyOutcome(name, expected, verify(bytes, allowlist))
        }
    }

    /**
     * spec/versioning.md: a capsule declaring a KNOWN format version
     * verifies under that era's rules with the observed version REPORTED
     * machine-readably; a well-formed unknown version is refused at open
     * with a diagnosis distinct from tamper detection (verifier-too-old
     * vs unknown-older), a grammar-violating one as malformed. The
     * unknown-version fixtures are internally coherent under their
     * declared version's domain strings, so only the version gate
     * refuses them. Even on refusal, the verify result still reports
     * the observed version (expected.observed_version pin).
     */
    @Test
    fun versionCompatRegistryOutcomes() {
        val file = File(vectorsDir(), "version-compat/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "version-compat registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val expected = v.getAsJsonObject("expected")
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            val result = verify(bytes, allowlist)
            val declaredOpen = expected.has("stage") && expected.get("stage").asString == "open"
            if (declaredOpen) {
                assertOpenRefusal(name, expected, result)
            } else {
                assertVerifyOutcome(name, expected, result)
            }
        }
    }

    /**
     * spec/profiles.md: a capsule may DECLARE the verification profile
     * that governs it. Absence in a 0.6/0.7 capsule means the default
     * profile v0.6-suite/1.0, permanently, and the explicit default is
     * exactly equivalent to absence. A declared pair outside this
     * verifier's table is refused at OPEN with `unsupported_profile` — a
     * limitation of the verifier, never a defect of the capsule —
     * disagreeing declarations with `profile_mismatch` (a defect), and a
     * shape/grammar violation as a malformed document. Every negative
     * fixture is internally coherent under default rules except for the
     * declaration under test, so a lane that skips the gate verifies it
     * ok=true and fails here.
     */
    @Test
    fun profileDeclarationRegistryOutcomes() {
        val file = File(vectorsDir(), "profile-declaration/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "profile-declaration registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val expected = v.getAsJsonObject("expected")
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            val result = verify(bytes, allowlist)
            if (expected.has("stage") && expected.get("stage").asString == "open") {
                assertOpenRefusal(name, expected, result)
            } else {
                assertVerifyOutcome(name, expected, result)
            }
        }
    }

    /**
     * spec/results.md: the normalized verdict surface. `expected.qualifiers`
     * is an EXACT array in the spec-defined order (x- vendor entries
     * stripped first), so cross-lane emission cannot drift by omission or
     * invention. Several vectors verify the SAME capsule bytes under
     * different host configurations — the per-vector `allowlist` and
     * `accept_versions` — because the host-relative qualifiers are facts
     * about THIS verification, which is exactly why they can never be
     * capsule members. The encrypted vector stays gated by
     * requires:["encryption"]: the registry gates what this plain-only
     * lane RUNS, while its runtime verdict for such a capsule
     * (`unsupported` / `unsupported_capability`) is pinned by
     * [assertEncryptedRefused].
     */
    @Test
    fun resultVocabularyRegistryOutcomes() {
        val file = File(vectorsDir(), "result-vocabulary/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val keys = JsonParser.parseString(
            File(base, doc.get("keys_file").asString).readText()
        ).asJsonObject
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "result-vocabulary registry is empty")
        var evaluated = 0
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            if (requiresUnimplementedCapability(v)) continue
            evaluated += 1
            val allowlist = v.getAsJsonArray("allowlist")?.map { keyName ->
                keys.getAsJsonObject(keyName.asString)?.get("publicKey")?.asString
                    ?: error("$name: allowlist entry ${keyName.asString} not in keys_file")
            }?.toSet() ?: emptySet()
            val acceptVersions = v.getAsJsonArray("accept_versions")
                ?.map { it.asString }?.toSet()
            val expected = v.getAsJsonObject("expected")
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            val result = CapsuleVerifier.verify(
                bytes = bytes, allowlist = allowlist, acceptVersions = acceptVersions)
            if (expected.has("stage") && expected.get("stage").asString == "open") {
                assertOpenRefusal(name, expected, result)
            } else {
                assertVerifyOutcome(name, expected, result)
            }
        }
        assertTrue(evaluated > 0, "every result-vocabulary vector was skipped")
    }

    @Test
    fun malformedRegistryOutcomes() {
        val file = File(vectorsDir(), "malformed-layout/vectors.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val base = file.parentFile
        val allowlist = registryAllowlist(doc, base)
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "malformed-layout registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val expected = v.getAsJsonObject("expected")
            val bytes = File(base, v.get("capsule_file").asString).readBytes()
            val declaredOpen = expected.has("stage") && expected.get("stage").asString == "open"
            if (declaredOpen || name in OPEN_REJECTED_VERIFY_VECTORS) {
                val result = verify(bytes, allowlist)
                assertFalse(result.ok, "$name: open-stage fixture must not verify")
                val parse = result.checks.firstOrNull { it.name == "parse" }
                assertEquals(false, parse?.ok, "$name: reader must refuse this container; got ${result.checks}")
                if (declaredOpen) {
                    val reason = expected.get("reason").asString
                    val needles = openReasonNeedles(reason)
                    assertTrue(
                        needles.any { parse!!.detail.contains(it) },
                        "$name: expected reason $reason (any of $needles); got ${parse!!.detail}",
                    )
                }
                continue
            }
            assertVerifyOutcome(name, expected, verify(bytes, allowlist))
        }
    }

    /**
     * JCS object-member ordering registry (RFC 8785 §3.2.3): members sort
     * on their UTF-16 code-unit sequences.
     *
     * AUDIT RESULT: this lane was already correct and needs no source
     * change. `sortedBy { it.first }` is `sortedWith(compareBy(selector))`,
     * whose comparator body is `compareValues(a, b)` ->
     * `(a as Comparable<Any>).compareTo(b)` -> `java.lang.String.compareTo`,
     * specified to compare `char` values — and a Java `char` IS a UTF-16
     * code unit. Contrast Rust (`str: Ord` is UTF-8 byte order == code-point
     * order) and Swift (`String: Comparable` is normalization-aware), both
     * of which needed fixes. These vectors pin the property so nobody
     * "improves" it into a `java.text.Collator` or a `codePoints()`
     * comparison.
     */
    @Test
    fun jcsKeyOrderRegistry() {
        val file = File(vectorsDir(), "jcs-key-order.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "jcs-key-order registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val keys = v.getAsJsonArray("keys").map { it.asString }
            val pairs: List<Pair<String, JCSValue>> =
                keys.mapIndexed { i, k -> k to JCSValue.Integer(i.toLong()) }
            val canon = JCS.bytes(JCSValue.Obj(pairs))
            assertEquals(v.get("canonical_utf8_hex").asString, CapsuleCrypto.bytesToHex(canon), name)
            assertEquals(v.get("sha256_hex").asString, CapsuleCrypto.sha256Hex(canon), name)
        }
    }

    /**
     * spec/canonicalization.md: the acceptance boundary is identical in
     * every lane. A reject vector is satisfied by refusal at parse time OR
     * at the canonicalization gate — whichever this lane reaches first.
     * Gson accepts lone-surrogate escapes, so in this lane both halves are
     * enforced by `JCS.assertAcceptable` inside `CapsuleReader.parseJson`.
     */
    @Test
    fun ijsonAcceptanceRegistry() {
        val reasons = setOf("integer_out_of_range", "unpaired_surrogate", "duplicate_member")
        val file = File(vectorsDir(), "ijson-acceptance.json")
        val doc = JsonParser.parseString(file.readText()).asJsonObject
        val vectors = doc.getAsJsonArray("vectors")
        assertTrue(vectors.size() > 0, "ijson-acceptance registry is empty")
        for (entry in vectors) {
            val v = entry.asJsonObject
            val name = v.get("name").asString
            val bytes = v.get("input_json").asString.toByteArray(Charsets.UTF_8)
            if (v.get("expect").asString == "accept") {
                assertEquals(
                    v.get("canonical").asString,
                    JCS.canonical(CapsuleReader.parseJson(bytes)),
                    name,
                )
                continue
            }
            val reason = v.get("reason").asString
            assertTrue(reasons.contains(reason), "$name: unknown reason $reason")
            assertFailsWith<IllegalArgumentException>(
                "$name: the value must never reach a hash"
            ) { CapsuleReader.parseJson(bytes) }
        }
    }

    /**
     * The comparator claim itself, independent of the vector file: the two
     * orderings genuinely differ, so `jcsKeyOrderRegistry` above is not
     * passing by coincidence.
     */
    @Test
    fun stringCompareToIsUtf16CodeUnitOrder() {
        val emoji = String(Character.toChars(0x1F600)) // D83D DE00
        val privateUse = String(Character.toChars(0xE000)) // E000
        assertTrue(
            emoji < privateUse,
            "String.compareTo must be UTF-16 code-unit order (RFC 8785 3.2.3)",
        )
        assertTrue(
            Character.codePointAt(emoji, 0) > Character.codePointAt(privateUse, 0),
            "...and must NOT be code-point order",
        )
    }

    private fun assertEncryptedRefused(name: String, bytes: ByteArray) {
        val result = verify(bytes, emptySet())
        assertFalse(result.ok, "$name: core is a plain-capsule verifier and must refuse it")
        val parse = result.checks.firstOrNull { it.name == "parse" }
        assertEquals(false, parse?.ok, "$name: expected a failing parse check; got ${result.checks}")
        assertTrue(
            parse!!.detail.contains("encrypted capsule"),
            "$name: expected the plain-only refusal; got ${parse.detail}",
        )
        // spec/results.md: this lane can parse the container but not
        // process the class, and another conforming lane verifies the same
        // bytes — so the refusal is a limitation of THIS verifier
        // ("unsupported"), never a claim that the capsule is corrupt.
        assertEquals("unsupported", result.verdict, "$name: verdict mismatch")
        assertEquals(
            "unsupported_capability", result.verdictReason,
            "$name: verdictReason mismatch",
        )
    }

    /**
     * An open-stage vector: the reader must refuse the capsule for the
     * pinned reason, and the fail-closed verify result must still REPORT
     * the observed facts (spec/versioning.md, spec/profiles.md) plus the
     * normalized verdict surface (spec/results.md) — what keeps "this
     * verifier is too old / lacks that profile" apart from "this capsule
     * is corrupt".
     */
    private fun assertOpenRefusal(
        name: String,
        expected: JsonObject,
        result: CapsuleVerification,
    ) {
        assertFalse(result.ok, "$name: open-stage fixture must not verify")
        val parse = result.checks.firstOrNull { it.name == "parse" }
        assertEquals(false, parse?.ok, "$name: reader must refuse this capsule; got ${result.checks}")
        val reason = expected.get("reason").asString
        val needles = openReasonNeedles(reason)
        assertTrue(
            needles.any { parse!!.detail.contains(it) },
            "$name: expected reason $reason (any of $needles); got ${parse!!.detail}",
        )
        assertResultVocabulary(name, expected, result)
    }

    /**
     * The normalized verdict surface (spec/results.md) and the profile
     * channel (spec/profiles.md). `qualifiers` is an EXACT array in the
     * spec-defined order, compared after stripping x- vendor entries:
     * omitting one is as much a failure as inventing one, which is what
     * makes the vocabulary portable rather than per-lane folklore.
     */
    private fun assertResultVocabulary(
        name: String,
        expected: JsonObject,
        result: CapsuleVerification,
    ) {
        if (expected.has("verdict")) {
            assertEquals(
                expected.get("verdict").asString, result.verdict, "$name: verdict mismatch")
        }
        if (expected.has("verdict_reason")) {
            assertEquals(
                nullableString(expected.get("verdict_reason")), result.verdictReason,
                "$name: verdictReason mismatch",
            )
        }
        if (expected.has("qualifiers")) {
            assertEquals(
                expected.getAsJsonArray("qualifiers").map { it.asString },
                result.qualifiers.filter { !it.startsWith("x-") },
                "$name: qualifiers mismatch",
            )
        }
        // spec/versioning.md: the observed version is a REPORTED fact even
        // when open is refused — what lets an auditor tell "this verifier
        // is too old" apart from "this capsule is corrupt".
        if (expected.has("observed_version")) {
            assertEquals(
                expected.get("observed_version").asString, result.formatVersion.observed,
                "$name: formatVersion.observed mismatch",
            )
        }
        if (expected.has("observed_profile")) {
            assertEquals(
                nullableString(expected.get("observed_profile")), result.profile.observed,
                "$name: profile.observed mismatch",
            )
        }
        if (expected.has("observed_profile_version")) {
            assertEquals(
                nullableString(expected.get("observed_profile_version")),
                result.profile.observedVersion,
                "$name: profile.observedVersion mismatch",
            )
        }
        // Suite honesty: the suite fact is nulled whenever the effective
        // profile is not the era default — including on a profile-gate
        // refusal, where reporting "v0.6" would assert something false
        // about rules this verifier never applied.
        if (expected.has("suite")) {
            assertEquals(
                nullableString(expected.get("suite")), result.formatVersion.suite,
                "$name: formatVersion.suite mismatch",
            )
        }
        if (!expected.has("profile")) return
        val members = mapOf<String, Any?>(
            "observed" to result.profile.observed,
            "observed_version" to result.profile.observedVersion,
            "declared" to result.profile.declared,
            "effective" to result.profile.effective,
            "effective_version" to result.profile.effectiveVersion,
            "supported" to result.profile.supported,
            "status" to result.profile.status,
        )
        for ((key, want) in expected.getAsJsonObject("profile").entrySet()) {
            if (key !in members) error("$name: unknown profile channel member $key")
            val expectedValue: Any? = when {
                want.isJsonNull -> null
                want.asJsonPrimitive.isBoolean -> want.asBoolean
                else -> want.asString
            }
            assertEquals(expectedValue, members[key], "$name: profile.$key mismatch")
        }
    }

    private fun nullableString(v: com.google.gson.JsonElement): String? =
        if (v.isJsonNull) null else v.asString

    private fun assertVerifyOutcome(
        name: String,
        expected: JsonObject,
        result: CapsuleVerification,
    ) {
        val expectedOk = expected.get("ok").asBoolean
        assertEquals(
            expectedOk, result.ok,
            "$name: expected ok=$expectedOk; failing checks: " +
                result.checks.filter { !it.ok }.joinToString { "${it.name}:${it.detail}" },
        )
        val failing = expected.getAsJsonArray("failing") ?: JsonArray()
        for (area in failing) {
            val checkName = AREA_CHECK[area.asString]
                ?: error("$name: unknown or unsupported failing area ${area.asString}")
            val check = result.checks.firstOrNull { it.name == checkName }
            assertEquals(
                false, check?.ok,
                "$name: expected $checkName to fail; got ${result.checks}",
            )
        }
        if (expected.has("error_includes")) {
            val needle = expected.get("error_includes").asString
            val haystack = result.checks.joinToString(" ") { "${it.name} ${it.detail}" }
            assertTrue(
                haystack.contains(needle),
                "$name: expected an error containing $needle; got $haystack",
            )
        }
        if (expected.has("signer_set_bound")) {
            assertEquals(
                expected.get("signer_set_bound").asBoolean, result.signerSetBound,
                "$name: signerSetBound mismatch",
            )
        }
        // Actor-set binding (chain.md step 6) follows the signer-set
        // contract: a non-empty manifest.participants[] binds the chain's
        // actors; an empty one must be REPORTED as unbound, never
        // rejected.
        if (expected.has("actor_set_bound")) {
            assertEquals(
                expected.get("actor_set_bound").asBoolean, result.actorSetBound,
                "$name: actorSetBound mismatch",
            )
        }
        // Honest-reporting pin: some rules require the verifier to REPORT
        // a weaker claim machine-readably, not just to pass/fail.
        if (expected.has("notes_includes")) {
            val needle = expected.get("notes_includes").asString
            assertTrue(
                result.notes.any { it.contains(needle) },
                "$name: expected a note containing $needle; got ${result.notes}",
            )
        }
        // Skill-trust derivation (spec/trust.md "Skill trust"): the tier
        // MUST come from the verify result — capsuleSigned plus the exact
        // per-id map — never from any skill_trust member in the capsule.
        if (expected.has("skill_trust")) {
            val want = expected.getAsJsonObject("skill_trust")
            assertEquals(
                want.get("capsule_signed").asBoolean, result.skillTrust.capsuleSigned,
                "$name: skillTrust.capsuleSigned mismatch",
            )
            val wantSkills = want.getAsJsonObject("skills")?.entrySet()
                ?.associate { it.key to it.value.asString } ?: emptyMap()
            assertEquals(
                wantSkills, result.skillTrust.skills,
                "$name: skillTrust.skills mismatch",
            )
        }
        assertResultVocabulary(name, expected, result)
    }

    private fun verify(bytes: ByteArray, allowlist: Set<String>): CapsuleVerification =
        CapsuleVerifier.verify(bytes = bytes, allowlist = allowlist)

    private fun registryAllowlist(doc: JsonObject, base: File): Set<String> {
        doc.get("originator_public_key_hex")?.let { return setOf(it.asString) }
        doc.get("keys_file")?.let {
            val keys = JsonParser.parseString(File(base, it.asString).readText()).asJsonObject
            return setOf(keys.getAsJsonObject("originator").get("publicKey").asString)
        }
        return emptySet()
    }

    /**
     * Per-lane mapping of the registry's normative open-stage reason
     * categories onto this lane's reader messages.
     */
    private fun openReasonNeedles(reason: String): List<String> = when (reason) {
        "missing_required_file" ->
            listOf("missing manifest.json", "missing provenance/envelope.json")
        "invalid_json" -> listOf("failed to parse manifest.json")
        // Every manifest shape error from CapsuleReader's validation is
        // prefixed with the offending field path (or names manifest.json
        // itself), mirroring the JS reference's validateManifestShape.
        // Profile declaration shape errors follow the same idiom and may
        // name either document (spec/profiles.md: the closed profile
        // object lives in both).
        "invalid_manifest_shape" -> listOf("manifest.", "envelope.")
        "duplicate_entry" -> listOf("duplicate entry")
        "unsafe_path" -> listOf("zip path traversal", "zip path: absolute")
        "unsupported_compression" -> listOf("only STORED supported")
        "symlink_entry" -> listOf("symlink")
        "directory_marker_shape" -> listOf(
            "directory attribute on non-directory name",
            "directory marker with nonzero size",
        )
        "local_central_name_mismatch" -> listOf("local/central name mismatch")
        // spec/versioning.md: unknown versions fail closed with a
        // diagnosis DISTINCT from malformation or tampering.
        "unsupported_version_newer" -> listOf("newer than this verifier supports")
        "unsupported_version_older" -> listOf("older than any version this verifier supports")
        // spec/profiles.md: a declared profile outside this verifier's
        // table is a LIMITATION OF THE VERIFIER (never corruption);
        // disagreeing manifest/envelope declarations are a capsule defect,
        // diagnosed before any table lookup.
        "unsupported_profile" -> listOf("is not supported by this verifier")
        "profile_mismatch" -> listOf("envelope.profile does not match manifest.format.profile")
        else -> error("unknown open-stage reason $reason")
    }

    companion object {

        /**
         * Per-lane mapping of the registry's normative verify-stage reason
         * categories (semantic-binding/vectors.json) onto this lane's
         * check details.
         */
        private val VERIFY_REASON_NEEDLES = mapOf(
            "first_event_hash_binding" to "manifest.first_event_hash mismatch",
            "encryption_shape" to "manifest.encryption must be",
            "encryption_metadata_path" to "manifest.encryption.metadata_path",
            "cipher_without_blob" to "plain capsule must have cipher='none'",
            "blob_without_cipher" to "encrypted blob present but envelope.",
        )

        /** Registry `failing` area → this lane's check name. */
        private val AREA_CHECK = mapOf(
            "content_index" to "content_index_hash",
            "chain" to "chain",
            "envelope" to "envelope_signature",
            "signer_set" to "signer_commitment",
            "originator_binding" to "originator_binding",
        )

        /**
         * Encrypted fixtures. The core module is a plain-capsule (L2)
         * verifier: it has no X25519/ChaCha20 path and `CapsuleReader.parse`
         * refuses any capsule whose SIGNED envelope.cipher is not "none"
         * while a `content.enc` blob is present (never the manifest's own
         * claim). Refusing is strictly stronger than the registry's
         * expectation for `clean-encrypted` (ok=true), so these are
         * asserted against the documented refusal instead. Pinned by name:
         * when this module grows an encryption path, drop the name here
         * and the registry expectation applies again.
         */
        private val ENCRYPTED_VECTORS = setOf("clean-encrypted", "tampered-blob")

        /**
         * Verify-stage vectors that THIS lane legitimately rejects at OPEN:
         * `CapsuleReader.parse` requires chain/events.jsonl and program.md
         * before it hands back a ParsedCapsule, so a capsule with a missing
         * or unparseable chain never reaches the per-area checks. Refusing
         * earlier is strictly stronger than the registry's ok=false
         * requirement. Pinned by name so a lane that starts *accepting* one
         * of these fails here.
         */
        private val OPEN_REJECTED_VERIFY_VECTORS = setOf("missing-chain", "invalid-chain-json")

        /**
         * Verify-stage vectors in malformed-shape that THIS lane refuses at
         * the parse gate (see malformedShapeRegistryOutcomes). Pinned by
         * name so a lane that starts ACCEPTING the value fails here.
         */
        private val SHAPE_PARSE_REJECTED_VECTORS = setOf("manifest-hostile-number")

        /** Walk up from the gradle module dir until we find spec/vectors. */
        private fun repoRoot(): File {
            var p: File? = File(System.getProperty("user.dir")).absoluteFile
            while (p != null) {
                if (File(p, "spec/vectors/tamper-detection/output/keys.json").exists()) return p
                p = p.parentFile
            }
            error(
                "could not locate repo root containing " +
                    "spec/vectors/tamper-detection/output/keys.json " +
                    "starting from ${System.getProperty("user.dir")}",
            )
        }

        private fun vectorsDir(): File = File(repoRoot(), "spec/vectors")
    }
}
