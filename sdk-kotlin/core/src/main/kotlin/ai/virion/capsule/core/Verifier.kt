// CapsuleVerifier — the canonical surface for verifying a sealed capsule.
//
// Mirrors sdk/src/verifier.js's verifyCapsule. Returns per-check booleans
// plus per-signer trust attribution against an optional allowlist of
// public keys. trusted=true only when both the signature is valid AND
// the signer's pubkey is on the allowlist.

package ai.virion.capsule.core

data class CapsuleVerification(
    val ok: Boolean,
    val level: String,                                  // "L2"
    val checks: List<VerifyCheck>,
    val signers: List<SignerCheck>,
    /**
     * Number of DISTINCT public keys that are both valid and on the
     * allowlist — never signer rows (the same key under two roles is one
     * trusted key).
     */
    val trustedSignerCount: Int,
    /**
     * Signer-set binding (manifest.signer_commitment): PRESENCE BINDS,
     * ABSENCE REPORTS. `true` means the manifest commits to the exact
     * signer set (the `signer_commitment` check reflects the match,
     * fail-closed); `false` means the capsule does not assert signer-set
     * integrity — verification can still succeed, at a visibly lower
     * assurance.
     */
    val signerSetBound: Boolean,
    val notes: List<String>,
) {
    data class SignerCheck(
        val role: String,
        val publicKey: String,
        val valid: Boolean,
        val trusted: Boolean,
    )
}

object CapsuleVerifier {
    fun verify(bytes: ByteArray, allowlist: Set<String> = emptySet()): CapsuleVerification {
        val checks = mutableListOf<VerifyCheck>()
        fun rec(name: String, ok: Boolean, detail: String = "") {
            checks += VerifyCheck(name, ok, detail)
        }
        val notes = mutableListOf<String>()
        if (allowlist.isEmpty()) {
            notes += "no allowlist provided; trusted=false for all signers regardless of signature validity"
        }

        val parsed = try { CapsuleReader.parse(bytes) } catch (e: Throwable) {
            return CapsuleVerification(
                ok = false, level = "L2",
                checks = listOf(VerifyCheck("parse", false, e.message ?: "$e")),
                signers = emptyList(), trustedSignerCount = 0,
                signerSetBound = false, notes = notes,
            )
        }
        rec("zip_parse", true, "${parsed.files.size} files")
        rec("json_parse", true)

        val pubHex = CapsuleReader.lookupString(parsed.manifest, listOf("originator", "public_key"))
        val firstHash = CapsuleReader.lookupString(parsed.manifest, listOf("first_event_hash"))
        val mfId = CapsuleReader.lookupString(parsed.manifest, listOf("id"))
        val envId = CapsuleReader.lookupString(parsed.envelope, listOf("capsule_id"))
        if (pubHex != null && firstHash != null && mfId != null && envId != null) {
            val expected = Manifest.computeCapsuleId(CapsuleCrypto.hexToBytes(pubHex), firstHash)
            rec("capsule_id", expected == mfId && expected == envId, expected.take(12) + "…")
        } else rec("capsule_id", false, "missing fields")

        val mh = Manifest.hash(parsed.manifest)
        val storedMh = CapsuleReader.lookupString(parsed.envelope, listOf("manifest_hash"))
        rec("manifest_hash", mh == storedMh, mh.take(12) + "…")

        // `content.enc` drops out of the index only when the SIGNED envelope
        // declares a cipher (it is bound instead by
        // envelope.encrypted_blob_hash). Keying off file presence would let
        // an attacker append a stray blob to a signed plain capsule and have
        // it excluded for free; keying off the signed cipher means the stray
        // blob is indexed here and fails verification. See spec/manifest.md.
        val indexCipher = CapsuleReader.lookupString(parsed.envelope, listOf("cipher")) ?: "none"
        val excluded = Manifest.contentIndexExclusions(indexCipher != "none")
        val indexInputs = parsed.files
            .filter { it.key !in excluded }
            .map { it.key to it.value }
        val ci = Manifest.buildContentIndex(indexInputs, excluded)
        // Per-file attribution, so a failing index names the offending paths
        // instead of only reporting a hash mismatch (mirrors the JS
        // reference's contentIndex.errors).
        val storedIndex = LinkedHashMap<String, String>()
        val storedRows = ((parsed.manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "content_index" }?.second as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "files" }?.second as? JCSValue.Arr
        storedRows?.items?.forEach { row ->
            val cols = (row as? JCSValue.Obj)?.pairs ?: return@forEach
            val path = (cols.firstOrNull { it.first == "path" }?.second as? JCSValue.Str)?.v
            val hash = (cols.firstOrNull { it.first == "sha256" }?.second as? JCSValue.Str)?.v
            if (path != null && hash != null) storedIndex[path] = hash
        }
        val indexProblems = mutableListOf<String>()
        for ((path, hash) in ci.files) {
            val want = storedIndex[path]
            if (want == null) indexProblems += "file present but not in manifest index: $path"
            else if (want != hash) indexProblems += "file hash mismatch: $path"
        }
        val recomputedPaths = ci.files.map { it.first }.toSet()
        for (path in storedIndex.keys.sorted()) {
            if (path !in recomputedPaths) {
                indexProblems += "file in manifest index but missing from package: $path"
            }
        }
        val storedIdxMf = CapsuleReader.lookupString(parsed.manifest, listOf("content_index", "index_hash"))
        val storedIdxEnv = CapsuleReader.lookupString(parsed.envelope, listOf("content_index_hash"))
        val indexHashesMatch = ci.indexHash == storedIdxMf && ci.indexHash == storedIdxEnv
        rec("content_index_hash",
            indexHashesMatch && indexProblems.isEmpty(),
            (listOf(ci.indexHash.take(12) + "…") + indexProblems).joinToString("; "))

        rec("chain", verifyChain(parsed.events), "${parsed.events.size} events")

        val firstEvHash = parsed.events.firstOrNull()?.let {
            CapsuleReader.lookupString(it, listOf("hash"))
        }
        val envFirst = CapsuleReader.lookupString(parsed.envelope, listOf("first_event_hash"))
        if (firstEvHash != null && envFirst != null) rec("first_event_hash", firstEvHash == envFirst)

        val lastEvHash = parsed.events.lastOrNull()?.let {
            CapsuleReader.lookupString(it, listOf("hash"))
        }
        val envEntry = CapsuleReader.lookupString(parsed.envelope, listOf("entry_hash"))
        if (lastEvHash != null && envEntry != null) rec("entry_hash", lastEvHash == envEntry)

        val env = Envelope.verifySignatures(parsed.envelope)
        val signers = env.signers.map { (role, pk, valid) ->
            CapsuleVerification.SignerCheck(
                role = role, publicKey = pk,
                valid = valid,
                trusted = valid && (pk.lowercase() in allowlist),
            )
        }
        val detail = signers.joinToString(", ") {
            "${it.role}:${if (it.valid) "ok" else "bad"}${if (it.trusted) " (trusted)" else ""}"
        }
        rec("envelope_signature", env.ok, if (detail.isEmpty()) (env.note ?: "") else detail)

        // Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS. A present
        // manifest.signer_commitment must equal the normalized envelope
        // signer set exactly (integrity invariant, fail-closed). An absent
        // commitment downgrades the reported assurance — it never fails
        // verification (templates and other writers make a weaker claim
        // honestly).
        val commitment = (parsed.manifest as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "signer_commitment" }?.second
        val signerSetBound = commitment != null
        if (commitment != null) {
            val scErrors = signerCommitmentErrors(commitment, parsed.envelope)
            rec(
                "signer_commitment",
                scErrors.isEmpty(),
                if (scErrors.isEmpty()) "exact membership matched" else scErrors.joinToString("; "),
            )
        } else {
            rec("signer_commitment", true, "absent (signer set not bound by seal)")
            notes += "manifest.signer_commitment absent: the signer set is not bound by the seal"
        }

        // Originator binding (invariant): the manifest names an originator
        // key — that key must actually have sealed the capsule with a valid
        // envelope signature under role "originator".
        val originatorKey = CapsuleReader
            .lookupString(parsed.manifest, listOf("originator", "public_key"))?.lowercase()
        val originatorSigned = env.signers.any { (role, pk, valid) ->
            role == "originator" && valid && pk.lowercase() == originatorKey
        }
        rec(
            "originator_binding", originatorSigned,
            if (originatorSigned) ""
            else "originator binding: manifest.originator.public_key " +
                "${originatorKey ?: "(missing)"} has no valid envelope signature " +
                "with role 'originator'",
        )

        val ok = checks.all { it.ok }
        return CapsuleVerification(
            ok = ok, level = "L2", checks = checks,
            signers = signers,
            // DISTINCT trusted keys, never rows.
            trustedSignerCount = signers.filter { it.trusted }
                .map { it.publicKey.lowercase() }.toSet().size,
            signerSetBound = signerSetBound,
            notes = notes,
        )
    }

    /**
     * Validate a stored signer_commitment against the envelope's signer
     * set. Returns the failure messages (empty = bound and matched).
     * Rules: spec/manifest.md "signer_commitment".
     */
    private fun signerCommitmentErrors(commitment: JCSValue, envelope: JCSValue): List<String> {
        val list = (commitment as? JCSValue.Arr)?.items
            ?: return listOf(
                "manifest.signer_commitment malformed: must be a non-empty array of {role, public_key}"
            )
        if (list.isEmpty()) {
            return listOf("manifest.signer_commitment malformed: must not be empty when present")
        }
        val problems = mutableListOf<String>()
        val members = mutableListOf<Pair<String, String>>() // (public_key, role)
        val keyHex = Regex("^[0-9a-f]{64}$")
        for ((i, m) in list.withIndex()) {
            val pairs = (m as? JCSValue.Obj)?.pairs
            if (pairs == null) {
                problems += "manifest.signer_commitment malformed: member $i is not an object"
                continue
            }
            val role = (pairs.firstOrNull { it.first == "role" }?.second as? JCSValue.Str)?.v
            val key = (pairs.firstOrNull { it.first == "public_key" }?.second as? JCSValue.Str)?.v
            if (pairs.map { it.first }.sorted() != listOf("public_key", "role") ||
                role == null || key == null
            ) {
                problems += "manifest.signer_commitment malformed: member $i must carry exactly {role, public_key}"
                continue
            }
            if (role.isEmpty()) {
                problems += "manifest.signer_commitment malformed: member $i: role must be a non-empty string"
            }
            if (!keyHex.matches(key)) {
                problems += "manifest.signer_commitment malformed: member $i: public_key must be lowercase 64-hex"
            }
            members += key to role
        }
        if (problems.isNotEmpty()) return problems
        for (i in 1 until members.size) {
            val a = members[i - 1]
            val b = members[i]
            if (a == b) {
                problems += "manifest.signer_commitment malformed: duplicate member " +
                    "(role=${b.second}, public_key=${b.first})"
            } else if (a.first > b.first || (a.first == b.first && a.second > b.second)) {
                problems += "manifest.signer_commitment malformed: members not sorted " +
                    "ascending by (public_key, role)"
                break
            }
        }
        if (problems.isNotEmpty()) return problems

        // Normalized envelope signer set, sorted the same way.
        val signersArr = ((envelope as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "signers" }?.second as? JCSValue.Arr)?.items.orEmpty()
        val actual = signersArr.map { s ->
            val pairs = (s as? JCSValue.Obj)?.pairs.orEmpty()
            val role = (pairs.firstOrNull { it.first == "role" }?.second as? JCSValue.Str)?.v ?: ""
            val key = (pairs.firstOrNull { it.first == "public_key" }?.second as? JCSValue.Str)?.v
                ?.lowercase() ?: ""
            key to role
        }.sortedWith(compareBy({ it.first }, { it.second }))

        // Merge-walk both sorted member lists; name every difference.
        val errors = mutableListOf<String>()
        var i = 0
        var j = 0
        while (i < members.size || j < actual.size) {
            val cmp = when {
                i >= members.size -> 1
                j >= actual.size -> -1
                else -> compareValuesBy(members[i], actual[j], { it.first }, { it.second })
            }
            when {
                cmp == 0 -> { i++; j++ }
                cmp < 0 -> {
                    val (key, role) = members[i]; i++
                    errors += "signer_commitment mismatch: no envelope signer matches " +
                        "committed member (role=$role, public_key=$key)"
                }
                else -> {
                    val (key, role) = actual[j]; j++
                    errors += "signer_commitment mismatch: envelope signer not committed " +
                        "(role=$role, public_key=$key)"
                }
            }
        }
        return errors
    }

    private fun verifyChain(events: List<JCSValue>): Boolean {
        var prev = Chain.GENESIS_PREV
        events.forEachIndexed { i, e ->
            val obj = e as? JCSValue.Obj ?: return false
            var stored: String? = null
            val withoutHash = mutableListOf<Pair<String, JCSValue>>()
            for ((k, v) in obj.pairs) {
                if (k == "hash" && v is JCSValue.Str) stored = v.v
                else withoutHash += k to v
            }
            val storedHash = stored ?: return false
            val prevHex = (obj.pairs.firstOrNull { it.first == "prev_hash" }?.second
                as? JCSValue.Str)?.v ?: return false
            if (i == 0 && prevHex != CapsuleCrypto.bytesToHex(Chain.GENESIS_PREV)) return false
            if (i > 0 && prevHex != CapsuleCrypto.bytesToHex(prev)) return false
            val canonical = JCS.bytes(JCSValue.Obj(withoutHash))
            val h = CapsuleCrypto.sha256(CapsuleCrypto.concat(prev, canonical))
            if (CapsuleCrypto.bytesToHex(h) != storedHash) return false
            prev = h
        }
        return true
    }
}
