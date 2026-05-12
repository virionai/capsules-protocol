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
    val trustedSignerCount: Int,
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
                signers = emptyList(), trustedSignerCount = 0, notes = notes,
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

        val indexInputs = parsed.files
            .filter { it.key !in Manifest.CONTENT_INDEX_EXCLUDED }
            .map { it.key to it.value }
        val ci = Manifest.buildContentIndex(indexInputs)
        val storedIdxMf = CapsuleReader.lookupString(parsed.manifest, listOf("content_index", "index_hash"))
        val storedIdxEnv = CapsuleReader.lookupString(parsed.envelope, listOf("content_index_hash"))
        rec("content_index_hash",
            ci.indexHash == storedIdxMf && ci.indexHash == storedIdxEnv,
            ci.indexHash.take(12) + "…")

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

        val ok = checks.all { it.ok }
        return CapsuleVerification(
            ok = ok, level = "L2", checks = checks,
            signers = signers, trustedSignerCount = signers.count { it.trusted },
            notes = notes,
        )
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
