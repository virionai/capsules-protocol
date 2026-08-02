// Provenance envelope: build, sign, verify.

package ai.virion.capsule.core

object Envelope {
    const val VERSION = "0.6"
    val SUPPORTED_CIPHERS = setOf("none", "ChaCha20-Poly1305")

    data class Signer(val role: String, val keyPair: CapsuleCrypto.Ed25519KeyPair)

    fun build(
        capsuleId: String,
        firstEventHash: String,
        entryHash: String,
        manifestHash: String,
        contentIndexHash: String,
        encryptedBlobHash: String? = null,
        cipher: String = "none",
        signedAt: String,
    ): JCSValue {
        require(cipher in SUPPORTED_CIPHERS) { "unsupported cipher: $cipher" }
        if (cipher == "none") require(encryptedBlobHash == null)
        else require(encryptedBlobHash?.length == 64)
        return JCSValue.Obj(listOf(
            "version" to JCSValue.Str(VERSION),
            "capsule_id" to JCSValue.Str(capsuleId),
            "first_event_hash" to JCSValue.Str(firstEventHash),
            "entry_hash" to JCSValue.Str(entryHash),
            "manifest_hash" to JCSValue.Str(manifestHash),
            "content_index_hash" to JCSValue.Str(contentIndexHash),
            "encrypted_blob_hash" to (encryptedBlobHash?.let { JCSValue.Str(it) } ?: JCSValue.Null),
            "cipher" to JCSValue.Str(cipher),
            "signed_at" to JCSValue.Str(signedAt),
            "signers" to JCSValue.Arr(emptyList()),
        ))
    }

    private fun canonicalPayload(envelope: JCSValue): ByteArray {
        val obj = envelope as JCSValue.Obj
        return JCS.bytes(JCSValue.Obj(obj.pairs.filterNot { it.first == "signers" }))
    }

    /**
     * `domain_sep || canonical(envelope_minus_signers)` — the signing
     * input. The domain embeds the envelope's DECLARED version — keyed
     * selection per spec/versioning.md, so an older era's signatures
     * stay verifiable under that era's domain forever. (Whether the
     * declared version is one this verifier knows is gated earlier.)
     */
    fun signingInput(envelope: JCSValue, role: String): ByteArray {
        require(role.isNotEmpty())
        val version = ((envelope as? JCSValue.Obj)?.pairs
            ?.firstOrNull { it.first == "version" }?.second as? JCSValue.Str)?.v
            ?: CapsuleVersions.CURRENT
        val domain = CapsuleVersions.provenanceDomain(version, role)
        return CapsuleCrypto.concat(domain, canonicalPayload(envelope))
    }

    fun sign(envelope: JCSValue, signers: List<Signer>): JCSValue {
        val obj = envelope as JCSValue.Obj
        val sigIdx = obj.pairs.indexOfFirst { it.first == "signers" }
        require(sigIdx >= 0) { "envelope missing signers field" }
        val existing = obj.pairs[sigIdx].second as JCSValue.Arr
        require(existing.items.isEmpty()) { "envelope already has signers" }
        val signed = signers.map { s ->
            val input = signingInput(envelope, s.role)
            val sig = s.keyPair.sign(input)
            JCSValue.Obj(listOf(
                "role" to JCSValue.Str(s.role),
                "public_key" to JCSValue.Str(s.keyPair.publicKeyHex),
                "signature" to JCSValue.Str(CapsuleCrypto.bytesToHex(sig)),
            ))
        }
        val mutated = obj.pairs.toMutableList()
        mutated[sigIdx] = "signers" to JCSValue.Arr(signed)
        return JCSValue.Obj(mutated)
    }

    data class VerifyResult(
        val ok: Boolean,
        val signers: List<Triple<String, String, Boolean>>, // role, pkHex, valid
        val note: String? = null,
    )

    fun verifySignatures(envelope: JCSValue): VerifyResult {
        val obj = envelope as? JCSValue.Obj
            ?: return VerifyResult(false, emptyList(), "envelope is not an object")
        // Any KNOWN version verifies under its own era's domain strings;
        // an unknown one fails closed with the standard distinguishable
        // diagnosis (spec/versioning.md), never a tamper-flavored one.
        val versionStr = (obj.pairs.firstOrNull { it.first == "version" }?.second as? JCSValue.Str)?.v
        when (val status = CapsuleVersions.classify(versionStr)) {
            CapsuleVersions.Status.KNOWN -> Unit
            CapsuleVersions.Status.INVALID ->
                return VerifyResult(false, emptyList(), "unsupported version")
            else -> return VerifyResult(
                false, emptyList(),
                CapsuleVersions.unsupportedMessage("envelope.version", versionStr!!, status),
            )
        }
        val cipher = (obj.pairs.firstOrNull { it.first == "cipher" }?.second as? JCSValue.Str)?.v
        if (cipher !in SUPPORTED_CIPHERS) return VerifyResult(false, emptyList(), "unsupported cipher")
        val signers = (obj.pairs.firstOrNull { it.first == "signers" }?.second as? JCSValue.Arr)?.items
            ?: return VerifyResult(false, emptyList(), "no signers")
        if (signers.isEmpty()) return VerifyResult(false, emptyList(), "envelope has no signers")
        // Duplicate (role, public_key) entries are malformed: counting rows
        // instead of distinct members lets one key satisfy an M-of-N policy.
        // Same key under different roles is permitted (distinct members).
        val seen = mutableSetOf<Pair<String, String>>()
        for (s in signers) {
            val sObj = s as? JCSValue.Obj ?: continue
            val role = (sObj.pairs.firstOrNull { it.first == "role" }?.second as? JCSValue.Str)?.v ?: ""
            val pk = (sObj.pairs.firstOrNull { it.first == "public_key" }?.second as? JCSValue.Str)?.v ?: ""
            if (!seen.add(role to pk.lowercase())) {
                return VerifyResult(
                    false, emptyList(),
                    "duplicate signer entry (role=$role, public_key=$pk)",
                )
            }
        }
        var allValid = true
        val results = mutableListOf<Triple<String, String, Boolean>>()
        for (s in signers) {
            val sObj = s as? JCSValue.Obj ?: run { allValid = false; continue }
            val role = (sObj.pairs.firstOrNull { it.first == "role" }?.second as? JCSValue.Str)?.v
            val pk = (sObj.pairs.firstOrNull { it.first == "public_key" }?.second as? JCSValue.Str)?.v
            val sig = (sObj.pairs.firstOrNull { it.first == "signature" }?.second as? JCSValue.Str)?.v
            if (role == null || pk == null || sig == null) { allValid = false; continue }
            // Hex strings on the wire are attacker-controlled — a malformed
            // (or non-canonical uppercase) key or signature is an INVALID
            // signature, never an exception through verify(). The signing
            // input itself can also refuse canonicalization; same idiom.
            val valid = try {
                val input = signingInput(envelope, role)
                CapsuleCrypto.ed25519Verify(
                    CapsuleCrypto.hexToBytes(pk), input, CapsuleCrypto.hexToBytes(sig)
                )
            } catch (_: IllegalArgumentException) {
                false
            }
            if (!valid) allValid = false
            results += Triple(role, pk, valid)
        }
        return VerifyResult(allValid, results)
    }
}
