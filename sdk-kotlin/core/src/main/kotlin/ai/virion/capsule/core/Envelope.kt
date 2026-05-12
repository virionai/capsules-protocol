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

    fun signingInput(envelope: JCSValue, role: String): ByteArray {
        require(role.isNotEmpty())
        val domain = "capsule-provenance-v$VERSION:$role ".toByteArray(Charsets.UTF_8)
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
        val versionStr = (obj.pairs.firstOrNull { it.first == "version" }?.second as? JCSValue.Str)?.v
        if (versionStr != VERSION) return VerifyResult(false, emptyList(), "unsupported version")
        val cipher = (obj.pairs.firstOrNull { it.first == "cipher" }?.second as? JCSValue.Str)?.v
        if (cipher !in SUPPORTED_CIPHERS) return VerifyResult(false, emptyList(), "unsupported cipher")
        val signers = (obj.pairs.firstOrNull { it.first == "signers" }?.second as? JCSValue.Arr)?.items
            ?: return VerifyResult(false, emptyList(), "no signers")
        if (signers.isEmpty()) return VerifyResult(false, emptyList(), "envelope has no signers")
        var allValid = true
        val results = mutableListOf<Triple<String, String, Boolean>>()
        for (s in signers) {
            val sObj = s as? JCSValue.Obj ?: run { allValid = false; continue }
            val role = (sObj.pairs.firstOrNull { it.first == "role" }?.second as? JCSValue.Str)?.v
            val pk = (sObj.pairs.firstOrNull { it.first == "public_key" }?.second as? JCSValue.Str)?.v
            val sig = (sObj.pairs.firstOrNull { it.first == "signature" }?.second as? JCSValue.Str)?.v
            if (role == null || pk == null || sig == null) { allValid = false; continue }
            val input = signingInput(envelope, role)
            val valid = CapsuleCrypto.ed25519Verify(
                CapsuleCrypto.hexToBytes(pk), input, CapsuleCrypto.hexToBytes(sig)
            )
            if (!valid) allValid = false
            results += Triple(role, pk, valid)
        }
        return VerifyResult(allValid, results)
    }
}
