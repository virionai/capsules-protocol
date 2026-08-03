// Manifest construction + capsule_id derivation.

package ai.virion.capsule.core

object Manifest {
    /**
     * Excluded from content_index.files by structural necessity, for every
     * capsule regardless of profile: manifest.json (the index lives inside
     * it) and provenance/envelope.json (it commits to the index hash).
     */
    val STRUCTURAL_EXCLUDED = setOf("manifest.json", "provenance/envelope.json")

    /**
     * `content.enc` is excluded from the content index ONLY for encrypted
     * capsules, where it is bound separately by
     * `envelope.encrypted_blob_hash`. In a plain capsule (`cipher: "none"`)
     * a `content.enc` entry MUST be indexed like any other file, so a signed
     * plain capsule cannot carry an unaccounted-for blob past verification
     * (spec/manifest.md).
     */
    val CONTENT_INDEX_EXCLUDED = STRUCTURAL_EXCLUDED + "content.enc"

    /**
     * Choose the content-index exclusion set for the capsule's profile.
     * [encrypted] must be derived from the SIGNED `envelope.cipher`, never
     * from the presence of a `content.enc` file.
     */
    fun contentIndexExclusions(encrypted: Boolean): Set<String> =
        if (encrypted) CONTENT_INDEX_EXCLUDED else STRUCTURAL_EXCLUDED
    fun computeCapsuleId(
        originatorPub: ByteArray,
        firstEventHashHex: String,
        version: String = CapsuleVersions.CURRENT,
    ): String {
        require(originatorPub.size == 32) { "originator pubkey must be 32 bytes" }
        require(firstEventHashHex.length == 64) { "first_event_hash must be 64-hex" }
        val first = CapsuleCrypto.hexToBytes(firstEventHashHex)
        // Domain keyed by the capsule's DECLARED version
        // (spec/versioning.md "Version-keyed domain separation").
        return CapsuleCrypto.sha256Hex(
            CapsuleCrypto.concat(CapsuleVersions.idDomain(version), originatorPub, first))
    }

    data class ContentIndex(
        val files: List<Pair<String, String>>,   // (path, sha256)
        val indexHash: String,
    )

    fun buildContentIndex(
        files: List<Pair<String, ByteArray>>,
        excluded: Set<String> = STRUCTURAL_EXCLUDED,
    ): ContentIndex {
        val entries = files
            .filter { it.first !in excluded }
            .map { it.first to CapsuleCrypto.sha256Hex(it.second) }
            .sortedBy { it.first }
        val arr = JCSValue.Arr(entries.map { (p, h) ->
            JCSValue.Obj(listOf("path" to JCSValue.Str(p), "sha256" to JCSValue.Str(h)))
        })
        val indexHash = CapsuleCrypto.sha256Hex(JCS.bytes(arr))
        return ContentIndex(entries, indexHash)
    }

    data class Originator(val publicKeyHex: String, val label: String)
    data class Participant(val actorId: String, val role: String, val label: String)

    /**
     * One member of `manifest.signer_commitment`: the exact seal-time
     * signer set, sorted ascending by (publicKeyHex, role). Bound into
     * every envelope signature via manifest_hash (spec/manifest.md).
     */
    data class SignerCommitmentMember(val role: String, val publicKeyHex: String)

    /**
     * Build a well-formed signer_commitment from seal-time members: sorts
     * ascending by (public_key, role) and throws on duplicate
     * (role, public_key) pairs — the same key under different roles is
     * permitted as distinct members.
     */
    fun buildSignerCommitment(
        members: List<SignerCommitmentMember>,
    ): List<SignerCommitmentMember> {
        val sorted = members
            .map { SignerCommitmentMember(it.role, it.publicKeyHex.lowercase()) }
            .sortedWith(compareBy({ it.publicKeyHex }, { it.role }))
        for (i in 1 until sorted.size) {
            require(sorted[i - 1] != sorted[i]) {
                "duplicate signer (role=${sorted[i].role}, public_key=${sorted[i].publicKeyHex})"
            }
        }
        return sorted
    }

    /**
     * `signerCommitment` is the exact seal-time signer set. Pass members
     * through [buildSignerCommitment] first; an empty list omits the
     * manifest member entirely (templates and other unsigned tiers
     * legitimately omit it — but a capsule sealed by this SDK always
     * carries it). JCS sorts keys at serialization time, so the member's
     * position in the pair list is irrelevant to the canonical bytes.
     */
    fun build(
        originator: Originator,
        participants: List<Participant>,
        contentIndex: ContentIndex,
        firstEventHash: String,
        encryption: JCSValue = JCSValue.Null,
        signerCommitment: List<SignerCommitmentMember> = emptyList(),
        createdAt: String,
        capsuleId: String,
    ): JCSValue {
        val commitmentPairs = if (signerCommitment.isEmpty()) emptyList() else listOf(
            "signer_commitment" to JCSValue.Arr(signerCommitment.map { m ->
                JCSValue.Obj(listOf(
                    "role" to JCSValue.Str(m.role),
                    "public_key" to JCSValue.Str(m.publicKeyHex),
                ))
            })
        )
        return JCSValue.Obj(listOf(
            "format" to JCSValue.Obj(listOf(
                // The ONE sealing version (spec/versioning.md): every
                // other version-keyed value in the seal path must agree
                // with this declaration.
                "version" to JCSValue.Str(CapsuleVersions.CURRENT),
                "container" to JCSValue.Str("zip"),
                "canonicalization" to JCSValue.Str("JCS-RFC8785"),
                "hash_algorithm" to JCSValue.Str("SHA-256"),
            )),
            "id" to JCSValue.Str(capsuleId),
            "originator" to JCSValue.Obj(listOf(
                "public_key" to JCSValue.Str(originator.publicKeyHex),
                "label" to JCSValue.Str(originator.label),
            )),
            "participants" to JCSValue.Arr(participants.map {
                JCSValue.Obj(listOf(
                    "actor_id" to JCSValue.Str(it.actorId),
                    "role" to JCSValue.Str(it.role),
                    "label" to JCSValue.Str(it.label),
                ))
            }),
            "first_event_hash" to JCSValue.Str(firstEventHash),
            "content_index" to JCSValue.Obj(listOf(
                "files" to JCSValue.Arr(contentIndex.files.map { (p, h) ->
                    JCSValue.Obj(listOf("path" to JCSValue.Str(p), "sha256" to JCSValue.Str(h)))
                }),
                "index_hash" to JCSValue.Str(contentIndex.indexHash),
            )),
            "encryption" to encryption,
            "created_at" to JCSValue.Str(createdAt),
        ) + commitmentPairs)
    }

    fun hash(manifest: JCSValue): String = CapsuleCrypto.sha256Hex(JCS.bytes(manifest))
    fun bytes(manifest: JCSValue): ByteArray = JCS.bytes(manifest)
}
