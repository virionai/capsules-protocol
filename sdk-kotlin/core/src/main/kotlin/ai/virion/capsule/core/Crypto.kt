// SHA-256 + Ed25519. Android 13+ ships Ed25519 in the platform JCA, but
// minSdk = 31 here so we register BouncyCastle once and use it for both
// keygen and sign/verify. This keeps behaviour identical across SDK 31..34.

package ai.virion.capsule.core

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Security
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

object CapsuleCrypto {
    init {
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }
    private val rng = SecureRandom()

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    fun sha256Hex(data: ByteArray): String = bytesToHex(sha256(data))

    fun bytesToHex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append(String.format("%02x", x))
        return sb.toString()
    }

    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "hex: odd length" }
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "hex: non-hex character" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        var n = 0
        for (p in parts) n += p.size
        val out = ByteArray(n)
        var off = 0
        for (p in parts) { System.arraycopy(p, 0, out, off, p.size); off += p.size }
        return out
    }

    /** Ed25519 keypair backed by BouncyCastle. Raw bytes are 32 / 32. */
    class Ed25519KeyPair(private val priv: Ed25519PrivateKeyParameters) {
        val publicKeyBytes: ByteArray get() = priv.generatePublicKey().encoded
        val publicKeyHex: String get() = bytesToHex(publicKeyBytes)
        val privateKeyBytes: ByteArray get() = priv.encoded

        fun sign(message: ByteArray): ByteArray {
            val s = Ed25519Signer()
            s.init(true, priv)
            s.update(message, 0, message.size)
            return s.generateSignature()
        }
    }

    fun generateEd25519(): Ed25519KeyPair {
        val priv = Ed25519PrivateKeyParameters(rng)
        return Ed25519KeyPair(priv)
    }

    fun ed25519FromRawPrivate(raw: ByteArray): Ed25519KeyPair {
        require(raw.size == 32) { "Ed25519 priv: 32 bytes required" }
        return Ed25519KeyPair(Ed25519PrivateKeyParameters(raw, 0))
    }

    fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        return try {
            val pub = Ed25519PublicKeyParameters(publicKey, 0)
            val v = Ed25519Signer()
            v.init(false, pub)
            v.update(message, 0, message.size)
            v.verifySignature(signature)
        } catch (_: Throwable) { false }
    }
}
