// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.crypto

import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.hybrid.HpkeParameters
import com.google.crypto.tink.hybrid.HpkePrivateKey
import com.google.crypto.tink.hybrid.HpkePublicKey
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.subtle.Ed25519Sign
import com.google.crypto.tink.subtle.Ed25519Verify
import com.google.crypto.tink.subtle.Hkdf
import com.google.crypto.tink.subtle.X25519
import com.google.crypto.tink.util.Bytes
import com.google.crypto.tink.util.SecretBytes
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * [Crypto] on the JVM. Tink's own code does Ed25519, X25519, HKDF and HPKE; the JDK does
 * SHA-2, AES-GCM and randomness.
 *
 * Verification is Tink's own Java code, named directly, as PROTOCOL.md Appendix C requires:
 * Tink's keyset path, and the JDK's `Signature.getInstance("Ed25519")`, hand it to whichever
 * provider is installed, which could be Bouncy Castle.
 */
class JvmCrypto : Crypto {
    private val random = SecureRandom()

    override suspend fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    override suspend fun sha512(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(data)

    override suspend fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray =
        Hkdf.computeHkdf("HMACSHA256", ikm, salt, info, length)

    override suspend fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        gcm(Cipher.ENCRYPT_MODE, key, nonce, aad).doFinal(plaintext)

    override suspend fun aesGcmOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray? =
        try {
            gcm(Cipher.DECRYPT_MODE, key, nonce, aad).doFinal(ciphertext)
        } catch (_: GeneralSecurityException) {
            null
        }

    override suspend fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        return try {
            Ed25519Verify(publicKey).verify(signature, message)
            true
        } catch (_: GeneralSecurityException) {
            false
        }
    }

    override suspend fun ed25519(seed: ByteArray): SigningKey {
        require(seed.size == 32) { "an Ed25519 seed is 32 bytes" }
        val signer = Ed25519Sign(seed)
        val pub = Ed25519Sign.KeyPair.newKeyPairFromSeed(seed).publicKey
        return object : SigningKey {
            override val publicKey: ByteArray get() = pub.copyOf()

            override suspend fun sign(message: ByteArray): ByteArray = signer.sign(message)
        }
    }

    override suspend fun x25519(privateKey: ByteArray): HpkeKey {
        require(privateKey.size == 32) { "an X25519 private key is 32 bytes" }
        val pub = X25519.publicFromPrivate(privateKey)
        val decrypt = KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                    HpkePrivateKey.create(
                        hpkePublic(pub),
                        SecretBytes.copyFrom(privateKey, InsecureSecretKeyAccess.get()),
                    ),
                ).withRandomId().makePrimary(),
            )
            .build()
            .getPrimitive(RegistryConfiguration.get(), HybridDecrypt::class.java)
        return object : HpkeKey {
            override val publicKey: ByteArray get() = pub.copyOf()

            override suspend fun open(enc: ByteArray, info: ByteArray, ciphertext: ByteArray): ByteArray? {
                if (enc.size != 32) return null
                return try {
                    decrypt.decrypt(enc + ciphertext, info)
                } catch (_: GeneralSecurityException) {
                    null
                }
            }
        }
    }

    override suspend fun hpkeSeal(publicKey: ByteArray, info: ByteArray, plaintext: ByteArray): HpkeSealed {
        val sealed = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hpkePublic(publicKey)).withRandomId().makePrimary())
            .build()
            .getPrimitive(RegistryConfiguration.get(), HybridEncrypt::class.java)
            .encrypt(plaintext, info)
        return HpkeSealed(sealed.copyOfRange(0, 32), sealed.copyOfRange(32, sealed.size))
    }

    override fun randomBytes(length: Int): ByteArray = ByteArray(length).also(random::nextBytes)

    private fun gcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray): Cipher {
        require(key.size == 32 && nonce.size == 12) { "AES-256-GCM takes a 32-byte key and a 12-byte nonce" }
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
        }
    }

    private fun hpkePublic(key: ByteArray): HpkePublicKey = HpkePublicKey.create(SUITE, Bytes.copyFrom(key), null)

    private companion object {
        init {
            HybridConfig.register()
        }

        /** Cipher suite 0x0001's HPKE, with no Tink prefix: the ciphertext is enc ‖ ct. */
        val SUITE: HpkeParameters = HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build()
    }
}
