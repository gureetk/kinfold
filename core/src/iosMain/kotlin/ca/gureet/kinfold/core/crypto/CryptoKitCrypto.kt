// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.crypto

import ca.gureet.kinfold.core.crypto.cryptokit.KFCryptoKit
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.memcpy

/**
 * [Crypto] on iOS: Apple's CryptoKit, through the Swift layer in src/iosMain/swift. Every
 * primitive is CryptoKit's own; the byte checks of PROTOCOL.md §3.3 and §3.5 stay in front of
 * it, in [Primitives].
 *
 * Two things differ from Tink. CryptoKit adds randomness to every Ed25519 signature, so a
 * signature never repeats, though every one verifies (§3.3). And its HPKE takes no fixed
 * ephemeral key, so the vectors' byte-exact seals can't be rebuilt here (§3.5).
 */
class CryptoKitCrypto : Crypto {
    override suspend fun sha256(data: ByteArray): ByteArray = KFCryptoKit.sha256(data.toNSData()).toByteArray()

    override suspend fun sha512(data: ByteArray): ByteArray = KFCryptoKit.sha512(data.toNSData()).toByteArray()

    override suspend fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        // CryptoKit stops the process for a length HKDF can't give, where Tink throws.
        require(length in 1..255 * 32) { "HKDF-SHA-256 gives 1 to 8,160 bytes" }
        return KFCryptoKit.hkdf(ikm.toNSData(), salt.toNSData(), info.toNSData(), length.toLong()).toByteArray()
    }

    override suspend fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        requireGcm(key, nonce)
        val sealed = KFCryptoKit.aesGcmSeal(key.toNSData(), nonce.toNSData(), plaintext.toNSData(), aad.toNSData())
        return checkNotNull(sealed) { "AES-GCM sealing failed" }.toByteArray()
    }

    override suspend fun aesGcmOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray? {
        requireGcm(key, nonce)
        return KFCryptoKit.aesGcmOpen(key.toNSData(), nonce.toNSData(), ciphertext.toNSData(), aad.toNSData())?.toByteArray()
    }

    override suspend fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        publicKey.size == 32 &&
            signature.size == 64 &&
            KFCryptoKit.ed25519Verify(publicKey.toNSData(), message.toNSData(), signature.toNSData())

    override suspend fun ed25519(seed: ByteArray): SigningKey {
        require(seed.size == 32) { "an Ed25519 seed is 32 bytes" }
        val key = seed.toNSData()
        val pub = checkNotNull(KFCryptoKit.ed25519PublicKey(key)) { "CryptoKit refused an Ed25519 seed" }.toByteArray()
        return object : SigningKey {
            override val publicKey: ByteArray get() = pub.copyOf()

            override suspend fun sign(message: ByteArray): ByteArray =
                checkNotNull(KFCryptoKit.ed25519Sign(key, message.toNSData())) { "Ed25519 signing failed" }.toByteArray()
        }
    }

    override suspend fun x25519(privateKey: ByteArray): HpkeKey {
        require(privateKey.size == 32) { "an X25519 private key is 32 bytes" }
        val key = privateKey.toNSData()
        val pub = checkNotNull(KFCryptoKit.x25519PublicKey(key)) { "CryptoKit refused an X25519 key" }.toByteArray()
        return object : HpkeKey {
            override val publicKey: ByteArray get() = pub.copyOf()

            override suspend fun open(enc: ByteArray, info: ByteArray, ciphertext: ByteArray): ByteArray? {
                if (enc.size != 32) return null
                return KFCryptoKit.hpkeOpen(key, enc.toNSData(), info.toNSData(), ciphertext.toNSData())?.toByteArray()
            }
        }
    }

    override suspend fun hpkeSeal(publicKey: ByteArray, info: ByteArray, plaintext: ByteArray): HpkeSealed {
        val sealed = KFCryptoKit.hpkeSeal(publicKey.toNSData(), info.toNSData(), plaintext.toNSData())
        val bytes = checkNotNull(sealed) { "HPKE sealing failed" }.toByteArray()
        return HpkeSealed(bytes.copyOfRange(0, 32), bytes.copyOfRange(32, bytes.size))
    }

    override fun randomBytes(length: Int): ByteArray {
        require(length >= 0) { "a negative length" }
        return checkNotNull(KFCryptoKit.randomBytes(length.toLong())) { "the system's random generator failed" }.toByteArray()
    }

    private fun requireGcm(key: ByteArray, nonce: ByteArray) =
        require(key.size == 32 && nonce.size == 12) { "AES-256-GCM takes a 32-byte key and a 12-byte nonce" }
}

/** The bytes as NSData, copied. */
internal fun ByteArray.toNSData(): NSData =
    if (isEmpty()) NSData() else usePinned { NSData.create(bytes = it.addressOf(0), length = size.toULong()) }

/** The NSData's bytes, copied. */
internal fun NSData.toByteArray(): ByteArray {
    val out = ByteArray(length.toInt())
    if (out.isNotEmpty()) out.usePinned { memcpy(it.addressOf(0), bytes, length) }
    return out
}
