// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.crypto

/**
 * The primitives of cipher suite 0x0001 (PROTOCOL.md §3.1), from the platform's own
 * libraries: Tink and the JDK on the JVM and Android, CryptoKit on iOS, WebCrypto in a
 * browser. The core never implements a primitive itself. It makes the byte checks of §3.3
 * and §3.5 in front of these ([Primitives]), so that every platform gives the same verdict.
 *
 * Calls that a platform offers only asynchronously (WebCrypto) suspend. Private keys are
 * reached through [SigningKey] and [HpkeKey], so a platform can keep them in hardware.
 */
interface Crypto {
    suspend fun sha256(data: ByteArray): ByteArray

    suspend fun sha512(data: ByteArray): ByteArray

    /** HKDF-SHA-256 (RFC 5869): Extract with [salt], then Expand with [info] to [length] bytes. */
    suspend fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray

    /** AES-256-GCM with a 12-byte nonce: the ciphertext, then the 16-byte tag. */
    suspend fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray

    /** The plaintext, or null if the tag doesn't verify. */
    suspend fun aesGcmOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray?

    /**
     * The platform's own Ed25519 verdict (RFC 8032, one signature, no cofactor), for a 32-byte
     * key and a 64-byte signature. Callers go through [Primitives.verifyMessage], which makes
     * the checks of §3.3 first.
     */
    suspend fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean

    /** The Ed25519 key with this 32-byte seed. */
    suspend fun ed25519(seed: ByteArray): SigningKey

    /** The X25519 key with this 32-byte private key. */
    suspend fun x25519(privateKey: ByteArray): HpkeKey

    /**
     * HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM:
     * one message, empty `aad` (§3.5), under a fresh ephemeral key.
     */
    suspend fun hpkeSeal(publicKey: ByteArray, info: ByteArray, plaintext: ByteArray): HpkeSealed

    /** [length] bytes from the platform's cryptographically secure generator (§3.6). */
    fun randomBytes(length: Int): ByteArray
}

/** An Ed25519 key that signs; its private half may never leave the platform. */
interface SigningKey {
    val publicKey: ByteArray

    suspend fun sign(message: ByteArray): ByteArray
}

/** An X25519 key that opens HPKE seals made to [publicKey]. */
interface HpkeKey {
    val publicKey: ByteArray

    /** The plaintext of a single-shot base-mode seal with empty `aad`, or null if it doesn't open. */
    suspend fun open(enc: ByteArray, info: ByteArray, ciphertext: ByteArray): ByteArray?
}

/** An HPKE seal: the 32-byte encapsulated key and the ciphertext. */
class HpkeSealed(val enc: ByteArray, val ciphertext: ByteArray)
