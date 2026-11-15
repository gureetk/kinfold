// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.crypto

import ca.gureet.kinfold.core.wire.concat

/**
 * The protocol's functions over a platform's [Crypto] (PROTOCOL.md §3.3): hashes, signatures
 * and key derivations bound to a [Label], and verification with the byte checks in front.
 */
class Primitives(val crypto: Crypto) {
    /** H(label, data) = SHA-256(vec16(label) ‖ data), over the parts in order. */
    suspend fun h(label: Label, vararg data: ByteArray): ByteArray = crypto.sha256(concat(label.prefix, *data))

    /** KDF(ikm, label, L) = HKDF-Expand(HKDF-Extract(32 zero bytes, ikm), vec16(label), L). */
    suspend fun kdf(ikm: ByteArray, label: Label, length: Int): ByteArray =
        crypto.hkdf(ikm, ZERO_SALT, label.prefix, length)

    /** Sign(sk, label, data) = Ed25519-Sign(sk, vec16(label) ‖ data). */
    suspend fun sign(key: SigningKey, label: Label, vararg data: ByteArray): ByteArray =
        key.sign(concat(label.prefix, *data))

    /** Verify(pk, label, data, sig): [verifyMessage] over vec16(label) ‖ data. */
    suspend fun verify(publicKey: ByteArray, label: Label, data: ByteArray, signature: ByteArray): Boolean =
        verifyMessage(publicKey, concat(label.prefix, data), signature)

    /**
     * Ed25519 verification as §3.3 defines it: false when a byte check fails, and otherwise
     * the platform's verdict.
     */
    suspend fun verifyMessage(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        Ed25519Checks.pass(publicKey, signature) && crypto.ed25519Verify(publicKey, message, signature)

    /** Seal(pk_R, info, pt) of §3.5. The key must pass the check of §3.5. */
    suspend fun seal(publicKey: ByteArray, info: ByteArray, plaintext: ByteArray): HpkeSealed {
        require(!X25519Checks.isInvalidKey(publicKey)) { "sealing to an invalid X25519 key" }
        return crypto.hpkeSeal(publicKey, info, plaintext)
    }

    fun random(length: Int): ByteArray = crypto.randomBytes(length)

    private companion object {
        val ZERO_SALT = ByteArray(32)
    }
}
