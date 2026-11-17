// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.CryptoKitCrypto
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** What CryptoKit does differently from Tink, which PROTOCOL.md §3.3 and Appendix C rely on. */
class CryptoKitTest {
    private val p = Primitives(CryptoKitCrypto())

    /**
     * CryptoKit adds randomness to each Ed25519 signature: two over the same message differ, and
     * both verify. If a later iOS stops doing this, the tests go back to comparing signatures byte
     * for byte, and the note in §3.3 needs a look.
     */
    @Test
    fun signaturesDontRepeat() = sync {
        val key = p.crypto.ed25519(ByteArray(32) { 1 })
        val data = "kinfold".encodeToByteArray()
        val first = p.sign(key, Label.TEST, data)
        val second = p.sign(key, Label.TEST, data)
        assertFalse(first.contentEquals(second), "two signatures over the same message")
        assertTrue(p.verify(key.publicKey, Label.TEST, data, first))
        assertTrue(p.verify(key.publicKey, Label.TEST, data, second))
        assertFalse(signsDeterministically)
    }

    /** A seal made here opens here, and nowhere it shouldn't. */
    @Test
    fun hpkeRoundTrip() = sync {
        val recipient = p.crypto.x25519(ByteArray(32) { 9 })
        val info = ByteArray(32) { 2 }
        val sealed = p.crypto.hpkeSeal(recipient.publicKey, info, "hello".encodeToByteArray())
        assertEquals("hello", recipient.open(sealed.enc, info, sealed.ciphertext)?.decodeToString())
        assertNull(recipient.open(sealed.enc, ByteArray(32) { 3 }, sealed.ciphertext), "another info")
        assertNull(p.crypto.x25519(ByteArray(32) { 4 }).open(sealed.enc, info, sealed.ciphertext), "another key")
        val flipped = sealed.ciphertext.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertNull(recipient.open(sealed.enc, info, flipped), "a flipped bit")
    }
}
