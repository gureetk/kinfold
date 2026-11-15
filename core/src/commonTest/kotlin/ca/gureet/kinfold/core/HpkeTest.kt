// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.Primitives
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/** HPKE (PROTOCOL.md §3.5) and the `hpke_rfc9180` and `x25519` vectors; the RFC's own messages are opened in `TinkHpkeTest` on the JVM. */
class HpkeTest {
    private val crypto = platformCrypto()
    private val p = Primitives(crypto)
    private val v = Vectors.group("hpke_rfc9180")

    @Test
    fun cipherSuite() {
        assertEquals(0, v.int("mode"))
        assertEquals(0x20, v.int("kem_id"))
        assertEquals(1, v.int("kdf_id"))
        assertEquals(2, v.int("aead_id"))
    }

    @Test
    fun keys() = sync {
        assertContentEquals(v.hex("pkRm"), crypto.x25519(v.hex("skRm")).publicKey)
        assertContentEquals(v.hex("pkEm"), crypto.x25519(v.hex("skEm")).publicKey)
        assertContentEquals(v.hex("pkEm"), v.hex("enc"))
    }

    @Test
    fun sealAndOpen() = sync {
        val key = crypto.x25519(ByteArray(32) { it.toByte() })
        val info = ByteArray(32) { 7 }
        val message = "a wrapped secret".encodeToByteArray()
        val sealed = p.seal(key.publicKey, info, message)
        assertEquals(32, sealed.enc.size)
        assertEquals(message.size + 16, sealed.ciphertext.size)
        assertContentEquals(message, key.open(sealed.enc, info, sealed.ciphertext))
        assertNull(key.open(sealed.enc, ByteArray(32), sealed.ciphertext), "other info")
        val tampered = sealed.ciphertext.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertNull(key.open(sealed.enc, info, tampered), "a flipped bit")
        assertNull(key.open(ByteArray(32), info, sealed.ciphertext), "a low-order encapsulated key")
        assertNull(key.open(sealed.enc.copyOf(31), info, sealed.ciphertext), "a short encapsulated key")
        val other = crypto.x25519(ByteArray(32) { 9 })
        assertNull(other.open(sealed.enc, info, sealed.ciphertext), "another key")
    }

    @Test
    fun x25519Keys() = sync {
        val keys = Vectors.group("x25519").list("keys")
        assertEquals(10, keys.size)
        for (k in keys) {
            assertEquals(k.bool("invalid"), ca.gureet.kinfold.core.crypto.X25519Checks.isInvalidKey(k.hex("pub")), k.str("note"))
            if (k.bool("invalid")) assertFailsWith<IllegalArgumentException> { p.seal(k.hex("pub"), ByteArray(32), byteArrayOf()) }
        }
    }
}
