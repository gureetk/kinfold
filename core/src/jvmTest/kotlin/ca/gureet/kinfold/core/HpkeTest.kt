// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.JvmCrypto
import ca.gureet.kinfold.core.crypto.Primitives
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.hybrid.HpkeParameters
import com.google.crypto.tink.hybrid.HpkePrivateKey
import com.google.crypto.tink.hybrid.HpkePublicKey
import com.google.crypto.tink.hybrid.internal.HpkeContext
import com.google.crypto.tink.hybrid.internal.HpkeKemKeyFactory
import com.google.crypto.tink.hybrid.internal.HpkePrimitiveFactory
import com.google.crypto.tink.util.Bytes
import com.google.crypto.tink.util.SecretBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/** HPKE (PROTOCOL.md §3.5) and the `hpke_rfc9180` and `x25519` vectors. */
class HpkeTest {
    private val crypto = JvmCrypto()
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

    /**
     * The RFC's messages carry `aad`, which the protocol never uses and Tink's public API
     * doesn't take, so they are opened through Tink's own HPKE context: the code that
     * [JvmCrypto]'s seals and opens run on.
     */
    @Test
    fun rfcMessages() {
        val suite = HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build()
        val public = HpkePublicKey.create(suite, Bytes.copyFrom(v.hex("pkRm")), null)
        val private = HpkePrivateKey.create(public, SecretBytes.copyFrom(v.hex("skRm"), InsecureSecretKeyAccess.get()))
        val context = HpkeContext.createRecipientContext(
            v.hex("enc"),
            HpkeKemKeyFactory.createPrivate(private),
            HpkePrimitiveFactory.createKem(suite.kemId),
            HpkePrimitiveFactory.createKdf(suite.kdfId),
            HpkePrimitiveFactory.createAead(suite.aeadId),
            v.hex("info"),
        )
        val messages = v.list("encryptions")
        assertEquals(2, messages.size)
        for (m in messages) assertContentEquals(m.hex("pt"), context.open(m.hex("ct"), m.hex("aad")))
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
