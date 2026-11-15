// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

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

/** The `hpke_rfc9180` vector's own messages, opened with Tink on the JVM. */
class TinkHpkeTest {
    private val v = Vectors.group("hpke_rfc9180")

    /**
     * The RFC's messages carry `aad`, which the protocol never uses and Tink's public API
     * doesn't take, so they are opened through Tink's own HPKE context: the code that
     * `TinkCrypto`'s seals and opens run on.
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
}
