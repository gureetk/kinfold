// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.identity

import ca.gureet.kinfold.core.crypto.HpkeKey
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed

/** A 32-byte secret sealed to one device's current encryption key (PROTOCOL.md §4.6). */
class Wrap(val recipient: Bytes, val keyId: Bytes, val enc: Bytes, val ct: Bytes) {
    fun encode(): ByteArray = encode {
        bytes(recipient)
        bytes(keyId)
        bytes(enc)
        bytes(ct)
    }

    /** The secret, or null if the wrap doesn't open or doesn't hold 32 bytes. */
    suspend fun open(key: HpkeKey, info: ByteArray): ByteArray? =
        key.open(enc.toByteArray(), info, ct.toByteArray())?.takeIf { it.size == 32 }

    companion object {
        const val SIZE = 104

        fun read(r: Reader): Wrap = Wrap(Bytes.of(r.bytes(16)), Bytes.of(r.bytes(8)), Bytes.of(r.bytes(32)), Bytes.of(r.bytes(48)))

        /** A list of wraps, the bytes of a `vec32`: a multiple of 104 bytes, or `malformed`. Order is checked where it matters. */
        fun parseList(bytes: ByteArray): List<Wrap> {
            if (bytes.size % SIZE != 0) malformed()
            val r = Reader(bytes)
            return List(bytes.size / SIZE) { read(r) }
        }

        fun encodeList(wraps: List<Wrap>): ByteArray = encode { wraps.forEach { bytes(it.encode()) } }

        /** [secret] sealed to [dekPub] for the device [recipient] under [info]. */
        suspend fun seal(p: Primitives, recipient: Bytes, keyId: Bytes, dekPub: ByteArray, info: ByteArray, secret: ByteArray): Wrap {
            require(secret.size == 32) { "a wrap carries a 32-byte secret" }
            val sealed = p.seal(dekPub, info, secret)
            return Wrap(recipient, keyId, Bytes.of(sealed.enc), Bytes.of(sealed.ciphertext))
        }
    }
}
