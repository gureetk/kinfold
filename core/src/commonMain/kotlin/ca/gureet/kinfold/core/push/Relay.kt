// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.push

import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.encode

/**
 * The signature a server puts on each push it hands the iOS relay (PROTOCOL.md §14.4). The server
 * signs and the relay checks; no device does either, but the core carries it so that every vector
 * group runs here.
 */
object Relay {
    const val ALERT = 1
    const val BACKGROUND = 2
    const val LOCATION = 3

    /** What the server signs: `capability ‖ sealed ‖ u64(sent_at) ‖ u8(delivery)`. */
    fun signed(capability: ByteArray, sealed: ByteArray, sentAt: ULong, delivery: Int): ByteArray = encode {
        bytes(capability)
        bytes(sealed)
        u64(sentAt)
        u8(delivery)
    }

    suspend fun sign(p: Primitives, server: SigningKey, capability: ByteArray, sealed: ByteArray, sentAt: ULong, delivery: Int): ByteArray =
        p.sign(server, Label.RELAY_PUSH, signed(capability, sealed, sentAt, delivery))

    /** Whether [sig] is the server's for this sealed push, of a known [delivery] type. */
    suspend fun isSigned(
        p: Primitives,
        serverKey: Bytes,
        capability: ByteArray,
        sealed: ByteArray,
        sentAt: ULong,
        delivery: Int,
        sig: ByteArray,
    ): Boolean = sealed.size == Pushes.SEALED_SIZE && delivery in ALERT..LOCATION &&
        p.verify(serverKey.toByteArray(), Label.RELAY_PUSH, signed(capability, sealed, sentAt, delivery), sig)
}
