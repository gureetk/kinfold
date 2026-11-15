// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.server

import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.encode

/** A device's side of logging in to its server (PROTOCOL.md §13.2). */
object Login {
    const val CHALLENGE_SIZE = 32

    /**
     * Step 3: whether the server's challenge, for [deviceId] until [expiresAt], was signed by the
     * key the device trusts. The device signs nothing until it was.
     */
    suspend fun isChallengeSigned(
        p: Primitives,
        serverKey: Bytes,
        challenge: ByteArray,
        deviceId: Bytes,
        expiresAt: ULong,
        sig: ByteArray,
    ): Boolean = challenge.size == CHALLENGE_SIZE &&
        p.verify(serverKey.toByteArray(), Label.AUTH_CHALLENGE, challengeSigned(challenge, deviceId, expiresAt), sig)

    /**
     * Step 4: the device's signature. It covers the server key, so a server can't pass it on to
     * log in somewhere else.
     */
    suspend fun deviceSig(p: Primitives, dsk: SigningKey, serverKey: Bytes, challenge: ByteArray, deviceId: Bytes): ByteArray {
        require(challenge.size == CHALLENGE_SIZE) { "a challenge is 32 bytes" }
        return p.sign(dsk, Label.AUTH, serverKey.toByteArray(), challenge, deviceId.toByteArray())
    }

    /** What the server signs: `challenge ‖ device_id ‖ u64(expires_at)`. */
    fun challengeSigned(challenge: ByteArray, deviceId: Bytes, expiresAt: ULong): ByteArray = encode {
        bytes(challenge)
        bytes(deviceId)
        u64(expiresAt)
    }
}
