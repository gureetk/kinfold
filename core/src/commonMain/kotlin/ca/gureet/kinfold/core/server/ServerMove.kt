// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.server

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.server.ServerException.Failure
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed
import ca.gureet.kinfold.core.wire.readAll

/**
 * A move notice (PROTOCOL.md §13.3): the old key hands the server over to a new address, a new key,
 * or both. Without the old key there is no hand-over; every device is set up again.
 */
class ServerMove(
    val oldUrl: String,
    val oldKey: Bytes,
    val newUrl: String,
    /** The same as [oldKey] when only the address changes. */
    val newKey: Bytes,
    val issuedAt: ULong,
    val sig: Bytes,
) {
    /** Everything before `sig`, which it covers. */
    fun signedPart(): ByteArray = encode {
        u8(Protocol.VERSION)
        vec16(oldUrl.encodeToByteArray())
        bytes(oldKey)
        vec16(newUrl.encodeToByteArray())
        bytes(newKey)
        u64(issuedAt)
    }

    fun encode(): ByteArray = concat(signedPart(), sig.toByteArray())

    /** Whether `sig` verifies under the old key the notice names. */
    suspend fun isSigned(p: Primitives): Boolean = p.verify(oldKey.toByteArray(), Label.SERVER_MOVE, signedPart(), sig.toByteArray())

    companion object {
        /** A notice moving the server at [oldUrl], whose key is [old], to [newUrl] and [newKey]. */
        suspend fun sign(p: Primitives, old: SigningKey, oldUrl: String, newUrl: String, newKey: Bytes, issuedAt: ULong): ServerMove {
            val unsigned = ServerMove(oldUrl, Bytes.of(old.publicKey), newUrl, newKey, issuedAt, Bytes.zero(64))
            return ServerMove(oldUrl, unsigned.oldKey, newUrl, newKey, issuedAt, Bytes.of(p.sign(old, Label.SERVER_MOVE, unsigned.signedPart())))
        }

        /** The notice in [raw], or `malformed`; version 0 only. */
        fun parse(raw: ByteArray): ServerMove = readAll(raw) {
            if (u8() != Protocol.VERSION) malformed()
            ServerMove(utf8(), Bytes.of(bytes(32)), utf8(), Bytes.of(bytes(32)), u64(), Bytes.of(bytes(64)))
        }

        /**
         * What a client that trusts [trustedKey] at [trustedUrl] checks before it follows a notice:
         * that it moves that server, and that the trusted key signed it. The client then switches
         * to the new address and key, checks the new [ServerInfo] against them, and tells the person.
         */
        suspend fun check(p: Primitives, raw: ByteArray, trustedUrl: String, trustedKey: Bytes): ServerMove {
            val move = parsing { parse(raw) }
            if (move.oldUrl != trustedUrl) refuse(Failure.WRONG_URL)
            if (move.oldKey != trustedKey) refuse(Failure.OTHER_KEY)
            if (!move.isSigned(p)) refuse(Failure.BAD_SIGNATURE)
            return move
        }
    }
}
