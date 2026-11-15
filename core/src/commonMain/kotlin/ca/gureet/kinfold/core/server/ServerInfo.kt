// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.server

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.identity.SafetyCode
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed
import ca.gureet.kinfold.core.wire.readAll

/**
 * Why a client didn't accept what a server says it is (PROTOCOL.md §13). The spec gives these no
 * codes: the client refuses to go on and tells the person.
 */
class ServerException(val failure: Failure) : Exception(failure.name.lowercase()) {
    enum class Failure {
        /** The bytes don't parse, or are of another version. */
        MALFORMED,

        /** Not the URL the client used, or a move notice for another address than the one it trusts. */
        WRONG_URL,

        /** A key other than the one the client trusts: another server, unless it shows a valid move notice (§13.3). */
        OTHER_KEY,

        /** The signature doesn't verify. */
        BAD_SIGNATURE,
    }
}

internal fun refuse(failure: ServerException.Failure): Nothing = throw ServerException(failure)

/** Runs [read]; any parsing failure becomes `MALFORMED`. */
internal inline fun <T> parsing(read: () -> T): T = try {
    read()
} catch (_: ProtocolException) {
    refuse(ServerException.Failure.MALFORMED)
}

/**
 * A server's signed statement of its address and key (§13.1), which `/.well-known/kinfold` carries.
 * A client believes nothing else the server says until [check] has passed.
 */
class ServerInfo(
    val serverUrl: String,
    val serverKey: Bytes,
    val issuedAt: ULong,
    val expiresAt: ULong,
    val sig: Bytes,
) {
    /** Everything before `sig`, which it covers. */
    fun signedPart(): ByteArray = encode {
        u8(Protocol.VERSION)
        vec16(serverUrl.encodeToByteArray())
        bytes(serverKey)
        u64(issuedAt)
        u64(expiresAt)
    }

    fun encode(): ByteArray = concat(signedPart(), sig.toByteArray())

    /** Whether `sig` verifies under the key the statement names. */
    suspend fun isSigned(p: Primitives): Boolean =
        p.verify(serverKey.toByteArray(), Label.SERVER_INFO, signedPart(), sig.toByteArray())

    companion object {
        /** A statement for [serverUrl], signed by the server's key [server]. */
        suspend fun sign(p: Primitives, server: SigningKey, serverUrl: String, issuedAt: ULong, expiresAt: ULong): ServerInfo {
            val unsigned = ServerInfo(serverUrl, Bytes.of(server.publicKey), issuedAt, expiresAt, Bytes.zero(64))
            return ServerInfo(serverUrl, unsigned.serverKey, issuedAt, expiresAt, Bytes.of(p.sign(server, Label.SERVER_INFO, unsigned.signedPart())))
        }

        /** The statement in [raw], or `malformed`; version 0 only. */
        fun parse(raw: ByteArray): ServerInfo = readAll(raw) {
            if (u8() != Protocol.VERSION) malformed()
            ServerInfo(utf8(), Bytes.of(bytes(32)), u64(), u64(), Bytes.of(bytes(64)))
        }

        /**
         * What a client checks before it believes anything else (§13.1): a statement for the [url]
         * it used, naming the key it trusts, [trustedKey], and signed by it. `OTHER_KEY` means
         * another server; the client goes on only if the server shows a valid [ServerMove].
         */
        suspend fun check(p: Primitives, raw: ByteArray, url: String, trustedKey: Bytes): ServerInfo {
            val info = parsing { parse(raw) }
            if (info.serverUrl != url) refuse(ServerException.Failure.WRONG_URL)
            if (info.serverKey != trustedKey) refuse(ServerException.Failure.OTHER_KEY)
            if (!info.isSigned(p)) refuse(ServerException.Failure.BAD_SIGNATURE)
            return info
        }

        /**
         * The key's fingerprint (§13.1): 30 digits in six groups of five, built as half a safety
         * code is (§11) under its own label. An app shows it when a device is set up by typing an
         * address, for the person to compare with what the server's command line prints.
         */
        suspend fun fingerprint(p: Primitives, serverKey: Bytes): String =
            SafetyCode.digits(p, Label.SERVER_FINGERPRINT, serverKey.toByteArray()).chunked(5).joinToString(" ")
    }
}
