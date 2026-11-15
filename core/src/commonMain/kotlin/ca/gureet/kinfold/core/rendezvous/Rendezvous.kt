// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.rendezvous

import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed

/**
 * Why a device refused a message of an invite, a link or a share link (PROTOCOL.md §9, §10, §12).
 * The spec gives these no codes, since nothing else sees them; the device just refuses.
 */
class RendezvousException(val failure: Failure) : Exception(failure.name.lowercase()) {
    enum class Failure {
        /** The bytes don't parse. */
        MALFORMED,

        /** A join request or result for another invite, or of another version. */
        WRONG_INVITE,

        /** A link or share message for another link, of another type, or of another version. */
        WRONG_LINK,

        /** The ciphertext doesn't open. */
        BAD_CIPHERTEXT,

        /** The plaintext isn't padded as §7.4 requires. */
        BAD_PADDING,

        /** A share update's payload isn't one (§8.1). */
        BAD_PAYLOAD,

        /** A certificate that isn't well-formed, doesn't prove its account, or is of the wrong account, key or kind. */
        BAD_CERT,

        /** A key bundle that isn't valid for the device, or isn't current. */
        BAD_BUNDLE,

        /** A join request committing to terms other than the invite's. */
        BAD_TERMS,

        /** A join consent that doesn't verify. */
        BAD_CONSENT,

        /** A link request that isn't the one its commit fixed. */
        BAD_COMMIT,

        /** A device kind the link's direction doesn't allow. */
        KIND_NOT_ALLOWED,

        /** A link response whose signature doesn't verify. */
        BAD_SIGNATURE,

        /** A link response from a device that never saw the code. */
        BAD_CONFIRM,

        /** A link response whose identity key or chain isn't the account's. */
        BAD_IDENTITY,
    }
}

internal fun refuse(failure: RendezvousException.Failure): Nothing = throw RendezvousException(failure)

/** Runs [read]; any parsing failure becomes `MALFORMED`. */
internal inline fun <T> parsing(read: () -> T): T = try {
    read()
} catch (_: ProtocolException) {
    refuse(RendezvousException.Failure.MALFORMED)
}

/** Strict UTF-8, or `malformed`. */
internal fun Reader.utf8(): String = try {
    vec16().decodeToString(throwOnInvalidSequence = true)
} catch (_: CharacterCodingException) {
    malformed()
}

/**
 * The messages of §9, §10 and §12 share a shape: a clear head, a 12-byte nonce, and a `vec32`
 * ciphertext whose associated data is the head.
 */
internal object Sealed {
    suspend fun seal(p: Primitives, key: ByteArray, head: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        require(nonce.size == 12) { "a nonce is 12 bytes" }
        return concat(head, nonce, encode { vec32(p.crypto.aesGcmSeal(key, nonce, plaintext, head)) })
    }

    /**
     * The plaintext of [msg], whose head is [headSize] bytes. The whole message is parsed first
     * (`MALFORMED`), then [checkHead] looks at the head, then the ciphertext is opened.
     */
    suspend fun open(
        p: Primitives,
        key: ByteArray,
        msg: ByteArray,
        headSize: Int,
        checkHead: (Reader) -> Unit,
    ): ByteArray {
        val (head, nonce, ct) = parsing {
            val r = Reader(msg)
            val head = r.bytes(headSize)
            val nonce = r.bytes(12)
            val ct = r.vec32()
            r.finish()
            Triple(head, nonce, ct)
        }
        checkHead(Reader(head))
        return p.crypto.aesGcmOpen(key, nonce, ct, head) ?: refuse(RendezvousException.Failure.BAD_CIPHERTEXT)
    }
}
