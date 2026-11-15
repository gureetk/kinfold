// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.rendezvous

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.rendezvous.RendezvousException.Failure
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Padding
import ca.gureet.kinfold.core.wire.encode

/** One update a share link carries: a `loc` payload, perhaps with a `name` (PROTOCOL.md §12). */
class ShareUpdate(val seq: ULong, val expiresAt: ULong, val payload: Json.Obj)

/**
 * Share links (§12): a live location for someone without the app. The key stays in the URL's
 * fragment, so an honest server never has it; the app says, when a link is made, that the server
 * is trusted with it all the same.
 */
object ShareLinks {
    suspend fun linkId(p: Primitives, secret: Bytes): Bytes = Bytes.of(p.h(Label.SHARE_ID, secret.toByteArray()).copyOf(16))

    suspend fun shareKey(p: Primitives, secret: Bytes): ByteArray = p.kdf(secret.toByteArray(), Label.SHARE_KEY, 32)

    /** `server_url/s/b64u(link_id)#b64u(secret)`. */
    suspend fun url(p: Primitives, serverUrl: String, secret: Bytes): String =
        "$serverUrl/s/${Base64Url.encode(linkId(p, secret).toByteArray())}#${Base64Url.encode(secret.toByteArray())}"

    /** An update: [payload], padded and sealed under the share key with [nonce]. */
    suspend fun update(
        p: Primitives,
        secret: Bytes,
        seq: ULong,
        expiresAt: ULong,
        payload: ByteArray,
        nonce: ByteArray = p.random(12),
    ): ByteArray = Sealed.seal(p, shareKey(p, secret), head(linkId(p, secret), seq, expiresAt), nonce, Padding.pad(payload))

    /** What a viewer does with an update for the link with [secret]. */
    suspend fun open(p: Primitives, secret: Bytes, msg: ByteArray): ShareUpdate {
        val lid = linkId(p, secret)
        var seq = 0UL
        var expiresAt = 0UL
        val padded = Sealed.open(p, shareKey(p, secret), msg, HEAD_SIZE) { r ->
            if (r.u8() != Protocol.VERSION || Bytes.of(r.bytes(16)) != lid) refuse(Failure.WRONG_LINK)
            seq = r.u64()
            expiresAt = r.u64()
        }
        val payload = Padding.unpadBucket(padded) ?: refuse(Failure.BAD_PADDING)
        return ShareUpdate(seq, expiresAt, Json.parsePayload(payload) ?: refuse(Failure.BAD_PAYLOAD))
    }

    /** `u8 version ‖ link_id[16] ‖ u64 seq ‖ u64 expires_at`, an update's associated data. */
    private const val HEAD_SIZE = 33

    private fun head(lid: Bytes, seq: ULong, expiresAt: ULong): ByteArray = encode {
        u8(Protocol.VERSION)
        bytes(lid)
        u64(seq)
        u64(expiresAt)
    }
}
