// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.payload

import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.log.Details
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes

/** Epoch secrets received in a `welcome` or a `refresh` (PROTOCOL.md §8.5). */
object EpochSecrets {
    /** What a `welcome` or `refresh` yields once checked against the receiver's log. */
    sealed class Received {
        /** The log doesn't hold the payload's `head` yet: fetch and verify up to it, then look again. */
        data object HeadUnknown : Received()

        /** The secrets that match the log's commitments, by epoch. Any other entry was discarded. */
        class Secrets(val byEpoch: Map<Long, ByteArray>) : Received()
    }

    /**
     * The secrets in [payload]'s `epochs` (base64url, one per epoch, the index being the epoch),
     * each kept only if it matches [state]'s commitment for its epoch (§6.5). A payload without a
     * readable `head` or `epochs` yields no secrets.
     */
    suspend fun from(p: Primitives, state: CircleState, payload: Json.Obj): Received {
        val head = payload.string("head")?.let { Base64Url.decode(it) }?.takeIf { it.size == 32 }
            ?: return Received.Secrets(emptyMap())
        if (!state.hasEntry(Bytes.of(head))) return Received.HeadUnknown
        val epochs = (payload["epochs"] as? Json.Arr)?.items ?: return Received.Secrets(emptyMap())
        val out = mutableMapOf<Long, ByteArray>()
        epochs.forEachIndexed { i, item ->
            val epoch = i.toLong()
            val secret = (item as? Json.Str)?.value?.let { Base64Url.decode(it) }?.takeIf { it.size == 32 }
            val commit = state.commits[epoch]
            if (secret != null && commit != null && Details.epochCommit(p, epoch, secret) == commit) out[epoch] = secret
        }
        return Received.Secrets(out)
    }
}
