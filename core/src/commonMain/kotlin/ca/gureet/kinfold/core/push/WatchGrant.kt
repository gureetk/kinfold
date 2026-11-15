// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.push

import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.readAll

/**
 * A silence-watch grant (PROTOCOL.md §14.1), as its bytes lay it out. Parsing checks only the
 * structure; whether a server may register it is a separate question.
 */
class WatchGrant(
    val version: Int,
    val circleId: Bytes,
    val watchedDevice: Bytes,
    val watcherAccount: Bytes,
    val afterMin: Int,
    val issuedAt: ULong,
    val notAfter: ULong,
    val sig: Bytes,
) {
    companion object {
        const val SIZE = 131

        /** The grant in [raw], which must be exactly [SIZE] bytes, or `malformed`. */
        fun parse(raw: ByteArray): WatchGrant = readAll(raw) {
            WatchGrant(
                version = u8(),
                circleId = Bytes.of(bytes(16)),
                watchedDevice = Bytes.of(bytes(16)),
                watcherAccount = Bytes.of(bytes(16)),
                afterMin = u16(),
                issuedAt = u64(),
                notAfter = u64(),
                sig = Bytes.of(bytes(64)),
            )
        }
    }
}
