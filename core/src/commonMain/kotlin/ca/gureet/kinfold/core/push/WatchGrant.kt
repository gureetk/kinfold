// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.push

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.readAll

/**
 * A silence-watch grant (PROTOCOL.md §14.1): a phone or tablet's consent to a watcher being told
 * when it goes quiet. Parsing checks only the structure; [isValidAt] is what a server checks
 * before it registers the watch, and what a guardian's app checks of the grants a teen's phones send.
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
    /** The first 67 bytes, which `sig` covers. */
    fun signedPart(): ByteArray = encode {
        u8(version)
        bytes(circleId)
        bytes(watchedDevice)
        bytes(watcherAccount)
        u16(afterMin)
        u64(issuedAt)
        u64(notAfter)
    }

    fun encode(): ByteArray = concat(signedPart(), sig.toByteArray())

    /**
     * Valid at [t] in the circle whose verified log gave [state] (§14.1): version 0, this circle, a
     * watched device that is an active phone or tablet, a watcher that is a current member, an
     * interval of 15 to 1,440 minutes, issued no more than 10 minutes after [t], not yet ended,
     * lasting at most 35 days, and signed by the watched device's key. The sums are written as
     * differences, so that no time near the top of the u64 range can wrap (Appendix C).
     */
    suspend fun isValidAt(p: Primitives, state: CircleState, t: ULong): Boolean {
        val device = state.device(watchedDevice) ?: return false
        return version == Protocol.VERSION &&
            circleId == state.circleId &&
            device.kind.isPhoneOrTablet &&
            watcherAccount in state.members &&
            afterMin in MIN_AFTER..MAX_AFTER &&
            (issuedAt <= t || issuedAt - t <= SKEW_MS) &&
            t < notAfter &&
            issuedAt < notAfter &&
            notAfter - issuedAt <= MAX_LIFE_MS &&
            p.verify(device.dskPub.toByteArray(), Label.WATCH_GRANT, signedPart(), sig.toByteArray())
    }

    companion object {
        const val SIZE = 131

        /** The shortest and longest silence a grant may name, in minutes. */
        const val MIN_AFTER = 15
        const val MAX_AFTER = 1440

        /** How far a grant's `issued_at` may be ahead of the checker's clock. */
        const val SKEW_MS: ULong = 600_000UL

        /** 35 days, the longest a grant may last. */
        const val MAX_LIFE_MS: ULong = 3_024_000_000UL

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

        /**
         * A grant from the device whose signing key is [dsk], at its trusted time [issuedAt] (§8.4),
         * letting [watcherAccount] be told after [afterMin] minutes of silence until [notAfter].
         */
        suspend fun issue(
            p: Primitives,
            dsk: SigningKey,
            circleId: Bytes,
            watchedDevice: Bytes,
            watcherAccount: Bytes,
            afterMin: Int,
            issuedAt: ULong,
            notAfter: ULong,
        ): WatchGrant {
            val unsigned = WatchGrant(Protocol.VERSION, circleId, watchedDevice, watcherAccount, afterMin, issuedAt, notAfter, Bytes.zero(64))
            val sig = p.sign(dsk, Label.WATCH_GRANT, unsigned.signedPart())
            return WatchGrant(Protocol.VERSION, circleId, watchedDevice, watcherAccount, afterMin, issuedAt, notAfter, Bytes.of(sig))
        }
    }
}
