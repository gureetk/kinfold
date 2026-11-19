// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import kotlin.concurrent.Volatile

/** Milliseconds on a clock that never goes back and keeps counting while the device sleeps. */
internal expect fun monotonicMillis(): Long

/** The device's wall clock, in milliseconds since the epoch: what the person may have changed. */
internal expect fun wallMillis(): Long

/**
 * Trusted time (PROTOCOL.md §8.4): the latest server time heard, from `Kinfold-Time` on every
 * response and the stream's `time` messages, plus the monotonic time elapsed since.
 *
 * Until the server is first heard in this process, it is the later of the wall clock and the
 * server time [saved] before, which is what §8.4 asks after a restart. A monotonic reading is never
 * carried from one process to the next: a reboot starts the monotonic clock again.
 */
class TrustedClock(
    saved: ULong = 0UL,
    private val monotonic: () -> Long = ::monotonicMillis,
    private val wall: () -> Long = ::wallMillis,
) {
    private class Heard(val serverTime: ULong, val at: Long)

    @Volatile
    private var heard: Heard? = null

    private val saved: ULong = saved

    /** Takes in a server time, in milliseconds since the epoch. The latest one heard counts. */
    fun observe(serverTime: ULong) {
        heard = Heard(serverTime, monotonic())
    }

    /** Whether the server has been heard since this clock was made. */
    val hasHeard: Boolean get() = heard != null

    /** The latest server time heard, or the one saved before: what to save for the next process. */
    val lastServerTime: ULong get() = heard?.serverTime ?: saved

    /** Trusted time now, in milliseconds since the epoch. */
    fun now(): ULong {
        val h = heard ?: return maxOf(wall().coerceAtLeast(0).toULong(), saved)
        val elapsed = monotonic() - h.at
        return h.serverTime + elapsed.coerceAtLeast(0).toULong()
    }
}
