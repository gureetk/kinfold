// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike.harness

import ca.gureet.kinfold.core.wire.Bytes
import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt

/** A position as `loc` carries it: units of 10⁻⁷ degree, and the sender's time. Kept in memory only. */
class Fix(val ts: ULong, val latE7: Long, val lonE7: Long, val accM: Long, val speedCms: Long?)

/** The great-circle distance between two positions, in metres. */
fun distanceM(a: Fix, b: Fix): Double {
    val r = 6_371_008.8
    val lat1 = Math.toRadians(a.latE7 / 1e7)
    val lat2 = Math.toRadians(b.latE7 / 1e7)
    val dLat = lat2 - lat1
    val dLon = Math.toRadians((b.lonE7 - a.lonE7) / 1e7)
    val h = sin(dLat / 2).pow(2) + cos(lat1) * cos(lat2) * sin(dLon / 2).pow(2)
    return 2 * r * asin(sqrt(h.coerceIn(0.0, 1.0)))
}

/**
 * The recent positions of each device, in memory and never written anywhere: the latest, for
 * its age, and those of the last [windowMs], to tell whether the device is moving.
 */
class Positions(private val windowMs: ULong = 600_000UL) {
    private val recent = HashMap<Bytes, ArrayDeque<Fix>>()

    @Synchronized
    fun add(device: Bytes, fix: Fix): Fix? {
        val q = recent.getOrPut(device) { ArrayDeque() }
        val previous = q.lastOrNull()
        if (previous != null && fix.ts <= previous.ts) return previous // older than what is held: ignore it
        q.addLast(fix)
        while (q.size > 1 && fix.ts - q.first().ts > windowMs) q.removeFirst()
        return previous
    }

    @Synchronized
    fun latest(device: Bytes): Fix? = recent[device]?.lastOrNull()

    /**
     * Moving: at least [moveM] metres between the oldest and the newest position of the window,
     * or a latest speed of at least 1 m/s.
     */
    @Synchronized
    fun moving(device: Bytes, moveM: Double = 150.0): Boolean {
        val q = recent[device] ?: return false
        val last = q.lastOrNull() ?: return false
        return (last.speedCms ?: 0) >= 100 || distanceM(q.first(), last) >= moveM
    }

    @Synchronized
    fun devices(): Set<Bytes> = recent.keys.toSet()
}
