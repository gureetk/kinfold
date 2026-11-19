// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.roundToLong
import kotlin.math.sin
import kotlin.math.sqrt

/** A fix as the engine keeps it, in memory only: it is never logged and never stored. */
class Fix(
    /** When it was taken, in the phone's elapsed time (milliseconds since boot, sleep included). */
    val atMs: Long,
    val latE7: Long,
    val lonE7: Long,
    val accM: Long,
    /** Centimetres per second, or null when the fix carries no speed. */
    val spdCms: Long?,
)

/** How the phone is sharing, from plan §9's adaptive modes, simplified for the spike. */
enum class Mode(val intervalMs: Long) {
    /** Not moving: no fixes, a heartbeat now and then, and the motion sensor to wake it. */
    STILL(0),

    /** Walking or about: a fix every 30 seconds, each one uploaded. */
    MOVING(30_000),

    /** Faster than about 25 km/h: a fix every 10 seconds, uploaded together once a minute. */
    DRIVING(10_000),

    /** Someone asked for live updates: a fix every 5 seconds, each one uploaded, for a minute. */
    LIVE(5_000),
}

/** What becomes of one fix: the mode after it, whether it changed, and whether it goes up now with [prev]. */
class Step(val mode: Mode, val changed: Boolean, val upload: Boolean, val prev: List<Fix>, val movedM: Long?)

/**
 * The location engine's decisions: when to change modes and when a fix goes to the server. It has
 * no clock and touches nothing Android has, so it is tested on its own.
 */
class Motion(mode: Mode = Mode.MOVING) {
    var mode: Mode = mode
        private set

    private val recent = ArrayDeque<Fix>()
    private val waiting = ArrayList<Fix>()
    private var lastUploadMs: Long? = null
    private var liveUntilMs = 0L
    private var fast = 0
    private var slowSinceMs: Long? = null
    private var anchor: Fix? = null

    /** Live updates until [nowMs] + [forMs]. True if that changed the mode. */
    fun live(nowMs: Long, forMs: Long): Boolean {
        liveUntilMs = max(liveUntilMs, nowMs + forMs)
        return leave(Mode.LIVE)
    }

    /** Ends live updates once their time is up. True if that changed the mode. */
    fun tick(nowMs: Long): Boolean = mode == Mode.LIVE && nowMs >= liveUntilMs && set(Mode.MOVING)

    /** The motion sensor fired. True if that changed the mode. */
    fun motionDetected(): Boolean = mode == Mode.STILL && leave(Mode.MOVING)

    fun add(fix: Fix): Step {
        val before = mode
        val moved = recent.lastOrNull()?.let { distanceM(it, fix) }
        recent.addLast(fix)
        while (recent.size > 1 && fix.atMs - recent.first().atMs > HISTORY_MS) recent.removeFirst()
        val speed = fix.spdCms
        when (mode) {
            Mode.LIVE -> if (fix.atMs >= liveUntilMs) set(Mode.MOVING)
            Mode.STILL -> {
                val a = anchor
                val away = a != null && distanceM(a, fix) > max(LEFT_M, 2 * fix.accM)
                if (away || (speed != null && speed > WALKING_CMS)) {
                    leave(Mode.MOVING)
                    recent.addLast(fix)
                }
            }
            Mode.MOVING -> {
                fast = if (speed != null && speed >= DRIVING_CMS) fast + 1 else 0
                if (fast >= 2) {
                    set(Mode.DRIVING)
                } else if (stillFor(STILL_AFTER_MS)) {
                    set(Mode.STILL)
                    anchor = fix
                }
            }
            Mode.DRIVING -> {
                if (speed == null || speed < SLOW_CMS) {
                    val since = slowSinceMs ?: fix.atMs.also { slowSinceMs = it }
                    if (fix.atMs - since >= SLOW_FOR_MS) set(Mode.MOVING)
                } else {
                    slowSinceMs = null
                }
            }
        }
        val last = lastUploadMs
        val upload = when (mode) {
            Mode.LIVE -> true
            Mode.MOVING -> last == null || fix.atMs - last >= MOVING_UPLOAD_MS
            Mode.DRIVING -> last == null || fix.atMs - last >= DRIVING_UPLOAD_MS
            // The fix that showed the phone has stopped goes up once, so the map shows where it stopped.
            Mode.STILL -> before != Mode.STILL
        }
        val prev = if (upload) waiting.takeLast(MAX_PREV) else emptyList()
        if (upload) {
            lastUploadMs = fix.atMs
            waiting.clear()
        } else if (mode == Mode.DRIVING) {
            waiting.add(fix)
        }
        return Step(mode, mode != before, upload, prev, moved)
    }

    /** Changes the mode; leaving [Mode.STILL], only fixes from now on count towards the next stop. */
    private fun leave(m: Mode): Boolean {
        val wasStill = mode == Mode.STILL
        return set(m).also { if (it && wasStill) recent.clear() }
    }

    private fun set(m: Mode): Boolean {
        if (m == mode) return false
        mode = m
        fast = 0
        slowSinceMs = null
        if (m != Mode.STILL) anchor = null
        if (m != Mode.DRIVING) waiting.clear()
        return true
    }

    /** Whether every fix of the last [ms] stayed near the latest, slower than a walk, with at least [ms] of fixes. */
    private fun stillFor(ms: Long): Boolean {
        val latest = recent.last()
        if (latest.atMs - recent.first().atMs < ms) return false
        return recent.filter { latest.atMs - it.atMs <= ms }.all {
            distanceM(it, latest) <= max(NEAR_M, it.accM + latest.accM) && (it.spdCms ?: 0) < WALKING_CMS
        }
    }

    companion object {
        const val HISTORY_MS = 5 * 60_000L
        const val STILL_AFTER_MS = 3 * 60_000L
        const val NEAR_M = 50L
        const val LEFT_M = 100L
        const val WALKING_CMS = 100L
        const val DRIVING_CMS = 700L
        const val SLOW_CMS = 300L
        const val SLOW_FOR_MS = 2 * 60_000L
        const val MOVING_UPLOAD_MS = 25_000L
        const val DRIVING_UPLOAD_MS = 60_000L

        /** `prev` holds at most 8 earlier fixes (PROTOCOL.md §8.2). */
        const val MAX_PREV = 8
    }
}

/** The distance between two fixes along the earth's surface, in metres. */
fun distanceM(a: Fix, b: Fix): Long {
    val r = 6_371_008.8
    val lat1 = Math.toRadians(a.latE7 / 1e7)
    val lat2 = Math.toRadians(b.latE7 / 1e7)
    val dLat = lat2 - lat1
    val dLon = Math.toRadians((b.lonE7 - a.lonE7) / 1e7)
    val h = sin(dLat / 2) * sin(dLat / 2) + cos(lat1) * cos(lat2) * sin(dLon / 2) * sin(dLon / 2)
    return (2 * r * asin(sqrt(h.coerceIn(0.0, 1.0)))).roundToLong()
}
