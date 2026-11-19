// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MotionTest {
    /** A fix [northM] metres north of a fixed point, at [s] seconds. */
    private fun fix(s: Long, northM: Double, spdCms: Long? = null, accM: Long = 10): Fix =
        Fix(s * 1_000, 491_234_567 + (northM / 111_195.0 * 1e7).toLong(), -1_231_234_567, accM, spdCms)

    @Test
    fun distances() {
        assertEquals(0, distanceM(fix(0, 0.0), fix(0, 0.0)))
        assertEquals(500, distanceM(fix(0, 0.0), fix(0, 500.0)))
    }

    @Test
    fun walkingUploadsEachFixAndStopsAfterThreeStillMinutes() {
        val m = Motion()
        assertTrue(m.add(fix(0, 0.0, 140)).upload)
        assertTrue(m.add(fix(30, 40.0, 140)).upload)
        assertEquals(40, m.add(fix(60, 80.0, 140)).movedM)
        // Standing at 80 m for three minutes, with GPS wobbling by a few metres.
        var last: Step? = null
        for (s in 90L..270L step 30) last = m.add(fix(s, 80.0 + (s % 60) / 10.0, 0))
        assertEquals(Mode.STILL, last!!.mode)
        assertTrue(last.changed)
        assertTrue(last.upload, "where it stopped goes up once")
        assertFalse(m.add(fix(300, 81.0, 0)).upload)
    }

    @Test
    fun stillWakesOnMotionOrDistance() {
        val m = Motion()
        for (s in 0L..240L step 30) m.add(fix(s, 0.0, 0))
        assertEquals(Mode.STILL, m.mode)
        assertTrue(m.motionDetected())
        assertEquals(Mode.MOVING, m.mode)
        for (s in 270L..540L step 30) m.add(fix(s, 0.0, 0))
        assertEquals(Mode.STILL, m.mode)
        val away = m.add(fix(600, 150.0))
        assertEquals(Mode.MOVING, away.mode)
        assertTrue(away.changed)
        assertTrue(away.upload)
    }

    @Test
    fun drivingBatchesAMinuteOfFixes() {
        val m = Motion()
        m.add(fix(0, 0.0, 1_500))
        val second = m.add(fix(10, 150.0, 1_500))
        assertEquals(Mode.DRIVING, second.mode)
        val steps = (2L..7L).map { m.add(fix(it * 10, it * 150.0, 1_500)) }
        assertEquals(listOf(false, false, false, false, true, false), steps.map { it.upload })
        assertEquals(5, steps[4].prev.size, "the fixes since the last upload ride along")
        assertTrue(steps[4].prev.zipWithNext().all { (a, b) -> a.atMs < b.atMs }, "oldest first")
        // Slow for two minutes: back to moving.
        var last: Step? = null
        for (s in 80L..200L step 10) last = m.add(fix(s, 1_050.0 + s, 100))
        assertEquals(Mode.MOVING, last!!.mode)
    }

    @Test
    fun liveUploadsEveryFixUntilItsTimeIsUp() {
        val m = Motion()
        for (s in 0L..240L step 30) m.add(fix(s, 0.0, 0))
        assertEquals(Mode.STILL, m.mode)
        assertTrue(m.live(nowMs = 250_000, forMs = 60_000))
        assertTrue((0L..5L).map { m.add(fix(255 + it * 5, 0.0, 0)).upload }.all { it })
        assertFalse(m.tick(300_000))
        assertTrue(m.tick(310_000))
        assertEquals(Mode.MOVING, m.mode)
    }
}
