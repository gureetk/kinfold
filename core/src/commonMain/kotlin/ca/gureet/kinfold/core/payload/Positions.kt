// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.payload

/** A position in units of 10⁻⁷ degree (PROTOCOL.md §8.1). */
data class PositionE7(val lat: Long, val lon: Long)

/** Approximate positions (§8.3): snapped to the centre of a fixed grid cell, never blurred with noise. */
object Approx {
    /** The grid's cell, 0.02°, in units of 10⁻⁷ degree. */
    const val CELL_E7 = 200_000L

    /** The smallest `acc` a device reports while it shares approximately, in metres. */
    const val MIN_ACCURACY_M = 2000

    /** The centre of the cell holding [p]. Longitudes from 180° on count as negative, so the grid has no seam. */
    fun snap(p: PositionE7): PositionE7 {
        val lat = minOf(p.lat, 899_999_999L)
        val lon = if (p.lon >= 1_800_000_000L) p.lon - 3_600_000_000L else p.lon
        return PositionE7(centre(lat), centre(lon))
    }

    // floorDiv rounds toward −∞, which puts negative coordinates in the right cell.
    private fun centre(v: Long): Long = v.floorDiv(CELL_E7) * CELL_E7 + CELL_E7 / 2
}
