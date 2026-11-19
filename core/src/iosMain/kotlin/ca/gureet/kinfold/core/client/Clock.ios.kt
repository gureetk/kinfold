// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import platform.Foundation.NSDate
import platform.Foundation.timeIntervalSince1970
import platform.darwin.mach_continuous_time
import platform.darwin.mach_timebase_info
import platform.darwin.mach_timebase_info_data_t

/** The ratio that turns Mach ticks into nanoseconds. */
private val timebase: Pair<ULong, ULong> by lazy {
    memScoped {
        val info = alloc<mach_timebase_info_data_t>()
        mach_timebase_info(info.ptr)
        info.numer.toULong() to info.denom.toULong()
    }
}

// mach_continuous_time keeps counting while the device sleeps, unlike mach_absolute_time.
internal actual fun monotonicMillis(): Long {
    val (numer, denom) = timebase
    return (mach_continuous_time() * numer / denom / 1_000_000u).toLong()
}

internal actual fun wallMillis(): Long = (NSDate().timeIntervalSince1970 * 1000.0).toLong()
