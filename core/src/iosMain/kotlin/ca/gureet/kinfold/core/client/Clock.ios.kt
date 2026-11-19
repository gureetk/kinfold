// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import kotlinx.cinterop.convert
import platform.Foundation.NSDate
import platform.Foundation.timeIntervalSince1970
import platform.posix.CLOCK_MONOTONIC
import platform.posix.clock_gettime_nsec_np

// On Apple's systems CLOCK_MONOTONIC keeps counting while the device sleeps (CLOCK_UPTIME_RAW doesn't).
internal actual fun monotonicMillis(): Long = (clock_gettime_nsec_np(CLOCK_MONOTONIC.convert()) / 1_000_000u).toLong()

internal actual fun wallMillis(): Long = (NSDate().timeIntervalSince1970 * 1000.0).toLong()
