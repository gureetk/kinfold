// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import android.os.SystemClock

// Time since boot, deep sleep included: a phone in Doze keeps counting.
internal actual fun monotonicMillis(): Long = SystemClock.elapsedRealtime()

internal actual fun wallMillis(): Long = System.currentTimeMillis()
