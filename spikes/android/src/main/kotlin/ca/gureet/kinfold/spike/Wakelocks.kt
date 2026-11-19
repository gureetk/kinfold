// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import android.content.Context
import android.os.PowerManager

/** Keeps the processor awake for a moment of work, never longer than [ms]. */
object Wakelocks {
    fun hold(context: Context, tag: String, ms: Long): PowerManager.WakeLock =
        context.getSystemService(PowerManager::class.java).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "kinfold:$tag").apply {
            setReferenceCounted(false)
            acquire(ms)
        }

    fun release(lock: PowerManager.WakeLock) {
        if (lock.isHeld) lock.release()
    }
}
