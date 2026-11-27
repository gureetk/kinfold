// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.share

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import ca.gureet.kinfold.Kinfold

/**
 * The watchdog: an alarm every 15 minutes that Android delivers even in Doze, though no more often
 * than it allows there. It wakes the service, which logs the phone's state and sends a heartbeat
 * if nothing has gone up for a while; and if the service was stopped, from the task manager say,
 * it starts it again. Android allows that from the background because the person exempted the app
 * from battery optimization, and refuses it otherwise, which the log shows.
 */
class Watchdog : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // Awake until the service has taken over; the lock lapses by itself.
        Wakelocks.hold(context, "watchdog", 60_000)
        schedule(context)
        if (Kinfold.sharing) SharingService.start(context, SharingService.KEEPALIVE, intent.getLongExtra(AT, 0L))
    }

    companion object {
        private const val AT = "at"
        const val EVERY_MS = 15 * 60_000L

        fun schedule(context: Context) {
            val at = SystemClock.elapsedRealtime() + EVERY_MS
            val am = context.getSystemService(AlarmManager::class.java)
            am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pending(context, at))
        }

        fun cancel(context: Context) {
            context.getSystemService(AlarmManager::class.java).cancel(pending(context, 0))
        }

        private fun pending(context: Context, at: Long): PendingIntent =
            PendingIntent.getBroadcast(
                context,
                0,
                Intent(context, Watchdog::class.java).putExtra(AT, at),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
    }
}

/** Starts sharing again after a reboot or an update of the app, if the person had it on. */
class Restart : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val why = when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> "boot"
            Intent.ACTION_MY_PACKAGE_REPLACED -> "updated"
            else -> return
        }
        Kinfold.log.write("restart", "why" to why, "sharing" to Kinfold.sharing)
        if (!Kinfold.sharing) return
        Watchdog.schedule(context)
        SharingService.start(context, why)
    }
}
