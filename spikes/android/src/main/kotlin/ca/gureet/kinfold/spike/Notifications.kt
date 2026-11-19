// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

/** The sharing notification the foreground service needs, and the alerts the harness sends. */
object Notifications {
    const val SHARING = "sharing"
    const val ALERTS = "alerts"
    const val SHARING_ID = 1

    fun channels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(SHARING, "Sharing", NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(ALERTS, "Alerts", NotificationManager.IMPORTANCE_HIGH))
    }

    fun sharing(context: Context, text: String): Notification =
        Notification.Builder(context, SHARING)
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentTitle("Kinfold spike: sharing")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openApp(context))
            .build()

    fun alert(context: Context, id: Int, title: String, text: String) {
        val n = Notification.Builder(context, ALERTS)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(text)
            .setCategory(Notification.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .build()
        context.getSystemService(NotificationManager::class.java).notify(id, n)
    }

    private fun openApp(context: Context): PendingIntent =
        PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
}
