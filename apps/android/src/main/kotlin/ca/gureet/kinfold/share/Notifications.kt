// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.share

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import ca.gureet.kinfold.R
import ca.gureet.kinfold.ui.MainActivity

/**
 * The sharing notification the foreground service needs, which also tells the person that their
 * location is being shared; the alerts that a family member's phone has gone quiet; and the
 * notice that someone is asking to join.
 */
object Notifications {
    const val SHARING = "sharing"
    const val ALERTS = "alerts"
    const val JOINS = "joins"
    const val SHARING_ID = 1
    private const val JOIN_ID = 2

    fun channels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(SHARING, "Sharing your location", NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(ALERTS, "Alerts about your family", NotificationManager.IMPORTANCE_HIGH))
        nm.createNotificationChannel(NotificationChannel(JOINS, "People asking to join", NotificationManager.IMPORTANCE_DEFAULT))
    }

    fun sharing(context: Context, circle: String?, text: String): Notification =
        Notification.Builder(context, SHARING)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(if (circle != null) "Sharing your location with $circle" else "Sharing your location")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openApp(context))
            .build()

    /** A family member's phone has been quiet for a while (PROTOCOL.md §14.1); [id] keeps one per phone. */
    fun alert(context: Context, id: Int, title: String, text: String) {
        val n = Notification.Builder(context, ALERTS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setCategory(Notification.CATEGORY_STATUS)
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .build()
        context.getSystemService(NotificationManager::class.java).notify(id, n)
    }

    fun joinRequest(context: Context, name: String) {
        val n = Notification.Builder(context, JOINS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("$name is asking to join")
            .setContentText("Open Kinfold to compare safety codes and let them in.")
            .setAutoCancel(true)
            .setContentIntent(openApp(context))
            .build()
        context.getSystemService(NotificationManager::class.java).notify(JOIN_ID, n)
    }

    fun clearJoinRequest(context: Context) {
        context.getSystemService(NotificationManager::class.java).cancel(JOIN_ID)
    }

    private fun openApp(context: Context): PendingIntent =
        PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
}
