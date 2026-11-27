// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.share

import android.Manifest
import android.app.ActivityManager
import android.app.NotificationManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.os.PowerManager
import ca.gureet.kinfold.Kinfold

/**
 * Sharing health (plan §17): every permission and setting that sharing depends on, each green or
 * red, with what to do about a red one.
 */
object Health {
    enum class Fix { LOCATION_SETTINGS, LOCATION, BACKGROUND_LOCATION, NOTIFICATIONS, BATTERY, APP_INFO, SHARING }

    /** One row: whether it's as sharing needs, and what tapping it does when it isn't. */
    class Check(val title: String, val ok: Boolean, val detail: String, val fix: Fix?, val warningOnly: Boolean = false)

    fun checks(context: Context): List<Check> {
        val lm = context.getSystemService(LocationManager::class.java)
        val pm = context.getSystemService(PowerManager::class.java)
        val am = context.getSystemService(ActivityManager::class.java)
        val nm = context.getSystemService(NotificationManager::class.java)
        val fine = granted(context, Manifest.permission.ACCESS_FINE_LOCATION)
        val coarse = granted(context, Manifest.permission.ACCESS_COARSE_LOCATION)
        val always = granted(context, Manifest.permission.ACCESS_BACKGROUND_LOCATION)
        val notifications = (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || granted(context, Manifest.permission.POST_NOTIFICATIONS)) && nm.areNotificationsEnabled()
        val bucket = context.getSystemService(UsageStatsManager::class.java).appStandbyBucket
        val samsung = Build.MANUFACTURER.equals("samsung", ignoreCase = true)
        return listOf(
            Check("Location is on", lm.isLocationEnabled, if (lm.isLocationEnabled) "The phone's location services are on." else "Turn on location in the phone's settings.", Fix.LOCATION_SETTINGS),
            Check(
                "Precise location",
                fine,
                when {
                    fine -> "Kinfold may use your precise location."
                    coarse -> "Kinfold has approximate location only. Allow precise location."
                    else -> "Kinfold may not use your location yet."
                },
                Fix.LOCATION,
            ),
            Check(
                "Location all the time",
                always,
                if (always) "Sharing works with the app closed." else "In the next screen, choose Allow all the time, so sharing works with the app closed.",
                if (fine) Fix.BACKGROUND_LOCATION else Fix.LOCATION,
            ),
            Check("Notifications", notifications, if (notifications) "Kinfold can tell you when a family member's phone goes quiet." else "Allow notifications, so Kinfold can show that it's sharing and tell you about your family.", Fix.NOTIFICATIONS),
            Check(
                "Battery optimization off",
                pm.isIgnoringBatteryOptimizations(context.packageName),
                "Android lets an app that is not optimized keep its connection in deep sleep, and restart sharing if it was stopped.",
                Fix.BATTERY,
            ),
            Check(
                "Background activity allowed",
                !am.isBackgroundRestricted && bucket < UsageStatsManager.STANDBY_BUCKET_RESTRICTED,
                if (samsung) {
                    "In App info › Battery, choose Unrestricted. On Samsung phones also check that Kinfold isn't under Settings › Battery › Background usage limits as a sleeping app."
                } else {
                    "In App info › Battery, choose Unrestricted."
                },
                Fix.APP_INFO,
            ),
            Check("Sharing is on", Kinfold.sharing && SharingService.running, if (Kinfold.sharing) SharingService.status else "Sharing is off: your family doesn't see where you are.", Fix.SHARING),
            Check("Connected to your server", Connection.connected.value, if (Connection.connected.value) "Updates go to your family as they happen." else "Not connected right now. Kinfold keeps trying.", null),
            Check(
                "Battery saver off",
                !pm.isPowerSaveMode,
                if (pm.isPowerSaveMode) "Battery saver may delay updates." else "Battery saver is off.",
                null,
                warningOnly = true,
            ),
        )
    }

    /** Whether every check that matters is green. */
    fun allGood(context: Context): Boolean = checks(context).all { it.ok || it.warningOnly }

    private fun granted(context: Context, permission: String): Boolean = context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
}
