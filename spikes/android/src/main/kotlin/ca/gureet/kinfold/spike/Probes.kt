// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager

/**
 * What the phone itself says about the app's chances: battery, Doze, power saving, the battery
 * exemption, the standby bucket, background restrictions, the network, and why the process last
 * ended. Only states and numbers; nothing that names a network or a place.
 */
object Probes {
    class Battery(val pct: Int, val microAh: Int?, val charging: Boolean)

    fun battery(context: Context): Battery {
        val bm = context.getSystemService(BatteryManager::class.java)
        val uah = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER).takeIf { it > 0 }
        return Battery(bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY), uah, bm.isCharging)
    }

    /** The phone's state as log fields. */
    fun state(context: Context): Array<Pair<String, Any?>> {
        val pm = context.getSystemService(PowerManager::class.java)
        val b = battery(context)
        val fields = arrayListOf<Pair<String, Any?>>(
            "bat" to b.pct,
            "uah" to b.microAh,
            "charging" to b.charging,
            "screen" to pm.isInteractive,
            "doze" to pm.isDeviceIdleMode,
            "saver" to pm.isPowerSaveMode,
            "exempt" to pm.isIgnoringBatteryOptimizations(context.packageName),
            "net" to network(context),
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) fields.add("light_doze" to pm.isDeviceLightIdleMode)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            fields.add("bucket" to context.getSystemService(UsageStatsManager::class.java).appStandbyBucket)
            fields.add("restricted" to context.getSystemService(ActivityManager::class.java).isBackgroundRestricted)
        }
        return fields.toTypedArray()
    }

    /** `wifi`, `cell`, `ethernet`, `other` or `none`, and whether Android found the internet through it. */
    fun network(context: Context): String {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) } ?: return "none"
        return kind(caps) + if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) "" else " (not validated)"
    }

    private fun kind(caps: NetworkCapabilities): String = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cell"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
        else -> "other"
    }

    /** Logs each way the process ended since the last one logged (Android 11 and later). */
    fun logExits(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
        val am = context.getSystemService(ActivityManager::class.java)
        val since = Spike.exitLoggedAt
        val exits = am.getHistoricalProcessExitReasons(context.packageName, 0, 16).filter { it.timestamp > since }.sortedBy { it.timestamp }
        for (e in exits) {
            Spike.log.write(
                "exit",
                "at" to e.timestamp,
                "reason" to reason(e.reason),
                "status" to e.status,
                "importance" to e.importance,
                "description" to e.description?.take(120),
            )
        }
        exits.lastOrNull()?.let { Spike.exitLoggedAt = it.timestamp }
    }

    private fun reason(r: Int): String = when (r) {
        ApplicationExitInfo.REASON_EXIT_SELF -> "exit_self"
        ApplicationExitInfo.REASON_SIGNALED -> "signaled"
        ApplicationExitInfo.REASON_LOW_MEMORY -> "low_memory"
        ApplicationExitInfo.REASON_CRASH -> "crash"
        ApplicationExitInfo.REASON_CRASH_NATIVE -> "crash_native"
        ApplicationExitInfo.REASON_ANR -> "anr"
        ApplicationExitInfo.REASON_INITIALIZATION_FAILURE -> "initialization_failure"
        ApplicationExitInfo.REASON_PERMISSION_CHANGE -> "permission_change"
        ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "excessive_resource_usage"
        ApplicationExitInfo.REASON_USER_REQUESTED -> "user_requested"
        ApplicationExitInfo.REASON_USER_STOPPED -> "user_stopped"
        ApplicationExitInfo.REASON_DEPENDENCY_DIED -> "dependency_died"
        ApplicationExitInfo.REASON_OTHER -> "other"
        ApplicationExitInfo.REASON_FREEZER -> "freezer"
        ApplicationExitInfo.REASON_PACKAGE_STATE_CHANGE -> "package_state_change"
        ApplicationExitInfo.REASON_PACKAGE_UPDATED -> "package_updated"
        else -> "reason_$r"
    }

    /** Logs Doze, power saving, the screen and the network as they change, until [close]. */
    class Watcher(private val context: Context) : AutoCloseable {
        private val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                val pm = c.getSystemService(PowerManager::class.java)
                when (intent.action) {
                    PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> Spike.log.write("doze", "on" to pm.isDeviceIdleMode)
                    PowerManager.ACTION_POWER_SAVE_MODE_CHANGED -> Spike.log.write("saver", "on" to pm.isPowerSaveMode)
                    Intent.ACTION_SCREEN_ON -> Spike.log.write("screen", "on" to true)
                    Intent.ACTION_SCREEN_OFF -> Spike.log.write("screen", "on" to false)
                }
            }
        }
        private val network = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(n: Network) = Spike.log.write("net", "state" to "available", "net" to network(context))

            override fun onLost(n: Network) = Spike.log.write("net", "state" to "lost")
        }

        init {
            val filter = IntentFilter().apply {
                addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
                addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                context.registerReceiver(receiver, filter)
            }
            context.getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(network)
        }

        override fun close() {
            context.unregisterReceiver(receiver)
            context.getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(network)
        }
    }
}
