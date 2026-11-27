// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.share

import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.location.Location
import android.os.IBinder
import android.os.SystemClock
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.app.Battery
import ca.gureet.kinfold.core.app.Fix
import ca.gureet.kinfold.core.app.FixDetails
import ca.gureet.kinfold.core.app.Step
import ca.gureet.kinfold.core.app.activityOf
import ca.gureet.kinfold.core.app.sendFix
import ca.gureet.kinfold.core.app.sendHeartbeat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.math.roundToLong

/**
 * Sharing: a foreground service of type `location` that keeps the connection to the server open
 * (API.md §7), uploads fixes as [Locator] and [Motion] decide, sends a heartbeat when nothing else
 * has gone up for a while, and answers live-view requests. [Watchdog] wakes it every 15 minutes and
 * starts it again if it was stopped. Its notification tells the person their location is shared.
 * Everything it does goes to the log as times, delays and states, never positions.
 */
class SharingService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val log get() = Kinfold.log
    private var started = false
    private var locator: Locator? = null
    private var watcher: Probes.Watcher? = null

    /** When the phone last uploaded anything, in elapsed time. */
    @Volatile
    private var sentMs = 0L

    @Volatile
    private var fixMs = 0L

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!foreground()) return START_NOT_STICKY
        // A null intent means Android restarted the service after ending the process.
        val why = intent?.getStringExtra(WHY) ?: "restarted by Android"
        if (!started) {
            started = true
            instance = this
            log.write("service", "state" to "start", "why" to why)
            scope.launch { run() }
            if (why == KEEPALIVE) scope.launch { keepalive(intent?.getLongExtra(AT, 0L) ?: 0L) }
        } else if (why == KEEPALIVE) {
            scope.launch { keepalive(intent?.getLongExtra(AT, 0L) ?: 0L) }
        } else {
            log.write("service", "state" to "running", "why" to why)
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        log.write("service", "state" to "task_removed")
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        log.write("service", "state" to "stop")
        instance = null
        locator?.stop()
        watcher?.close()
        Connection.release(OWNER)
        runBlocking { Kinfold.family.flush() }
        scope.cancel()
        super.onDestroy()
    }

    /** Puts the service in the foreground; false, and the service stopped, if Android refuses. */
    private fun foreground(): Boolean {
        try {
            startForeground(Notifications.SHARING_ID, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
            return true
        } catch (e: Exception) {
            // Without location permission Android 14 and later refuse a location service.
            log.write("service", "state" to "refused", "error" to Kinfold.describe(e))
            stopSelf()
            return false
        }
    }

    private suspend fun run() {
        if (Kinfold.loadClient() == null) {
            log.write("service", "state" to "not_set_up")
            stopSelf()
            return
        }
        Connection.acquire(OWNER)
        watcher = Probes.Watcher(this)
        locator = Locator(this, ::onFix).also { it.start() }
        Watchdog.schedule(this)
        log.write("state", *Probes.state(this))
        update()
    }

    // ---- what goes up ----

    private fun onFix(fix: Fix, step: Step, location: Location) {
        fixMs = SystemClock.elapsedRealtime()
        log.write(
            "fix",
            "age_ms" to fixMs - fix.atMs,
            "acc_m" to fix.accM,
            "spd_cms" to fix.spdCms,
            "moved_m" to step.movedM,
            "provider" to location.provider,
            "mode" to step.mode.name.lowercase(),
            "upload" to step.upload,
        )
        if (step.upload) upload(fix, step, location)
        update()
    }

    private fun upload(fix: Fix, step: Step, location: Location) {
        val wake = Wakelocks.hold(this, "upload", 30_000)
        scope.launch {
            try {
                val b = Probes.battery(this@SharingService)
                val details = FixDetails(
                    if (location.hasBearing()) location.bearing.roundToLong() else null,
                    Battery(b.pct, b.charging),
                    activityOf(step.mode, fix.spdCms),
                    Locator.isMock(location),
                )
                if (Kinfold.home.sendFix(fix, step.prev, SystemClock.elapsedRealtime(), details, via())) sentMs = SystemClock.elapsedRealtime()
            } finally {
                Wakelocks.release(wake)
            }
        }
    }

    private suspend fun heartbeat(why: String) {
        val b = Probes.battery(this)
        if (Kinfold.home.sendHeartbeat(Battery(b.pct, b.charging), why, via())) sentMs = SystemClock.elapsedRealtime()
    }

    /** How an upload goes: on the stream when it is open. */
    private fun via(): String = if (Connection.connected.value) "stream" else "https"

    // ---- the watchdog ----

    /** The watchdog's visit: logs the phone's state, keeps the server hearing from the phone, and mends the stream. */
    private suspend fun keepalive(scheduledAt: Long) {
        val wake = Wakelocks.hold(this, "keepalive", 60_000)
        try {
            val now = SystemClock.elapsedRealtime()
            val down = Connection.downSinceMs
            log.write(
                "keepalive",
                "late_ms" to (if (scheduledAt > 0) now - scheduledAt else null),
                "stream" to Connection.connected.value,
                "down_ms" to (if (down != 0L) now - down else null),
                "since_sent_ms" to (if (sentMs != 0L) now - sentMs else null),
                "since_fix_ms" to (if (fixMs != 0L) now - fixMs else null),
                "mode" to locator?.mode?.name?.lowercase(),
                *Probes.state(this),
            )
            if (Kinfold.loadClient()?.circles()?.firstOrNull() == null) return
            if (sentMs == 0L || now - sentMs >= HEARTBEAT_AFTER_MS) heartbeat("quiet")
            if (!Connection.connected.value && down != 0L && now - down >= STREAM_STUCK_MS) Connection.restart("down too long")
            Kinfold.family.maintain("keepalive")
            Kinfold.family.flush()
            locator?.tick()
            update()
        } finally {
            Wakelocks.release(wake)
        }
    }

    /** The notification's line, and the screen's. */
    private fun update() {
        val now = SystemClock.elapsedRealtime()
        fun ago(ms: Long): String = when {
            ms == 0L -> "never"
            now - ms < 60_000 -> "just now"
            else -> "${(now - ms) / 60_000} min ago"
        }
        status = (if (Connection.connected.value) "Connected" else "Connecting") + " · last update sent " + ago(sentMs)
        getSystemService(NotificationManager::class.java).notify(Notifications.SHARING_ID, notification())
    }

    private fun notification() = Notifications.sharing(this, Kinfold.family.ui.value.circleName, status)

    companion object {
        const val WHY = "why"
        const val AT = "at"
        const val KEEPALIVE = "keepalive"
        private const val OWNER = "service"

        /** A heartbeat goes up after this long without any upload: well inside the server's 35 minutes. */
        const val HEARTBEAT_AFTER_MS = 25 * 60_000L

        /** A stream down this long is started again, which resets its backoff. */
        const val STREAM_STUCK_MS = 10 * 60_000L

        @Volatile
        private var instance: SharingService? = null

        /** Whether the service is sharing now. */
        val running: Boolean get() = instance != null

        /** What the screen shows of the service. */
        @Volatile
        var status: String = "Starting"
            private set

        /** Fixes every 5 seconds for [forMs], each uploaded: the answer to a live-view request. */
        fun live(forMs: Long) {
            val s = instance ?: return
            Wakelocks.hold(s, "live", forMs + 15_000)
            s.locator?.live(forMs)
        }

        /** Shows the service's state again, after the stream changed. */
        fun show() {
            instance?.update()
        }

        /** Starts the service, or tells the running one [why]; Android may refuse it in the background. */
        fun start(context: Context, why: String, at: Long = 0) {
            try {
                context.startForegroundService(Intent(context, SharingService::class.java).putExtra(WHY, why).putExtra(AT, at))
            } catch (e: Exception) {
                Kinfold.log.write("service", "state" to "start_refused", "why" to why, "error" to Kinfold.describe(e))
            }
        }

        /** Turns sharing on, from the app: the person chose to. */
        fun turnOn(context: Context) {
            Kinfold.sharing = true
            Kinfold.log.write("sharing", "on" to true)
            start(context, "turned on in the app")
            Watchdog.schedule(context)
        }

        fun turnOff(context: Context) {
            Kinfold.sharing = false
            Kinfold.log.write("sharing", "on" to false)
            Watchdog.cancel(context)
            context.stopService(Intent(context, SharingService::class.java))
        }
    }
}
