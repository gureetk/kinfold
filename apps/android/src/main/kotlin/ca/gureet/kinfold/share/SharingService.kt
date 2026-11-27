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
import ca.gureet.kinfold.core.app.Seen
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.Payloads
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.Bytes
import kotlinx.coroutines.CancellationException
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
                val c = Kinfold.loadClient() ?: return@launch
                val id = c.circles().firstOrNull() ?: return@launch
                val now = c.clock.now()
                val elapsed = SystemClock.elapsedRealtime()
                fun ts(f: Fix): ULong = now - (elapsed - f.atMs).coerceAtLeast(0).toULong()
                val b = Probes.battery(this@SharingService)
                val extra = LinkedHashMap<String, Json>()
                fix.spdCms?.let { extra["spd"] = Json.Num(it) }
                if (location.hasBearing()) extra["hdg"] = Json.Num(location.bearing.roundToLong() % 360)
                extra["bat"] = Json.Num(b.pct.toLong())
                extra["chg"] = Json.Bool(b.charging)
                val act = activity(step.mode, fix.spdCms)
                extra["act"] = Json.Str(act)
                if (Locator.isMock(location)) extra["mock"] = Json.Bool(true)
                if (step.prev.isNotEmpty()) {
                    extra["prev"] = Json.Arr(step.prev.map { Json.Arr(listOf(Json.Num(ts(it).toLong()), Json.Num(it.latE7), Json.Num(it.lonE7), Json.Num(it.accM))) })
                }
                send(c, id, "loc", Payloads.loc(ts(fix), fix.latE7, fix.lonE7, fix.accM, extra = extra), "age_ms" to elapsed - fix.atMs, "prev" to step.prev.size)
                Kinfold.family.mine(Seen(ts(fix).toLong(), fix.latE7, fix.lonE7, fix.accM, b.pct.toLong(), b.charging, act))
            } finally {
                Wakelocks.release(wake)
            }
        }
    }

    private suspend fun heartbeat(c: Client, id: Bytes, why: String) {
        val b = Probes.battery(this)
        val payload = Payloads.heartbeat(c.clock.now(), listOf("sharing"), mapOf("bat" to Json.Num(b.pct.toLong()), "chg" to Json.Bool(b.charging)))
        send(c, id, "hb", payload, "why" to why)
    }

    /** Uploads one envelope to the circle, on the stream when it is open, and logs how it went. */
    private suspend fun send(c: Client, id: Bytes, type: String, payload: Json.Obj, vararg fields: Pair<String, Any?>) {
        val via = if (Connection.connected.value) "stream" else "https"
        val started = SystemClock.elapsedRealtime()
        try {
            val receivedAt = c.send(id, payload)
            sentMs = SystemClock.elapsedRealtime()
            log.write("upload", "type" to type, "via" to via, "took_ms" to sentMs - started, "stored" to (receivedAt != null), *fields)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            log.write("upload", "type" to type, "via" to via, "took_ms" to SystemClock.elapsedRealtime() - started, "error" to Kinfold.describe(e), *fields)
        }
    }

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
            val c = Kinfold.loadClient() ?: return
            val id = c.circles().firstOrNull() ?: return
            if (sentMs == 0L || now - sentMs >= HEARTBEAT_AFTER_MS) heartbeat(c, id, "quiet")
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

        /** A rough activity from the mode and the speed (PROTOCOL.md §8.2 `act`). */
        fun activity(mode: Mode, spdCms: Long?): String = when {
            mode == Mode.STILL -> "still"
            spdCms == null -> if (mode == Mode.DRIVING) "drive" else "walk"
            spdCms < 50 -> "still"
            spdCms < 300 -> "walk"
            spdCms < 700 -> "cycle"
            else -> "drive"
        }
    }
}
