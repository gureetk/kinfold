// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.location.Location
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.ClientListener
import ca.gureet.kinfold.core.client.Delivery
import ca.gureet.kinfold.core.client.Payloads
import ca.gureet.kinfold.core.client.ServerEvent
import ca.gureet.kinfold.core.client.SilenceAlert
import ca.gureet.kinfold.core.client.StreamChange
import ca.gureet.kinfold.core.client.grantWatch
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.Bytes
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.min
import kotlin.math.roundToLong

/**
 * Sharing, as spike 2 tests it: a foreground service of type `location` that keeps one stream to
 * the server open (API.md §7), uploads fixes as [Locator] and [Motion] decide, sends a heartbeat
 * when nothing else has gone up for a while, answers live-view requests, shows alerts and tells
 * the harness when it did. [Watchdog] wakes it every 15 minutes and restarts it if it was stopped.
 * Everything it does goes to the log as times, delays and states.
 */
class SharingService : Service(), ClientListener {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val log get() = Spike.log
    private var running = false
    private var client: Client? = null
    private var circle: Bytes? = null
    private var locator: Locator? = null
    private var watcher: Probes.Watcher? = null
    private var stream: Job? = null
    private val received = ConcurrentHashMap<String, AtomicInteger>()
    private val alertIds = AtomicInteger(100)

    @Volatile
    private var connected = false

    /** When the stream last went down, in elapsed time; 0 while it is up. */
    @Volatile
    private var downSinceMs = 0L

    /** When the phone last uploaded anything, in elapsed time. */
    @Volatile
    private var sentMs = 0L

    @Volatile
    private var fixMs = 0L

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Notifications.channels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!foreground("Starting")) return START_NOT_STICKY
        // A null intent means Android restarted the service after ending the process.
        val why = intent?.getStringExtra(WHY) ?: "restarted by Android"
        if (!running) {
            running = true
            log.write("service", "state" to "start", "why" to why)
            scope.launch { run() }
            if (why == KEEPALIVE) scope.launch { keepalive(intent?.getLongExtra(AT, 0L) ?: 0L) }
        } else {
            when (why) {
                KEEPALIVE -> scope.launch { keepalive(intent?.getLongExtra(AT, 0L) ?: 0L) }
                RESTREAM -> client?.let { restartStream(it, "ping changed") }
                else -> log.write("service", "state" to "running", "why" to why)
            }
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        log.write("service", "state" to "task_removed")
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        log.write("service", "state" to "stop")
        status = "Stopped"
        locator?.stop()
        watcher?.close()
        scope.cancel()
        super.onDestroy()
    }

    /** Puts the service in the foreground; false, and the service stopped, if Android refuses. */
    private fun foreground(text: String): Boolean {
        val n = Notifications.sharing(this, text)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(Notifications.SHARING_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
            } else {
                startForeground(Notifications.SHARING_ID, n)
            }
            return true
        } catch (e: Exception) {
            // Without location permission Android 14 and later refuse a location service.
            log.write("service", "state" to "refused", "error" to Spike.describe(e))
            stopSelf()
            return false
        }
    }

    private suspend fun run() {
        Probes.logExits(this)
        val c = Spike.loadClient()
        if (c == null) {
            log.write("service", "state" to "not_joined")
            stopSelf()
            return
        }
        client = c
        c.listener = this
        var waitMs = 5_000L
        while (true) {
            try {
                c.start()
                break
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log.write("start_failed", "error" to Spike.describe(e), "retry_ms" to waitMs, "net" to Probes.network(this))
                delay(waitMs)
                waitMs = min(waitMs * 2, 300_000L)
            }
        }
        val id = c.circles().firstOrNull()
        if (id == null) {
            log.write("service", "state" to "no_circle")
            stopSelf()
            return
        }
        circle = id
        restartStream(c, "start")
        greet(c, id)
        watcher = Probes.Watcher(this)
        locator = Locator(this, ::onFix).also { it.start() }
        Watchdog.schedule(this)
        log.write("state", *Probes.state(this))
        show()
    }

    // ---- the stream ----

    private fun restartStream(c: Client, why: String) {
        stream?.cancel()
        log.write("stream", "state" to "starting", "why" to why, "ping_s" to Spike.pingS)
        stream = scope.launch {
            val code = c.runStream(Spike.pingS * 1_000L)
            log.write("stream", "state" to "ended", "code" to code)
        }
    }

    override suspend fun stream(change: StreamChange) {
        val now = SystemClock.elapsedRealtime()
        when (change) {
            is StreamChange.Connected -> {
                connected = true
                log.write("stream", "state" to "connected", "down_ms" to (if (downSinceMs != 0L) now - downSinceMs else null), "net" to Probes.network(this))
                downSinceMs = 0L
            }
            is StreamChange.Disconnected -> {
                if (connected || downSinceMs == 0L) downSinceMs = now
                connected = false
                log.write("stream", "state" to "disconnected", "code" to change.code, "retry_ms" to change.retryInMs, "net" to Probes.network(this))
            }
            is StreamChange.Stopped -> {
                connected = false
                log.write("stream", "state" to "stopped", "code" to change.code)
            }
        }
        show()
    }

    // ---- what goes up ----

    /** The phone's name, once a day, and its silence watch for the harness, renewed before its week ends. */
    private suspend fun greet(c: Client, id: Bytes) {
        val now = c.clock.now().toLong()
        val name = Spike.deviceName()
        if (Spike.profileName != name || now - Spike.profileAt > DAY_MS) {
            attempt("sending the name") {
                c.send(id, Json.Obj(linkedMapOf("t" to Json.Str("profile"), "name" to Json.Str(name))))
                Spike.profileName = name
                Spike.profileAt = now
            }
        }
        if (now - Spike.grantedAt > GRANT_RENEW_MS) {
            val watcher = c.state(id)?.members?.values?.firstOrNull { it.admin && it.accountId != c.keys.accountId }?.accountId
            if (watcher == null) {
                log.write("watch", "error" to "no harness in the circle")
            } else {
                attempt("granting the watch") {
                    c.grantWatch(id, watcher, afterMin = WATCH_AFTER_MIN)
                    Spike.grantedAt = now
                    log.write("watch", "after_min" to WATCH_AFTER_MIN, "watcher" to Spike.id(watcher))
                }
            }
        }
    }

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
        show()
    }

    private fun upload(fix: Fix, step: Step, location: Location) {
        val c = client ?: return
        val id = circle ?: return
        val wake = Wakelocks.hold(this, "upload", 30_000)
        scope.launch {
            try {
                val now = c.clock.now()
                val elapsed = SystemClock.elapsedRealtime()
                fun ts(f: Fix): ULong = now - (elapsed - f.atMs).coerceAtLeast(0).toULong()
                val b = Probes.battery(this@SharingService)
                val extra = LinkedHashMap<String, Json>()
                fix.spdCms?.let { extra["spd"] = Json.Num(it) }
                if (location.hasBearing()) extra["hdg"] = Json.Num(location.bearing.roundToLong() % 360)
                extra["bat"] = Json.Num(b.pct.toLong())
                extra["chg"] = Json.Bool(b.charging)
                extra["act"] = Json.Str(activity(step.mode, fix.spdCms))
                if (Locator.isMock(location)) extra["mock"] = Json.Bool(true)
                if (step.prev.isNotEmpty()) {
                    extra["prev"] = Json.Arr(step.prev.map { Json.Arr(listOf(Json.Num(ts(it).toLong()), Json.Num(it.latE7), Json.Num(it.lonE7), Json.Num(it.accM))) })
                }
                send(c, id, "loc", Payloads.loc(ts(fix), fix.latE7, fix.lonE7, fix.accM, extra = extra), "age_ms" to elapsed - fix.atMs, "prev" to step.prev.size)
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
        val via = if (connected) "stream" else "https"
        val started = SystemClock.elapsedRealtime()
        try {
            val receivedAt = c.send(id, payload)
            sentMs = SystemClock.elapsedRealtime()
            log.write("upload", "type" to type, "via" to via, "took_ms" to sentMs - started, "stored" to (receivedAt != null), *fields)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            log.write("upload", "type" to type, "via" to via, "took_ms" to SystemClock.elapsedRealtime() - started, "error" to Spike.describe(e), *fields)
        }
    }

    // ---- the watchdog ----

    /** The watchdog's visit: logs the phone's state, keeps the server hearing from the phone, and mends the stream. */
    private suspend fun keepalive(scheduledAt: Long) {
        val wake = Wakelocks.hold(this, "keepalive", 60_000)
        try {
            val now = SystemClock.elapsedRealtime()
            val counts = received.entries.joinToString(",") { "${it.key}:${it.value.getAndSet(0)}" }
            log.write(
                "keepalive",
                "late_ms" to (if (scheduledAt > 0) now - scheduledAt else null),
                "stream" to connected,
                "down_ms" to (if (downSinceMs != 0L) now - downSinceMs else null),
                "since_sent_ms" to (if (sentMs != 0L) now - sentMs else null),
                "since_fix_ms" to (if (fixMs != 0L) now - fixMs else null),
                "mode" to locator?.mode?.name?.lowercase(),
                "received" to counts.ifEmpty { null },
                *Probes.state(this),
            )
            val c = client ?: return
            val id = circle ?: return
            if (sentMs == 0L || now - sentMs >= HEARTBEAT_AFTER_MS) heartbeat(c, id, "quiet")
            if (!connected && downSinceMs != 0L && now - downSinceMs >= STREAM_STUCK_MS) restartStream(c, "down too long")
            greet(c, id)
            locator?.tick()
            show()
        } finally {
            Wakelocks.release(wake)
        }
    }

    // ---- what comes down ----

    override suspend fun delivered(delivery: Delivery) {
        val type = delivery.payload.string("t") ?: "?"
        when {
            type == "sig" && delivery.payload.string("k") == "live_req" -> live(delivery)
            type == "evt" || type == "sos" -> alert(delivery, type)
            else -> received.getOrPut(type) { AtomicInteger() }.incrementAndGet()
        }
    }

    private fun live(d: Delivery) {
        val c = client ?: return
        val until = d.payload.long("until")
        val forMs = until?.let { (it - c.clock.now().toLong()).coerceIn(5_000L, 300_000L) } ?: LIVE_MS
        log.write(
            "live_req",
            "from" to Spike.id(d.sender.id),
            "sent_at" to d.sentAt,
            "received_at" to d.receivedAt,
            "opened_at" to d.openedAt,
            "for_ms" to forMs,
            "via" to if (connected) "stream" else "inbox",
        )
        Wakelocks.hold(this, "live", forMs + 15_000)
        locator?.live(forMs)
    }

    private suspend fun alert(d: Delivery, type: String) {
        val c = client ?: return
        val id = circle ?: return
        val title = if (type == "sos") "SOS (spike test)" else "Alert (spike test)"
        Notifications.alert(this, alertIds.incrementAndGet(), title, d.payload.string("detail") ?: "From the harness")
        val shownAt = c.clock.now()
        val via = if (connected) "stream" else "inbox"
        log.write(
            "alert",
            "type" to type,
            "from" to Spike.id(d.sender.id),
            "sent_at" to d.sentAt,
            "received_at" to d.receivedAt,
            "opened_at" to d.openedAt,
            "shown_at" to shownAt,
            "via" to via,
            "delay_ms" to shownAt.toLong() - d.sentAt.toLong(),
        )
        val ack = Json.Obj(
            linkedMapOf(
                "t" to Json.Str("spike_ack"),
                "of" to Json.Str(type),
                "sent_at" to Json.Num(d.sentAt.toLong()),
                "opened_at" to Json.Num(d.openedAt.toLong()),
                "shown_at" to Json.Num(shownAt.toLong()),
                "via" to Json.Str(via),
            ),
        )
        attempt("acknowledging an alert") { c.send(id, ack, to = listOf(d.sender.id)) }
    }

    override suspend fun refused(circleId: Bytes?, reason: Reason) {
        log.write("refused", "reason" to reason.toString())
    }

    override suspend fun silence(alert: SilenceAlert) {
        log.write("silence", "device" to Spike.id(alert.watchedDevice), "last_seen_at" to alert.lastSeenAt)
    }

    override suspend fun event(event: ServerEvent) {
        log.write("event", "type" to event::class.simpleName)
    }

    override suspend fun failed(what: String, error: Throwable) {
        log.write("failed", "what" to what, "error" to Spike.describe(error))
    }

    private suspend fun attempt(what: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            failed(what, e)
        }
    }

    /** The screen's view of the service, and the notification's line. */
    private fun show() {
        val now = SystemClock.elapsedRealtime()
        fun ago(ms: Long): String = if (ms == 0L) "never" else "${(now - ms) / 1_000} s ago"
        status = listOf(
            "Stream: " + if (connected) "connected" else "down",
            "Mode: " + (locator?.mode?.name?.lowercase() ?: "starting"),
            "Last fix: " + ago(fixMs),
            "Last upload: " + ago(sentMs),
        ).joinToString("\n")
    }

    companion object {
        const val WHY = "why"
        const val AT = "at"
        const val KEEPALIVE = "keepalive"
        const val RESTREAM = "restream"

        /** A heartbeat goes up after this long without any upload: well inside the server's 35 minutes. */
        const val HEARTBEAT_AFTER_MS = 25 * 60_000L

        /** A stream down this long is started again, which resets its backoff. */
        const val STREAM_STUCK_MS = 10 * 60_000L

        const val LIVE_MS = 60_000L
        const val WATCH_AFTER_MIN = 60
        const val DAY_MS = 86_400_000L

        /** Grants last a week (Client.grantWatch); the phone renews after five days. */
        const val GRANT_RENEW_MS = 5 * DAY_MS

        /** What the screen shows of the service. */
        @Volatile
        var status: String = "Not running"
            private set

        /** Starts the service, or tells the running one [why]; Android may refuse it in the background. */
        fun start(context: Context, why: String, at: Long = 0) {
            try {
                context.startForegroundService(Intent(context, SharingService::class.java).putExtra(WHY, why).putExtra(AT, at))
            } catch (e: Exception) {
                Spike.log.write("service", "state" to "start_refused", "why" to why, "error" to Spike.describe(e))
            }
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
