// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.share

import android.net.ConnectivityManager
import android.net.Network
import android.os.SystemClock
import ca.gureet.kinfold.Kinfold
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.StreamChange
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlin.math.min

/**
 * The device's connection to its server: the client started, and one stream kept open (API.md §7)
 * for as long as something needs it, the sharing service or a screen in front of the person.
 *
 * When the phone moves to another network, the stream starts again on the new one at once. A
 * connection on the old network can otherwise die quietly, and the stream would only notice when
 * a ping went unanswered, minutes later.
 */
object Connection {
    private val owners = HashSet<String>()
    private var main: Job? = null
    private var stream: Job? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var network: Network? = null

    @Volatile
    private var started: Client? = null

    private val up = MutableStateFlow(false)

    /** Whether the stream is open now. */
    val connected: StateFlow<Boolean> get() = up

    /** When the stream last went down, in elapsed time; 0 while it is up or before it first opened. */
    @Volatile
    var downSinceMs = 0L
        private set

    /** [owner] needs the connection; it opens if it isn't open. */
    @Synchronized
    fun acquire(owner: String) {
        owners.add(owner)
        if (main?.isActive != true) open()
    }

    /** [owner] no longer needs it; the last one out closes it. */
    @Synchronized
    fun release(owner: String) {
        owners.remove(owner)
        if (owners.isEmpty()) close()
    }

    /** After the phone has been set up or joined: opens the connection for whoever is waiting on it. */
    @Synchronized
    fun kick() {
        if (owners.isNotEmpty() && main?.isActive != true) open()
    }

    /** Starts the stream again, which also resets its backoff. */
    @Synchronized
    fun restart(why: String) {
        val c = started ?: return
        startStream(c, why)
    }

    /** What the client tells the app about its stream, through the core's [ca.gureet.kinfold.core.app.FamilyEvents]. */
    fun changed(change: StreamChange) {
        val now = SystemClock.elapsedRealtime()
        when (change) {
            is StreamChange.Connected -> {
                Kinfold.log.write("stream", "state" to "connected", "down_ms" to (if (downSinceMs != 0L) now - downSinceMs else null), "net" to Probes.network(Kinfold.context))
                downSinceMs = 0L
                up.value = true
            }
            is StreamChange.Disconnected -> {
                if (up.value || downSinceMs == 0L) downSinceMs = now
                up.value = false
                Kinfold.log.write("stream", "state" to "disconnected", "code" to change.code, "retry_ms" to change.retryInMs, "net" to Probes.network(Kinfold.context))
            }
            is StreamChange.Stopped -> {
                if (up.value || downSinceMs == 0L) downSinceMs = now
                up.value = false
                Kinfold.log.write("stream", "state" to "stopped", "code" to change.code)
            }
        }
    }

    private fun open() {
        main = Kinfold.scope.launch {
            val c = Kinfold.loadClient()
            if (c == null) {
                Kinfold.log.write("connection", "state" to "not_set_up")
                return@launch
            }
            var waitMs = 5_000L
            while (true) {
                try {
                    c.start()
                    break
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Kinfold.log.write("start_failed", "error" to Kinfold.describe(e), "retry_ms" to waitMs, "net" to Probes.network(Kinfold.context))
                    delay(waitMs)
                    waitMs = min(waitMs * 2, 300_000L)
                }
            }
            synchronized(this@Connection) {
                started = c
                startStream(c, "start")
                watchNetwork()
            }
            Kinfold.family.started(c)
        }
    }

    private fun close() {
        main?.cancel()
        stream?.cancel()
        main = null
        stream = null
        started = null
        callback?.let { Kinfold.context.getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        callback = null
        network = null
        up.value = false
        Kinfold.log.write("connection", "state" to "closed")
    }

    private fun startStream(c: Client, why: String) {
        stream?.cancel()
        Kinfold.log.write("stream", "state" to "starting", "why" to why, "ping_s" to Kinfold.PING_MS / 1_000)
        stream = Kinfold.scope.launch {
            val code = c.runStream(Kinfold.PING_MS)
            Kinfold.log.write("stream", "state" to "ended", "code" to code)
        }
    }

    private fun watchNetwork() {
        if (callback != null) return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(n: Network) {
                Kinfold.log.write("net", "state" to "available", "net" to Probes.network(Kinfold.context))
                val changed = synchronized(this@Connection) {
                    val before = network
                    network = n
                    before != null && before != n
                }
                if (changed) restart("network changed")
            }

            override fun onLost(n: Network) {
                Kinfold.log.write("net", "state" to "lost")
            }
        }
        Kinfold.context.getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(cb)
        callback = cb
    }
}
