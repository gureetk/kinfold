// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike.harness

import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.client.ApiException
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.ClientListener
import ca.gureet.kinfold.core.client.Delivery
import ca.gureet.kinfold.core.client.Payloads
import ca.gureet.kinfold.core.client.ServerEvent
import ca.gureet.kinfold.core.client.SilenceAlert
import ca.gureet.kinfold.core.client.StreamChange
import ca.gureet.kinfold.core.client.Wake
import ca.gureet.kinfold.core.client.admit
import ca.gureet.kinfold.core.client.grantOf
import ca.gureet.kinfold.core.client.pendingInvites
import ca.gureet.kinfold.core.client.registerWatch
import ca.gureet.kinfold.core.log.Device
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.push.PushReceipt
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap

/** How often the harness does what, in milliseconds; 0 turns a schedule off. */
class Schedule(
    val locateEveryMs: Long = 30 * MINUTE,
    val alertEveryMs: Long = 3 * HOUR,
    /** `evt` (an arrival) or `sos`: every alert looks the same to the server (PROTOCOL.md §14.3). */
    val alertType: String = "evt",
    val pingMs: Long = Client.DEFAULT_PING_MS,
    val sampleEveryMs: Long = MINUTE,
) {
    companion object {
        const val MINUTE = 60_000L
        const val HOUR = 60 * MINUTE
    }
}

/**
 * The other family member, for the spikes: a device in the test circle that keeps its stream
 * open, lets in whoever uses its invites, registers the silence watches the phones grant it, asks
 * the phones for their location and sends them alerts on a schedule, and logs what comes back as
 * times, delays and distances. Positions stay in memory; the log never holds one.
 */
class Harness(
    private val client: Client,
    private val circleId: Bytes,
    private val log: EventLog,
    private val schedule: Schedule = Schedule(),
) : ClientListener {
    private val positions = Positions()
    private val names = ConcurrentHashMap<Bytes, String>()

    /** When the server received each phone's latest live-view request, until the phone answers it. */
    private val asked = ConcurrentHashMap<Bytes, ULong>()
    private val joinRequests = Channel<Unit>(Channel.CONFLATED)

    private fun now(): ULong = client.clock.now()

    /** Runs until cancelled. */
    suspend fun run() = coroutineScope {
        client.listener = this@Harness
        client.start()
        log.write(now(), "start", "device" to id(client.keys.deviceId), "circle" to id(circleId), "server" to client.serverUrl)
        launch {
            val code = client.runStream(schedule.pingMs)
            log.write(now(), "stream", "state" to "stopped", "code" to code)
        }
        launch { admitLoop() }
        if (schedule.locateEveryMs > 0) launch { every(schedule.locateEveryMs) { askForLocations() } }
        if (schedule.alertEveryMs > 0) launch { every(schedule.alertEveryMs) { sendAlert() } }
        if (schedule.sampleEveryMs > 0) launch { every(schedule.sampleEveryMs) { sample() } }
    }

    /** The phones and tablets of the circle other than the harness. */
    suspend fun phones(): List<Device> =
        client.state(circleId)?.receivingDevices()?.filter { it.kind.isPhoneOrTablet && it.id != client.keys.deviceId } ?: emptyList()

    /** Asks every phone for a live update, waking its location extension where it has one (§8.2, `sig`). */
    suspend fun askForLocations() {
        for (d in phones()) {
            val receivedAt = client.send(circleId, Payloads.liveRequest(), to = listOf(d.id), wake = Wake.LOCATE) ?: continue
            asked[d.id] = receivedAt
            log.write(now(), "live_req", "device" to id(d.id), "received_at" to receivedAt)
        }
    }

    /** Sends the circle an alert with `notify`; the phones log when they show it and answer with `spike_ack`. */
    suspend fun sendAlert() {
        val t = now()
        val payload = if (schedule.alertType == "sos") {
            Payloads.sos(t, "start", 0, 0, 0)
        } else {
            Json.Obj(linkedMapOf("t" to Json.Str("evt"), "ts" to Json.Num(t.toLong()), "k" to Json.Str("arrive"), "detail" to Json.Str("spike test alert")))
        }
        val receivedAt = client.send(circleId, payload, wake = Wake.NOTIFY) ?: return
        log.write(now(), "alert", "type" to schedule.alertType, "sent_at" to t, "received_at" to receivedAt)
    }

    /** Each phone's position age now, and whether it is moving. */
    suspend fun sample() {
        val t = now()
        for (d in phones()) {
            val latest = positions.latest(d.id)
            if (latest == null) {
                log.write(t, "sample", "device" to id(d.id), "no_fix" to true)
            } else {
                log.write(t, "sample", "device" to id(d.id), "age_ms" to age(t, latest.ts), "moving" to positions.moving(d.id))
            }
        }
    }

    private suspend fun admitLoop() {
        while (true) {
            for (pending in client.pendingInvites()) {
                try {
                    val a = client.admit(pending) ?: continue
                    names[a.deviceId] = a.name
                    log.write(now(), "joined", "device" to id(a.deviceId), "account" to id(a.accountId), "name" to a.name)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    if (e !is ApiException || e.status != 410) failed("admitting", e)
                }
            }
            withTimeoutOrNull(ADMIT_POLL_MS) { joinRequests.receive() }
        }
    }

    private suspend fun every(periodMs: Long, task: suspend () -> Unit) {
        while (true) {
            delay(periodMs)
            try {
                task()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                failed("a scheduled task", e)
            }
        }
    }

    // ---- what the client reports ----

    override suspend fun delivered(delivery: Delivery) {
        val d = delivery
        val from = id(d.sender.id)
        when (d.payload.string("t")) {
            "loc" -> location(d)
            "hb" -> log.write(
                d.openedAt, "hb", "device" to from, "ts" to d.payload.long("ts"), "received_at" to d.receivedAt,
                "flags" to ((d.payload["flags"] as? Json.Arr)?.items?.mapNotNull { (it as? Json.Str)?.value }), "bat" to d.payload.long("bat"),
            )
            "watch_grant" -> {
                val grant = grantOf(d.payload)
                if (grant != null && grant.watcherAccount == client.keys.accountId) {
                    try {
                        client.registerWatch(grant)
                        log.write(d.openedAt, "watch", "device" to id(grant.watchedDevice), "after_min" to grant.afterMin, "not_after" to grant.notAfter)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        failed("registering a watch", e)
                    }
                }
            }
            "profile" -> d.payload.string("name")?.let {
                names[d.sender.id] = it
                log.write(d.openedAt, "profile", "device" to from, "name" to it)
            }
            "spike_ack" -> log.write(
                d.openedAt, "ack", "device" to from, "of" to d.payload.string("of"), "alert_sent_at" to d.payload.long("sent_at"),
                "opened_at" to d.payload.long("opened_at"), "shown_at" to d.payload.long("shown_at"), "via" to d.payload.string("via"),
                "received_at" to d.receivedAt,
            )
            else -> log.write(d.openedAt, "payload", "device" to from, "type" to d.payload.string("t"))
        }
    }

    private fun location(d: Delivery) {
        val p = d.payload
        val ts = p.long("ts")?.takeIf { it >= 0 }?.toULong() ?: return
        val fix = Fix(ts, p.long("lat") ?: return, p.long("lon") ?: return, p.long("acc") ?: 0, p.long("spd"))
        val previous = positions.add(d.sender.id, fix)
        val askedAt = asked[d.sender.id]
        val answers = askedAt != null && d.receivedAt >= askedAt
        if (answers) asked.remove(d.sender.id)
        log.write(
            d.openedAt, "loc",
            "device" to id(d.sender.id),
            "ts" to ts,
            "received_at" to d.receivedAt,
            "age_ms" to age(d.openedAt, ts),
            "gap_ms" to previous?.let { age(ts, it.ts) },
            "moved_m" to previous?.let { distanceM(it, fix).toLong() },
            "acc_m" to fix.accM,
            "spd_cms" to fix.speedCms,
            "bat" to p.long("bat"),
            "act" to p.string("act"),
            "prec" to p.string("prec"),
            // The first position after a live-view request: how long after the server took the request.
            "answer_ms" to if (answers) age(d.receivedAt, askedAt) else null,
        )
    }

    override suspend fun refused(circleId: Bytes?, reason: Reason) {
        log.write(now(), "refused", "reason" to reason.code)
    }

    override suspend fun silence(alert: SilenceAlert) {
        log.write(
            now(), "silence", "device" to id(alert.watchedDevice), "last_seen_at" to alert.lastSeenAt, "sent_at" to alert.sentAt,
            "quiet_ms" to if (alert.lastSeenAt == 0UL) null else age(alert.sentAt, alert.lastSeenAt),
        )
    }

    override suspend fun event(event: ServerEvent) {
        when (event) {
            is ServerEvent.JoinRequest -> joinRequests.trySend(Unit)
            is ServerEvent.WatchEnded -> log.write(now(), "watch_ended", "device" to id(event.watchedDevice), "reason" to event.reason)
            is ServerEvent.Notice -> log.write(now(), "notice", "code" to event.code)
            else -> log.write(now(), "event", "type" to (event::class.simpleName ?: "?"))
        }
    }

    override suspend fun stream(change: StreamChange) {
        when (change) {
            is StreamChange.Connected -> {
                log.write(now(), "stream", "state" to "connected")
                joinRequests.trySend(Unit) // requests may have come while the stream was down
            }
            is StreamChange.Disconnected -> log.write(now(), "stream", "state" to "disconnected", "code" to change.code, "retry_ms" to change.retryInMs)
            is StreamChange.Stopped -> log.write(now(), "stream", "state" to "stopped", "code" to change.code)
        }
    }

    override suspend fun pushDropped(reason: PushReceipt.Drop) {
        log.write(now(), "push_dropped", "reason" to reason.name.lowercase())
    }

    override suspend fun failed(what: String, error: Throwable) {
        log.write(now(), "failed", "what" to what, "error" to (error::class.simpleName ?: "?"), "message" to error.message)
    }

    private companion object {
        const val ADMIT_POLL_MS = 30_000L

        fun id(b: Bytes): String = Base64Url.encode(b.toByteArray())

        /** How much later [later] is than [earlier], in milliseconds; negative when it is earlier. */
        fun age(later: ULong, earlier: ULong): Long = if (later >= earlier) (later - earlier).toLong() else -(earlier - later).toLong()
    }
}
