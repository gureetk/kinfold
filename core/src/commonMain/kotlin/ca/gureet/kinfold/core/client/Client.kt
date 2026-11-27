// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.envelope.Envelope
import ca.gureet.kinfold.core.envelope.EnvelopeHeader
import ca.gureet.kinfold.core.envelope.Envelopes
import ca.gureet.kinfold.core.envelope.Receipt
import ca.gureet.kinfold.core.envelope.ReplayRecord
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.identity.IdentityChain
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.log.Device
import ca.gureet.kinfold.core.log.LogEntry
import ca.gureet.kinfold.core.log.MemberLog
import ca.gureet.kinfold.core.log.Outcome
import ca.gureet.kinfold.core.payload.EpochSecrets
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.push.PushReceipt
import ca.gureet.kinfold.core.push.WatchGrant
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.core.server.Login
import ca.gureet.kinfold.core.server.ServerInfo
import ca.gureet.kinfold.core.server.Setup
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.readAll
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile
import kotlin.coroutines.cancellation.CancellationException

/** An envelope that passed every check of PROTOCOL.md §7.6, and what the app needs to act on it. */
class Delivery(
    val circleId: Bytes,
    /** The sending device, as the verified log has it. */
    val sender: Device,
    /** [EnvelopeHeader.CIRCLE] or [EnvelopeHeader.DIRECT]. */
    val kind: Int,
    val payload: Json.Obj,
    /** The sender's trusted time when it sealed the envelope. */
    val sentAt: ULong,
    /**
     * The envelope's sequence number, which strictly increases for each sending device in a circle
     * (PROTOCOL.md §7.1). An app never lets a lower one replace what a higher one set (§7.6).
     */
    val seq: ULong,
    /** The server's clock when it stored the envelope. */
    val receivedAt: ULong,
    /** This device's trusted time when it opened the envelope. */
    val openedAt: ULong,
)

/** A silence alert (PROTOCOL.md §14.1): [watchedDevice] has been quiet since [lastSeenAt], 0 if the server doesn't know. */
class SilenceAlert(val circleId: Bytes, val watchedDevice: Bytes, val lastSeenAt: ULong, val sentAt: ULong)

/** An event on the stream (API.md §7). Each is a hint, which the client has acted on where it can. */
sealed class ServerEvent {
    /** This device left [circleId] at entry [seq]; the client has fetched the log to check it. */
    class Removed(val circleId: Bytes, val seq: Long) : ServerEvent()

    /** Someone is waiting on an invite this account made. */
    class JoinRequest(val inviteId: Bytes) : ServerEvent()

    class ShareView(val linkId: Bytes, val views: Long) : ServerEvent()

    /** A watch this account held has ended: `expired`, `deleted` or `device_removed`. */
    class WatchEnded(val circleId: Bytes, val watchedDevice: Bytes, val reason: String) : ServerEvent()

    /** The push address stopped working; register again. */
    data object PushDropped : ServerEvent()

    /** `repair_mode`, `moving` or `restarting`. */
    class Notice(val code: String) : ServerEvent()
}

/** The stream connected, ended or stopped for good (API.md §7). */
sealed class StreamChange {
    data object Connected : StreamChange()

    /** It ended with [code] (1006 when the network failed); the client tries again after [retryInMs]. */
    class Disconnected(val code: Int, val retryInMs: Long) : StreamChange()

    /** It ended with [code] and the client won't reconnect: another connection replaced it (4409), or the app is too old (4426). */
    class Stopped(val code: Int) : StreamChange()
}

/**
 * What a [Client] tells the app as things happen. Each call comes from the coroutine doing the
 * work and holds it up, so return quickly. Nothing passed here holds a key; a [Delivery] holds what
 * an envelope carried, which an app logs only as times and distances, never as positions.
 */
interface ClientListener {
    suspend fun delivered(delivery: Delivery) {}

    /** An envelope was discarded for [reason]; [circleId] is null when even that couldn't be read. */
    suspend fun refused(circleId: Bytes?, reason: Reason) {}

    suspend fun silence(alert: SilenceAlert) {}

    suspend fun event(event: ServerEvent) {}

    suspend fun stream(change: StreamChange) {}

    /**
     * [circleId]'s verified log grew to entry [seq]: someone may have joined or left. An app that
     * keeps data envelopes don't carry for long, such as its member's profile, sends it again
     * (PROTOCOL.md §8.6).
     */
    suspend fun logChanged(circleId: Bytes, seq: Long) {}

    /** A push was dropped without telling anyone (PROTOCOL.md §14.2); the reason is only for logs. */
    suspend fun pushDropped(reason: PushReceipt.Drop) {}

    /** Something went wrong that the client got past: [what] it was doing, and why it failed. */
    suspend fun failed(what: String, error: Throwable) {}

    companion object {
        val NONE: ClientListener = object : ClientListener {}
    }
}

/**
 * A device's side of its Kinfold server: the "sync" of the shared core. It keeps what the device
 * knows in [Storage], talks to the server through a [Transport], and leaves every rule to the rest
 * of the core: the server's identity and login (PROTOCOL.md §13), the member log (§6), envelopes
 * (§7), invites (§9), watch grants and pushes (§14).
 *
 * Make one with [setUp] (a setup code), [forInvite] (an invite), or [load] (a device set up
 * before), then call [start]. Its methods may be called from any coroutine.
 */
class Client private constructor(
    val p: Primitives,
    private val transport: Transport,
    private val storage: Storage,
    val clock: TrustedClock,
    /** The server's address and key, which the device trusts since it was set up (§13.1). */
    val serverUrl: String,
    val serverKey: Bytes,
    val keys: DeviceKeys,
) {
    val api: ServerApi = ServerApi(transport, serverUrl, clock)

    /** Set before [start]. */
    @Volatile
    var listener: ClientListener = ClientListener.NONE

    /** The server's discovery document, as of [start]. */
    @Volatile
    var discovery: Discovery? = null
        private set

    val features: Set<String> get() = discovery?.features ?: emptySet()

    /** Guards everything below and every use of [storage]. Nothing waits on the network while holding it. */
    internal val lock = Mutex()
    private val loginLock = Mutex()
    private val views = LinkedHashMap<Bytes, CircleView>()
    private var cursor: String? = null

    @Volatile
    private var sessionExpiresAt: ULong = 0UL

    @Volatile
    internal var connection: StreamConnection? = null

    @Volatile
    private var clockSavedAt: Long = Long.MIN_VALUE

    /** A circle this device is a member of (§9.4): its verified log, epoch secrets and replay record. */
    private class CircleView(val id: Bytes) {
        val entries = ArrayList<ByteArray>()
        var state = CircleState()
        val secrets = LinkedHashMap<Long, ByteArray>()
        val replay = Replay()

        /** Records held while this device's private state is frozen (§7.6 step 15), to open again. */
        val held = ArrayList<ByteArray>()
    }

    /** The replay record of §7.6 step 9, in memory, with what was added since it was last stored. */
    private class Replay : ReplayRecord {
        val seen = HashMap<Pair<Bytes, ULong>, ULong>()
        val added = ArrayList<ByteArray>()

        override fun contains(sender: Bytes, seq: ULong): Boolean = (sender to seq) in seen

        override fun add(sender: Bytes, seq: ULong, sentAt: ULong) {
            seen[sender to seq] = sentAt
            added.add(replayEntry(sender, seq, sentAt))
        }
    }

    // ---- starting ----

    /**
     * Checks the server against the key the device trusts (§13.1), finishes a registration an
     * earlier run left unfinished, logs in, and catches up the log of every circle the device is in.
     */
    suspend fun start() {
        checkServer()
        lock.withLock { storage.read(Names.PENDING_TOKEN) }?.let { register(Bytes.of(it)) }
        login()
        for (id in circles()) {
            attempt { sync(id) }.exceptionOrNull()?.let { listener.failed("catching up a circle's log", it) }
        }
    }

    /** Reads the discovery document and believes it only once its `ServerInfo` checks out (§13.1). */
    suspend fun checkServer() {
        val d = api.discovery()
        ServerInfo.check(p, d.serverInfo, serverUrl, serverKey)
        val revision = ServerApi.API_REVISION.toLong()
        if (revision !in d.apiMin..d.apiMax) throw ClientException("the server takes API revisions ${d.apiMin} to ${d.apiMax}, not $revision")
        discovery = d
    }

    /** Registers this device's account with [token] (API.md §5). A device registered already counts as success. */
    suspend fun register(token: Bytes) {
        try {
            api.register(keys.cert, IdentityChain(emptyList()), keys.bundle, token)
        } catch (e: ApiException) {
            // An earlier attempt may have registered the device and spent the token before its reply was lost.
            val registered = e.error == "already_registered" || (e.error == "bad_token" && attempt { login() }.isSuccess)
            if (!registered) throw e
        }
        lock.withLock { storage.delete(Names.PENDING_TOKEN) }
    }

    // ---- login ----

    /**
     * Logs in (§13.2): the device signs the server's challenge only after checking that the key it
     * trusts signed it. Then puts the push registration and the watches again (API.md §5).
     */
    suspend fun login() = renew(stale = null, force = true)

    /**
     * Logs in, unless another call has done so since [stale] was the session (or [force]). Calls
     * that find the session missing, ending or refused at the same moment then share one login,
     * rather than each signing a challenge of its own, which the server allows only a few times a
     * minute. The old session stays in use until the new one replaces it, so calls already under
     * way keep theirs.
     */
    private suspend fun renew(stale: ByteArray?, force: Boolean = false) {
        val renewed = loginLock.withLock {
            val current = api.token
            if (!force && current != null && current !== stale && !sessionEnding()) return@withLock false
            val ch = api.challenge(keys.deviceId)
            if (!Login.isChallengeSigned(p, serverKey, ch.challenge, keys.deviceId, ch.expiresAt, ch.sig)) {
                throw ClientException("the server's login challenge isn't signed by its key")
            }
            val s = api.session(keys.deviceId, ch.challenge, Login.deviceSig(p, keys.signing, serverKey, ch.challenge, keys.deviceId))
            api.token = s.token
            sessionExpiresAt = s.expiresAt
            true
        }
        if (renewed) afterLogin()
    }

    private fun sessionEnding(): Boolean = clock.now() + SESSION_MARGIN_MS >= sessionExpiresAt

    /** Logs in again after the server refused [stale], unless another call already has. */
    internal suspend fun renewAfter(stale: ByteArray?) = renew(stale)

    /** The session the stream last opened with, so that its end renews that one alone. */
    @Volatile
    internal var streamSession: ByteArray? = null

    /** Ends the session on the server. */
    suspend fun logout() {
        attempt { api.endSession() }
        api.token = null
    }

    /** Runs [call] with a session, logging in first when there is none or it is about to end, and once more on 401. */
    internal suspend fun <T> authed(call: suspend () -> T): T {
        var used = api.token
        if (used == null || sessionEnding()) {
            renew(used)
            used = api.token
        }
        val result = try {
            call()
        } catch (e: ApiException) {
            if (e.status != 401) throw e
            renew(used)
            call()
        }
        saveClock()
        return result
    }

    private suspend fun afterLogin() {
        val push = lock.withLock { storage.read(Names.PUSH) }
        if (push != null) attempt { api.putPush(ServerApi.obj(push)) }.exceptionOrNull()?.let { listener.failed("putting the push registration again", it) }
        for (grant in lock.withLock { watchedGrants() }) {
            attempt { api.putWatch(grant.circleId, grant.watchedDevice, grant.encode()) }.exceptionOrNull()?.let { e ->
                // A grant the server no longer takes is dropped: it expired, or the watched person ended the watch.
                if (e is ApiException && (e.status == 409 || e.status == 422 || e.status == 404)) {
                    lock.withLock { forgetGrant(grant.circleId, grant.watchedDevice) }
                } else {
                    listener.failed("putting a watch again", e)
                }
            }
        }
    }

    // ---- circles and their logs ----

    /** The circles this device is a member of (§9.4). */
    suspend fun circles(): List<Bytes> = lock.withLock { views.keys.toList() }

    /** A copy of [circleId]'s verified state, or null if the device isn't a member. */
    suspend fun state(circleId: Bytes): CircleState? = lock.withLock { views[circleId]?.state?.copy() }

    /** The epoch secrets this device holds for [circleId]. */
    suspend fun secrets(circleId: Bytes): Map<Long, ByteArray> = lock.withLock { views[circleId]?.secrets?.toMap() ?: emptyMap() }

    /**
     * Fetches the entries of [circleId]'s log this device doesn't hold yet and verifies each as
     * §6.3 requires before keeping it. [ClientException] when an entry breaks the log, or when the
     * server's reported head disagrees with the log it served (§7.7).
     */
    suspend fun sync(circleId: Bytes) {
        val before = lock.withLock { (views[circleId] ?: notMember()).state.seq }
        while (true) {
            val after = lock.withLock { (views[circleId] ?: notMember()).state.seq }
            val page = authed { api.log(circleId, after.takeIf { it >= 0 }) }
            if (lock.withLock { applyPage(views[circleId] ?: notMember(), page) }) break
        }
        val now = lock.withLock { views[circleId]?.state?.seq } ?: return
        if (now > before) listener.logChanged(circleId, now)
    }

    /** Applies a page of entries; whether the device has caught up with the head the server reports. */
    private suspend fun applyPage(v: CircleView, page: LogPage): Boolean {
        for (raw in page.entries) {
            val seq = try {
                LogEntry.parse(raw).header.seq.toLong()
            } catch (_: ProtocolException) {
                throw ClientException("an entry of the circle's log is malformed")
            }
            if (seq <= v.state.seq) continue // a sync running alongside took it first
            when (val o = MemberLog.apply(p, v.state, raw, v.secrets)) {
                is Outcome.Fatal -> throw ClientException("the circle's log breaks at entry $seq: ${o.reason.code}")
                is Outcome.Applied -> {
                    v.state = o.state
                    v.entries.add(raw)
                    storage.append(Names.log(v.id), frames(raw))
                }
            }
        }
        return when {
            v.state.seq < page.seq -> if (page.entries.isEmpty()) throw ClientException("the server reports entries it doesn't serve") else false
            v.state.seq > page.seq -> throw ClientException("the server holds less of the circle's log than this device does")
            v.state.head != page.head -> throw ClientException("the server reports a head the log it served doesn't have")
            else -> true
        }
    }

    /** Starts keeping [id] as a circle this device is a member of, with any epoch secrets it already holds. */
    internal suspend fun addCircle(id: Bytes, secrets: Map<Long, ByteArray> = emptyMap()) {
        lock.withLock {
            if (id in views) throw ClientException("this device is already in the circle")
            val v = CircleView(id)
            views[id] = v
            if (secrets.isNotEmpty()) {
                v.secrets.putAll(secrets)
                storage.write(Names.secrets(id), encodeSecrets(v.secrets))
            }
            storage.write(Names.CIRCLES, frames(*views.keys.map { it.toByteArray() }.toTypedArray()))
        }
    }

    /** Forgets [id] and everything kept for it. */
    internal suspend fun dropCircle(id: Bytes) {
        lock.withLock {
            if (views.remove(id) == null) return
            for (name in listOf(Names.log(id), Names.secrets(id), Names.replay(id))) storage.delete(name)
            storage.write(Names.CIRCLES, frames(*views.keys.map { it.toByteArray() }.toTypedArray()))
        }
    }

    /** The raw entries of [circleId]'s verified log, from `GENESIS`. */
    internal suspend fun entries(circleId: Bytes): List<ByteArray> = lock.withLock { views[circleId]?.entries?.toList() ?: notMember() }

    /**
     * Takes epoch secrets for [circleId] that the log commits to (§8.5), and runs the log again with
     * them, so that the private rules apply (§6.5). Whether anything new was taken.
     */
    internal suspend fun takeSecrets(circleId: Bytes, secrets: Map<Long, ByteArray>): Boolean {
        val changed = lock.withLock {
            val v = views[circleId] ?: return false
            val new = secrets.filterKeys { it !in v.secrets }
            if (new.isEmpty()) return@withLock false
            v.secrets.putAll(new)
            storage.write(Names.secrets(circleId), encodeSecrets(v.secrets))
            val (state, outcomes) = MemberLog.replay(p, v.entries, v.secrets)
            if (outcomes.size != v.entries.size || outcomes.any { it is Outcome.Fatal }) throw ClientException("the circle's log no longer verifies")
            v.state = state
            true
        }
        if (changed) openHeld(circleId)
        return changed
    }

    /**
     * Appends an entry that [build] makes from the circle's current state and epoch secrets, then
     * fetches it back and verifies it like any other. When another entry got there first, catches
     * up and builds it again. The entry's bytes.
     */
    internal suspend fun appendEntry(circleId: Bytes, build: suspend (CircleState, Map<Long, ByteArray>) -> ByteArray): ByteArray {
        repeat(APPEND_TRIES) {
            val raw = lock.withLock {
                val v = views[circleId] ?: notMember()
                build(v.state, v.secrets)
            }
            try {
                authed { api.append(circleId, raw) }
                sync(circleId)
                return raw
            } catch (e: ApiException) {
                if (e.status != 409 || e.error != "conflict") throw e
                sync(circleId)
            }
        }
        throw ClientException("the circle's log kept moving while this device appended to it")
    }

    // ---- sending ----

    /**
     * Seals [payload] (§7.3) and uploads it: to every other receiving device of the circle, or, for
     * a direct envelope, to the devices in [to]. [wake] asks the server to wake recipients that have
     * no stream open (§14.3). When the server says the envelope was built on an old view of the
     * log, the device catches up and builds it again, once. The server's `received_at`, or null
     * when the circle had no one else to send to.
     */
    suspend fun send(circleId: Bytes, payload: Json.Obj, to: Collection<Bytes>? = null, wake: Wake? = null, ttlS: Long = DEFAULT_TTL_S): ULong? {
        require(wake != Wake.LOCATE || to != null) { "locate is for direct envelopes" }
        var again = true
        while (true) {
            val raw = lock.withLock { seal(circleId, payload, to, ttlS) } ?: return null
            try {
                return upload(circleId, raw, wake)
            } catch (e: ApiException) {
                if (!again || e.reason !in RESEAL) throw e
                again = false
                sync(circleId)
            }
        }
    }

    private suspend fun seal(circleId: Bytes, payload: Json.Obj, to: Collection<Bytes>?, ttlS: Long): ByteArray? {
        val v = views[circleId] ?: notMember()
        if (v.state.device(keys.deviceId) == null) throw ClientException("this device is no longer in the circle")
        val recipients = if (to == null) {
            Envelopes.circleRecipients(v.state, keys.deviceId)
        } else {
            val named = to.toSet()
            v.state.receivingDevices().filter { it.id in named }.also {
                if (it.size != named.size) throw ClientException("a device named isn't a receiving device of the circle")
            }
        }
        if (recipients.isEmpty()) return null
        val kind = if (to == null) EnvelopeHeader.CIRCLE else EnvelopeHeader.DIRECT
        val header = EnvelopeHeader(kind, circleId, keys.deviceId, nextSeq(), clock.now(), ttlS, v.state.head)
        return Envelope.seal(p, keys.signing, header, recipients, payload.encode())
    }

    /** The next envelope sequence number, stored as used before it is (§7.1). */
    private fun nextSeq(): ULong {
        val seq = storage.read(Names.SEQ)?.let { readAll(it) { u64() } } ?: 1UL
        storage.write(Names.SEQ, encode { u64(seq + 1UL) })
        return seq
    }

    /** Uploads on the stream where the server takes that (`stream_post`), otherwise by HTTP. */
    private suspend fun upload(circleId: Bytes, raw: ByteArray, wake: Wake?): ULong {
        val conn = connection
        if (conn != null && "stream_post" in features) {
            try {
                return conn.post(raw, wake)
            } catch (_: TransportException) {
                // the stream went away or didn't answer: the same bytes by HTTP, which is safe (API.md §1)
            } catch (_: WebSocketClosed) {
            }
        }
        return authed { api.post(circleId, raw, wake) }
    }

    // ---- receiving ----

    /**
     * Fetches and handles every record the inbox holds past the device's cursor (API.md §7), and
     * moves the cursor on. How many records there were.
     */
    suspend fun fetchInbox(): Int {
        var count = 0
        while (true) {
            val since = lock.withLock { cursor }
            val page = authed { api.inbox(since) }
            for (record in page.records) {
                receiveSafely(record)
                count++
            }
            page.cursor?.let { saveCursor(it) }
            if (!page.more || page.records.isEmpty()) return count
        }
    }

    /** [receive], with what goes wrong reported rather than thrown, so that one bad record doesn't stop the rest. */
    internal suspend fun receiveSafely(record: ByteArray) {
        attempt { receive(record) }.exceptionOrNull()?.let { listener.failed("opening a record", it) }
    }

    /**
     * Handles one delivery record, `u64 received_at ‖ envelope` (API.md §7), from the inbox, the
     * stream or a push: opens it as §7.6 requires, after catching up the log if the envelope names
     * a head or a sender the device doesn't know yet, and acts on what it carries.
     */
    suspend fun receive(record: ByteArray) {
        if (record.size < 8) return listener.refused(null, Reason.MALFORMED)
        val receivedAt = readAll(record.copyOf(8)) { u64() }
        val raw = record.copyOfRange(8, record.size)
        val circleId = try {
            Envelope.parse(raw).header.circleId
        } catch (e: ProtocolException) {
            return listener.refused(null, e.reason)
        }
        val held = heldSeq(circleId) ?: return listener.refused(circleId, Reason.WRONG_CIRCLE)
        if (held < 0) sync(circleId) // a circle being joined: its log comes first
        var receipt = lock.withLock { open(circleId, raw) } ?: return listener.refused(circleId, Reason.WRONG_CIRCLE)
        if (receipt is Receipt.Refused && receipt.reason in RESYNC) {
            sync(circleId)
            receipt = lock.withLock { open(circleId, raw) } ?: return listener.refused(circleId, Reason.WRONG_CIRCLE)
        }
        when (receipt) {
            is Receipt.Refused -> listener.refused(circleId, receipt.reason)
            is Receipt.Held -> lock.withLock { views[circleId]?.held?.add(record) }
            is Receipt.Accepted -> {
                val t = receipt.payload.string("t")
                if (t == "welcome" || t == "refresh") takeEpochSecrets(circleId, receipt.payload)
                val h = receipt.envelope.header
                listener.delivered(Delivery(circleId, receipt.sender, h.kind, receipt.payload, h.sentAt, h.seq, receivedAt, clock.now()))
            }
        }
    }

    /** §7.6 for one envelope of a circle the device is in, keeping the replay record; null for any other circle. */
    private suspend fun open(circleId: Bytes, raw: ByteArray): Receipt? {
        val v = views[circleId] ?: return null
        val receipt = Envelopes.open(p, raw, v.state, keys.deviceId, keys.hpkeKeys, v.replay, clock.now())
        if (v.replay.added.isNotEmpty()) {
            storage.append(Names.replay(circleId), concat(*v.replay.added.toTypedArray()))
            v.replay.added.clear()
        }
        return receipt
    }

    private suspend fun takeEpochSecrets(circleId: Bytes, payload: Json.Obj) {
        repeat(2) { round ->
            val got = lock.withLock { views[circleId]?.let { EpochSecrets.from(p, it.state, payload) } } ?: return
            when (got) {
                is EpochSecrets.Received.HeadUnknown -> if (round == 0) sync(circleId) else return
                is EpochSecrets.Received.Secrets -> {
                    takeSecrets(circleId, got.byEpoch)
                    return
                }
            }
        }
    }

    /** Opens again the records held while the private state was frozen. */
    private suspend fun openHeld(circleId: Bytes) {
        val held = lock.withLock { views[circleId]?.held?.toList()?.also { views[circleId]?.held?.clear() } } ?: return
        for (record in held) receiveSafely(record)
    }

    internal suspend fun saveCursor(value: String) = lock.withLock {
        cursor = value
        storage.write(Names.CURSOR, value.encodeToByteArray())
    }

    /** Forgets the inbox cursor, for a server that no longer knows it; the replay record catches what comes again. */
    internal suspend fun dropCursor() = lock.withLock {
        cursor = null
        storage.delete(Names.CURSOR)
    }

    internal suspend fun cursor(): String? = lock.withLock { cursor }

    /** The `seq` this device holds of [circleId]'s log, or null if it isn't a member. */
    internal suspend fun heldSeq(circleId: Bytes): Long? = lock.withLock { views[circleId]?.state?.seq }

    /** Keeps the latest server time for the next run (§8.4), at most once a minute. */
    internal suspend fun saveClock() {
        val now = monotonicMillis()
        if (clockSavedAt != Long.MIN_VALUE && now - clockSavedAt < CLOCK_SAVE_MS) return
        clockSavedAt = now
        lock.withLock { storage.write(Names.CLOCK, encode { u64(clock.lastServerTime) }) }
    }

    // ---- the stream ----

    /**
     * Keeps the stream open (API.md §7) until cancelled: records as they arrive, log heads, silence
     * alerts, events and the server's time, and uploads where the server takes them on the stream.
     * Reconnects with backoff from 1 second to 5 minutes, with jitter, and logs in again when the
     * session ends. Returns the close code that stopped it for good: 4409 when another connection
     * of this device replaced it, 4426 when the server needs a newer app.
     */
    suspend fun runStream(pingIntervalMs: Long = DEFAULT_PING_MS): Int = StreamRunner(this, pingIntervalMs).run()

    /** Opens one stream connection from the device's cursor. */
    internal suspend fun openStream(pingIntervalMs: Long): WebSocket {
        val before = api.token
        if (before == null || sessionEnding()) renew(before)
        val token = api.token ?: throw ClientException("no session")
        streamSession = token
        val since = cursor()
        val url = "wss://" + serverUrl.removePrefix("https://") + "/v1/stream" + (since?.let { "?since=" + percentEncode(it) } ?: "")
        val headers = mapOf("Authorization" to "Bearer " + Base64Url.encode(token), "Kinfold-Api" to ServerApi.API_REVISION)
        return transport.connect(url, headers, pingIntervalMs)
    }

    // ---- push and watches ----

    /** Replaces this device's push registration (API.md §12), and keeps it to put again after every login. */
    suspend fun registerPush(registration: Json.Obj) {
        authed { api.putPush(registration) }
        lock.withLock { storage.write(Names.PUSH, registration.encode()) }
    }

    suspend fun removePush() {
        authed { api.deletePush() }
        lock.withLock { storage.delete(Names.PUSH) }
    }

    /** The grants this account registered as a watcher, kept to put again after every login. */
    internal fun watchedGrants(): List<WatchGrant> =
        storage.read(Names.WATCHING)?.let { framesLenient(it) }?.mapNotNull {
            try {
                WatchGrant.parse(it)
            } catch (_: ProtocolException) {
                null
            }
        } ?: emptyList()

    /** Keeps [grant] in place of any older grant for the same circle and device. */
    internal fun keepGrant(grant: WatchGrant) {
        val others = watchedGrants().filterNot { it.circleId == grant.circleId && it.watchedDevice == grant.watchedDevice }
        storage.write(Names.WATCHING, frames(*(others + grant).map { it.encode() }.toTypedArray()))
    }

    internal fun forgetGrant(circleId: Bytes, watchedDevice: Bytes) {
        val others = watchedGrants().filterNot { it.circleId == circleId && it.watchedDevice == watchedDevice }
        storage.write(Names.WATCHING, frames(*others.map { it.encode() }.toTypedArray()))
    }

    // ---- storage of pending invites, for Rendezvous.kt ----

    internal fun storageRead(name: String): ByteArray? = storage.read(name)

    internal fun storageWrite(name: String, data: ByteArray) = storage.write(name, data)

    internal fun storageDelete(name: String) = storage.delete(name)

    // ---- loading ----

    /** Reads back everything a previous run kept. */
    private suspend fun loadState() {
        cursor = storage.read(Names.CURSOR)?.decodeToString()
        val ids = storage.read(Names.CIRCLES)?.let { framesLenient(it) } ?: emptyList()
        for (id in ids.filter { it.size == 16 }.map { Bytes.of(it) }) {
            val v = CircleView(id)
            storage.read(Names.secrets(id))?.let { v.secrets.putAll(decodeSecrets(it)) }
            val entries = storage.read(Names.log(id))?.let { framesLenient(it) } ?: emptyList()
            val (state, outcomes) = MemberLog.replay(p, entries, v.secrets)
            if (outcomes.size == entries.size && outcomes.none { it is Outcome.Fatal }) {
                v.state = state
                v.entries.addAll(entries)
            } else {
                // What was kept doesn't verify: start this circle's log again from the server.
                storage.delete(Names.log(id))
            }
            if (entries.size != v.entries.size) storage.write(Names.log(id), frames(*v.entries.toTypedArray()))
            loadReplay(v)
            views[id] = v
        }
    }

    /** The replay record, without pairs older than the record must keep; written back without them. */
    private fun loadReplay(v: CircleView) {
        val raw = storage.read(Names.replay(v.id)) ?: return
        val now = clock.now()
        val kept = ArrayList<ByteArray>()
        val r = Reader(raw)
        while (r.remaining >= REPLAY_ENTRY) {
            val entry = r.bytes(REPLAY_ENTRY)
            val (sender, seq, sentAt) = readAll(entry) { Triple(Bytes.of(bytes(16)), u64(), u64()) }
            if (sentAt > now || now - sentAt < REPLAY_KEEP_MS) {
                v.replay.seen[sender to seq] = sentAt
                kept.add(entry)
            }
        }
        if (kept.size * REPLAY_ENTRY != raw.size) storage.write(Names.replay(v.id), concat(*kept.toTypedArray()))
    }

    private fun notMember(): Nothing = throw ClientException("this device isn't a member of the circle")

    companion object {
        /** Envelopes live a day unless the sender says otherwise. */
        const val DEFAULT_TTL_S = 86_400L

        /** A ping a minute: well inside the 35 minutes after which the server closes a quiet stream. */
        const val DEFAULT_PING_MS = 60_000L

        /** A session is renewed this long before it ends. */
        private const val SESSION_MARGIN_MS: ULong = 60_000UL

        private const val CLOCK_SAVE_MS = 60_000L
        private const val APPEND_TRIES = 3

        /** `sender[16] ‖ u64 seq ‖ u64 sent_at`. */
        private const val REPLAY_ENTRY = 32

        /** The replay record keeps a pair 31 days after `sent_at` (§7.6); a day more for clocks. */
        private const val REPLAY_KEEP_MS: ULong = 2_764_800_000UL

        /** Refusals that mean the device's log is behind: catch up and try again. */
        private val RESYNC = setOf(Reason.UNKNOWN_LOG_HEAD, Reason.SENDER_NOT_ACTIVE)

        /** Refusals of an upload that mean it was built on an old view of the log. */
        private val RESEAL = setOf(Reason.STALE_HEAD, Reason.BAD_WRAPS, Reason.UNKNOWN_LOG_HEAD)

        /** The device kept in [storage] before, or null if it holds none. Call [start] next. */
        suspend fun load(p: Primitives, transport: Transport, storage: Storage): Client? {
            val server = storage.read(Names.SERVER) ?: return null
            val device = storage.read(Names.DEVICE) ?: return null
            val (url, key) = readAll(server) { utf8() to Bytes.of(bytes(32)) }
            val saved = storage.read(Names.CLOCK)?.let { readAll(it) { u64() } } ?: 0UL
            return Client(p, transport, storage, TrustedClock(saved), url, key, DeviceKeys.decode(p, device)).also { it.loadState() }
        }

        /**
         * A new device for the server in a setup code (§13.1): it trusts the code's key, makes its
         * keys, registers with the code's token and logs in.
         */
        suspend fun setUp(p: Primitives, transport: Transport, storage: Storage, setupCode: String, kind: DeviceKind = DeviceKind.PHONE): Client {
            val setup = Setup.fromCode(setupCode.trim())
            return create(p, transport, storage, setup.serverUrl, setup.serverKey, setup.regToken, kind).also { it.start() }
        }

        /**
         * A new device for the server an invite names (§9.2): it trusts the invite's key, makes its
         * keys, registers with the invite's token if it carries one, and logs in. [join] comes next.
         */
        suspend fun forInvite(p: Primitives, transport: Transport, storage: Storage, invite: Invite, kind: DeviceKind = DeviceKind.PHONE): Client {
            if (invite.regToken.size == 0) throw ClientException("the invite carries no registration token: the server's operator issues one")
            return create(p, transport, storage, invite.serverUrl, invite.serverKey, invite.regToken, kind).also { it.start() }
        }

        private suspend fun create(p: Primitives, transport: Transport, storage: Storage, url: String, key: Bytes, token: Bytes, kind: DeviceKind): Client {
            check(storage.read(Names.DEVICE) == null) { "this storage already holds a device" }
            if (!url.startsWith("https://") || url.endsWith("/")) throw ClientException("a server's address is https, without a trailing slash")
            val clock = TrustedClock()
            // The server's identity first, and its time with it: the new bundle must be current by the server's clock.
            ServerInfo.check(p, ServerApi(transport, url, clock).discovery().serverInfo, url, key)
            val keys = DeviceKeys.create(p, kind, clock.now())
            storage.write(Names.SERVER, encode {
                vec16(url.encodeToByteArray())
                bytes(key)
            })
            storage.write(Names.DEVICE, keys.encode())
            storage.write(Names.PENDING_TOKEN, token.toByteArray())
            return Client(p, transport, storage, clock, url, key, keys)
        }
    }
}

/** The names a [Client] keeps in its [Storage]. */
internal object Names {
    const val SERVER = "server"
    const val DEVICE = "device"
    const val PENDING_TOKEN = "pending-token"
    const val CLOCK = "clock"
    const val SEQ = "seq"
    const val CURSOR = "cursor"
    const val CIRCLES = "circles"
    const val PUSH = "push"
    const val WATCHING = "watching"
    const val INVITES = "invites"

    fun log(circleId: Bytes): String = "log-" + circleId.hex

    fun secrets(circleId: Bytes): String = "secrets-" + circleId.hex

    fun replay(circleId: Bytes): String = "replay-" + circleId.hex

    fun invite(inviteId: Bytes): String = "invite-" + inviteId.hex
}

/** Runs [block], keeping any failure but cancellation, which must go on up. */
internal inline fun <T> attempt(block: () -> T): Result<T> = try {
    Result.success(block())
} catch (e: CancellationException) {
    throw e
} catch (e: Exception) {
    Result.failure(e)
}

/** Frames as kept in storage: whole frames only, so that a cut-off last addition is left out. */
internal fun framesLenient(data: ByteArray): List<ByteArray> {
    val out = ArrayList<ByteArray>()
    var at = 0
    while (data.size - at >= 4) {
        var n = 0L
        for (i in 0 until 4) n = (n shl 8) or (data[at + i].toLong() and 0xff)
        if (n > data.size - at - 4) break
        out.add(data.copyOfRange(at + 4, at + 4 + n.toInt()))
        at += 4 + n.toInt()
    }
    return out
}

private fun replayEntry(sender: Bytes, seq: ULong, sentAt: ULong): ByteArray = encode {
    bytes(sender)
    u64(seq)
    u64(sentAt)
}

private fun encodeSecrets(secrets: Map<Long, ByteArray>): ByteArray = encode {
    for ((epoch, secret) in secrets) {
        u32(epoch)
        bytes(secret)
    }
}

private fun decodeSecrets(data: ByteArray): Map<Long, ByteArray> {
    val r = Reader(data)
    val out = LinkedHashMap<Long, ByteArray>()
    while (r.remaining >= 36) out[r.u32()] = r.bytes(32)
    return out
}
