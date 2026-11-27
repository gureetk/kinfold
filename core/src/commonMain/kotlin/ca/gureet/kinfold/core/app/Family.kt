// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.Delivery
import ca.gureet.kinfold.core.client.JoinAsk
import ca.gureet.kinfold.core.client.Payloads
import ca.gureet.kinfold.core.client.PendingInvite
import ca.gureet.kinfold.core.client.SilenceAlert
import ca.gureet.kinfold.core.client.Wake
import ca.gureet.kinfold.core.client.admit
import ca.gureet.kinfold.core.client.createCircle
import ca.gureet.kinfold.core.client.decline
import ca.gureet.kinfold.core.client.endInvite
import ca.gureet.kinfold.core.client.endWatch
import ca.gureet.kinfold.core.client.grantOf
import ca.gureet.kinfold.core.client.grantWatch
import ca.gureet.kinfold.core.client.invite
import ca.gureet.kinfold.core.client.joinAsks
import ca.gureet.kinfold.core.client.pendingInvites
import ca.gureet.kinfold.core.client.registerWatch
import ca.gureet.kinfold.core.client.watches
import ca.gureet.kinfold.core.identity.SafetyCode
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.log.Role
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile

/** A family member's latest position as this phone received it. Kept in memory and in the sealed `app-family` file only. */
data class Seen(
    val ts: Long,
    val latE7: Long,
    val lonE7: Long,
    val accM: Long,
    val bat: Long?,
    val charging: Boolean?,
    val act: String?,
)

/** One person in the circle, as this phone knows them. */
data class Person(
    val accountId: Bytes,
    /** From their latest profile (PROTOCOL.md §8.2); null until one arrives. */
    val name: String?,
    val isMe: Boolean,
    val admin: Boolean,
    val devices: Int,
    val seen: Seen?,
    /** When their phone last sent a position or a heartbeat, by its own trusted time. */
    val heardAt: Long?,
    /** Whether their phone lets this account know when it goes quiet. */
    val watchedByMe: Boolean,
)

/** Someone asking to join, with the safety code both screens show (PROTOCOL.md §11). */
data class Ask(val pending: PendingInvite, val ask: JoinAsk, val safetyCode: String)

/** A live-view request this phone received, kept where its person can see who asked and when (§8.2). */
data class LiveAsk(val from: Bytes, val at: Long, val honored: Boolean)

/** What the screens show. */
data class FamilyState(
    val setUp: Boolean = false,
    val circleId: Bytes? = null,
    val circleName: String? = null,
    val myName: String? = null,
    val people: List<Person> = emptyList(),
    val invite: PendingInvite? = null,
    val asks: List<Ask> = emptyList(),
    val liveAsks: List<LiveAsk> = emptyList(),
    /** Who this phone lets know when it goes quiet, by account. */
    val watchers: List<Bytes> = emptyList(),
)

/**
 * The family as this phone knows it, and what keeps it current: the circle, each person's name
 * from their profile, their latest position, who watches whom for silence, live-view requests,
 * and people asking to join. Names and positions are kept sealed in `app-family`; the log gets
 * only times, distances and IDs.
 */
class Family(private val host: FamilyHost) {
    private val lock = Mutex()
    private val state = MutableStateFlow(FamilyState())
    private var rec = Records()

    /** When each sending device's newest accepted position was sent, by its envelope's sequence number (§7.6). */
    private val seqs = HashMap<Bytes, ULong>()

    /** The device's client, loaded from storage when first needed; null before the phone is set up. */
    private suspend fun client(): Client? = host.client()

    /** While this phone lets someone in: it sends its profile once the new member can read it. */
    @Volatile
    private var admitting = false

    /** While a join is under way: the device mustn't send to the circle until it is a member (§9.4). */
    @Volatile
    var joining = false

    val ui: StateFlow<FamilyState> get() = state

    init {
        rec = host.storage.read(FILE)?.let { Records.decode(it) } ?: Records()
        state.value = FamilyState(setUp = host.hasDevice(), myName = rec.myName)
    }

    // ---- what the phone does ----

    /** The client has started: show the circle as it is, and send what the others need from this phone. */
    @Suppress("UNUSED_PARAMETER")
    suspend fun started(c: Client) {
        refresh()
        maintain("start")
    }

    /** Sets the phone up from the server's setup code, then founds the family's circle. */
    suspend fun create(c: Client, myName: String, circleName: String): Bytes {
        lock.withLock {
            rec.myName = myName
            save()
        }
        val id = c.createCircle(circleName)
        log("circle", "state" to "created", "circle" to b64(id))
        refresh()
        maintain("created")
        return id
    }

    /** Remembers the person's own name, and tells the circle. */
    suspend fun setMyName(name: String) {
        lock.withLock {
            rec.myName = name
            rec.profileAt = 0
            save()
        }
        refresh()
        maintain("name changed")
    }

    /**
     * Keeps up what the others need from this phone: its person's profile whenever someone joins
     * and at least weekly (§8.6), and, if the person agreed, a silence-watch grant for each other
     * adult, renewed before it runs out (§14.1).
     */
    suspend fun maintain(why: String) {
        val c = client() ?: return
        if (joining) return
        val id = c.circles().firstOrNull() ?: return
        val st = c.state(id) ?: return
        if (st.device(c.keys.deviceId) == null) return
        val nowMs = host.now().toLong()
        val name = rec.myName
        val devices = st.receivingDevices().map { b64(it.id) }.sorted()
        if (name != null && (nowMs - rec.profileAt > PROFILE_EVERY_MS || !rec.profileFor.containsAll(devices))) {
            attempt("sending the profile") {
                val p = Json.Obj(
                    linkedMapOf(
                        "t" to Json.Str("profile"),
                        "name" to Json.Str(name),
                        "devices" to Json.Obj(mapOf(b64(c.keys.deviceId) to Json.Str(host.deviceName()))),
                    ),
                )
                c.send(id, p)
                lock.withLock {
                    rec.profileAt = nowMs
                    rec.profileFor = devices.toSet()
                    save()
                }
                log("profile", "state" to "sent", "why" to why, "devices" to devices.size)
            }
        }
        if (host.watchConsent == true) {
            for (m in st.members.values) {
                if (m.accountId == c.keys.accountId || m.role != Role.ADULT) continue
                val key = b64(m.accountId)
                val at = rec.grants[key]
                if (at != null && nowMs - at < GRANT_RENEW_MS) continue
                attempt("granting a watch") {
                    c.grantWatch(id, m.accountId, afterMin = WATCH_AFTER_MIN, validForMs = GRANT_VALID_MS.toULong())
                    lock.withLock {
                        rec.grants[key] = nowMs
                        save()
                    }
                    log("watch", "state" to "granted", "watcher" to key, "after_min" to WATCH_AFTER_MIN)
                }
            }
        }
        refresh()
    }

    /**
     * The person's answer on watches (§14.1). Yes grants one to each other adult; no ends every
     * watch on this phone, and the server refuses the grants issued before (API.md §8).
     */
    suspend fun setWatchConsent(on: Boolean) {
        host.watchConsent = on
        log("watch", "state" to if (on) "consented" else "declined")
        val c = client() ?: return
        if (on) {
            maintain("consented")
            return
        }
        val id = c.circles().firstOrNull() ?: return
        attempt("ending the watches") {
            for (w in c.watches(id).filter { it.watchedDevice == c.keys.deviceId }) {
                c.endWatch(id, w.watcherAccount)
                log("watch", "state" to "ended", "watcher" to b64(w.watcherAccount))
            }
        }
        lock.withLock {
            rec.grants.clear()
            save()
        }
        refresh()
    }

    /** Makes an invite to the circle, to show as a QR code (§9.1). */
    suspend fun invite(): PendingInvite? {
        val c = client() ?: return null
        val id = c.circles().firstOrNull() ?: return null
        val st = c.state(id) ?: return null
        val pending = c.invite(id, st.name, rec.myName ?: "")
        log("invite", "state" to "made", "valid_ms" to INVITE_VALID_MS)
        state.value = state.value.copy(invite = pending)
        return pending
    }

    /** Stops showing the invite; it stays open on the server until it is used or ends. */
    fun closeInvite() {
        state.value = state.value.copy(invite = null)
    }

    /** Looks for people waiting on this phone's invites, with each one's safety code. */
    suspend fun pollAsks(): List<Ask> {
        val c = client() ?: return emptyList()
        val asks = ArrayList<Ask>()
        for (pending in c.pendingInvites()) {
            val found = try {
                c.joinAsks(pending)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("failed", "what" to "fetching join requests", "error" to describe(e))
                continue
            }
            for (a in found) asks.add(Ask(pending, a, SafetyCode.code(c.p, c.keys.identity.publicKey, a.ikPub.toByteArray())))
        }
        state.value = state.value.copy(asks = asks)
        if (asks.isNotEmpty()) log("join_request", "waiting" to asks.size)
        return asks
    }

    /** The person compared the safety codes and tapped Allow. */
    suspend fun allow(ask: Ask) {
        val c = client() ?: return
        // The log grows while admitting; the profile waits until the new member has its welcome.
        admitting = true
        val admitted = try {
            c.admit(ask.pending, ask.ask)
        } finally {
            admitting = false
        }
        lock.withLock {
            rec.names[b64(admitted.accountId)] = admitted.name
            rec.profileAt = 0
            save()
        }
        log("admitted", "account" to b64(admitted.accountId), "device" to b64(admitted.deviceId))
        state.value = state.value.copy(asks = state.value.asks - ask, invite = null)
        refresh()
        maintain("member added")
    }

    suspend fun decline(ask: Ask) {
        val c = client() ?: return
        c.decline(ask.pending)
        log("declined")
        state.value = state.value.copy(asks = state.value.asks.filter { it.pending != ask.pending }, invite = null)
    }

    /** Ends an invite nobody used, so its code no longer lets anyone ask. */
    suspend fun endInvite(pending: PendingInvite) {
        val c = client() ?: return
        attempt("ending an invite") { c.endInvite(pending) }
        closeInvite()
    }

    /**
     * Asks [person]'s phones for frequent updates for a couple of minutes (§8.2 `live_req`), waking
     * an iPhone's location extension if it has no stream (§14.3).
     */
    suspend fun askForLive(person: Bytes) {
        val c = client() ?: return
        val id = c.circles().firstOrNull() ?: return
        val devices = c.state(id)?.members?.get(person)?.devices?.values?.filter { it.kind.receives }?.map { it.id } ?: return
        if (devices.isEmpty()) return
        val until = host.now() + LIVE_MS.toULong()
        attempt("asking for live updates") {
            c.send(id, Payloads.liveRequest(until), to = devices, wake = Wake.LOCATE)
            log("live_req", "state" to "sent", "to" to b64(person), "devices" to devices.size)
        }
    }

    // ---- what comes in ----

    /** One envelope that passed every check (§7.6). Returns the live-view time to answer with, if any. */
    suspend fun onDelivery(d: Delivery, sharing: Boolean): Long? {
        val p = d.payload
        val from = d.sender.accountId
        when (p.string("t")) {
            "loc" -> position(d)
            "hb" -> heard(from, p.long("ts"))
            "profile" -> {
                val name = p.string("name")?.trim()?.take(MAX_NAME)?.takeIf { it.isNotEmpty() } ?: return null
                lock.withLock {
                    rec.names[b64(from)] = name
                    save()
                }
                log("profile", "state" to "received", "from" to b64(d.sender.id))
                refresh()
            }
            "watch_grant" -> {
                val c = client() ?: return null
                val grant = grantOf(p) ?: return null
                if (grant.watcherAccount != c.keys.accountId) return null
                attempt("registering a watch") {
                    c.registerWatch(grant)
                    log("watch", "state" to "registered", "device" to b64(grant.watchedDevice), "after_min" to grant.afterMin)
                    lock.withLock {
                        rec.watching.add(b64(from))
                        save()
                    }
                    refresh()
                }
            }
            "sig" -> if (p.string("k") == "live_req") return live(d, sharing)
        }
        return null
    }

    private suspend fun position(d: Delivery) {
        val p = d.payload
        val ts = p.long("ts") ?: return
        val lat = p.long("lat")?.takeIf { it in -900_000_000L..900_000_000L } ?: return
        val lon = p.long("lon")?.takeIf { it in -1_800_000_000L..1_800_000_000L } ?: return
        val acc = p.long("acc")?.takeIf { it >= 0 } ?: return
        val from = d.sender.accountId
        val newer = lock.withLock {
            // A lower sequence number never replaces what a higher one set (§7.6), and across a
            // person's devices the newest position wins.
            val last = seqs[d.sender.id]
            if (last != null && d.seq <= last) return@withLock false
            seqs[d.sender.id] = d.seq
            val key = b64(from)
            val old = rec.seen[key]
            if (old != null && old.ts >= ts) return@withLock false
            rec.seen[key] = Seen(ts, lat, lon, acc, p.long("bat"), (p.fields["chg"] as? Json.Bool)?.value, p.string("act"))
            rec.heard[key] = maxOf(rec.heard[key] ?: 0, ts)
            saveSoon()
            true
        }
        log(
            "position",
            "from" to b64(d.sender.id),
            "age_ms" to d.openedAt.toLong() - ts,
            "transit_ms" to d.openedAt.toLong() - d.sentAt.toLong(),
            "acc_m" to acc,
            "prev" to (p.fields["prev"] as? Json.Arr)?.items?.size,
            "newer" to newer,
        )
        if (newer) refresh()
    }

    private suspend fun heard(from: Bytes, ts: Long?) {
        ts ?: return
        lock.withLock {
            val key = b64(from)
            rec.heard[key] = maxOf(rec.heard[key] ?: 0, ts)
            saveSoon()
        }
        refresh()
    }

    /**
     * A live-view request (§8.2): honoured at most once a minute for each person who asks, and
     * only while sharing is on, for the time asked within 30 seconds to 5 minutes. Every request is
     * recorded where the person can see it.
     */
    private suspend fun live(d: Delivery, sharing: Boolean): Long? {
        val from = d.sender.accountId
        val nowMs = host.now().toLong()
        val until = d.payload.long("until")
        val forMs = (until?.let { it - nowMs } ?: LIVE_MS).coerceIn(30_000L, 300_000L)
        val honored = lock.withLock {
            val last = rec.live.lastOrNull { it.from == from && it.honored }
            val ok = sharing && (last == null || nowMs - last.at >= LIVE_EVERY_MS)
            rec.live.add(LiveAsk(from, nowMs, ok))
            while (rec.live.size > MAX_LIVE) rec.live.removeAt(0)
            save()
            ok
        }
        log(
            "live_req",
            "state" to "received",
            "from" to b64(d.sender.id),
            "sent_at" to d.sentAt,
            "received_at" to d.receivedAt,
            "opened_at" to d.openedAt,
            "for_ms" to forMs,
            "honored" to honored,
        )
        refresh()
        return if (honored) forMs else null
    }

    /** The server says a phone this account watches has gone quiet (§14.1). The text for the alert. */
    suspend fun silence(alert: SilenceAlert): Pair<String, String> {
        val c = client()
        val account = c?.state(alert.circleId)?.device(alert.watchedDevice)?.accountId
        val name = account?.let { lock.withLock { rec.names[b64(it)] } } ?: "A family member"
        log("silence", "device" to b64(alert.watchedDevice), "last_seen_at" to alert.lastSeenAt, "sent_at" to alert.sentAt)
        val since = if (alert.lastSeenAt > 0UL) " since " + host.timeOfDay(alert.lastSeenAt.toLong()) else ""
        return "No updates from $name's phone" to "Kinfold hasn't heard from it$since. It may be off, out of battery or without a connection."
    }

    /** A watch this account held has ended (API.md §8). */
    suspend fun watchEnded(watchedDevice: Bytes, reason: String) {
        val c = client() ?: return
        val account = c.circles().firstOrNull()?.let { c.state(it) }?.device(watchedDevice)?.accountId
        log("watch", "state" to "ended_by_server", "device" to b64(watchedDevice), "reason" to reason)
        if (account != null) {
            lock.withLock {
                rec.watching.remove(b64(account))
                save()
            }
        }
        refresh()
    }

    /** Whether [circleId]'s log grew while this phone was a member: someone may have joined. */
    suspend fun logChanged() {
        refresh()
        if (!admitting) maintain("log changed")
    }

    /** The phone's own latest fix, for its own row. */
    suspend fun mine(fix: Seen) {
        val c = client() ?: return
        lock.withLock {
            val key = b64(c.keys.accountId)
            rec.seen[key] = fix
            rec.heard[key] = fix.ts
            saveSoon()
        }
        refresh()
    }

    /** Rebuilds what the screens show from the circle's verified log and the records. */
    suspend fun refresh() {
        val c = client()
        if (c == null) {
            state.value = state.value.copy(setUp = host.hasDevice(), myName = rec.myName)
            return
        }
        val id = if (joining) null else c.circles().firstOrNull()
        val st: CircleState? = id?.let { c.state(it) }
        val me = c.keys.accountId
        val people = lock.withLock {
            st?.members?.values?.map { m ->
                val key = b64(m.accountId)
                Person(
                    m.accountId,
                    if (m.accountId == me) rec.myName else rec.names[key],
                    m.accountId == me,
                    m.admin,
                    m.devices.size,
                    rec.seen[key],
                    rec.heard[key],
                    key in rec.watching,
                )
            }?.sortedWith(compareBy({ !it.isMe }, { it.name?.lowercase() ?: "￿" })) ?: emptyList()
        }
        val watchers = lock.withLock { rec.grants.keys.mapNotNull { k -> Base64Url.decode(k)?.let { Bytes.of(it) } } }
        state.value = state.value.copy(
            setUp = true,
            circleId = id,
            circleName = st?.name,
            myName = rec.myName,
            people = people,
            liveAsks = lock.withLock { rec.live.toList().asReversed() },
            watchers = watchers,
        )
    }

    /** The name this phone knows for [account], or null. */
    suspend fun nameOf(account: Bytes): String? = lock.withLock { rec.names[b64(account)] }

    // ---- keeping the records ----

    private var dirtySince = 0L

    private fun save() {
        host.storage.write(FILE, rec.encode())
        dirtySince = 0
    }

    /** Positions arrive often; they are written at most every half minute. */
    private fun saveSoon() {
        val t = host.now().toLong()
        if (dirtySince == 0L) dirtySince = t
        if (t - dirtySince >= SAVE_EVERY_MS) save()
    }

    /**
     * Reads the records again, after another process that shares the files wrote them, as an
     * iPhone's app extensions do. What this process held back is dropped: the files are newer.
     */
    suspend fun reload() {
        lock.withLock {
            rec = host.storage.read(FILE)?.let { Records.decode(it) } ?: Records()
            dirtySince = 0
        }
        refresh()
    }

    /** Writes what [saveSoon] held back; the service calls it on its rounds and when it stops. */
    suspend fun flush() = lock.withLock { if (dirtySince != 0L) save() }

    private fun log(event: String, vararg fields: Pair<String, Any?>) = host.log(event, fields.toList())

    private suspend fun attempt(what: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            log("failed", "what" to what, "error" to describe(e))
        }
    }

    companion object {
        const val FILE = "app-family"
        const val PROFILE_EVERY_MS = 6 * 86_400_000L
        const val WATCH_AFTER_MIN = 60
        const val GRANT_VALID_MS = 7 * 86_400_000L
        const val GRANT_RENEW_MS = 5 * 86_400_000L
        const val INVITE_VALID_MS = 86_400_000L
        const val LIVE_MS = 120_000L
        const val LIVE_EVERY_MS = 60_000L
        const val MAX_LIVE = 100
        const val MAX_NAME = 60
        const val SAVE_EVERY_MS = 30_000L

        fun b64(b: Bytes): String = Base64Url.encode(b.toByteArray())
    }
}

/** What `app-family` holds: names, positions and times this phone learned, and its own choices. */
internal class Records {
    var myName: String? = null
    val names = HashMap<String, String>()
    val seen = HashMap<String, Seen>()
    val heard = HashMap<String, Long>()
    var profileAt = 0L
    var profileFor: Set<String> = emptySet()

    /** When this phone last granted each account a watch. */
    val grants = HashMap<String, Long>()

    /** The accounts whose phones let this one know when they go quiet. */
    val watching = HashSet<String>()
    val live = ArrayList<LiveAsk>()

    fun encode(): ByteArray {
        val o = LinkedHashMap<String, Json>()
        myName?.let { o["name"] = Json.Str(it) }
        o["names"] = Json.Obj(names.mapValues { Json.Str(it.value) })
        o["seen"] = Json.Obj(
            seen.mapValues { (_, s) ->
                Json.Obj(
                    buildMap {
                        put("ts", Json.Num(s.ts))
                        put("lat", Json.Num(s.latE7))
                        put("lon", Json.Num(s.lonE7))
                        put("acc", Json.Num(s.accM))
                        s.bat?.let { put("bat", Json.Num(it)) }
                        s.charging?.let { put("chg", Json.Bool(it)) }
                        s.act?.let { put("act", Json.Str(it)) }
                    },
                )
            },
        )
        o["heard"] = Json.Obj(heard.mapValues { Json.Num(it.value) })
        o["profile_at"] = Json.Num(profileAt)
        o["profile_for"] = Json.Arr(profileFor.sorted().map { Json.Str(it) })
        o["grants"] = Json.Obj(grants.mapValues { Json.Num(it.value) })
        o["watching"] = Json.Arr(watching.sorted().map { Json.Str(it) })
        o["live"] = Json.Arr(live.map { Json.Arr(listOf(Json.Str(Family.b64(it.from)), Json.Num(it.at), Json.Bool(it.honored))) })
        return Json.Obj(o).encode()
    }

    companion object {
        fun decode(data: ByteArray): Records? {
            val o = Json.parseObject(data, Json.Limits.MESSAGE) ?: return null
            val r = Records()
            r.myName = o.string("name")
            (o.fields["names"] as? Json.Obj)?.fields?.forEach { (k, v) -> (v as? Json.Str)?.let { r.names[k] = it.value } }
            (o.fields["seen"] as? Json.Obj)?.fields?.forEach { (k, v) ->
                val s = v as? Json.Obj ?: return@forEach
                r.seen[k] = Seen(
                    s.long("ts") ?: return@forEach,
                    s.long("lat") ?: return@forEach,
                    s.long("lon") ?: return@forEach,
                    s.long("acc") ?: return@forEach,
                    s.long("bat"),
                    (s.fields["chg"] as? Json.Bool)?.value,
                    s.string("act"),
                )
            }
            (o.fields["heard"] as? Json.Obj)?.fields?.forEach { (k, v) -> (v as? Json.Num)?.let { r.heard[k] = it.value } }
            r.profileAt = o.long("profile_at") ?: 0
            r.profileFor = ((o.fields["profile_for"] as? Json.Arr)?.items ?: emptyList()).mapNotNull { (it as? Json.Str)?.value }.toSet()
            (o.fields["grants"] as? Json.Obj)?.fields?.forEach { (k, v) -> (v as? Json.Num)?.let { r.grants[k] = it.value } }
            ((o.fields["watching"] as? Json.Arr)?.items ?: emptyList()).forEach { (it as? Json.Str)?.let { s -> r.watching.add(s.value) } }
            ((o.fields["live"] as? Json.Arr)?.items ?: emptyList()).forEach { item ->
                val a = (item as? Json.Arr)?.items ?: return@forEach
                val from = (a.getOrNull(0) as? Json.Str)?.value?.let { Base64Url.decode(it) } ?: return@forEach
                val at = (a.getOrNull(1) as? Json.Num)?.value ?: return@forEach
                r.live.add(LiveAsk(Bytes.of(from), at, (a.getOrNull(2) as? Json.Bool)?.value == true))
            }
            return r
        }
    }
}
