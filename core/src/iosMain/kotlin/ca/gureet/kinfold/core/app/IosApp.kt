// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.Joined
import ca.gureet.kinfold.core.client.PendingInvite
import ca.gureet.kinfold.core.client.Region
import ca.gureet.kinfold.core.client.Regions
import ca.gureet.kinfold.core.client.StreamChange
import ca.gureet.kinfold.core.client.TransportException
import ca.gureet.kinfold.core.client.UrlSessionTransport
import ca.gureet.kinfold.core.client.join
import ca.gureet.kinfold.core.client.monotonicMillis
import ca.gureet.kinfold.core.client.regionUrl
import ca.gureet.kinfold.core.client.regions
import ca.gureet.kinfold.core.client.sessionHeaders
import ca.gureet.kinfold.core.client.wallMillis
import ca.gureet.kinfold.core.crypto.CryptoKitCrypto
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.identity.SafetyCode
import ca.gureet.kinfold.core.log.Role
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.math.min

/** What only the iOS app knows, in plain types. */
interface IosPlatform {
    /** The name this phone gives itself in a profile's device list. */
    fun deviceName(): String

    /** The person's answer on silence watches (PROTOCOL.md §14.1): 1 yes, 0 no, -1 not asked yet. */
    fun watchConsent(): Int

    fun setWatchConsent(on: Boolean)

    /** Adds one line, already formatted ([LogLines]), to the app's log. */
    fun writeLog(line: String)

    /** [ms] as the phone shows a time of day. */
    fun timeOfDay(ms: Long): String
}

/** What the core asks of the iOS app. Each is called on the main thread. */
interface IosHooks {
    /** Whether the person shares their location now. */
    fun sharing(): Boolean

    /** A live-view request was honoured: fixes as often as the phone gives them for [forMs] milliseconds. */
    fun live(forMs: Long)

    fun silenceAlert(id: Int, title: String, text: String)

    fun joinRequest(name: String)

    /** The stream to the server opened or closed. */
    fun connected(up: Boolean)

    /** The family as this phone knows it changed. */
    fun familyChanged(state: FamilyState)
}

/** An invite as the join screen shows it, before anything is sent (PROTOCOL.md §9.1). */
class InviteTerms(val code: String, val circleName: String, val inviterName: String, val adult: Boolean, val expiresAt: Long)

/** A region as the map screen offers it. */
class RegionOffer(val region: Region, val id: String, val name: String, val size: Long, val sha256: String, val etag: String)

/**
 * The core as the iOS app holds it, in calls that Swift makes without Kotlin's coroutines: each
 * runs on the main thread and answers through a callback, since Swift can't cancel a suspend call
 * of Kotlin's. It keeps what Android's app keeps in its own Kotlin: the stream to the server, the
 * ways in, the location engine's decisions, and the heartbeat. The rules are the core's ([Home],
 * [Family], [Motion], [sendFix]).
 */
class IosApp(dir: String, sealer: IosSealer, private val ios: IosPlatform, private val hooks: IosHooks) {
    private val scope = MainScope()
    private val storage = FileStorage(dir, sealer)

    private val platform: Platform = object : Platform {
        override fun hasDevice(): Boolean = storage.hasDevice()

        override fun deviceName(): String = ios.deviceName()

        override var watchConsent: Boolean?
            get() = when (ios.watchConsent()) {
                1 -> true
                0 -> false
                else -> null
            }
            set(v) {
                if (v != null) ios.setWatchConsent(v)
            }

        override fun log(event: String, fields: List<Pair<String, Any?>>) = ios.writeLog(LogLines.format(home.now(), event, fields))

        override fun timeOfDay(ms: Long): String = ios.timeOfDay(ms)

        override fun wallMs(): Long = wallMillis()
    }

    private val familyHooks: FamilyHooks = object : FamilyHooks {
        override fun sharing(): Boolean = hooks.sharing()

        override fun live(forMs: Long) {
            scope.launch { startLive(forMs) }
        }

        override fun silenceAlert(id: Int, title: String, text: String) {
            scope.launch { hooks.silenceAlert(id, title, text) }
        }

        override fun joinRequest(name: String) {
            scope.launch { hooks.joinRequest(name) }
        }

        override fun stream(change: StreamChange) {
            scope.launch { streamChanged(change) }
        }
    }

    /** The core as an app holds it. */
    val home: Home = Home(Primitives(CryptoKitCrypto()), UrlSessionTransport(), storage, platform, familyHooks)

    val family: Family get() = home.family

    init {
        scope.launch { family.ui.collect { hooks.familyChanged(it) } }
        scope.launch { family.refresh() }
        log("process", "state" to "start")
    }

    /** Trusted time once there is a client, the phone's clock before. */
    fun now(): Long = home.now().toLong()

    /** Writes one line to the log. [values] are Kotlin numbers (`KotlinLong`, `KotlinInt`), booleans (`KotlinBoolean`) or strings. */
    fun log(event: String, keys: List<String>, values: List<Any>) = platform.log(event, keys.zip(values))

    private fun log(event: String, vararg fields: Pair<String, Any?>) = platform.log(event, fields.toList())

    /** base64url, for an ID in Swift. */
    fun idOf(b: Bytes): String = Base64Url.encode(b.toByteArray())

    // ---- the connection ----

    private var main: Job? = null
    private var stream: Job? = null
    private var started: Client? = null
    private var up = false
    private var downSinceMs = 0L

    /** Whether the stream is open now. */
    val connected: Boolean get() = up

    /** Opens the connection: the client started, and one stream kept open (API.md §7). */
    fun connect() {
        if (main?.isActive == true) return
        main = scope.launch {
            val c = home.loadClient()
            if (c == null) {
                log("connection", "state" to "not_set_up")
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
                    log("start_failed", "error" to describe(e), "retry_ms" to waitMs)
                    delay(waitMs)
                    waitMs = min(waitMs * 2, 300_000L)
                }
            }
            started = c
            startStream(c, "start")
            family.started(c)
        }
        keepGoing()
    }

    /** Closes it, as when the app is no longer needed in the background. */
    fun disconnect() {
        main?.cancel()
        stream?.cancel()
        main = null
        stream = null
        started = null
        if (up) streamChanged(StreamChange.Stopped(0))
        log("connection", "state" to "closed")
    }

    /** Starts the stream again, as when the phone moves to another network: a connection on the old one can die quietly. */
    fun restart(why: String) {
        val c = started ?: return
        startStream(c, why)
    }

    private fun startStream(c: Client, why: String) {
        stream?.cancel()
        log("stream", "state" to "starting", "why" to why, "ping_s" to PING_MS / 1_000)
        stream = scope.launch {
            val code = c.runStream(PING_MS)
            log("stream", "state" to "ended", "code" to code)
        }
    }

    private fun streamChanged(change: StreamChange) {
        val now = monotonicMillis()
        when (change) {
            is StreamChange.Connected -> {
                log("stream", "state" to "connected", "down_ms" to (if (downSinceMs != 0L) now - downSinceMs else null))
                downSinceMs = 0L
                up = true
            }
            is StreamChange.Disconnected -> {
                if (up || downSinceMs == 0L) downSinceMs = now
                up = false
                log("stream", "state" to "disconnected", "code" to change.code, "retry_ms" to change.retryInMs)
            }
            is StreamChange.Stopped -> {
                if (up || downSinceMs == 0L) downSinceMs = now
                up = false
                log("stream", "state" to "stopped", "code" to change.code)
            }
        }
        hooks.connected(up)
    }

    // ---- getting in ----

    private var flow: Job? = null

    /** The invite in [code] as the join screen shows it, or null if it isn't one. */
    fun inviteTerms(code: String): InviteTerms? = try {
        val invite = Invite.fromCode(code.trim())
        val adult = try {
            invite.terms.role == Role.ADULT.code
        } catch (_: Exception) {
            false
        }
        InviteTerms(code.trim(), invite.circleName, invite.inviterName, adult, invite.expiresAt.toLong())
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        null
    }

    /**
     * From the server's setup code (PROTOCOL.md §13.1): the account, then the family's circle.
     * [progress] gets what is happening; [done] gets null, or what went wrong in words.
     */
    fun setUp(code: String, myName: String, circleName: String, progress: (String) -> Unit, done: (String?) -> Unit) {
        if (flow?.isActive == true) return
        progress("Checking your server")
        flow = scope.launch {
            try {
                val c = home.setUp(code)
                log("setup", "state" to "done", "server_features" to c.features.size)
                progress("Creating $circleName")
                family.create(c, myName, circleName)
                connect()
                done(null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("setup", "state" to "failed", "error" to describe(e))
                done(explain(e))
            }
        }
    }

    /** Founds a circle on a phone that is set up but in none, as after a setup that stopped half way. */
    fun createCircle(myName: String, circleName: String, done: (String?) -> Unit) {
        if (flow?.isActive == true) return
        flow = scope.launch {
            try {
                val c = home.loadClient() ?: error("this phone isn't set up")
                c.start()
                family.create(c, myName, circleName)
                connect()
                done(null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("circle", "state" to "failed", "error" to describe(e))
                done(explain(e))
            }
        }
    }

    /**
     * Joins with the invite in [code] (PROTOCOL.md §9.2), once the person has seen its terms and
     * agreed. [waiting] gets the inviter's name and the safety code to compare while the inviter's
     * phone lets this one in; [done] gets null once in, or what went wrong.
     */
    fun join(code: String, myName: String, waiting: (String, String) -> Unit, done: (String?) -> Unit) {
        if (flow?.isActive == true) return
        flow = scope.launch {
            family.joining = true
            try {
                val invite = Invite.fromCode(code.trim())
                family.setMyName(myName)
                val c = home.forInvite(invite)
                waiting(invite.inviterName.ifBlank { "the inviter" }, SafetyCode.code(c.p, c.keys.identity.publicKey, invite.inviterIkPub.toByteArray()))
                val joined: Joined = c.join(invite, myName, JOIN_WAIT_MS)
                log("joined", "details_matched" to joined.detailsMatched)
                family.joining = false
                family.started(c)
                connect()
                done(null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("join", "state" to "failed", "error" to describe(e))
                done(explain(e))
            } finally {
                family.joining = false
            }
        }
    }

    /** Stops a setup or a join under way. */
    fun cancel() {
        flow?.cancel()
        flow = null
    }

    private fun explain(e: Exception): String {
        val m = e.message ?: ""
        return when {
            m.contains("declined") -> "The inviter didn't let this phone in."
            m.contains("no answer") -> "Nobody let this phone in in time. Ask for a new invite."
            m.contains("another server") -> "That invite is for another server than the one this phone uses."
            e is TransportException -> "Couldn't reach the family's server. Check the connection and try again."
            else -> "That didn't work: " + describe(e)
        }
    }

    // ---- the family ----

    /** Makes an invite (§9.1); [done] gets the pending invite, whose `code` the QR code shows, or null. */
    fun invite(done: (PendingInvite?) -> Unit) {
        scope.launch {
            val pending = try {
                family.invite()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("failed", "what" to "making an invite", "error" to describe(e))
                null
            }
            done(pending)
        }
    }

    fun closeInvite() = family.closeInvite()

    fun endInvite(pending: PendingInvite) {
        scope.launch { family.endInvite(pending) }
    }

    /** Looks for people waiting on this phone's invites; the family's state lists them. */
    fun pollAsks() {
        scope.launch { family.pollAsks() }
    }

    /** The person compared the safety codes and tapped Allow; [done] gets null, or what went wrong. */
    fun allow(ask: Ask, done: (String?) -> Unit) = act("letting someone in", done) { family.allow(ask) }

    fun decline(ask: Ask, done: (String?) -> Unit) = act("declining", done) { family.decline(ask) }

    fun askForLive(account: Bytes) {
        scope.launch { family.askForLive(account) }
    }

    fun setWatchConsent(on: Boolean) {
        scope.launch { family.setWatchConsent(on) }
    }

    fun setMyName(name: String) {
        scope.launch { family.setMyName(name) }
    }

    private fun act(what: String, done: (String?) -> Unit, block: suspend () -> Unit) {
        scope.launch {
            try {
                block()
                done(null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("failed", "what" to what, "error" to describe(e))
                done(explain(e))
            }
        }
    }

    // ---- sharing ----

    private val motion = Motion()
    private var sentMs = 0L
    private var fixMs = 0L
    private var takenAtMs = 0L

    /** The engine's mode now, in lower case: `still`, `moving`, `driving` or `live`. */
    val mode: String get() = motion.mode.name.lowercase()

    /**
     * A fix from Core Location. [atMs] is when it was taken, on the phone's clock; [spdCms],
     * [headingDeg] and [batPct] are -1 when unknown. The engine decides whether it goes up.
     *
     * Core Location gives fixes as often as it likes, up to one a second; the engine takes them
     * as often as the Android app asks for them in each mode ([Mode.intervalMs]), and lets the
     * rest go, so that both send what the same engine decides and no more.
     */
    fun fix(atMs: Long, latE7: Long, lonE7: Long, accM: Long, spdCms: Long, headingDeg: Long, batPct: Int, charging: Boolean, mock: Boolean) {
        val interval = motion.mode.intervalMs
        if (interval > 0 && takenAtMs != 0L && atMs >= takenAtMs && atMs - takenAtMs < interval * 9 / 10) return
        takenAtMs = atMs
        val f = Fix(atMs, latE7, lonE7, accM.coerceAtLeast(1), spdCms.takeIf { it >= 0 })
        val step = motion.add(f)
        val now = wallMillis()
        fixMs = now
        log(
            "fix",
            "age_ms" to now - atMs,
            "acc_m" to f.accM,
            "spd_cms" to f.spdCms,
            "moved_m" to step.movedM,
            "provider" to "core_location",
            "mode" to step.mode.name.lowercase(),
            "upload" to step.upload,
        )
        if (!step.upload) return
        val details = FixDetails(headingDeg.takeIf { it >= 0 }, if (batPct >= 0) Battery(batPct, charging) else null, activityOf(step.mode, f.spdCms), mock)
        scope.launch {
            if (home.sendFix(f, step.prev, wallMillis(), details, via())) sentMs = monotonicMillis()
        }
    }

    /** Sharing started or stopped; [why] goes in the log. */
    fun sharingChanged(on: Boolean, why: String) {
        log("sharing", "on" to on, "why" to why)
        if (on) connect()
    }

    private fun startLive(forMs: Long) {
        motion.live(wallMillis(), forMs)
        log("engine", "mode" to "live", "why" to "live", "for_ms" to forMs)
        hooks.live(forMs)
        scope.launch {
            delay(forMs + 500)
            if (motion.tick(wallMillis())) log("engine", "mode" to motion.mode.name.lowercase(), "why" to "live_end")
        }
    }

    private fun via(): String = if (up) "stream" else "https"

    private var keeper: Job? = null

    /**
     * While the app runs: a heartbeat after [HEARTBEAT_AFTER_MS] without an upload, the profile and
     * watch grants kept up, the records written, and a stream that stayed down too long started again.
     */
    private fun keepGoing() {
        if (keeper?.isActive == true) return
        keeper = scope.launch {
            while (true) {
                delay(KEEP_EVERY_MS)
                val c = home.client ?: continue
                if (c.circles().isEmpty()) continue
                val now = monotonicMillis()
                if (hooks.sharing() && (sentMs == 0L || now - sentMs >= HEARTBEAT_AFTER_MS)) {
                    if (home.sendHeartbeat(null, "quiet", via())) sentMs = monotonicMillis()
                }
                if (!up && downSinceMs != 0L && now - downSinceMs >= STREAM_STUCK_MS) restart("down too long")
                family.maintain("keepalive")
                family.flush()
            }
        }
    }

    // ---- the map ----

    /** The regions the server offers (API.md §13); [done] gets them with the credit to show, or an error in words. */
    fun regions(done: (List<RegionOffer>?, String?, String?) -> Unit) {
        scope.launch {
            try {
                val c = home.loadClient() ?: error("this phone isn't set up")
                val r: Regions = c.regions()
                done(r.regions.map { RegionOffer(it, it.id, it.name, it.size, idOf(it.sha256), it.etag) }, r.attribution, null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("region", "state" to "list_failed", "error" to describe(e))
                done(null, null, explain(e))
            }
        }
    }

    /**
     * Where to download [region] from and the headers to send, which carry the session; [relogin]
     * logs in again first, after the server answered 401. [done] gets the URL and the headers, or
     * an error in words.
     */
    fun regionRequest(region: Region, relogin: Boolean, done: (String?, Map<String, String>?, String?) -> Unit) {
        scope.launch {
            try {
                val c = home.loadClient() ?: error("this phone isn't set up")
                if (relogin) c.login()
                done(c.regionUrl(region), c.sessionHeaders(), null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                done(null, null, explain(e))
            }
        }
    }

    companion object {
        /** How often the stream pings: often enough to notice a dead connection, rarely enough to let the radio sleep. */
        const val PING_MS = 240_000L

        /** A heartbeat goes up after this long without any upload: well inside the server's 35 minutes. */
        const val HEARTBEAT_AFTER_MS = 25 * 60_000L

        const val STREAM_STUCK_MS = 10 * 60_000L

        private const val KEEP_EVERY_MS = 60_000L

        /** How long a join waits for the inviter's phone. */
        private const val JOIN_WAIT_MS = 15 * 60_000L
    }
}
