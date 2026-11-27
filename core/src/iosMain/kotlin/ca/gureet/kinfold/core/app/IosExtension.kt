// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.client.StreamChange
import ca.gureet.kinfold.core.client.UrlSessionTransport
import ca.gureet.kinfold.core.client.monotonicMillis
import ca.gureet.kinfold.core.client.wallMillis
import ca.gureet.kinfold.core.crypto.CryptoKitCrypto
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.push.PushMessage
import ca.gureet.kinfold.core.push.PushReceipt
import ca.gureet.kinfold.core.wire.Base64Url
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch

/** What a push came to, for the extension that opened it. */
class PushOutcome(
    /** `silence`, `records`, `wake`, `dropped`, `not_set_up` or `failed`, as the log has it. */
    val kind: String,
    /** The alert to show when the push carried one this phone can word, or null for the app's fixed text. */
    val title: String?,
    val text: String?,
    /** Whether the push opened and the person shares their location: a location push then gets a fix. */
    val wantsFix: Boolean,
)

/**
 * The core in one of the iOS app's extensions (API.md §12): the notification service extension,
 * which words the alert a push carries, and the location-push extension, which answers a push
 * with a fix. Each runs in a process of its own, for a few seconds and a few megabytes, on the
 * files the app keeps in the app group's container. It loads the device as the app left it,
 * opens the push, and handles what it holds as the app would, through the same [Home] and
 * [Family]; it never opens the stream. [sharing] is the person's choice as the app last stored it,
 * and [route] (`alert` or `location`) goes in the log.
 *
 * Afterwards it counts a change in [CHANGES], so that the app reads the files again before it
 * goes on (IosApp). The envelope sequence number is safe across the processes ([FileStorage.next]).
 */
class IosExtension(dir: String, sealer: IosSealer, private val ios: IosPlatform, private val sharing: Boolean, private val route: String) {
    private val scope = MainScope()
    private val storage = FileStorage(dir, sealer)
    private val startedMs = monotonicMillis()
    private var alert: Pair<String, String>? = null

    private val platform: Platform = IosPlatformAdapter(storage, ios) { home.now() }

    private val hooks: FamilyHooks = object : FamilyHooks {
        override fun sharing(): Boolean = sharing

        // A location push gets one fix whatever it held (wantsFix); there is no live mode here.
        override fun live(forMs: Long) {}

        override fun silenceAlert(id: Int, title: String, text: String) {
            alert = title to text
        }

        // Join requests and the stream's changes come only on the stream, which an extension doesn't open.
        override fun joinRequest(name: String) {}

        override fun stream(change: StreamChange) {}
    }

    val home: Home = Home(Primitives(CryptoKitCrypto()), UrlSessionTransport(), storage, platform, hooks)

    /** Writes one line to the log, as [IosApp.log] does. */
    fun log(event: String, keys: List<String>, values: List<Any>) = platform.log(event, keys.zip(values))

    private fun log(event: String, vararg fields: Pair<String, Any?>) = platform.log(event, fields.toList())

    /** How long this extension has run, in milliseconds. */
    fun ranMs(): Long = monotonicMillis() - startedMs

    /** Handles the push in [payload], the notification's `kinfold` value (API.md §12); [done] gets what it came to. */
    fun pushed(payload: String, done: (PushOutcome) -> Unit) {
        scope.launch {
            val outcome = try {
                open(payload)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("push", "route" to route, "kind" to "failed", "error" to describe(e))
                PushOutcome("failed", null, null, false)
            }
            changed()
            done(outcome)
        }
    }

    private suspend fun open(payload: String): PushOutcome {
        val c = home.loadClient()
        if (c == null) {
            log("push", "route" to route, "kind" to "not_set_up")
            return PushOutcome("not_set_up", null, null, false)
        }
        val sealed = try {
            Base64Url.decode(payload)
        } catch (_: Exception) {
            null
        }
        val receipt = if (sealed == null) null else c.pushed(sealed)
        val kind = when (receipt) {
            null, is PushReceipt.Dropped -> "dropped"
            is PushReceipt.Opened -> when (receipt.message) {
                is PushMessage.Silence -> "silence"
                is PushMessage.Records -> "records"
                is PushMessage.Wake -> "wake"
            }
        }
        home.family.flush()
        val sentAt = (receipt as? PushReceipt.Opened)?.message?.sentAt
        log("push", "route" to route, "kind" to kind, "age_ms" to sentAt?.let { home.now().toLong() - it.toLong() }, "took_ms" to ranMs())
        val opened = receipt is PushReceipt.Opened
        return PushOutcome(kind, alert?.first, alert?.second, opened && sharing)
    }

    /**
     * One fix from Core Location, as [IosApp.fix] takes it, sent to the family at once: the
     * answer to a location push. [done] gets whether the server has it.
     */
    fun fix(atMs: Long, latE7: Long, lonE7: Long, accM: Long, spdCms: Long, headingDeg: Long, batPct: Int, charging: Boolean, mock: Boolean, done: (Boolean) -> Unit) {
        scope.launch {
            val f = Fix(atMs, latE7, lonE7, accM.coerceAtLeast(1), spdCms.takeIf { it >= 0 })
            val details = FixDetails(headingDeg.takeIf { it >= 0 }, if (batPct >= 0) Battery(batPct, charging) else null, null, mock)
            log("fix", "age_ms" to wallMillis() - atMs, "acc_m" to f.accM, "provider" to "core_location", "why" to "location_push")
            val sent = try {
                home.sendFix(f, emptyList(), wallMillis(), details, "https")
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("failed", "what" to "answering a location push", "error" to describe(e))
                false
            }
            home.family.flush()
            changed()
            done(sent)
        }
    }

    /** A heartbeat instead, when Core Location gave no fix in time (PROTOCOL.md §8.4). [done] gets whether the server has it. */
    fun heartbeat(batPct: Int, charging: Boolean, why: String, done: (Boolean) -> Unit) {
        scope.launch {
            val sent = try {
                home.sendHeartbeat(if (batPct >= 0) Battery(batPct, charging) else null, why, "https")
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("failed", "what" to "answering a location push", "error" to describe(e))
                false
            }
            changed()
            done(sent)
        }
    }

    /** Tells the app that the files changed under it. */
    private fun changed() {
        try {
            storage.next(CHANGES, 0UL)
        } catch (e: Exception) {
            log("failed", "what" to "counting a change for the app", "error" to describe(e))
        }
    }

    companion object {
        /** The count of the extensions' runs that may have changed the files, which the app watches. */
        internal const val CHANGES = "changed-elsewhere"
    }
}

/** [Platform] from the iOS app's [IosPlatform], for the app and its extensions alike. */
internal class IosPlatformAdapter(private val storage: FileStorage, private val ios: IosPlatform, private val now: () -> ULong) : Platform {
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

    override fun log(event: String, fields: List<Pair<String, Any?>>) = ios.writeLog(LogLines.format(now(), event, fields))

    override fun timeOfDay(ms: Long): String = ios.timeOfDay(ms)

    override fun wallMs(): Long = wallMillis()
}
