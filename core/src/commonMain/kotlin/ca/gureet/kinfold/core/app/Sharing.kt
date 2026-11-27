// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.Payloads
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.Bytes
import kotlinx.coroutines.CancellationException
import kotlin.time.TimeSource

/** The phone's battery, as a payload carries it (§8.2 `bat`, `chg`). */
class Battery(val pct: Int, val charging: Boolean)

/** What goes up with a fix besides its position (§8.2 `loc`): its heading in degrees, the battery, the activity, and whether the fix came from a mock provider. */
class FixDetails(val headingDeg: Long?, val battery: Battery?, val activity: String?, val mock: Boolean)

/**
 * Sends [fix] to the family's circle as a `loc` (§8.2), with the fixes held back since the last
 * upload as its `prev`, and keeps it as this phone's own position. [Fix.atMs] is measured on the
 * phone's elapsed clock, which reads [elapsedNowMs] now. [via] is what the log says it went by.
 * True once the server has it.
 */
suspend fun Home.sendFix(fix: Fix, prev: List<Fix>, elapsedNowMs: Long, details: FixDetails, via: String): Boolean {
    val c = loadClient() ?: return false
    val id = c.circles().firstOrNull() ?: return false
    val now = c.clock.now()
    fun ts(f: Fix): ULong = now - (elapsedNowMs - f.atMs).coerceAtLeast(0).toULong()
    val extra = LinkedHashMap<String, Json>()
    fix.spdCms?.let { extra["spd"] = Json.Num(it) }
    details.headingDeg?.let { extra["hdg"] = Json.Num(((it % 360) + 360) % 360) }
    details.battery?.let {
        extra["bat"] = Json.Num(it.pct.toLong())
        extra["chg"] = Json.Bool(it.charging)
    }
    details.activity?.let { extra["act"] = Json.Str(it) }
    if (details.mock) extra["mock"] = Json.Bool(true)
    if (prev.isNotEmpty()) {
        extra["prev"] = Json.Arr(prev.map { Json.Arr(listOf(Json.Num(ts(it).toLong()), Json.Num(it.latE7), Json.Num(it.lonE7), Json.Num(it.accM))) })
    }
    val payload = Payloads.loc(ts(fix), fix.latE7, fix.lonE7, fix.accM, extra = extra)
    val sent = upload(c, id, "loc", payload, via, listOf("age_ms" to elapsedNowMs - fix.atMs, "prev" to prev.size))
    family.mine(Seen(ts(fix).toLong(), fix.latE7, fix.lonE7, fix.accM, details.battery?.pct?.toLong(), details.battery?.charging, details.activity))
    return sent
}

/** Sends a heartbeat to the family's circle (§8.4): the phone shares, but has no new position to send. True once the server has it. */
suspend fun Home.sendHeartbeat(battery: Battery?, why: String, via: String): Boolean {
    val c = loadClient() ?: return false
    val id = c.circles().firstOrNull() ?: return false
    val extra = LinkedHashMap<String, Json>()
    battery?.let {
        extra["bat"] = Json.Num(it.pct.toLong())
        extra["chg"] = Json.Bool(it.charging)
    }
    return upload(c, id, "hb", Payloads.heartbeat(c.clock.now(), listOf("sharing"), extra), via, listOf("why" to why))
}

/** Uploads one envelope to the circle, on the stream when it is open, and logs how it went. */
private suspend fun Home.upload(c: Client, id: Bytes, type: String, payload: Json.Obj, via: String, fields: List<Pair<String, Any?>>): Boolean {
    val started = TimeSource.Monotonic.markNow()
    return try {
        val receivedAt = c.send(id, payload)
        log("upload", listOf("type" to type, "via" to via, "took_ms" to started.elapsedNow().inWholeMilliseconds, "stored" to (receivedAt != null)) + fields)
        true
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        log("upload", listOf("type" to type, "via" to via, "took_ms" to started.elapsedNow().inWholeMilliseconds, "error" to describe(e)) + fields)
        false
    }
}
