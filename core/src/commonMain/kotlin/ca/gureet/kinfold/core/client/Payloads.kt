// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.push.WatchGrant
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes

/**
 * Payloads of PROTOCOL.md §8.2 that the client layer sends or that its users send most often.
 * Positions are in units of 10⁻⁷ degree, distances in metres, times in milliseconds since the epoch.
 */
object Payloads {
    /** `loc`: a position. [extra] adds the optional fields (`spd`, `bat`, `act` and so on). */
    fun loc(ts: ULong, latE7: Long, lonE7: Long, accM: Long, prec: String = "exact", extra: Map<String, Json> = emptyMap()): Json.Obj =
        obj("t" to str("loc"), "ts" to num(ts), "lat" to Json.Num(latE7), "lon" to Json.Num(lonE7), "acc" to Json.Num(accM), "prec" to str(prec), extra = extra)

    /** `hb`: a heartbeat without a position, with exactly one of `sharing`, `paused` or `approx` among its [flags] (§8.4). */
    fun heartbeat(ts: ULong, flags: List<String>, extra: Map<String, Json> = emptyMap()): Json.Obj =
        obj("t" to str("hb"), "ts" to num(ts), "flags" to Json.Arr(flags.map { str(it) }), extra = extra)

    /** `sig` with `live_req`: asks the receiver for frequent updates for a few minutes. */
    fun liveRequest(until: ULong? = null): Json.Obj =
        obj("t" to str("sig"), "k" to str("live_req"), extra = until?.let { mapOf("until" to num(it)) } ?: emptyMap())

    /** `sos` (`state` is `start`, `update` or `cancel`), always with an exact position. */
    fun sos(ts: ULong, state: String, latE7: Long, lonE7: Long, accM: Long): Json.Obj =
        obj("t" to str("sos"), "ts" to num(ts), "state" to str(state), "lat" to Json.Num(latE7), "lon" to Json.Num(lonE7), "acc" to Json.Num(accM))

    /** `watch_grant`, carrying a grant from the sending device (§14.1). */
    fun watchGrant(grant: WatchGrant): Json.Obj = obj("t" to str("watch_grant"), "grant" to str(Base64Url.encode(grant.encode())))

    /**
     * `welcome` (§8.5) with the newest run of consecutive [secrets], at most 256 and ending at the
     * newest epoch held, and the log [head] the receiver checks them against. A circle with more
     * epochs than one payload holds needs more payloads, which this client doesn't yet send.
     */
    fun welcome(secrets: Map<Long, ByteArray>, head: Bytes): Json.Obj {
        val last = secrets.keys.maxOrNull() ?: error("no epoch secrets to send")
        var first = last
        while (first - 1 in secrets && last - (first - 1) < MAX_EPOCHS) first--
        val epochs = (first..last).map { str(Base64Url.encode(secrets.getValue(it))) }
        return obj("t" to str("welcome"), "epochs" to Json.Arr(epochs), "first" to Json.Num(first), "head" to str(Base64Url.encode(head.toByteArray())))
    }

    /** The most items in a payload's array (§8.1). */
    private const val MAX_EPOCHS = 256

    private fun obj(vararg fields: Pair<String, Json>, extra: Map<String, Json> = emptyMap()): Json.Obj {
        val all = LinkedHashMap<String, Json>()
        for ((k, v) in fields) all[k] = v
        for ((k, v) in extra) if (k !in all) all[k] = v
        return Json.Obj(all)
    }

    private fun str(s: String): Json = Json.Str(s)

    private fun num(t: ULong): Json = Json.Num(t.toLong())
}
