// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.payload.Json

/**
 * The apps' log, line by line, the same on every phone: one JSON object a line, in the format the
 * spikes' harness writes. Every line has `t`, the phone's trusted time in milliseconds, and `e`,
 * what happened, then its fields in the order given. A line holds times, delays, distances,
 * accuracies, states and IDs: never a coordinate, a key, a name or an address.
 */
object LogLines {
    /** One line, without its newline. Whole numbers and booleans stay what they are; anything else becomes a string; null fields are left out. */
    fun format(t: ULong, event: String, fields: List<Pair<String, Any?>>): String {
        val map = LinkedHashMap<String, Json>()
        map["t"] = Json.Num(t.toLong())
        map["e"] = Json.Str(event)
        for ((k, v) in fields) {
            when (v) {
                null -> {}
                is Int -> map[k] = Json.Num(v.toLong())
                is Long -> map[k] = Json.Num(v)
                is UInt -> map[k] = Json.Num(v.toLong())
                is ULong -> map[k] = Json.Num(v.toLong())
                is Short -> map[k] = Json.Num(v.toLong())
                is Byte -> map[k] = Json.Num(v.toLong())
                is Boolean -> map[k] = Json.Bool(v)
                else -> map[k] = Json.Str(v.toString())
            }
        }
        return Json.Obj(map).write()
    }
}

/** An error, for the log and the screen: its kind and its message without addresses ([withoutAddresses]). */
fun describe(e: Throwable): String = (e::class.simpleName ?: "Error") + (e.message?.let { ": " + withoutAddresses(it).take(200) } ?: "")

/**
 * [message] with every address in it replaced: URLs by `<url>`, IP addresses by `<ip>` and host
 * names by `<host>`, each with its port. Errors from the network name the server they failed to
 * reach ("Failed to connect to …", "Unable to resolve host …"), and a log says what went wrong
 * without saying where.
 */
fun withoutAddresses(message: String): String = ADDRESSES.fold(message) { s, (pattern, by) -> pattern.replace(s, by) }

private val ADDRESSES = listOf(
    Regex("""[A-Za-z][A-Za-z0-9+.-]*://\S+""") to "<url>",
    Regex("""\[?(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[A-Za-z0-9]+)?\]?(?::\d+)?""") to "<ip>",
    Regex("""\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b""") to "<ip>",
    Regex("""\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b(?::\d+)?""") to "<host>",
)
