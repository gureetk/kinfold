// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.log

import ca.gureet.kinfold.core.payload.Json
import java.io.File
import java.io.FileWriter
import java.io.Writer
import java.time.Instant
import java.time.ZoneOffset

/**
 * What the phone saw, for the person to export and send when sharing misbehaves: one JSON object a
 * line, a file for each UTC day, in the format the spikes' harness writes. Every line has `t`, the
 * phone's trusted time in milliseconds, and `e`, what happened. A line holds times, delays,
 * distances, accuracies, states and IDs: never a coordinate, a key, a name or an address. Files
 * older than [KEEP_DAYS] days are deleted. A test build also copies each line to [mirror], for
 * the emulator test to read through adb.
 */
class EventLog(private val dir: File, private val mirror: ((String) -> Unit)?, private val now: () -> ULong) {
    private var day: String? = null
    private var out: Writer? = null
    private val recent = ArrayDeque<String>()

    init {
        dir.mkdirs()
        prune()
    }

    /** Writes one line, fields in the order given. Numbers are whole; anything else is a string. */
    @Synchronized
    fun write(event: String, vararg fields: Pair<String, Any?>) {
        val t = now()
        val map = LinkedHashMap<String, Json>()
        map["t"] = Json.Num(t.toLong())
        map["e"] = Json.Str(event)
        for ((k, v) in fields) {
            when (v) {
                null -> {}
                is Int -> map[k] = Json.Num(v.toLong())
                is Long -> map[k] = Json.Num(v)
                is ULong -> map[k] = Json.Num(v.toLong())
                is Boolean -> map[k] = Json.Bool(v)
                else -> map[k] = Json.Str(v.toString())
            }
        }
        val line = Json.Obj(map).write()
        try {
            writer(t).apply {
                write(line)
                write("\n")
                flush()
            }
        } catch (_: Exception) {
            // A full disk loses lines, not the app.
            out = null
            day = null
        }
        mirror?.invoke(line)
        recent.addLast(line)
        while (recent.size > RECENT) recent.removeFirst()
    }

    /** The latest lines, newest last, for the screen. */
    @Synchronized
    fun recent(): List<String> = recent.toList()

    /** Every day's file, oldest first. */
    fun files(): List<File> = dir.listFiles { f -> f.name.endsWith(".jsonl") }?.sortedBy { it.name } ?: emptyList()

    private fun writer(t: ULong): Writer {
        val today = Instant.ofEpochMilli(t.toLong()).atOffset(ZoneOffset.UTC).toLocalDate().toString()
        val w = out
        if (w != null && today == day) return w
        w?.close()
        prune()
        return FileWriter(File(dir, "$today.jsonl"), true).also {
            out = it
            day = today
        }
    }

    /** Deletes the days older than [KEEP_DAYS], by their names. */
    private fun prune() {
        val oldest = Instant.ofEpochMilli(now().toLong()).atOffset(ZoneOffset.UTC).toLocalDate().minusDays(KEEP_DAYS).toString()
        for (f in files()) if (f.name.removeSuffix(".jsonl") < oldest) f.delete()
    }

    private companion object {
        const val RECENT = 40
        const val KEEP_DAYS = 30L
    }
}

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
