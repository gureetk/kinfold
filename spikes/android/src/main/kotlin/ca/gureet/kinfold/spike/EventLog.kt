// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import ca.gureet.kinfold.core.payload.Json
import java.io.File
import java.io.FileWriter
import java.io.Writer
import java.time.Instant
import java.time.ZoneOffset

/**
 * What the phone saw, for the spike's results: one JSON object a line, a file for each UTC day, in
 * the format the harness writes. Every line has `t`, the phone's trusted time in milliseconds, and
 * `e`, what happened. A line holds times, delays, distances, accuracies, states and IDs: never a
 * coordinate, a key or an address. A test build also copies each line to [mirror], for the
 * emulator test to read through adb.
 */
class EventLog(private val dir: File, private val mirror: ((String) -> Unit)?, private val now: () -> ULong) {
    private var day: String? = null
    private var out: Writer? = null
    private val recent = ArrayDeque<String>()

    init {
        dir.mkdirs()
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
        return FileWriter(File(dir, "$today.jsonl"), true).also {
            out = it
            day = today
        }
    }

    private companion object {
        const val RECENT = 40
    }
}
