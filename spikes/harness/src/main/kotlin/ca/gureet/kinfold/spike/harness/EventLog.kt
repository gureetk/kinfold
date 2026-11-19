// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike.harness

import ca.gureet.kinfold.core.payload.Json
import java.io.Writer
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.time.Instant
import java.time.ZoneOffset

/**
 * The harness's measurements: one JSON object a line, a file for each UTC day, in `logs/` under
 * the data directory. A line holds times, delays, distances and IDs, and never a coordinate.
 * Every line has `t`, the harness's trusted time in milliseconds, and `e`, what happened.
 */
class EventLog(private val dir: Path, private val echo: Boolean) {
    private var day: String? = null
    private var out: Writer? = null

    init {
        Files.createDirectories(dir)
    }

    /** Writes one line, fields in the order given. Numbers are whole; anything else is a string. */
    @Synchronized
    fun write(t: ULong, event: String, vararg fields: Pair<String, Any?>) {
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
                is List<*> -> map[k] = Json.Arr(v.map { Json.Str(it.toString()) })
                else -> map[k] = Json.Str(v.toString())
            }
        }
        val line = Json.Obj(map).write()
        writer(t).apply {
            write(line)
            write("\n")
            flush()
        }
        if (echo) println(line)
    }

    private fun writer(t: ULong): Writer {
        val today = Instant.ofEpochMilli(t.toLong()).atOffset(ZoneOffset.UTC).toLocalDate().toString()
        if (today != day) {
            out?.close()
            out = Files.newBufferedWriter(dir.resolve("$today.jsonl"), StandardOpenOption.CREATE, StandardOpenOption.APPEND)
            day = today
        }
        return out!!
    }

    companion object {
        /** Every line of every log in [dir], oldest file first, as parsed objects. */
        fun read(dir: Path): Sequence<Json.Obj> {
            if (!Files.isDirectory(dir)) return emptySequence()
            val files = Files.list(dir).use { s -> s.filter { it.fileName.toString().endsWith(".jsonl") }.sorted().toList() }
            return files.asSequence().flatMap { f ->
                Files.readAllLines(f).asSequence().mapNotNull { Json.parseObject(it.encodeToByteArray(), Json.Limits.MESSAGE) }
            }
        }
    }
}
