// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike.harness

import ca.gureet.kinfold.core.payload.Json
import java.nio.file.Path

/**
 * A summary of the harness's logs since [sinceMs], per phone, against the spikes' targets: the age
 * of a moving phone's position, the answers to live-view requests, alert delivery, and silence
 * alerts. Names come from the phones' profiles.
 */
fun report(logDir: Path, sinceMs: Long): String {
    class PerDevice {
        val agesMoving = ArrayList<Long>()
        val agesAll = ArrayList<Long>()
        var noFix = 0
        var locs = 0
        val arrival = ArrayList<Long>()
        var asked = 0
        val answers = ArrayList<Long>()
        val acks = ArrayList<Long>()
        var silences = 0
    }
    val devices = LinkedHashMap<String, PerDevice>()
    val names = HashMap<String, String>()
    var alerts = 0
    var disconnects = 0
    var failures = 0
    var first = Long.MAX_VALUE
    var last = 0L
    fun of(o: Json.Obj): PerDevice? = o.string("device")?.let { devices.getOrPut(it) { PerDevice() } }

    for (o in EventLog.read(logDir)) {
        val t = o.long("t") ?: continue
        if (t < sinceMs) continue
        first = minOf(first, t)
        last = maxOf(last, t)
        when (o.string("e")) {
            "sample" -> of(o)?.let { d ->
                val age = o.long("age_ms")
                if (age == null) d.noFix++ else {
                    d.agesAll.add(age)
                    if ((o["moving"] as? Json.Bool)?.value == true) d.agesMoving.add(age)
                }
            }
            "loc" -> of(o)?.let { d ->
                d.locs++
                o.long("age_ms")?.let { d.arrival.add(it) }
                o.long("answer_ms")?.let { d.answers.add(it) }
            }
            "live_req" -> of(o)?.let { it.asked++ }
            "ack" -> of(o)?.let { d ->
                val sent = o.long("alert_sent_at")
                val shown = o.long("shown_at") ?: o.long("opened_at")
                if (sent != null && shown != null) d.acks.add(shown - sent)
            }
            "silence" -> of(o)?.let { it.silences++ }
            "alert" -> alerts++
            "stream" -> if (o.string("state") == "disconnected") disconnects++
            "failed" -> failures++
            "profile", "joined" -> o.string("device")?.let { id -> o.string("name")?.let { names[id] = it } }
        }
    }
    if (devices.isEmpty()) return "Nothing logged in that time.\n"

    return buildString {
        append("From ${java.time.Instant.ofEpochMilli(first)} to ${java.time.Instant.ofEpochMilli(last)}: ")
        append("$alerts alerts sent, $disconnects stream drops on the harness, $failures failures.\n")
        for ((id, d) in devices) {
            append("\n${names[id] ?: "?"} ($id)\n")
            val moving = d.agesMoving
            append("  position age while moving: ${moving.size} samples")
            if (moving.isNotEmpty()) {
                val under = moving.count { it < 120_000 } * 100.0 / moving.size
                append(", p50 ${secs(pct(moving, 50))}, p95 ${secs(pct(moving, 95))}, under 2 min ${"%.1f".format(under)}% (target 95%)")
            }
            append("\n  position age, all samples: ${d.agesAll.size}")
            if (d.agesAll.isNotEmpty()) append(", p50 ${secs(pct(d.agesAll, 50))}, p95 ${secs(pct(d.agesAll, 95))}")
            if (d.noFix > 0) append(", ${d.noFix} before any position")
            append("\n  positions: ${d.locs}")
            if (d.arrival.isNotEmpty()) append(", age on arrival p50 ${secs(pct(d.arrival, 50))}, p95 ${secs(pct(d.arrival, 95))}")
            append("\n  live-view requests: ${d.asked} asked, ${d.answers.size} answered")
            if (d.answers.isNotEmpty()) append(", p50 ${secs(pct(d.answers, 50))}, p95 ${secs(pct(d.answers, 95))}")
            append("\n  alerts shown: ${d.acks.size} of $alerts")
            if (d.acks.isNotEmpty()) {
                val under = d.acks.count { it < 10_000 } * 100.0 / d.acks.size
                append(", p50 ${secs(pct(d.acks, 50))}, p95 ${secs(pct(d.acks, 95))}, max ${secs(d.acks.max())}, under 10 s ${"%.1f".format(under)}%")
            }
            append("\n  silence alerts: ${d.silences}\n")
        }
    }
}

/** The [p]th percentile of [values], by the nearest rank. */
fun pct(values: List<Long>, p: Int): Long {
    val sorted = values.sorted()
    val rank = ((p / 100.0) * sorted.size).let { kotlin.math.ceil(it).toInt() }.coerceIn(1, sorted.size)
    return sorted[rank - 1]
}

private fun secs(ms: Long): String = if (ms < 120_000) "%.1f s".format(ms / 1000.0) else "%.1f min".format(ms / 60_000.0)
