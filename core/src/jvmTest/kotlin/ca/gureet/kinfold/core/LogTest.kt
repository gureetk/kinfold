// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.JvmCrypto
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.log.MemberLog
import ca.gureet.kinfold.core.log.Outcome
import ca.gureet.kinfold.core.log.Role
import ca.gureet.kinfold.core.wire.hexBytes
import ca.gureet.kinfold.core.wire.toHex
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The `log` vectors (PROTOCOL.md §5, §6): the main log and every case, as a client with the
 * epoch secrets and as a server in public mode, outcome by outcome and state by state.
 */
class LogTest {
    private val p = Primitives(JvmCrypto())
    private val v = Vectors.group("log")
    private val entries = v.list("entries")
    private val secrets: Map<Long, ByteArray> =
        v.getAsJsonObject("epoch_secrets").entrySet().associate { it.key.toLong() to hexBytes(it.value.asString) }

    private val privateFields = listOf("name", "flags", "private_unknown_from", "state_hash")
    private val privateMemberFields = listOf("role", "teen_until", "guardians", "rules", "pauses")

    @Test
    fun mainLog() = sync {
        assertEquals(21, entries.size)
        var client = CircleState()
        var server = CircleState()
        for (e in entries) {
            val name = "entry ${e.int("seq")}: ${e.str("description")}"
            client = check(name, client, e, secrets, private = true)
            server = check(name, server, e, null, private = false)
        }
        assertEquals(v.int("final_seq").toLong(), client.seq)
    }

    @Test
    fun cases() = sync {
        val cases = v.list("cases")
        assertEquals(206, cases.size)
        var checked = 0
        for (c in cases) {
            val keys = secrets.toMutableMap()
            c.getAsJsonObject("new_epoch_secrets")?.entrySet()?.forEach { keys[it.key.toLong()] = hexBytes(it.value.asString) }
            c.getAsJsonArray("withheld_epochs")?.forEach { keys.remove(it.asLong) }
            c.getAsJsonObject("wrong_epoch_secrets")?.entrySet()?.forEach { keys[it.key.toLong()] = hexBytes(it.value.asString) }
            val base = c.int("base_seq")
            var client = replay(base, secrets)
            var server = replay(base, null)
            for (e in c.list("entries")) {
                val name = "${c.str("name")} (${c.str("description")}), entry ${e.int("seq")}"
                client = check(name, client, e, keys, private = true)
                server = check(name, server, e, null, private = false)
                checked++
            }
        }
        assertEquals(327, checked)
    }

    @Test
    fun stateHash() = sync {
        val h = v.getAsJsonObject("state_hash")
        val state = replay(h.int("log_seq"), secrets)
        assertEquals(h.str("state_bytes"), state.stateBytes().toHex())
        assertEquals(h.str("state_hash"), state.stateHash(p)?.hex)
    }

    /** The main log, replayed through [seq] (-1 for none). */
    private suspend fun replay(seq: Int, keys: Map<Long, ByteArray>?): CircleState {
        val (state, outcomes) = MemberLog.replay(p, entries.take(seq + 1).map { it.hex("raw") }, keys)
        assertTrue(outcomes.all { it is Outcome.Applied })
        return state
    }

    /** Applies one vector entry and checks its outcome and the state after it; returns the state to continue from. */
    private suspend fun check(name: String, state: CircleState, e: JsonObject, keys: Map<Long, ByteArray>?, private: Boolean): CircleState {
        val mode = if (private) "client" else "server"
        val wantResult = e.str(if (private) "result" else "public_result")
        val wantReason = e.get(if (private) "reason" else "public_reason")?.takeUnless { it.isJsonNull }?.asString
        return when (val o = MemberLog.apply(p, state, e.hex("raw"), keys)) {
            is Outcome.Fatal -> {
                assertEquals("fatal" to wantReason, "fatal" to o.reason.code, "$name ($mode)")
                assertEquals(wantResult, "fatal", "$name ($mode)")
                state
            }
            is Outcome.Applied -> {
                assertEquals(wantResult to wantReason, o.result.name.lowercase() to o.reason?.code, "$name ($mode)")
                assertEquals(e.hex("hash").toHex(), o.state.head.hex, "$name: hash")
                val want = e.getAsJsonObject("state_after")
                if (want != null) {
                    val expected = if (private) want else publicOnly(want)
                    val actual = stateJson(o.state, private)
                    if (expected != actual) fail("$name ($mode): state differs\n  want $expected\n  got  $actual")
                }
                o.state
            }
        }
    }

    private fun publicOnly(state: JsonObject): JsonObject {
        val out = state.deepCopy()
        privateFields.forEach { out.remove(it) }
        for (m in out.getAsJsonArray("members")) privateMemberFields.forEach { m.asJsonObject.remove(it) }
        return out
    }

    /** The state as the vectors write it (spec/vectors/README.md, "State JSON"). */
    private suspend fun stateJson(s: CircleState, private: Boolean): JsonObject {
        val o = JsonObject()
        o.add("circle_id", s.circleId?.let { JsonPrimitive(it.hex) } ?: JsonNull.INSTANCE)
        o.addProperty("seq", s.seq)
        o.addProperty("head", s.head.hex)
        o.addProperty("epoch", s.epoch)
        o.addProperty("rekey_pending", s.rekeyPending)
        o.addProperty("options", s.options)
        o.add("used_invites", JsonArray().apply { s.usedInvites.sorted().forEach { add(it.hex) } })
        val members = JsonArray()
        for (m in s.members.values.sortedBy { it.accountId }) {
            val j = JsonObject()
            j.addProperty("account_id", m.accountId.hex)
            j.addProperty("ik_pub", m.ikPub.hex)
            j.addProperty("admin", m.admin)
            j.add(
                "devices",
                JsonArray().apply {
                    for (d in m.devices.values.sortedBy { it.id }) {
                        add(
                            JsonObject().apply {
                                addProperty("device_id", d.id.hex)
                                addProperty("kind", d.kind.code)
                                add("key_id", d.keyId?.let { JsonPrimitive(it.hex) } ?: JsonNull.INSTANCE)
                            },
                        )
                    }
                },
            )
            if (private) {
                j.addProperty("role", if (m.role == Role.TEEN) "teen" else "adult")
                j.addProperty("teen_until", m.teenUntil.toLong())
                j.add("guardians", JsonArray().apply { m.guardians.forEach { add(it.hex) } })
                j.add("rules", m.rules?.let { rulesJson(it) } ?: JsonNull.INSTANCE)
                j.add(
                    "pauses",
                    JsonArray().apply {
                        for ((id, pause) in m.pauses.entries.sortedBy { it.key }) {
                            add(
                                JsonObject().apply {
                                    addProperty("id", id.hex)
                                    addProperty("kind", pause.kind)
                                    addProperty("start", pause.start.toLong())
                                    addProperty("end", pause.end.toLong())
                                },
                            )
                        }
                    },
                )
            }
            members.add(j)
        }
        o.add("members", members)
        if (private) {
            o.addProperty("name", s.name)
            o.add(
                "flags",
                JsonArray().apply {
                    for ((seq, reason) in s.flags) add(JsonObject().apply { addProperty("seq", seq); addProperty("reason", reason.code) })
                },
            )
            o.add("private_unknown_from", s.privateUnknownFrom?.let { JsonPrimitive(it) } ?: JsonNull.INSTANCE)
            o.add("state_hash", s.stateHash(p)?.let { JsonPrimitive(it.hex) } ?: JsonNull.INSTANCE)
        }
        return o
    }

    private fun rulesJson(r: ca.gureet.kinfold.core.log.Rules): JsonElement = JsonObject().apply {
        addProperty("pause_mode", r.pauseMode)
        addProperty("approx_mode", r.approxMode)
        addProperty("speed_alert_kmh", r.speedAlertKmh)
        addProperty("phone_use_alerts", r.phoneUseAlerts)
        addProperty("history_days", r.historyDays)
        addProperty("silence_alert_min", r.silenceAlertMin)
        addProperty("tz", r.tzText)
        add(
            "schedule",
            JsonArray().apply {
                for (w in r.schedule) {
                    add(
                        JsonObject().apply {
                            addProperty("kind", w.kind)
                            addProperty("days", w.days)
                            addProperty("start_min", w.startMin)
                            addProperty("end_min", w.endMin)
                        },
                    )
                }
            },
        )
    }
}
