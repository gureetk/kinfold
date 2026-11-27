// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.blocking
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.Delivery
import ca.gureet.kinfold.core.client.MemoryStorage
import ca.gureet.kinfold.core.client.Storage
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.log.Device
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The family's rules for what comes in, which both apps share: positions, live-view requests and profiles. */
class FamilyTest {
    private class Host(override val storage: Storage = MemoryStorage()) : FamilyHost {
        var t = 1_800_000_000_000UL
        val lines = ArrayList<String>()

        override suspend fun client(): Client? = null

        override fun hasDevice(): Boolean = false

        override fun deviceName(): String = "Test phone"

        override var watchConsent: Boolean? = null

        override fun log(event: String, fields: List<Pair<String, Any?>>) {
            lines.add(LogLines.format(t, event, fields))
        }

        override fun now(): ULong = t

        override fun timeOfDay(ms: Long): String = "noon"
    }

    private val circle = Bytes.of(ByteArray(16) { 1 })
    private val alice = Bytes.of(ByteArray(16) { 2 })
    private val aliceDevice = Device(Bytes.of(ByteArray(16) { 3 }), alice, Bytes.of(ByteArray(32)), DeviceKind.PHONE, null, null, alice)

    private fun delivery(seq: Long, at: ULong, vararg fields: Pair<String, Json>) =
        Delivery(circle, aliceDevice, 0, Json.Obj(linkedMapOf(*fields)), at, seq.toULong(), at, at)

    private fun loc(ts: Long, lat: Long) =
        arrayOf("t" to Json.Str("loc"), "ts" to Json.Num(ts), "lat" to Json.Num(lat), "lon" to Json.Num(-1_231_000_000), "acc" to Json.Num(10))

    @Test
    fun positionsOnlyMoveForward() = blocking {
        val host = Host()
        val family = Family(host)
        val t = host.t.toLong()
        family.onDelivery(delivery(5, host.t, *loc(t, 491_000_000)), sharing = false)
        // A lower sequence number never replaces what a higher one set (§7.6)...
        family.onDelivery(delivery(4, host.t, *loc(t + 1_000, 492_000_000)), sharing = false)
        // ...and an older fix never replaces a newer one, whatever its number.
        family.onDelivery(delivery(6, host.t, *loc(t - 1_000, 493_000_000)), sharing = false)
        family.onDelivery(delivery(7, host.t, "t" to Json.Str("profile"), "name" to Json.Str("Alice")), sharing = false)
        family.flush()

        // The records survive in storage, for the next start.
        assertEquals("Alice", Family(host).nameOf(alice))
        // The log has the positions' ages and accuracies, never their coordinates.
        assertTrue(host.lines.none { "491" in it || "492" in it || "-123" in it }, host.lines.joinToString("\n"))
        assertEquals(listOf(true, false, false), host.lines.filter { "\"e\":\"position\"" in it }.map { "\"newer\":true" in it })
    }

    @Test
    fun liveRequestsAreHonouredOncePerMinuteWhileSharing() = blocking {
        val host = Host()
        val family = Family(host)
        fun ask(until: Long) = delivery(1, host.t, "t" to Json.Str("sig"), "k" to Json.Str("live_req"), "until" to Json.Num(until))
        val t = host.t.toLong()
        assertNull(family.onDelivery(ask(t + 120_000), sharing = false), "not while sharing is off")
        assertEquals(120_000L, family.onDelivery(ask(t + 120_000), sharing = true))
        host.t += 30_000UL
        assertNull(family.onDelivery(ask(t + 150_000), sharing = true), "not twice in a minute")
        host.t += 30_000UL
        // The time asked is held to 30 seconds to 5 minutes.
        assertEquals(300_000L, family.onDelivery(ask(t + 3_600_000), sharing = true))
        host.t += 60_000UL
        assertEquals(30_000L, family.onDelivery(ask(t), sharing = true))
    }

    @Test
    fun profilesGiveNames() = blocking {
        val family = Family(Host())
        family.onDelivery(delivery(1, 0UL, "t" to Json.Str("profile"), "name" to Json.Str("  " + "A".repeat(80) + "  ")), sharing = false)
        assertEquals("A".repeat(60), family.nameOf(alice))
        family.onDelivery(delivery(2, 0UL, "t" to Json.Str("profile"), "name" to Json.Str("   ")), sharing = false)
        assertEquals("A".repeat(60), family.nameOf(alice), "a blank name changes nothing")
    }

    @Test
    fun logLinesKeepTheirOrderAndKinds() {
        val line = LogLines.format(42UL, "upload", listOf("type" to "loc", "took_ms" to 120L, "stored" to true, "n" to 3, "seq" to 7UL, "missing" to null))
        assertEquals("""{"t":42,"e":"upload","type":"loc","took_ms":120,"stored":true,"n":3,"seq":7}""", line)
    }
}
