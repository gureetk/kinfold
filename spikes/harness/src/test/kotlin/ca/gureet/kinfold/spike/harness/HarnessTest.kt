// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike.harness

import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.ClientListener
import ca.gureet.kinfold.core.client.Delivery
import ca.gureet.kinfold.core.client.JdkTransport
import ca.gureet.kinfold.core.client.MemoryStorage
import ca.gureet.kinfold.core.client.Payloads
import ca.gureet.kinfold.core.client.createCircle
import ca.gureet.kinfold.core.client.grantWatch
import ca.gureet.kinfold.core.client.invite
import ca.gureet.kinfold.core.client.join
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.TinkCrypto
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.rendezvous.Invite
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The harness against a real server (`../../core/test-with-server.sh` starts one): a phone joins
 * through its invite, grants it a watch, names itself, moves, answers a live-view request and an
 * alert. The log must show all of it, and no position anywhere.
 */
class HarnessTest {
    private val server: String? = System.getProperty("kinfold.server")
    private val setupCode: String? = System.getProperty("kinfold.setup")
    private val cert: String? = System.getProperty("kinfold.cacert")

    private class Phone : ClientListener {
        val got = Channel<Delivery>(Channel.UNLIMITED)

        override suspend fun delivered(delivery: Delivery) {
            got.send(delivery)
        }

        suspend fun next(type: String): Delivery = withTimeout(20_000) {
            var d = got.receive()
            while (d.payload.string("t") != type) d = got.receive()
            d
        }
    }

    @Test
    fun aPhoneThroughTheHarness() = runBlocking {
        assumeTrue("no server: ../../core/test-with-server.sh starts one", server != null && setupCode != null && cert != null)
        val data = Files.createTempDirectory("harness")
        withTimeout(120_000) {
            val p = Primitives(TinkCrypto())
            val transport = JdkTransport.trusting(File(cert!!).readBytes())
            val h = Client.setUp(p, transport, FileStorage(data), setupCode!!)
            val circle = h.createCircle("Spikes")
            assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(data))
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(data.resolve("device")))
            val log = EventLog(data.resolve("logs"), echo = false)
            val harness = Harness(h, circle, log, Schedule(locateEveryMs = 0, alertEveryMs = 0, pingMs = 2_000, sampleEveryMs = 500))
            val running = launch { harness.run() }
            waitFor(data, "stream") { it.string("state") == "connected" }

            // A phone joins through the harness's invite; the harness lets it in on its own.
            val pending = h.invite(circle, "Spikes", "Kinfold harness")
            val invite = Invite.fromCode(pending.code)
            val phone = Client.forInvite(p, transport, MemoryStorage(), invite)
            val heard = Phone()
            phone.listener = heard
            phone.join(invite, "Test phone", timeoutMs = 60_000)
            val stream = launch { phone.runStream(pingIntervalMs = 2_000) }
            waitFor(data, "joined")

            // It grants the harness a watch, names itself and moves 500 metres north.
            phone.grantWatch(circle, h.keys.accountId, afterMin = 60)
            phone.send(circle, Json.Obj(mapOf("t" to Json.Str("profile"), "name" to Json.Str("Test phone"))))
            val t = phone.clock.now()
            phone.send(circle, Payloads.loc(t - 60_000UL, 491_234_567, -1_231_234_567, 10))
            phone.send(circle, Payloads.loc(t, 491_279_534, -1_231_234_567, 10, extra = mapOf("spd" to Json.Num(150))))
            waitFor(data, "watch")

            // The harness asks for its location; the phone answers with a position.
            harness.askForLocations()
            heard.next("sig")
            phone.send(circle, Payloads.loc(phone.clock.now(), 491_279_600, -1_231_234_500, 8))
            val answer = waitFor(data, "loc") { it.long("answer_ms") != null }
            assertTrue(answer.long("answer_ms")!! >= 0)

            // An alert reaches the phone, which acknowledges it to the harness.
            harness.sendAlert()
            val alert = heard.next("evt")
            phone.send(
                circle,
                Json.Obj(
                    mapOf(
                        "t" to Json.Str("spike_ack"), "of" to Json.Str("evt"), "sent_at" to Json.Num(alert.sentAt.toLong()),
                        "opened_at" to Json.Num(alert.openedAt.toLong()), "shown_at" to Json.Num(alert.openedAt.toLong()),
                    ),
                ),
                to = listOf(h.keys.deviceId),
            )
            waitFor(data, "ack")
            waitFor(data, "sample") { (it["moving"] as? Json.Bool)?.value == true }

            stream.cancel()
            running.cancel()
        }

        // What was logged: the join, the watch, the name, the distance moved, the answer and the alert.
        val lines = EventLog.read(data.resolve("logs")).toList()
        val moved = lines.first { it.string("e") == "loc" && it.long("moved_m") != null }.long("moved_m")!!
        assertTrue(moved in 490..510, "moved $moved m")
        assertEquals("Test phone", lines.first { it.string("e") == "profile" }.string("name"))
        assertNotNull(lines.firstOrNull { it.string("e") == "watch" && it.long("after_min") == 60L })
        assertNotNull(lines.firstOrNull { it.string("e") == "alert" })

        // ...and never a position, in any form.
        val text = Files.list(data.resolve("logs")).use { s -> s.toList() }.joinToString("\n") { Files.readString(it) }
        for (n in listOf("491234567", "1231234567", "491279534", "491279600", "1231234500", "49.123", "123.123", "49.127")) {
            assertFalse(n in text, "the log holds $n")
        }
        val summary = report(data.resolve("logs"), 0)
        assertTrue("Test phone" in summary, summary)
        assertTrue("live-view requests: 1 asked, 1 answered" in summary, summary)
    }

    /** Waits until the log holds an event [e] that [match]es, and returns it. */
    private suspend fun waitFor(data: Path, e: String, match: (Json.Obj) -> Boolean = { true }): Json.Obj {
        while (true) {
            EventLog.read(data.resolve("logs")).firstOrNull { it.string("e") == e && match(it) }?.let { return it }
            delay(100)
        }
    }
}
