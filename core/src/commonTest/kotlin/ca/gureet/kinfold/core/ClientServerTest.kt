// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.client.Admitted
import ca.gureet.kinfold.core.client.ApiException
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.ClientListener
import ca.gureet.kinfold.core.client.Delivery
import ca.gureet.kinfold.core.client.MemoryStorage
import ca.gureet.kinfold.core.client.Payloads
import ca.gureet.kinfold.core.client.StreamChange
import ca.gureet.kinfold.core.client.Transport
import ca.gureet.kinfold.core.client.Wake
import ca.gureet.kinfold.core.client.admit
import ca.gureet.kinfold.core.client.apnsRegistration
import ca.gureet.kinfold.core.client.createCircle
import ca.gureet.kinfold.core.client.grantOf
import ca.gureet.kinfold.core.client.grantWatch
import ca.gureet.kinfold.core.client.invite
import ca.gureet.kinfold.core.client.join
import ca.gureet.kinfold.core.client.registerWatch
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.envelope.EnvelopeHeader
import ca.gureet.kinfold.core.rendezvous.Invite
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** A server to test the client layer against, and the platform's transport, set to trust it. */
class TestServer(val url: String, val setupCode: String, val transport: Transport)

/**
 * The server `test-with-server.sh` started, if it did: it passes the server's URL, a setup code and
 * its certificate to Gradle as `kinfold.server`, `kinfold.setup` and `kinfold.cacert`, and the build
 * hands them on to the tests on the JVM and on Android devices. Null without them, and on a
 * platform without a transport yet.
 */
expect fun testServer(): TestServer?

/** Runs [block] on this thread until it ends. */
expect fun <T> blocking(block: suspend CoroutineScope.() -> T): T

/** Marks the test as skipped, where the platform's test runner has the notion, and returns. */
expect fun skip(why: String)

/**
 * The client layer against a real server, built from `server/` and started with TLS by
 * `test-with-server.sh`, over each platform's own transport. Skipped without a server.
 *
 * Two devices go through what the spikes need: setting up from a setup code, a circle, an invite
 * and a join, envelopes both ways on the stream, a watch grant, a live-view request with `locate`,
 * an alert fetched from the inbox, a restart from storage, a session that ends, and an error.
 */
class ClientServerTest {
    /** What a device was told, for the test to wait on. */
    private class Recorder : ClientListener {
        val deliveries = Channel<Delivery>(Channel.UNLIMITED)
        val connected = Channel<Unit>(Channel.UNLIMITED)
        val failures = Channel<String>(Channel.UNLIMITED)

        override suspend fun delivered(delivery: Delivery) {
            deliveries.send(delivery)
        }

        override suspend fun stream(change: StreamChange) {
            if (change is StreamChange.Connected) connected.send(Unit)
        }

        override suspend fun failed(what: String, error: Throwable) {
            failures.send("$what: $error")
        }

        suspend fun delivery(match: (Delivery) -> Boolean): Delivery = withTimeout(WAIT_MS) {
            var d = deliveries.receive()
            while (!match(d)) d = deliveries.receive()
            d
        }

        suspend fun streamOpen() = withTimeout(WAIT_MS) { connected.receive() }

        fun failed(): List<String> = generateSequence { failures.tryReceive().getOrNull() }.toList()
    }

    @Test
    fun twoDevicesThroughARealServer() {
        val server = testServer() ?: return skip("no server: core/test-with-server.sh starts one")
        blocking { withTimeout(180_000) { twoDevices(server) } }
    }

    private suspend fun CoroutineScope.twoDevices(server: TestServer) {
        val p = Primitives(platformCrypto())
        val transport = server.transport

        // A: the first device, from the setup code, founds a circle.
        val a = Client.setUp(p, transport, MemoryStorage(), server.setupCode)
        val aSaw = Recorder()
        a.listener = aSaw
        assertEquals(server.url, a.serverUrl)
        assertTrue("stream_post" in a.features)
        val circle = a.createCircle("Family")
        assertEquals(listOf(circle), a.circles())
        assertEquals("Family", a.state(circle)!!.name)

        // A invites B with a registration token in the invite; B joins while A admits.
        val pending = a.invite(circle, "Family", "A")
        assertTrue(pending.invite.regToken.size > 0, "the server mints tokens with invites")
        val invite = Invite.fromCode(pending.code)
        val bStorage = MemoryStorage()
        val b = Client.forInvite(p, transport, bStorage, invite)
        val bSaw = Recorder()
        b.listener = bSaw
        val joining = async { b.join(invite, "B", timeoutMs = 60_000) }
        var admitted: Admitted? = null
        while (admitted == null) {
            admitted = a.admit(pending)
            if (admitted == null) delay(200)
        }
        assertEquals(b.keys.deviceId, admitted.deviceId)
        assertEquals("B", admitted.name)
        val joined = joining.await()
        assertEquals(circle, joined.circleId)
        assertTrue(joined.detailsMatched)
        val bState = b.state(circle)!!
        assertEquals("Family", bState.name)
        assertEquals(2, bState.members.size)
        assertEquals(a.state(circle)!!.head, bState.head)

        // Both keep a stream open.
        val aStream = launch { a.runStream(pingIntervalMs = 2_000) }
        var bStream = launch { b.runStream(pingIntervalMs = 2_000) }
        aSaw.streamOpen()
        bSaw.streamOpen()

        // A's position reaches B on its stream; B's, uploaded on its stream, reaches A.
        a.send(circle, Payloads.loc(a.clock.now(), 492_827_000, -1_231_207_000, 12))
        val fromA = bSaw.delivery { it.payload.string("t") == "loc" }
        assertEquals(492_827_000L, fromA.payload.long("lat"))
        assertEquals(a.keys.deviceId, fromA.sender.id)
        assertEquals(EnvelopeHeader.CIRCLE, fromA.kind)
        // Trusted time trails the server's clock by the time its last answer took to arrive.
        assertTrue(fromA.openedAt + 1_000UL >= fromA.receivedAt)
        assertNotNull(b.send(circle, Payloads.loc(b.clock.now(), 491_000_000, -1_230_000_000, 30)))
        assertEquals(b.keys.deviceId, aSaw.delivery { it.payload.long("lat") == 491_000_000L }.sender.id)

        // B lets A watch it for silence; A registers the grant; each sees the watch.
        b.grantWatch(circle, a.keys.accountId, afterMin = 60)
        val grant = assertNotNull(grantOf(aSaw.delivery { it.payload.string("t") == "watch_grant" }.payload))
        a.registerWatch(grant)
        assertEquals(listOf(b.keys.deviceId), a.authed { a.api.watches(circle) }.map { it.watchedDevice })
        assertEquals(listOf(a.keys.accountId), b.authed { b.api.watches(circle) }.map { it.watcherAccount })

        // A asks B for a live update, with locate; B has a stream, so the request comes at once.
        a.send(circle, Payloads.liveRequest(), to = listOf(b.keys.deviceId), wake = Wake.LOCATE)
        val ask = bSaw.delivery { it.payload.string("t") == "sig" }
        assertEquals(EnvelopeHeader.DIRECT, ask.kind)

        // B goes offline; A's alert, with notify, waits in B's inbox.
        bStream.cancelAndJoin()
        a.send(circle, Payloads.sos(a.clock.now(), "start", 1, 2, 3), wake = Wake.NOTIFY)
        assertEquals(1, b.fetchInbox())
        assertEquals("start", bSaw.delivery { it.payload.string("t") == "sos" }.payload.string("state"))

        // B starts again from what it kept: the same circle and head, nothing new in the inbox,
        // and sequence numbers that carry on, so A takes its next position.
        val b2 = assertNotNull(Client.load(p, transport, bStorage))
        val b2Saw = Recorder()
        b2.listener = b2Saw
        b2.start()
        assertEquals(listOf(circle), b2.circles())
        assertEquals(a.state(circle)!!.head, b2.state(circle)!!.head)
        assertEquals(0, b2.fetchInbox())
        b2.send(circle, Payloads.loc(b2.clock.now(), 490_000_000, -1_229_000_000, 25))
        aSaw.delivery { it.payload.long("lat") == 490_000_000L }
        bStream = launch { b2.runStream(pingIntervalMs = 2_000) }
        b2Saw.streamOpen()

        // A session that ends is renewed on the next call.
        a.logout()
        a.sync(circle)

        // An error carries its status and code: this server holds no Apple key.
        val e = assertFailsWith<ApiException> { b2.registerPush(apnsRegistration(ByteArray(32), null, "sandbox")) }
        assertEquals(403, e.status)

        aStream.cancelAndJoin()
        bStream.cancelAndJoin()
        for (r in listOf(aSaw, bSaw, b2Saw)) assertEquals(emptyList(), r.failed())
    }

    private companion object {
        const val WAIT_MS = 20_000L
    }
}
