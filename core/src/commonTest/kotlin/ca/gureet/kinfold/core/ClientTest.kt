// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.client.Backoff
import ca.gureet.kinfold.core.client.ClientException
import ca.gureet.kinfold.core.client.DeviceKeys
import ca.gureet.kinfold.core.client.Payloads
import ca.gureet.kinfold.core.client.ServerApi
import ca.gureet.kinfold.core.client.TrustedClock
import ca.gureet.kinfold.core.client.frames
import ca.gureet.kinfold.core.client.framesLenient
import ca.gureet.kinfold.core.client.grantOf
import ca.gureet.kinfold.core.client.percentEncode
import ca.gureet.kinfold.core.client.unframe
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.push.PushMessage
import ca.gureet.kinfold.core.push.PushReceipt
import ca.gureet.kinfold.core.push.Pushes
import ca.gureet.kinfold.core.push.WatchGrant
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The parts of the client layer that need no server: trusted time, the backoff, frames, device
 * keys, payloads, pushes that come on the stream and the API's errors. ClientServerTest, on the
 * JVM, runs the rest against a real server.
 */
class ClientTest {
    private val p = Primitives(platformCrypto())

    @Test
    fun trustedTimeCountsOnFromTheServer() {
        var mono = 1_000L
        var wall = 5_000L
        val clock = TrustedClock(saved = 9_000UL, monotonic = { mono }, wall = { wall })
        // Before the server is heard: the later of the wall clock and the time saved (PROTOCOL.md §8.4).
        assertEquals(9_000UL, clock.now())
        wall = 20_000L
        assertEquals(20_000UL, clock.now())
        clock.observe(100_000UL)
        mono += 2_500
        assertEquals(102_500UL, clock.now())
        // From then on the wall clock doesn't count, whatever the person sets it to.
        wall = 0L
        assertEquals(102_500UL, clock.now())
        assertEquals(100_000UL, clock.lastServerTime)
        assertTrue(clock.hasHeard)
    }

    @Test
    fun backoffDoublesToFiveMinutesWithJitter() {
        val b = Backoff(Random(1))
        repeat(14) { i ->
            val base = minOf(1_000L shl minOf(i, 9), 300_000L)
            assertTrue(b.next() in base / 2..base, "wait $i")
        }
        b.reset()
        assertTrue(b.next() in 500L..1_000L)
        assertTrue(b.next(60_000L) >= 60_000L)
    }

    @Test
    fun framesRoundTripAndRefuseWhatDoesNotFit() {
        val parts = listOf(byteArrayOf(1, 2, 3), ByteArray(0), ByteArray(300) { it.toByte() })
        val body = frames(*parts.toTypedArray())
        assertEquals(parts.map { it.toList() }, unframe(body).map { it.toList() })
        assertFailsWith<ClientException> { unframe(body.copyOf(body.size - 1)) }
        assertFailsWith<ClientException> { unframe(body + byteArrayOf(0, 0)) }
        // What storage keeps: whole frames, without a last one a crash cut off.
        assertEquals(parts.map { it.toList() }, framesLenient(body + byteArrayOf(0, 0, 1)).map { it.toList() })
        assertEquals(2, framesLenient(body.copyOf(body.size - 1)).size)
    }

    @Test
    fun aQueryKeepsOnlyUnreservedCharacters() {
        assertEquals("aZ09-._~%2F%3D%20%C3%A9%25", percentEncode("aZ09-._~/= é%"))
    }

    @Test
    fun deviceKeysAreValidAndSurviveStorage() = sync {
        val now = 1_794_571_200_000UL
        val k = DeviceKeys.create(p, DeviceKind.PHONE, now)
        assertTrue(k.cert.isWellFormed(p))
        assertEquals(k.accountId, k.cert.accountId)
        assertTrue(k.bundle.isValidFor(p, k.cert.dskPub, k.accountId))
        assertTrue(k.bundle.isCurrentAt(now))
        assertEquals(KeyBundle.MAX_LIFE_MS, k.bundle.notAfter - k.bundle.notBefore)
        val back = DeviceKeys.decode(p, k.encode())
        assertEquals(k.deviceId, back.deviceId)
        assertEquals(k.accountId, back.accountId)
        assertEquals(k.keyId, back.keyId)
        assertContentEquals(k.cert.encode(), back.cert.encode())
        assertContentEquals(k.bundle.encode(), back.bundle.encode())
        assertContentEquals(k.identity.publicKey, back.identity.publicKey)
        assertContentEquals(k.encryption.publicKey, back.encryption.publicKey)
        assertFailsWith<ProtocolException> { DeviceKeys.decode(p, k.encode() + byteArrayOf(0)) }
        assertFailsWith<ProtocolException> { DeviceKeys.decode(p, byteArrayOf(2) + k.encode().copyOfRange(1, k.encode().size)) }
    }

    @Test
    fun aWelcomeCarriesTheNewestRunOfSecrets() {
        val head = Bytes.of(ByteArray(32) { 3 })
        val s = { b: Int -> ByteArray(32) { b.toByte() } }
        val w = Payloads.welcome(mapOf(0L to s(1), 1L to s(2), 3L to s(3)), head)
        assertEquals(3L, w.long("first"))
        assertEquals(listOf(Base64Url.encode(s(3))), (w["epochs"] as Json.Arr).items.map { (it as Json.Str).value })
        val w2 = Payloads.welcome(mapOf(0L to s(1), 1L to s(2)), head)
        assertEquals(0L, w2.long("first"))
        assertEquals(2, (w2["epochs"] as Json.Arr).items.size)
        assertNotNull(Json.parsePayload(w.encode()))
        val many = (0L until 300L).associateWith { s(it.toInt()) }
        val w3 = Payloads.welcome(many, head)
        assertEquals(44L, w3.long("first"))
        assertEquals(256, (w3["epochs"] as Json.Arr).items.size)
    }

    @Test
    fun aGrantTravelsInItsPayload() = sync {
        val dsk = p.crypto.ed25519(ByteArray(32) { 5 })
        val grant = WatchGrant.issue(p, dsk, Bytes.of(ByteArray(16) { 1 }), Bytes.of(ByteArray(16) { 2 }), Bytes.of(ByteArray(16) { 3 }), 60, 1_000UL, 2_000UL)
        val back = assertNotNull(grantOf(Json.parsePayload(Payloads.watchGrant(grant).encode())!!))
        assertContentEquals(grant.encode(), back.encode())
        assertNull(grantOf(Payloads.liveRequest()))
    }

    @Test
    fun aPushOnTheStreamIsCheckedLikeASealedOne() = sync {
        val server = p.crypto.ed25519(ByteArray(32) { 9 })
        val serverKey = Bytes.of(server.publicKey)
        val device = Bytes.of(ByteArray(16) { 4 })
        val sentAt = 1_794_571_200_000UL
        val body = Pushes.silenceBody(Bytes.of(ByteArray(16) { 1 }), Bytes.of(ByteArray(16) { 2 }), 77UL)
        val push = Pushes.make(p, server, device, Pushes.SILENCE, sentAt, body)
        val opened = assertIs<PushReceipt.Opened>(Pushes.openSigned(p, push, device, serverKey, sentAt + 600_000UL))
        assertEquals(77UL, assertIs<PushMessage.Silence>(opened.message).lastSeenAt)
        fun dropped(r: PushReceipt) = assertIs<PushReceipt.Dropped>(r).reason
        val other = Bytes.of(p.crypto.ed25519(ByteArray(32) { 8 }).publicKey)
        assertEquals(PushReceipt.Drop.BAD_SIGNATURE, dropped(Pushes.openSigned(p, push, Bytes.of(ByteArray(16) { 5 }), serverKey, sentAt)))
        assertEquals(PushReceipt.Drop.BAD_SIGNATURE, dropped(Pushes.openSigned(p, push, device, other, sentAt)))
        assertEquals(PushReceipt.Drop.BAD_TIME, dropped(Pushes.openSigned(p, push, device, serverKey, sentAt + 600_001UL)))
        assertEquals(PushReceipt.Drop.MALFORMED, dropped(Pushes.openSigned(p, push.copyOf(push.size - 1), device, serverKey, sentAt)))
        assertEquals(PushReceipt.Drop.WRONG_SIZE, dropped(Pushes.openSigned(p, ByteArray(Pushes.PLAIN_SIZE + 1), device, serverKey, sentAt)))
    }

    @Test
    fun jsonArraysAtTheTopLevel() {
        val limits = Json.Limits.MESSAGE
        assertEquals(3, Json.parseArray("""[{"a":1},2,"x"]""".encodeToByteArray(), limits)?.items?.size)
        assertEquals(0, Json.parseArray(" [ ] ".encodeToByteArray(), limits)?.items?.size)
        assertNull(Json.parseArray("""{"a":1}""".encodeToByteArray(), limits))
        assertNull(Json.parseArray("[1] x".encodeToByteArray(), limits))
        assertNull(Json.parseArray("""[{"a":1,"a":2}]""".encodeToByteArray(), limits))
        assertNull(Json.parseObject("[1]".encodeToByteArray(), limits))
    }

    @Test
    fun theServersErrorsCarryTheirFields() {
        val head = Base64Url.encode(ByteArray(32) { 6 })
        val e = ServerApi.errorOf(422, """{"error":"stale_head","message":"x","seq":4,"head":"$head"}""".encodeToByteArray(), 7)
        assertEquals(Reason.STALE_HEAD, e.reason)
        assertEquals(4L, e.seq)
        assertEquals(Bytes.of(ByteArray(32) { 6 }), e.head)
        assertEquals(7L, e.retryAfterS)
        val proxy = ServerApi.errorOf(502, "<html>".encodeToByteArray(), null)
        assertEquals("http_502", proxy.error)
        assertNull(proxy.reason)
        // A stream result has no headers, so a 429 carries retry_after in its JSON (API.md §7).
        assertEquals(30L, ServerApi.errorOf(429, """{"error":"rate_limited","retry_after":30}""".encodeToByteArray(), null).retryAfterS)
    }
}
