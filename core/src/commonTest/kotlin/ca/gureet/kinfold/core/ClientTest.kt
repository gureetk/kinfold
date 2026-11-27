// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.client.Backoff
import ca.gureet.kinfold.core.client.Client
import ca.gureet.kinfold.core.client.ClientListener
import ca.gureet.kinfold.core.client.ClientException
import ca.gureet.kinfold.core.client.DeviceKeys
import ca.gureet.kinfold.core.client.HttpRequest
import ca.gureet.kinfold.core.client.HttpResponse
import ca.gureet.kinfold.core.client.MemoryStorage
import ca.gureet.kinfold.core.client.Names
import ca.gureet.kinfold.core.client.Payloads
import ca.gureet.kinfold.core.client.ServerApi
import ca.gureet.kinfold.core.client.SilenceAlert
import ca.gureet.kinfold.core.client.Transport
import ca.gureet.kinfold.core.client.TransportException
import ca.gureet.kinfold.core.client.TrustedClock
import ca.gureet.kinfold.core.client.WebSocket
import ca.gureet.kinfold.core.client.frames
import ca.gureet.kinfold.core.client.framesLenient
import ca.gureet.kinfold.core.client.grantOf
import ca.gureet.kinfold.core.client.percentEncode
import ca.gureet.kinfold.core.client.unframe
import ca.gureet.kinfold.core.client.wallMillis
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
import ca.gureet.kinfold.core.wire.encode
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
        assertFailsWith<ProtocolException> { DeviceKeys.decode(p, byteArrayOf(3) + k.encode().copyOfRange(1, k.encode().size)) }
    }

    @Test
    fun aRotatedKeyKeepsTheOldOneForAWhile() = sync {
        val day = 86_400_000UL
        val now = 1_794_571_200_000UL
        val k = DeviceKeys.create(p, DeviceKind.PHONE, now)
        val r = k.rotated(p, now + 7UL * day)
        // A new encryption key and a two-week bundle for it (§4.5), the same device and account.
        assertTrue(r.keyId != k.keyId)
        assertEquals(k.deviceId, r.deviceId)
        assertTrue(r.bundle.isValidFor(p, r.cert.dskPub, r.accountId))
        assertTrue(r.bundle.isCurrentAt(now + 7UL * day))
        assertEquals(DeviceKeys.ROTATED_LIFE_MS, r.bundle.notAfter - r.bundle.notBefore)
        // Both keys open what was wrapped to them; the old one is retired, last current at the rotation.
        assertEquals(setOf(k.keyId, r.keyId), r.hpkeKeys.keys)
        assertContentEquals(k.encryption.publicKey, r.hpkeKeys.getValue(k.keyId).publicKey)
        assertEquals(listOf(now + 7UL * day), r.retired.map { it.lastCurrentAt })
        // Kept in storage, retired key and all.
        val back = DeviceKeys.decode(p, r.encode())
        assertEquals(r.keyId, back.keyId)
        assertEquals(setOf(k.keyId, r.keyId), back.hpkeKeys.keys)
        assertEquals(r.retired.map { it.lastCurrentAt }, back.retired.map { it.lastCurrentAt })
        // A device kept before keys were retired reads as one with none.
        val first = k.encode()
        assertEquals(0, first.last().toInt())
        val old = DeviceKeys.decode(p, byteArrayOf(1) + first.copyOfRange(1, first.size - 1))
        assertEquals(k.keyId, old.keyId)
        assertEquals(emptyList(), old.retired)
        // 32 days after it was last current the old key goes, unless a log still holds it.
        val rotatedAt = now + 7UL * day
        assertEquals(1, r.withRetired(emptySet(), rotatedAt + 31UL * day).retired.size)
        assertEquals(0, r.withRetired(emptySet(), rotatedAt + 33UL * day).retired.size)
        val held = r.withRetired(setOf(k.keyId), rotatedAt + 33UL * day)
        assertEquals(listOf(rotatedAt + 33UL * day), held.retired.map { it.lastCurrentAt })
        assertTrue(r.withRetired(setOf(k.keyId), rotatedAt + 60_000UL) === r, "no change within the hour")
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
    fun aSealedPushIsHandledAsTheStreamWould() = sync {
        // A device as an iPhone's extension finds it in the app's files, with no network at all.
        val server = p.crypto.ed25519(ByteArray(32) { 9 })
        val storage = MemoryStorage()
        val keys = DeviceKeys.create(p, DeviceKind.PHONE, wallMillis().toULong())
        storage.write(Names.SERVER, encode {
            vec16("https://kinfold.example".encodeToByteArray())
            bytes(server.publicKey)
        })
        storage.write(Names.DEVICE, keys.encode())
        val c = assertNotNull(Client.load(p, NoNetwork, storage))
        val heard = ArrayList<String>()
        c.listener = object : ClientListener {
            override suspend fun silence(alert: SilenceAlert) {
                heard.add("silence ${alert.lastSeenAt}")
            }

            override suspend fun pushDropped(reason: PushReceipt.Drop) {
                heard.add("dropped $reason")
            }
        }
        val sentAt = wallMillis().toULong()
        val body = Pushes.silenceBody(Bytes.of(ByteArray(16) { 1 }), Bytes.of(ByteArray(16) { 2 }), 77UL)
        val push = Pushes.make(p, server, keys.deviceId, Pushes.SILENCE, sentAt, body)
        val sealed = Pushes.seal(p, push, keys.deviceId, keys.encryption.publicKey)
        assertEquals(Pushes.SEALED_SIZE, sealed.size)
        assertIs<PushReceipt.Opened>(c.pushed(sealed))
        // Sealed to another key, cut short, or signed by another server: dropped, and only the log hears of it.
        val elsewhere = Pushes.seal(p, push, keys.deviceId, DeviceKeys.create(p, DeviceKind.PHONE, sentAt).encryption.publicKey)
        assertIs<PushReceipt.Dropped>(c.pushed(elsewhere))
        assertIs<PushReceipt.Dropped>(c.pushed(sealed.copyOf(sealed.size - 1)))
        val forged = Pushes.make(p, p.crypto.ed25519(ByteArray(32) { 8 }), keys.deviceId, Pushes.SILENCE, sentAt, body)
        assertIs<PushReceipt.Dropped>(c.pushed(Pushes.seal(p, forged, keys.deviceId, keys.encryption.publicKey)))
        assertEquals(listOf("silence 77", "dropped UNKNOWN_KEY", "dropped WRONG_SIZE", "dropped BAD_SIGNATURE"), heard)
    }

    @Test
    fun countersCarryOnFromWhatIsStored() {
        val storage = MemoryStorage()
        assertEquals(1UL, storage.next("seq", 1UL))
        assertEquals(2UL, storage.next("seq", 1UL))
        // The sequence number as clients before Storage.next kept it: a u64, the next one to use.
        storage.write("seq", encode { u64(41UL) })
        assertEquals(41UL, storage.next("seq", 1UL))
        assertContentEquals(encode { u64(42UL) }, storage.read("seq"))
        // Something that isn't a counter is an error, never a reason to count again from the start.
        storage.write("seq", byteArrayOf(1, 2, 3))
        assertFailsWith<ProtocolException> { storage.next("seq", 1UL) }
    }

    /** A transport for tests that must not reach a server. */
    private object NoNetwork : Transport {
        override suspend fun exchange(request: HttpRequest): HttpResponse = throw TransportException("no network in this test")

        override suspend fun connect(url: String, headers: Map<String, String>, pingIntervalMs: Long): WebSocket =
            throw TransportException("no network in this test")
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
