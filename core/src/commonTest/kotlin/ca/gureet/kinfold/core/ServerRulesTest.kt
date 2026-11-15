// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.HpkeKey
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.log.MemberLog
import ca.gureet.kinfold.core.push.PushMessage
import ca.gureet.kinfold.core.push.PushReceipt
import ca.gureet.kinfold.core.push.PushReceipt.Drop
import ca.gureet.kinfold.core.push.Pushes
import ca.gureet.kinfold.core.push.Relay
import ca.gureet.kinfold.core.push.WatchGrant
import ca.gureet.kinfold.core.server.Login
import ca.gureet.kinfold.core.server.ServerException
import ca.gureet.kinfold.core.server.ServerException.Failure
import ca.gureet.kinfold.core.server.ServerInfo
import ca.gureet.kinfold.core.server.ServerMove
import ca.gureet.kinfold.core.server.Setup
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Padding
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Each check of PROTOCOL.md §13 and §14 by hand, with something signed correctly that breaks that
 * check and nothing else, built from the vectors' server, people and devices.
 */
class ServerRulesTest {
    private val crypto = platformCrypto()
    private val p = Primitives(crypto)
    private val auth = Vectors.group("auth")
    private val url = auth.str("server_url")
    private val serverKey = Bytes.of(auth.hex("server_key"))
    private val devices: Map<String, JsonObject> = Vectors.group("identities").entrySet()
        .flatMap { (_, person) -> person.asJsonObject.getAsJsonObject("devices").entrySet().map { it.value.asJsonObject } }
        .associateBy { it.str("label") }

    private suspend fun server() = crypto.ed25519(auth.hex("server_seed"))

    /** Another server's key. */
    private suspend fun stranger() = crypto.ed25519(ByteArray(32) { 5 })

    @Test
    fun serverInfo() = sync {
        val raw = auth.hex("server_info")
        val info = ServerInfo.parse(raw)
        ServerInfo.check(p, raw, url, serverKey) // the vector passes
        assertEquals(Failure.WRONG_URL, refusal { ServerInfo.check(p, raw, "$url/", serverKey) })
        assertEquals(Failure.OTHER_KEY, refusal { ServerInfo.check(p, raw, url, Bytes.of(stranger().publicKey)) })
        val theirs = ServerInfo.sign(p, stranger(), url, info.issuedAt, info.expiresAt).encode()
        assertEquals(Failure.OTHER_KEY, refusal { ServerInfo.check(p, theirs, url, serverKey) }, "a statement signed by another server")
        assertEquals(Failure.BAD_SIGNATURE, refusal { ServerInfo.check(p, flip(raw, raw.size - 40), url, serverKey) })
        assertEquals(Failure.MALFORMED, refusal { ServerInfo.check(p, byteArrayOf(1) + raw.copyOfRange(1, raw.size), url, serverKey) })
        assertEquals(Failure.MALFORMED, refusal { ServerInfo.check(p, raw + byteArrayOf(0), url, serverKey) })
        assertEquals(Failure.MALFORMED, refusal { ServerInfo.check(p, raw.copyOf(raw.size - 1), url, serverKey) })
        // A URL that isn't UTF-8.
        val badUrl = ServerInfo(url, serverKey, info.issuedAt, info.expiresAt, info.sig).encode().also { it[3] = -1 }
        assertEquals(Failure.MALFORMED, refusal { ServerInfo.check(p, badUrl, url, serverKey) })
    }

    @Test
    fun serverMoves() = sync {
        val t = Vectors.root.getAsJsonArray("server_moves").map { it.asJsonObject }.first { it.str("name") == "new_address_and_key" }
        val raw = t.hex("move")
        val oldUrl = t.str("old_url")
        ServerMove.check(p, raw, oldUrl, serverKey)
        assertEquals(Failure.WRONG_URL, refusal { ServerMove.check(p, raw, "https://elsewhere.example", serverKey) })
        assertEquals(Failure.OTHER_KEY, refusal { ServerMove.check(p, raw, oldUrl, Bytes.of(stranger().publicKey)) })
        assertEquals(Failure.BAD_SIGNATURE, refusal { ServerMove.check(p, flip(raw, raw.size - 40), oldUrl, serverKey) })
        assertEquals(Failure.MALFORMED, refusal { ServerMove.check(p, byteArrayOf(1) + raw.copyOfRange(1, raw.size), oldUrl, serverKey) })
        assertEquals(Failure.MALFORMED, refusal { ServerMove.check(p, raw + byteArrayOf(0), oldUrl, serverKey) })
        // Signed by the old key, but naming another as the old key: still not the trusted server's.
        val unsigned = ServerMove.parse(raw)
        val forged = ServerMove(oldUrl, Bytes.of(stranger().publicKey), unsigned.newUrl, unsigned.newKey, unsigned.issuedAt, Bytes.zero(64))
        val forgedRaw = ServerMove(forged.oldUrl, forged.oldKey, forged.newUrl, forged.newKey, forged.issuedAt, Bytes.of(p.sign(server(), Label.SERVER_MOVE, forged.signedPart()))).encode()
        assertEquals(Failure.OTHER_KEY, refusal { ServerMove.check(p, forgedRaw, oldUrl, serverKey) })
    }

    @Test
    fun setupCodes() {
        val v = Vectors.group("setup")
        val raw = v.hex("setup")
        assertFailsWith<ProtocolException> { Setup.parse(byteArrayOf(1) + raw.copyOfRange(1, raw.size)) }
        assertFailsWith<ProtocolException> { Setup.parse(raw + byteArrayOf(0)) }
        assertFailsWith<ProtocolException> { Setup.parse(raw.copyOf(raw.size - 1)) }
        assertFailsWith<ProtocolException> { Setup.fromCode("KFI0" + v.str("code").substring(4)) }
        assertFailsWith<ProtocolException> { Setup.fromCode(v.str("code") + "=") }
    }

    @Test
    fun login() = sync {
        val challenge = auth.hex("challenge")
        val deviceId = Bytes.of(auth.hex("device_id"))
        val expiresAt = auth.get("expires_at").asLong.toULong()
        val sig = auth.hex("challenge_sig")
        assertTrue(Login.isChallengeSigned(p, serverKey, challenge, deviceId, expiresAt, sig))
        assertFalse(Login.isChallengeSigned(p, serverKey, challenge, Bytes.of(auth.hex("device_id").also { it[0] = 0 }), expiresAt, sig), "another device")
        assertFalse(Login.isChallengeSigned(p, serverKey, challenge, deviceId, expiresAt + 1UL, sig), "another expiry")
        assertFalse(Login.isChallengeSigned(p, Bytes.of(stranger().publicKey), challenge, deviceId, expiresAt, sig), "another server's key")
        val short = challenge.copyOf(31)
        val shortSig = p.sign(server(), Label.AUTH_CHALLENGE, Login.challengeSigned(short, deviceId, expiresAt))
        assertFalse(Login.isChallengeSigned(p, serverKey, short, deviceId, expiresAt, shortSig), "a challenge that isn't 32 bytes")
        val dsk = crypto.ed25519(devices.getValue(auth.str("device")).hex("dsk_seed"))
        assertFailsWith<IllegalArgumentException> { Login.deviceSig(p, dsk, serverKey, short, deviceId) }
        // The device's signature names the server, so another server can't use it.
        val sigHere = Login.deviceSig(p, dsk, serverKey, challenge, deviceId)
        assertFalse(p.verify(dsk.publicKey, Label.AUTH, concat(stranger().publicKey, challenge, deviceId.toByteArray()), sigHere))
    }

    private val w = Vectors.group("watch_grants")
    private val now = w.get("now").asLong.toULong()
    private val first = WatchGrant.parse(w.list("grants")[0].hex("grant"))

    /** The vector's first grant with any field replaced, signed by [signer]'s key. */
    private suspend fun grant(
        version: Int = 0,
        circle: Bytes = first.circleId,
        watched: String = "maya/phone",
        watcher: Bytes = first.watcherAccount,
        afterMin: Int = first.afterMin,
        issuedAt: ULong = first.issuedAt,
        notAfter: ULong = first.notAfter,
        signer: String = watched,
    ): WatchGrant {
        val id = Bytes.of(devices.getValue(watched).hex("device_id"))
        val unsigned = WatchGrant(version, circle, id, watcher, afterMin, issuedAt, notAfter, Bytes.zero(64))
        val sig = p.sign(crypto.ed25519(devices.getValue(signer).hex("dsk_seed")), Label.WATCH_GRANT, unsigned.signedPart())
        return WatchGrant(version, circle, id, watcher, afterMin, issuedAt, notAfter, Bytes.of(sig))
    }

    @Test
    fun watchGrants() = sync {
        val state = stateAt(w.int("log_seq"))
        suspend fun valid(g: WatchGrant, t: ULong = now) = g.isValidAt(p, state, t)
        assertTrue(valid(grant()), "the first grant, made again")
        assertFalse(valid(grant(version = 1)))
        assertFalse(valid(grant(circle = Bytes.of(ByteArray(16) { 1 }))))
        assertTrue(valid(grant(watched = "alex/tablet")), "a tablet")
        for (d in listOf("jordan/web", "jordan/ha", "jordan/recovery")) assertFalse(valid(grant(watched = d)), "$d isn't a phone or tablet")
        assertFalse(valid(grant(watched = "jordan/tablet")), "a device removed from the circle")
        assertFalse(valid(grant(watched = "sam/phone")), "a device never in the circle")
        val sam = Bytes.of(Vectors.group("identities").getAsJsonObject("sam").hex("account_id"))
        assertFalse(valid(grant(watcher = sam)), "a watcher who isn't a member")
        assertTrue(valid(grant(afterMin = 15)))
        assertTrue(valid(grant(afterMin = 1440)))
        assertFalse(valid(grant(afterMin = 14)))
        assertFalse(valid(grant(afterMin = 1441)))
        assertTrue(valid(grant(issuedAt = now + 600_000UL, notAfter = now + 700_000UL)), "issued 10 minutes ahead")
        assertFalse(valid(grant(issuedAt = now + 600_001UL, notAfter = now + 700_000UL)), "10 minutes and 1 ms ahead")
        assertTrue(valid(grant(), first.notAfter - 1UL), "the last moment")
        assertFalse(valid(grant(), first.notAfter), "ended")
        assertFalse(valid(grant(issuedAt = now + 1000UL, notAfter = now + 1000UL)), "ends as it is issued")
        assertTrue(valid(grant(notAfter = first.issuedAt + WatchGrant.MAX_LIFE_MS)), "35 days")
        assertFalse(valid(grant(notAfter = first.issuedAt + WatchGrant.MAX_LIFE_MS + 1UL)), "35 days and 1 ms")
        assertFalse(valid(grant(signer = "jordan/phone")), "signed by another device")
        assertFalse(valid(WatchGrant.parse(flip(grant().encode(), WatchGrant.SIZE - 40))), "a signature that doesn't verify")
        // Times at the top of the u64 range, where a sum would wrap.
        val top = ULong.MAX_VALUE
        assertTrue(valid(grant(issuedAt = top - 10UL, notAfter = top), top - 20UL))
        assertFalse(valid(grant(issuedAt = 5UL, notAfter = top), top - 20UL), "lasting far longer than 35 days")
    }

    private val pv = Vectors.group("push")
    private val wake = pv.list("valid").first { it.int("type") == Pushes.WAKE }
    private val me = Bytes.of(wake.hex("device_id"))
    private val pushNow = wake.get("now").asLong.toULong()

    private suspend fun myKeys(): Map<Bytes, HpkeKey> =
        wake.getAsJsonObject("keys").entrySet().associate { (kid, sk) -> Bytes.of(hexOf(kid)) to crypto.x25519(hexOf(sk.asString)) }

    private suspend fun myDek(): ByteArray = myKeys().values.single().publicKey

    /** A push signed by this device's server and sealed to it. */
    private suspend fun push(type: Int, body: ByteArray = ByteArray(0), sentAt: ULong = pushNow): ByteArray =
        Pushes.seal(p, Pushes.make(p, server(), me, type, sentAt, body), me, myDek())

    /** Any plaintext, sealed as a push is. */
    private suspend fun sealRaw(plaintext: ByteArray): ByteArray {
        val keyId = myKeys().keys.single()
        val sealed = p.seal(myDek(), p.h(Label.PUSH, me.toByteArray(), keyId.toByteArray()), plaintext)
        return concat(keyId.toByteArray(), sealed.enc, sealed.ciphertext)
    }

    private suspend fun open(sealed: ByteArray, keys: Map<Bytes, HpkeKey>? = null): PushReceipt =
        Pushes.open(p, sealed, me, keys ?: myKeys(), serverKey, pushNow)

    private suspend fun drop(sealed: ByteArray, keys: Map<Bytes, HpkeKey>? = null): Drop? = (open(sealed, keys) as? PushReceipt.Dropped)?.reason

    @Test
    fun pushes() = sync {
        assertIs<PushReceipt.Opened>(open(push(Pushes.WAKE)))
        assertEquals(Drop.WRONG_SIZE, drop(push(Pushes.WAKE) + byteArrayOf(0)))
        assertEquals(Drop.UNKNOWN_KEY, drop(push(Pushes.WAKE), emptyMap()))
        assertEquals(Drop.BAD_CIPHERTEXT, drop(flip(push(Pushes.WAKE), 100)))
        assertEquals(Drop.BAD_PADDING, drop(sealRaw(ByteArray(Pushes.PLAIN_SIZE))), "no padding")
        assertEquals(Drop.WRONG_SIZE, drop(sealRaw(Padding.padTo(byteArrayOf(1), Pushes.PLAIN_SIZE - 1))), "padded to another size")
        val unsignedWake = encode {
            u8(1)
            u8(Pushes.WAKE)
            u64(pushNow)
            vec16(ByteArray(0))
        }
        val v1 = concat(unsignedWake, p.sign(server(), Label.PUSH_SIG, me.toByteArray(), unsignedWake))
        assertEquals(Drop.MALFORMED, drop(sealRaw(Padding.padTo(v1, Pushes.PLAIN_SIZE))), "version 1")
        val good = Pushes.make(p, server(), me, Pushes.WAKE, pushNow, ByteArray(0))
        assertEquals(Drop.BAD_PADDING, drop(sealRaw(Padding.padTo(good, Pushes.PLAIN_SIZE).also { it[good.size] = 0x7f })), "no 0x80")
        assertEquals(Drop.MALFORMED, drop(sealRaw(Padding.padTo(good.copyOf(good.size - 1), Pushes.PLAIN_SIZE))), "a short signature")
        assertEquals(Drop.MALFORMED, drop(sealRaw(Padding.padTo(good + byteArrayOf(0), Pushes.PLAIN_SIZE))), "a byte after the signature")
        assertEquals(Drop.BAD_SIGNATURE, drop(Pushes.seal(p, Pushes.make(p, stranger(), me, Pushes.WAKE, pushNow, ByteArray(0)), me, myDek())))
        // Time, both ways.
        assertIs<PushReceipt.Opened>(open(push(Pushes.WAKE, sentAt = pushNow + 600_000UL)))
        assertIs<PushReceipt.Opened>(open(push(Pushes.WAKE, sentAt = pushNow - 600_000UL)))
        assertEquals(Drop.BAD_TIME, drop(push(Pushes.WAKE, sentAt = pushNow + 600_001UL)))
        assertEquals(Drop.BAD_TIME, drop(push(Pushes.WAKE, sentAt = pushNow - 600_001UL)))
        // Types and bodies.
        for (type in listOf(0, 4, 255)) assertEquals(Drop.UNKNOWN_TYPE, drop(push(type)), "type $type")
        assertEquals(Drop.MALFORMED, drop(push(Pushes.RECORDS)), "records with none")
        val envelope = byteArrayOf(9, 8, 7)
        val one = Pushes.recordsBody(listOf(PushMessage.Record(5UL, envelope)))
        val two = Pushes.recordsBody(listOf(PushMessage.Record(5UL, envelope), PushMessage.Record(6UL, ByteArray(0))))
        val got = (open(push(Pushes.RECORDS, two)) as PushReceipt.Opened).message as PushMessage.Records
        assertEquals(listOf(5UL, 6UL), got.records.map { it.receivedAt })
        assertContentEquals(envelope, got.records[0].envelope)
        assertEquals(Drop.MALFORMED, drop(push(Pushes.RECORDS, one + byteArrayOf(0))), "a byte after the last record")
        assertEquals(Drop.MALFORMED, drop(push(Pushes.RECORDS, byteArrayOf(0, 0, 0, 7) + ByteArray(7))), "a record shorter than its received_at")
        assertEquals(Drop.MALFORMED, drop(push(Pushes.RECORDS, byteArrayOf(0, 0, 0, 20) + ByteArray(8))), "a length past the end")
        val silence = Pushes.silenceBody(Bytes.of(ByteArray(16) { 1 }), Bytes.of(ByteArray(16) { 2 }), 7UL)
        val s = (open(push(Pushes.SILENCE, silence)) as PushReceipt.Opened).message as PushMessage.Silence
        assertEquals(7UL, s.lastSeenAt)
        assertEquals(Drop.MALFORMED, drop(push(Pushes.SILENCE, silence.copyOf(39))))
        assertEquals(Drop.MALFORMED, drop(push(Pushes.SILENCE, silence + byteArrayOf(0))))
        // The longest body fits; a longer one can't be made.
        assertIs<PushReceipt.Opened>(open(push(Pushes.RECORDS, Pushes.recordsBody(listOf(PushMessage.Record(1UL, ByteArray(Pushes.MAX_BODY - 12)))))))
        assertFailsWith<IllegalArgumentException> { Pushes.make(p, server(), me, Pushes.RECORDS, pushNow, ByteArray(Pushes.MAX_BODY + 1)) }
    }

    @Test
    fun relay() = sync {
        val r = pv.getAsJsonObject("relay")
        val cap = r.hex("capability")
        val sealed = r.hex("sealed")
        val sentAt = r.get("sent_at").asLong.toULong()
        assertTrue(Relay.isSigned(p, serverKey, cap, sealed, sentAt, r.int("delivery"), r.hex("sig")))
        assertFalse(Relay.isSigned(p, serverKey, cap, sealed, sentAt + 1UL, r.int("delivery"), r.hex("sig")))
        assertFalse(Relay.isSigned(p, Bytes.of(stranger().publicKey), cap, sealed, sentAt, r.int("delivery"), r.hex("sig")))
        for (d in listOf(0, 4)) {
            val sig = Relay.sign(p, server(), cap, sealed, sentAt, d)
            assertFalse(Relay.isSigned(p, serverKey, cap, sealed, sentAt, d, sig), "delivery $d")
        }
        val short = sealed.copyOf(sealed.size - 1)
        assertFalse(Relay.isSigned(p, serverKey, cap, short, sentAt, r.int("delivery"), Relay.sign(p, server(), cap, short, sentAt, r.int("delivery"))))
    }

    private suspend fun stateAt(seq: Int): CircleState =
        MemberLog.replay(p, Vectors.group("log").list("entries").take(seq + 1).map { it.hex("raw") }, null).first

    private fun hexOf(s: String): ByteArray = ca.gureet.kinfold.core.wire.hexBytes(s)

    private fun flip(b: ByteArray, i: Int): ByteArray = b.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }

    private suspend fun refusal(block: suspend () -> Unit): Failure {
        try {
            block()
        } catch (e: ServerException) {
            return e.failure
        }
        fail("not refused")
    }
}
