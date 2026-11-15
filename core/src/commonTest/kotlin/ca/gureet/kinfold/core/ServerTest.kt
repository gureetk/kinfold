// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.HpkeKey
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.log.MemberLog
import ca.gureet.kinfold.core.push.PushMessage
import ca.gureet.kinfold.core.push.PushReceipt
import ca.gureet.kinfold.core.push.Pushes
import ca.gureet.kinfold.core.push.Relay
import ca.gureet.kinfold.core.push.WatchGrant
import ca.gureet.kinfold.core.server.Login
import ca.gureet.kinfold.core.server.ServerException
import ca.gureet.kinfold.core.server.ServerInfo
import ca.gureet.kinfold.core.server.ServerMove
import ca.gureet.kinfold.core.server.Setup
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Codes
import ca.gureet.kinfold.core.wire.hexBytes
import ca.gureet.kinfold.core.wire.toHex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The `setup`, `server_moves`, `auth`, `watch_grants` and `push` vectors (PROTOCOL.md §13, §14):
 * every structure parsed and written again, every signature checked and made again, every grant
 * judged as a server judges it, and every push opened or dropped as a device does.
 */
class ServerTest {
    private val crypto = platformCrypto()
    private val p = Primitives(crypto)
    private val devices: Map<String, JsonObject> = Vectors.group("identities").entrySet()
        .flatMap { (_, person) -> person.asJsonObject.getAsJsonObject("devices").entrySet().map { it.value.asJsonObject } }
        .associateBy { it.str("label") }

    @Test
    fun setup() {
        val v = Vectors.group("setup")
        val setup = Setup.fromCode(v.str("code"))
        assertEquals(v.str("server_url"), setup.serverUrl)
        assertEquals(v.str("server_key"), setup.serverKey.hex)
        assertEquals(v.str("reg_token"), setup.regToken.hex)
        assertEquals(v.get("expires_at").asLong.toULong(), setup.expiresAt)
        assertContentEquals(v.hex("setup"), setup.encode(), "written again byte for byte")
        assertContentEquals(v.hex("setup"), Codes.read(Codes.SETUP, v.str("code")))
        assertEquals(v.str("code"), setup.code)
    }

    @Test
    fun serverMoves() = sync {
        val cases = Vectors.root.getAsJsonArray("server_moves").map { it.asJsonObject }
        assertEquals(setOf(true, false), cases.map { it.get("valid").asBoolean }.toSet())
        for (t in cases) {
            val name = t.str("name")
            val raw = t.hex("move")
            val move = ServerMove.parse(raw)
            assertEquals(t.str("old_url"), move.oldUrl, name)
            assertEquals(t.str("old_key"), move.oldKey.hex, name)
            assertEquals(t.str("new_url"), move.newUrl, name)
            assertEquals(t.str("new_key"), move.newKey.hex, name)
            assertEquals(t.get("issued_at").asLong.toULong(), move.issuedAt, name)
            assertContentEquals(raw, move.encode(), name)
            assertEquals(t.get("valid").asBoolean, move.isSigned(p), name)
            // What a client that trusts the old server does with it.
            val checked = runCatching { ServerMove.check(p, raw, t.str("old_url"), Bytes.of(t.hex("old_key"))) }
            if (t.get("valid").asBoolean) {
                assertEquals(move.newKey, checked.getOrThrow().newKey, name)
            } else {
                assertEquals(ServerException.Failure.BAD_SIGNATURE, (checked.exceptionOrNull() as? ServerException)?.failure, name)
            }
        }
        // The valid notice made again with the server's key, whose seed the auth vectors hold.
        val auth = Vectors.group("auth")
        val server = crypto.ed25519(auth.hex("server_seed"))
        val t = cases.first { it.str("name") == "new_address_and_key" }
        assertEquals(auth.str("server_key"), t.str("old_key"))
        val again = ServerMove.sign(p, server, t.str("old_url"), t.str("new_url"), Bytes.of(t.hex("new_key")), t.get("issued_at").asLong.toULong())
        assertContentEquals(t.hex("move"), again.encode())
    }

    @Test
    fun auth() = sync {
        val v = Vectors.group("auth")
        val serverKey = Bytes.of(v.hex("server_key"))
        val raw = v.hex("server_info")
        val info = ServerInfo.check(p, raw, v.str("server_url"), serverKey)
        assertContentEquals(raw, info.encode())
        val server = crypto.ed25519(v.hex("server_seed"))
        assertEquals(serverKey, Bytes.of(server.publicKey))
        assertContentEquals(raw, ServerInfo.sign(p, server, info.serverUrl, info.issuedAt, info.expiresAt).encode(), "signed again")
        assertEquals(v.str("fingerprint"), ServerInfo.fingerprint(p, serverKey))
        // Login: the device checks the challenge, then signs.
        val challenge = v.hex("challenge")
        val deviceId = Bytes.of(v.hex("device_id"))
        val expiresAt = v.get("expires_at").asLong.toULong()
        assertTrue(Login.isChallengeSigned(p, serverKey, challenge, deviceId, expiresAt, v.hex("challenge_sig")))
        val dev = devices.getValue(v.str("device"))
        assertEquals(dev.str("device_id"), deviceId.hex)
        val sig = Login.deviceSig(p, crypto.ed25519(dev.hex("dsk_seed")), serverKey, challenge, deviceId)
        assertEquals(v.str("device_sig"), sig.toHex())
        assertContentEquals(v.hex("challenge_sig"), p.sign(server, Label.AUTH_CHALLENGE, Login.challengeSigned(challenge, deviceId, expiresAt)))
    }

    @Test
    fun watchGrants() = sync {
        val w = Vectors.group("watch_grants")
        val state = stateAt(w.int("log_seq"))
        val now = w.get("now").asLong.toULong()
        val cases = w.list("grants")
        assertEquals(15, cases.size)
        for (t in cases) {
            val raw = t.hex("grant")
            val g = WatchGrant.parse(raw)
            assertContentEquals(raw, g.encode(), t.str("name"))
            assertEquals(t.get("valid").asBoolean, g.isValidAt(p, state, now), t.str("name"))
        }
        val f = w.getAsJsonObject("fields")
        val g = WatchGrant.parse(cases[0].hex("grant"))
        assertEquals(f.str("circle_id"), g.circleId.hex)
        assertEquals(f.str("watched_device_id"), g.watchedDevice.hex)
        assertEquals(f.str("watcher_account_id"), g.watcherAccount.hex)
        assertEquals(f.int("after_min"), g.afterMin)
        assertEquals(f.get("issued_at").asLong.toULong(), g.issuedAt)
        assertEquals(f.get("not_after").asLong.toULong(), g.notAfter)
        // The first grant issued again by the watched phone.
        val phone = devices.values.first { it.str("device_id") == g.watchedDevice.hex }
        val again = WatchGrant.issue(p, crypto.ed25519(phone.hex("dsk_seed")), g.circleId, g.watchedDevice, g.watcherAccount, g.afterMin, g.issuedAt, g.notAfter)
        assertContentEquals(cases[0].hex("grant"), again.encode())
    }

    @Test
    fun pushes() = sync {
        val v = Vectors.group("push")
        val serverKey = Bytes.of(v.hex("server_key"))
        val server = crypto.ed25519(Vectors.group("auth").hex("server_seed"))
        assertEquals(serverKey, Bytes.of(server.publicKey))
        val valid = v.list("valid")
        assertEquals(listOf(Pushes.WAKE, Pushes.RECORDS, Pushes.SILENCE), valid.map { it.int("type") })
        for (t in valid) {
            val name = t.str("name")
            val deviceId = Bytes.of(t.hex("device_id"))
            val sealed = t.hex("sealed")
            assertEquals(Pushes.SEALED_SIZE, sealed.size, name)
            val got = Pushes.open(p, sealed, deviceId, keys(t.getAsJsonObject("keys")), serverKey, t.get("now").asLong.toULong())
            assertIs<PushReceipt.Opened>(got, "$name: ${(got as? PushReceipt.Dropped)?.reason}")
            val m = got.message
            assertEquals(t.get("sent_at").asLong.toULong(), m.sentAt, name)
            when (m) {
                is PushMessage.Wake -> assertEquals("", t.str("body"), name)
                is PushMessage.Records -> assertContentEquals(t.hex("body"), Pushes.recordsBody(m.records), name)
                is PushMessage.Silence -> assertContentEquals(t.hex("body"), Pushes.silenceBody(m.circleId, m.watchedDevice, m.lastSeenAt), name)
            }
            // Made again with the server's key, and sealed again here: the device opens the same.
            val push = Pushes.make(p, server, deviceId, t.int("type"), m.sentAt, hexBytes(t.str("body")))
            assertContentEquals(t.hex("push"), push, name)
            val (keyId, sk) = t.getAsJsonObject("keys").entrySet().single().let { it.key to it.value.asString }
            val resealed = Pushes.seal(p, push, deviceId, crypto.x25519(hexBytes(sk)).publicKey)
            assertEquals(keyId, resealed.copyOf(8).toHex(), name)
            val again = Pushes.open(p, resealed, deviceId, keys(t.getAsJsonObject("keys")), serverKey, t.get("now").asLong.toULong())
            assertEquals(m.sentAt, (again as PushReceipt.Opened).message.sentAt, name)
        }
        val expected = mapOf(
            "other_server" to PushReceipt.Drop.BAD_SIGNATURE,
            "for_another_device" to PushReceipt.Drop.BAD_SIGNATURE,
            "stale" to PushReceipt.Drop.BAD_TIME,
            "wrong_size" to PushReceipt.Drop.WRONG_SIZE,
            "unknown_type" to PushReceipt.Drop.UNKNOWN_TYPE,
            "wake_with_body" to PushReceipt.Drop.MALFORMED,
        )
        val invalid = v.list("invalid")
        assertEquals(expected.keys, invalid.map { it.str("name") }.toSet())
        for (t in invalid) {
            val got = Pushes.open(p, t.hex("sealed"), Bytes.of(t.hex("device_id")), keys(t.getAsJsonObject("keys")), serverKey, t.get("now").asLong.toULong())
            assertEquals(expected[t.str("name")], (got as? PushReceipt.Dropped)?.reason ?: fail("${t.str("name")}: opened"), t.str("name"))
        }
        // The relay signature holds for its own delivery type and no other.
        val r = v.getAsJsonObject("relay")
        val sentAt = r.get("sent_at").asLong.toULong()
        for (d in Relay.ALERT..Relay.LOCATION) {
            assertEquals(d == r.int("delivery"), Relay.isSigned(p, serverKey, r.hex("capability"), r.hex("sealed"), sentAt, d, r.hex("sig")), "delivery $d")
        }
        assertContentEquals(r.hex("sig"), Relay.sign(p, server, r.hex("capability"), r.hex("sealed"), sentAt, r.int("delivery")))
    }

    private val entries = Vectors.group("log").list("entries")

    /** The main log through [seq], in public mode: a grant's validity needs nothing private. */
    private suspend fun stateAt(seq: Int): CircleState = MemberLog.replay(p, entries.take(seq + 1).map { it.hex("raw") }, null).first

    private suspend fun keys(o: JsonObject): Map<Bytes, HpkeKey> =
        o.entrySet().associate { (kid, sk) -> Bytes.of(hexBytes(kid)) to crypto.x25519(hexBytes(sk.asString)) }
}
