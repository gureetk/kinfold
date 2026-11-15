// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.HpkeKey
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.envelope.Envelope
import ca.gureet.kinfold.core.envelope.EnvelopeHeader
import ca.gureet.kinfold.core.envelope.Envelopes
import ca.gureet.kinfold.core.envelope.MemoryReplayRecord
import ca.gureet.kinfold.core.envelope.Receipt
import ca.gureet.kinfold.core.envelope.ReplayRecord
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.log.MemberLog
import ca.gureet.kinfold.core.payload.Approx
import ca.gureet.kinfold.core.payload.EpochSecrets
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.payload.PositionE7
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Padding
import ca.gureet.kinfold.core.wire.hexBytes
import ca.gureet.kinfold.core.wire.toHex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The `envelopes` and `approx` vectors (PROTOCOL.md §7, §8): every valid envelope opened by each
 * recipient, every invalid one refused for the vector's reason, the server's checks, replays, and a
 * device whose private state is frozen.
 */
class EnvelopeTest {
    private val crypto = platformCrypto()
    private val p = Primitives(crypto)
    private val e = Vectors.group("envelopes")
    private val now = e.get("receiver_now").asLong.toULong()
    private val entries = Vectors.group("log").list("entries")
    private val secrets: Map<Long, ByteArray> =
        Vectors.group("log").getAsJsonObject("epoch_secrets").entrySet().associate { it.key.toLong() to hexBytes(it.value.asString) }
    private val states = mutableMapOf<Int, CircleState>()

    /** Each device's vector object, by its label (`person/device`). */
    private val devices: Map<String, JsonObject> = Vectors.group("identities").entrySet()
        .flatMap { (_, person) -> person.asJsonObject.getAsJsonObject("devices").entrySet().map { it.value.asJsonObject } }
        .associateBy { it.str("label") }

    @Test
    fun valid() = sync {
        val cases = e.list("valid")
        assertEquals(24, cases.size)
        for (t in cases) {
            val name = t.str("name")
            val state = stateAt(t.int("log_seq"))
            val raw = t.hex("raw")
            val want = objOf(t.getAsJsonObject("payload"))
            for (r in t.list("recipients")) {
                val got = open(raw, state, r.hex("device_id"), r.getAsJsonObject("keys"))
                assertIs<Receipt.Accepted>(got, "$name -> ${r.str("device")}: ${(got as? Receipt.Refused)?.reason}")
                assertEquals(want, got.payload, "$name -> ${r.str("device")}")
            }
            assertNull(Envelopes.serverRefusal(p, raw, state, now), "$name: a server stores it")
            assertEquals(t.int("padded_length"), Padding.pad(t.hex("payload_bytes")).size, "$name: bucket")
        }
    }

    @Test
    fun invalid() = sync {
        val cases = e.list("invalid")
        assertEquals(45, cases.size)
        for (t in cases) {
            val name = t.str("name")
            val state = stateAt(t.int("log_seq"))
            val raw = t.hex("raw")
            val got = open(raw, state, t.hex("receiver_device_id"), t.getAsJsonObject("receiver_keys"))
            assertEquals(t.str("error"), (got as? Receipt.Refused)?.reason?.code, name)
            val serverError = t.get("server_error").takeUnless { it.isJsonNull }?.asString
            assertEquals(serverError, Envelopes.serverRefusal(p, raw, state, now)?.code, "$name (server)")
        }
    }

    @Test
    fun serverRejects() = sync {
        val cases = e.list("server_rejects")
        assertEquals(6, cases.size)
        for (t in cases) {
            val name = t.str("name")
            val state = stateAt(t.int("log_seq"))
            val raw = t.hex("raw")
            assertEquals(t.str("server_error"), Envelopes.serverRefusal(p, raw, state, now)?.code, "$name (server)")
            val got = open(raw, state, t.hex("receiver_device_id"), t.getAsJsonObject("receiver_keys"))
            assertIs<Receipt.Accepted>(got, "$name: the receiver opens it")
            assertEquals(objOf(t.getAsJsonObject("payload")), got.payload, name)
        }
    }

    @Test
    fun replay() = sync {
        val t = e.getAsJsonObject("replay")
        val state = stateAt(t.int("log_seq"))
        val record = MemoryReplayRecord()
        val got = t.getAsJsonArray("sequence").map { raw ->
            when (val r = open(hexBytes(raw.asString), state, t.hex("receiver_device_id"), t.getAsJsonObject("receiver_keys"), record)) {
                is Receipt.Accepted -> "ok"
                is Receipt.Refused -> r.reason.code
                is Receipt.Held -> "held"
            }
        }
        assertEquals(t.getAsJsonArray("results").map { it.asString }, got)
    }

    /** Beyond the vector file: a frozen device holds payloads whose sender rule needs roles, and only those. */
    @Test
    fun frozenState() = sync {
        val frozen = MemberLog.replay(p, entries.map { it.hex("raw") }, mapOf(0L to secrets.getValue(0L))).first
        assertNotNull(frozen.privateUnknownFrom)
        val byName = (e.list("valid") + e.list("invalid")).associateBy { it.str("name") }
        suspend fun openFrozen(name: String): Receipt {
            val t = byName.getValue(name)
            val r = t.optArray("recipients")?.first()?.asJsonObject
            return if (r != null) {
                open(t.hex("raw"), frozen, r.hex("device_id"), r.getAsJsonObject("keys"))
            } else {
                open(t.hex("raw"), frozen, t.hex("receiver_device_id"), t.getAsJsonObject("receiver_keys"))
            }
        }
        for (name in listOf("f9", "f8", "not_allowed_pause_request_from_adult", "not_allowed_place_id_mismatch")) {
            assertIs<Receipt.Held>(openFrozen(name), "held while frozen: $name")
        }
        for (name in listOf("f1", "f5", "f6", "f7", "f10")) {
            val got = openFrozen(name)
            assertIs<Receipt.Accepted>(got, "opened while frozen: $name")
            assertEquals(objOf(byName.getValue(name).getAsJsonObject("payload")), got.payload, name)
        }
        assertEquals(Reason.NOT_ALLOWED, (openFrozen("not_allowed_web_sends_location") as? Receipt.Refused)?.reason)
    }

    /**
     * Every valid envelope sealed again with a fresh secret and fresh HPKE keys (Tink can't fix
     * the ephemeral key, so this can't be byte for byte), then opened by each recipient.
     */
    @Test
    fun sealAndOpen() = sync {
        for (t in e.list("valid")) {
            val name = t.str("name")
            val state = stateAt(t.int("log_seq"))
            val sender = devices.getValue(t.str("sender"))
            val original = Envelope.parse(t.hex("raw"))
            val header = EnvelopeHeader(
                kind = t.int("kind"),
                circleId = checkNotNull(state.circleId),
                sender = Bytes.of(sender.hex("device_id")),
                seq = t.get("seq").asLong.toULong(),
                sentAt = t.get("sent_at").asLong.toULong(),
                ttlS = t.get("ttl_s").asLong,
                logHead = Bytes.of(t.hex("log_head")),
            )
            val recipients = original.wraps.map { checkNotNull(state.device(it.recipient)) }
            val raw = Envelope.seal(p, crypto.ed25519(sender.hex("dsk_seed")), header, recipients, t.hex("payload_bytes"))
            assertEquals(t.hex("raw").size, raw.size, "$name: size")
            assertContentEquals(t.hex("raw").copyOf(EnvelopeHeader.SIZE), raw.copyOf(EnvelopeHeader.SIZE), "$name: header")
            for (r in t.list("recipients")) {
                val got = open(raw, state, r.hex("device_id"), r.getAsJsonObject("keys"))
                assertIs<Receipt.Accepted>(got, "$name -> ${r.str("device")}: ${(got as? Receipt.Refused)?.reason}")
                assertEquals(objOf(t.getAsJsonObject("payload")), got.payload, name)
            }
            assertNull(Envelopes.serverRefusal(p, raw, state, now), "$name: a server stores it")
        }
    }

    /** A circle envelope built from the log as it stands is one a server stores, at either log position. */
    @Test
    fun circleEnvelopeFromTheLog() = sync {
        for (seq in listOf(13, 20)) {
            val state = stateAt(seq)
            val sender = devices.getValue("maya/phone")
            val id = Bytes.of(sender.hex("device_id"))
            val header = EnvelopeHeader(EnvelopeHeader.CIRCLE, checkNotNull(state.circleId), id, 7UL, now, 3600, state.head)
            val payload = """{"t":"hb","ts":${now.toLong()},"flags":["sharing"]}""".encodeToByteArray()
            val recipients = Envelopes.circleRecipients(state, id)
            val raw = Envelope.seal(p, crypto.ed25519(sender.hex("dsk_seed")), header, recipients, payload)
            assertNull(Envelopes.serverRefusal(p, raw, state, now), "at seq $seq")
            assertEquals(state.receivingDevices().size - 1, Envelope.parse(raw).wraps.size)
        }
    }

    /** The secrets in the `welcome` and `refresh` vectors, checked against the log (§8.5). */
    @Test
    fun epochSecrets() = sync {
        val byName = e.list("valid").associateBy { it.str("name") }
        for (name in listOf("f4", "f5")) {
            val t = byName.getValue(name)
            val payload = objOf(t.getAsJsonObject("payload"))
            val got = EpochSecrets.from(p, stateAt(t.int("log_seq")), payload)
            assertIs<EpochSecrets.Received.Secrets>(got, name)
            assertEquals(secrets.mapValues { it.value.toHex() }, got.byEpoch.mapValues { it.value.toHex() }, name)
            // A secret that doesn't match its commitment is discarded; the others still count.
            val epochs = (payload["epochs"] as Json.Arr).items.toMutableList()
            epochs[1] = Json.Str(Base64Url.encode(ByteArray(32) { 7 }))
            val tampered = EpochSecrets.from(p, stateAt(20), Json.Obj(payload.fields + ("epochs" to Json.Arr(epochs))))
            assertIs<EpochSecrets.Received.Secrets>(tampered, name)
            assertEquals(setOf(0L, 2L), tampered.byEpoch.keys, name)
            // A head this device hasn't verified yet: fetch the log first.
            assertEquals(EpochSecrets.Received.HeadUnknown, EpochSecrets.from(p, stateAt(13), payload), name)
        }
    }

    @Test
    fun approx() {
        val cases = Vectors.root.getAsJsonArray("approx").map { it.asJsonObject }
        for (a in cases) {
            val want = PositionE7(a.get("approx_lat").asLong, a.get("approx_lon").asLong)
            assertEquals(want, Approx.snap(PositionE7(a.get("lat").asLong, a.get("lon").asLong)), a.toString())
        }
    }

    private suspend fun open(raw: ByteArray, state: CircleState, me: ByteArray, keys: JsonObject, record: ReplayRecord = MemoryReplayRecord()): Receipt =
        Envelopes.open(p, raw, state, Bytes.of(me), keys(keys), record, now)

    private suspend fun keys(o: JsonObject): Map<Bytes, HpkeKey> =
        o.entrySet().associate { (kid, sk) -> Bytes.of(hexBytes(kid)) to crypto.x25519(hexBytes(sk.asString)) }

    /** The main log through [seq], with every epoch secret: the receiver's log in these vectors. */
    private suspend fun stateAt(seq: Int): CircleState =
        states.getOrPut(seq) { MemberLog.replay(p, entries.take(seq + 1).map { it.hex("raw") }, secrets).first }

}
