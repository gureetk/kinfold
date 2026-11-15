// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.push

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.crypto.HpkeKey
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.identity.Ids
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Padding
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed
import ca.gureet.kinfold.core.wire.readAll

/** A push a device opened (PROTOCOL.md §14.2). */
sealed class PushMessage(val sentAt: ULong) {
    /** Connect and fetch the inbox. */
    class Wake(sentAt: ULong) : PushMessage(sentAt)

    /** Delivery records, to handle as if fetched from the inbox. */
    class Records(sentAt: ULong, val records: List<Record>) : PushMessage(sentAt)

    /** A watched device has gone quiet: show the silence alert. */
    class Silence(sentAt: ULong, val circleId: Bytes, val watchedDevice: Bytes, val lastSeenAt: ULong) : PushMessage(sentAt)

    /** One delivery record (API.md §7): when the server received the envelope, and the envelope. */
    class Record(val receivedAt: ULong, val envelope: ByteArray)
}

/** What became of a push: opened, or dropped without telling anyone, for a reason that is only for logs. */
sealed interface PushReceipt {
    class Opened(val message: PushMessage) : PushReceipt

    class Dropped(val reason: Drop) : PushReceipt

    enum class Drop {
        /** Not 2,616 bytes. */
        WRONG_SIZE,

        /** Sealed to a key the device doesn't hold. */
        UNKNOWN_KEY,

        /** Doesn't open. */
        BAD_CIPHERTEXT,

        /** Doesn't unpad to a push. */
        BAD_PADDING,

        /** Doesn't parse, is of another version, or has a body that doesn't fit its type. */
        MALFORMED,

        /** Not signed by the device's server for this device. */
        BAD_SIGNATURE,

        /** Sent more than 10 minutes from the device's trusted time. */
        BAD_TIME,

        /** A type the device doesn't know. */
        UNKNOWN_TYPE,
    }
}

/**
 * Push messages (§14.2): what a server sends by any route other than the device's own connection,
 * signed by the server, sealed to the device, and always the same size, so that the relay, Apple or
 * a UnifiedPush distributor can't tell one kind from another.
 */
object Pushes {
    const val WAKE = 1
    const val RECORDS = 2
    const val SILENCE = 3

    /** A push padded before it is sealed. */
    const val PLAIN_SIZE = 2560

    /** `key_id[8] ‖ enc[32] ‖ ct`, every time. */
    const val SEALED_SIZE = 2616

    const val MAX_BODY = 2483

    /** How far a push's `sent_at` may be from the device's trusted time. */
    const val SKEW_MS: ULong = 600_000UL

    /**
     * What a device does with [sealed], at its trusted time [now] (§8.4): opens it with the key
     * [keys] holds for its key ID, checks that its server's key [serverKey] signed it for this
     * device [deviceId] within 10 minutes of [now], and checks that the body fits the type.
     */
    suspend fun open(
        p: Primitives,
        sealed: ByteArray,
        deviceId: Bytes,
        keys: Map<Bytes, HpkeKey>,
        serverKey: Bytes,
        now: ULong,
    ): PushReceipt {
        if (sealed.size != SEALED_SIZE) return dropped(PushReceipt.Drop.WRONG_SIZE)
        val keyId = Bytes.of(sealed.copyOf(8))
        val key = keys[keyId] ?: return dropped(PushReceipt.Drop.UNKNOWN_KEY)
        val padded = key.open(sealed.copyOfRange(8, 40), info(p, deviceId, keyId), sealed.copyOfRange(40, sealed.size))
            ?: return dropped(PushReceipt.Drop.BAD_CIPHERTEXT)
        val push = Padding.unpadExact(padded, PLAIN_SIZE) ?: return dropped(PushReceipt.Drop.BAD_PADDING)
        val parsed = try {
            readAll(push) {
                val version = u8()
                val type = u8()
                val sentAt = u64()
                val body = vec16()
                val signedSize = position
                Parsed(version, type, sentAt, body, signedSize, bytes(64))
            }
        } catch (_: ProtocolException) {
            return dropped(PushReceipt.Drop.MALFORMED)
        }
        if (parsed.version != Protocol.VERSION) return dropped(PushReceipt.Drop.MALFORMED)
        val signed = concat(deviceId.toByteArray(), push.copyOf(parsed.signedSize))
        if (!p.verify(serverKey.toByteArray(), Label.PUSH_SIG, signed, parsed.sig)) return dropped(PushReceipt.Drop.BAD_SIGNATURE)
        val apart = if (parsed.sentAt > now) parsed.sentAt - now else now - parsed.sentAt
        if (apart > SKEW_MS) return dropped(PushReceipt.Drop.BAD_TIME)
        val message = try {
            message(parsed.type, parsed.sentAt, parsed.body)
        } catch (_: ProtocolException) {
            return dropped(PushReceipt.Drop.MALFORMED)
        } ?: return dropped(PushReceipt.Drop.UNKNOWN_TYPE)
        return PushReceipt.Opened(message)
    }

    /** The push itself, before sealing: `u8 version ‖ u8 type ‖ u64 sent_at ‖ vec16 body ‖ sig`. */
    suspend fun make(p: Primitives, server: SigningKey, recipient: Bytes, type: Int, sentAt: ULong, body: ByteArray): ByteArray {
        require(body.size <= MAX_BODY) { "a push body is at most $MAX_BODY bytes" }
        val unsigned = encode {
            u8(Protocol.VERSION)
            u8(type)
            u64(sentAt)
            vec16(body)
        }
        return concat(unsigned, p.sign(server, Label.PUSH_SIG, recipient.toByteArray(), unsigned))
    }

    /** [push], padded to 2,560 bytes and sealed to the device's key [dekPub]: always 2,616 bytes. */
    suspend fun seal(p: Primitives, push: ByteArray, deviceId: Bytes, dekPub: ByteArray): ByteArray {
        val keyId = Ids.key(p, dekPub)
        val sealed = p.seal(dekPub, info(p, deviceId, keyId), Padding.padTo(push, PLAIN_SIZE))
        return concat(keyId.toByteArray(), sealed.enc, sealed.ciphertext)
    }

    /** A `records` body: each record as `u32 length ‖ u64 received_at ‖ envelope`. */
    fun recordsBody(records: List<PushMessage.Record>): ByteArray = encode {
        for (r in records) {
            u32(8L + r.envelope.size)
            u64(r.receivedAt)
            bytes(r.envelope)
        }
    }

    /** A `silence` body: `circle_id ‖ watched_device_id ‖ u64 last_seen_at`. */
    fun silenceBody(circleId: Bytes, watchedDevice: Bytes, lastSeenAt: ULong): ByteArray = encode {
        bytes(circleId)
        bytes(watchedDevice)
        u64(lastSeenAt)
    }

    /** The message of a known [type], or null; `malformed` when the body doesn't fit the type. */
    private fun message(type: Int, sentAt: ULong, body: ByteArray): PushMessage? = when (type) {
        WAKE -> if (body.isEmpty()) PushMessage.Wake(sentAt) else malformed()
        RECORDS -> PushMessage.Records(sentAt, records(body))
        SILENCE -> readAll(body) { PushMessage.Silence(sentAt, Bytes.of(bytes(16)), Bytes.of(bytes(16)), u64()) }
        else -> null
    }

    /** One or more records, each at least the 8 bytes of its `received_at`. */
    private fun records(body: ByteArray): List<PushMessage.Record> {
        val r = Reader(body)
        val out = ArrayList<PushMessage.Record>()
        while (r.remaining > 0) {
            val record = r.vec32()
            readAll(record) { out.add(PushMessage.Record(u64(), bytes(remaining))) }
        }
        if (out.isEmpty()) malformed()
        return out
    }

    private suspend fun info(p: Primitives, deviceId: Bytes, keyId: Bytes): ByteArray =
        p.h(Label.PUSH, deviceId.toByteArray(), keyId.toByteArray())

    private fun dropped(reason: PushReceipt.Drop): PushReceipt = PushReceipt.Dropped(reason)

    private class Parsed(val version: Int, val type: Int, val sentAt: ULong, val body: ByteArray, val signedSize: Int, val sig: ByteArray)
}
