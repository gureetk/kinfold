// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.envelope

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.identity.Wrap
import ca.gureet.kinfold.core.log.Device
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Padding
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode

/** The 88-byte header of an envelope (PROTOCOL.md §7.1). */
class EnvelopeHeader(
    val kind: Int,
    val circleId: Bytes,
    val sender: Bytes,
    val seq: ULong,
    val sentAt: ULong,
    val ttlS: Long,
    val logHead: Bytes,
    val version: Int = Protocol.VERSION,
    val suite: Int = Protocol.SUITE,
) {
    fun encode(): ByteArray = encode {
        u8(version)
        u16(suite)
        u8(kind)
        bytes(circleId)
        bytes(sender)
        u64(seq)
        u64(sentAt)
        u32(ttlS)
        bytes(logHead)
    }

    companion object {
        const val SIZE = 88

        /** Kind 1: to every receiving device but the sender. */
        const val CIRCLE = 1

        /** Kind 2: to chosen receiving devices. */
        const val DIRECT = 2

        /** The time-to-live a server accepts, in seconds: a minute to 30 days. */
        val TTL_RANGE: LongRange = 60L..2_592_000L

        fun read(r: Reader): EnvelopeHeader {
            val version = r.u8()
            val suite = r.u16()
            return EnvelopeHeader(
                kind = r.u8(),
                circleId = Bytes.of(r.bytes(16)),
                sender = Bytes.of(r.bytes(16)),
                seq = r.u64(),
                sentAt = r.u64(),
                ttlS = r.u32(),
                logHead = Bytes.of(r.bytes(32)),
                version = version,
                suite = suite,
            )
        }
    }
}

/**
 * An envelope, parsed (§7.1): a header, wraps of the message secret, the encrypted payload and the
 * sender's signature. Parsing checks structure only; [Envelopes.open] runs the rest of §7.6.
 */
class Envelope private constructor(
    private val raw: ByteArray,
    val header: EnvelopeHeader,
    val wraps: List<Wrap>,
    val ciphertext: ByteArray,
    val sig: ByteArray,
    private val wrapsEnd: Int,
) {
    val bytes: ByteArray get() = raw.copyOf()

    internal val headerBytes: ByteArray get() = raw.copyOfRange(0, EnvelopeHeader.SIZE)

    /** Everything the signature covers. */
    internal val signedPart: ByteArray get() = raw.copyOfRange(0, raw.size - 64)

    /** The header and `vec32(wraps)`: what the payload's associated data hashes. */
    internal val wrapsPart: ByteArray get() = raw.copyOfRange(0, wrapsEnd)

    companion object {
        /** Step 1 of §7.6: the envelope's structure, or `malformed`. */
        fun parse(raw: ByteArray): Envelope {
            val r = Reader(raw)
            val header = EnvelopeHeader.read(r)
            val wraps = Wrap.parseList(r.vec32())
            val wrapsEnd = r.position
            val ciphertext = r.vec32()
            val sig = r.bytes(64)
            r.finish()
            return Envelope(raw.copyOf(), header, wraps, ciphertext, sig, wrapsEnd)
        }

        /**
         * Builds an envelope (§7.3, §7.5) with a fresh message secret: [payload], padded, for the
         * [recipients], which must be receiving devices taken from the verified log, each with its
         * current key. The sender must store `header.seq` as used before posting the result.
         */
        suspend fun seal(
            p: Primitives,
            sender: SigningKey,
            header: EnvelopeHeader,
            recipients: List<Device>,
            payload: ByteArray,
        ): ByteArray {
            val secret = p.random(32)
            val hdr = header.encode()
            val wraps = recipients.sortedBy { it.id }.map { d ->
                val bundle = requireNotNull(d.bundle) { "a recipient must be a receiving device with a key" }
                val keyId = requireNotNull(d.keyId)
                Wrap.seal(p, d.id, keyId, bundle.dekPub.toByteArray(), wrapInfo(p, hdr, d.id, keyId), secret)
            }
            require(wraps.size in 1..Envelopes.MAX_WRAPS) { "an envelope carries 1 to 255 wraps" }
            require(wraps.zipWithNext().all { (a, b) -> a.recipient < b.recipient }) { "a device is named twice" }
            val wrapsPart = encode {
                bytes(hdr)
                vec32(Wrap.encodeList(wraps))
            }
            val (key, nonce) = payloadKeys(p, secret)
            val ct = p.crypto.aesGcmSeal(key, nonce, Padding.pad(payload), p.h(Label.ENV_AAD, wrapsPart))
            val body = encode {
                bytes(wrapsPart)
                vec32(ct)
            }
            return concat(body, p.sign(sender, Label.ENVELOPE, body))
        }

        /** `info` for one envelope wrap (§7.3). */
        internal suspend fun wrapInfo(p: Primitives, header: ByteArray, recipient: Bytes, keyId: Bytes): ByteArray =
            p.h(Label.WRAP, header, recipient.toByteArray(), keyId.toByteArray())

        /** The payload key and nonce derived from a message secret (§7.3). */
        internal suspend fun payloadKeys(p: Primitives, secret: ByteArray): Pair<ByteArray, ByteArray> =
            p.kdf(secret, Label.PAYLOAD_KEY, 32) to p.kdf(secret, Label.PAYLOAD_NONCE, 12)
    }
}
