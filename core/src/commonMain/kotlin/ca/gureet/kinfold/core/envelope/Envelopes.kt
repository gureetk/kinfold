// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.envelope

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.crypto.HpkeKey
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.log.Device
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Padding

/** What became of an envelope a device received (PROTOCOL.md §7.6). */
sealed class Receipt {
    /** Every check passed: act on [payload]. The pair (sender, seq) is now in the replay record. */
    class Accepted(val envelope: Envelope, val sender: Device, val payload: Json.Obj) : Receipt()

    /**
     * Every check up to step 15 passed, but the sender rule for this payload needs roles, and this
     * device's private state is frozen (§6.5). Keep the envelope and open it again once caught up.
     */
    class Held(val envelope: Envelope) : Receipt()

    /** Discarded, for [reason]. */
    class Refused(val reason: Reason) : Receipt()
}

/**
 * The pairs (sender device, seq) a device has accepted in one circle (§7.6, step 9). A device
 * keeps each pair for at least 31 days after the envelope's `sent_at`.
 */
interface ReplayRecord {
    fun contains(sender: Bytes, seq: ULong): Boolean

    fun add(sender: Bytes, seq: ULong, sentAt: ULong)
}

/** A [ReplayRecord] in memory, which never forgets. */
class MemoryReplayRecord : ReplayRecord {
    private val seen = mutableSetOf<Pair<Bytes, ULong>>()

    override fun contains(sender: Bytes, seq: ULong): Boolean = (sender to seq) in seen

    override fun add(sender: Bytes, seq: ULong, sentAt: ULong) {
        seen.add(sender to seq)
    }
}

/** Receiving envelopes, and the checks a server makes before it stores one (§7.5, §7.6). */
object Envelopes {
    /** The most wraps an envelope carries. */
    const val MAX_WRAPS = 255

    /** How far `sent_at` may lie before the receiver's clock: the longest time-to-live and a day. */
    const val MAX_AGE_MS: ULong = 2_678_400_000UL

    /** How far `sent_at` may lie after the receiver's clock. */
    const val MAX_AHEAD_MS: ULong = 86_400_000UL

    /**
     * Steps 1 to 15 of §7.6, as device [me] at the clock [now], with its verified log [state],
     * its encryption keys by key ID, and its [replay] record, which an accepted envelope joins.
     *
     * `sender_not_active` and `unknown_log_head` can mean the log has moved on: the caller fetches
     * new entries and tries again before it treats them as final (§7.6, §7.7).
     */
    suspend fun open(
        p: Primitives,
        raw: ByteArray,
        state: CircleState,
        me: Bytes,
        keys: Map<Bytes, HpkeKey>,
        replay: ReplayRecord,
        now: ULong,
    ): Receipt {
        val (env, sender) = try {
            common(p, raw, state, now, replay)
        } catch (e: ProtocolException) {
            return Receipt.Refused(e.reason)
        }
        val hdr = env.headerBytes
        val mine = env.wraps.firstOrNull { it.recipient == me } ?: return Receipt.Refused(Reason.NOT_A_RECIPIENT) // 11
        val key = keys[mine.keyId] ?: return Receipt.Refused(Reason.UNKNOWN_KEY)
        val secret = mine.open(key, Envelope.wrapInfo(p, hdr, mine.recipient, mine.keyId))
            ?: return Receipt.Refused(Reason.BAD_WRAP)
        val (payloadKey, nonce) = Envelope.payloadKeys(p, secret) // 12
        val padded = p.crypto.aesGcmOpen(payloadKey, nonce, env.ciphertext, p.h(Label.ENV_AAD, env.wrapsPart))
            ?: return Receipt.Refused(Reason.BAD_CIPHERTEXT)
        val bytes = Padding.unpadBucket(padded) ?: return Receipt.Refused(Reason.BAD_PADDING) // 13
        val payload = Json.parsePayload(bytes) ?: return Receipt.Refused(Reason.BAD_PAYLOAD) // 14
        when (SenderRules.verdict(p, payload, env.header.kind, sender, state, me)) { // 15
            SenderRules.Verdict.NOT_ALLOWED -> return Receipt.Refused(Reason.NOT_ALLOWED)
            SenderRules.Verdict.HELD -> return Receipt.Held(env)
            SenderRules.Verdict.ALLOWED -> {}
        }
        replay.add(env.header.sender, env.header.seq, env.header.sentAt)
        return Receipt.Accepted(env, sender, payload)
    }

    /**
     * What a server checks before it stores an envelope (§7.5): steps 1 to 10 of §7.6 with its own
     * clock, then the wraps, the time-to-live and, for a circle envelope, the log head and the set
     * of recipients. Null if a server would store it. A sender can run this on its own envelope.
     * The server's own record of posted envelopes, which makes posting idempotent, is the server's.
     */
    suspend fun serverRefusal(p: Primitives, raw: ByteArray, state: CircleState, now: ULong): Reason? {
        val env = try {
            common(p, raw, state, now, null).first
        } catch (e: ProtocolException) {
            return e.reason
        }
        val h = env.header
        val receiving = state.receivingDevices().map { it.id }.toSet()
        val named = env.wraps.map { it.recipient }
        if (named.any { it !in receiving }) return Reason.BAD_WRAPS
        if (h.ttlS !in EnvelopeHeader.TTL_RANGE) return Reason.BAD_TTL
        if (h.kind == EnvelopeHeader.CIRCLE) {
            if (state.hashes.indexOf(h.logHead) < state.receivingChangedSeq) return Reason.STALE_HEAD
            if (named.toSet() != receiving - h.sender) return Reason.BAD_WRAPS
        }
        return null
    }

    /**
     * The recipients of a circle envelope from [sender] (§7.2): every receiving device in [state]
     * but the sender itself. With `log_head` set to [state]'s head, a server accepts the set (§7.5).
     */
    fun circleRecipients(state: CircleState, sender: Bytes): List<Device> = state.receivingDevices().filter { it.id != sender }

    /** Steps 1 to 10 of §7.6, which receivers and servers share; throws [ProtocolException]. */
    private suspend fun common(p: Primitives, raw: ByteArray, state: CircleState, now: ULong, replay: ReplayRecord?): Pair<Envelope, Device> {
        val env = Envelope.parse(raw) // 1
        val h = env.header
        if (h.version != Protocol.VERSION || h.suite != Protocol.SUITE) refuse(Reason.BAD_VERSION) // 2
        if (h.kind != EnvelopeHeader.CIRCLE && h.kind != EnvelopeHeader.DIRECT) refuse(Reason.BAD_KIND) // 3
        if (h.circleId != state.circleId) refuse(Reason.WRONG_CIRCLE) // 4
        val sender = state.device(h.sender)?.takeIf { it.kind.receives } ?: refuse(Reason.SENDER_NOT_ACTIVE) // 5
        if (!p.verify(sender.dskPub.toByteArray(), Label.ENVELOPE, env.signedPart, env.sig)) refuse(Reason.BAD_SIGNATURE) // 6
        if (!state.hasEntry(h.logHead)) refuse(Reason.UNKNOWN_LOG_HEAD) // 7
        // 8: compared by subtraction, which can't overflow the way a sum near 2^64 would
        if (now > h.sentAt && now - h.sentAt > MAX_AGE_MS) refuse(Reason.EXPIRED)
        if (h.sentAt > now && h.sentAt - now > MAX_AHEAD_MS) refuse(Reason.BAD_TIME)
        if (replay != null && replay.contains(h.sender, h.seq)) refuse(Reason.REPLAY) // 9
        val ids = env.wraps.map { it.recipient } // 10
        if (ids.size !in 1..MAX_WRAPS || !ids.zipWithNext().all { (a, b) -> a < b }) refuse(Reason.BAD_WRAPS)
        return env to sender
    }

    private fun refuse(reason: Reason): Nothing = throw ProtocolException(reason)
}
