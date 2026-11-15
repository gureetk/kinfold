// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.log

import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Padding
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed
import ca.gureet.kinfold.core.wire.readAll

/** A schedule window (PROTOCOL.md §5.5): 1 pause allowed or 2 approximate allowed, on some days, between two times. */
class Window(val kind: Int, val days: Int, val startMin: Int, val endMin: Int) {
    val isValid: Boolean get() = (kind == 1 || kind == 2) && days in 1..127 && startMin < endMin && endMin <= 1440
}

/** A teen's rules (§5.5). [tz] is kept as bytes: one IANA zone name, checked character by character. */
class Rules(
    val pauseMode: Int,
    val approxMode: Int,
    val speedAlertKmh: Int,
    val phoneUseAlerts: Int,
    val historyDays: Int,
    val silenceAlertMin: Int,
    val tz: ByteArray,
    val schedule: List<Window>,
) {
    fun encode(): ByteArray = encode {
        u8(pauseMode)
        u8(approxMode)
        u16(speedAlertKmh)
        u8(phoneUseAlerts)
        u8(historyDays)
        u16(silenceAlertMin)
        vec16(tz)
        vec16(
            encode {
                for (w in schedule) {
                    u8(w.kind)
                    u8(w.days)
                    u16(w.startMin)
                    u16(w.endMin)
                }
            },
        )
    }

    /** Valid (§5.5): every field in range, `tz` of allowed characters, and a zone whenever there is a schedule. */
    val isValid: Boolean
        get() = pauseMode <= 2 &&
            approxMode <= 2 &&
            speedAlertKmh <= 300 &&
            phoneUseAlerts <= 1 &&
            historyDays in 1..30 &&
            (silenceAlertMin == 0 || silenceAlertMin in 15..1440) &&
            tz.size <= 64 &&
            tz.all { it.toInt().toChar() in TZ_CHARS } &&
            schedule.size <= 32 &&
            (tz.isNotEmpty() || schedule.isEmpty()) &&
            schedule.all { it.isValid }

    val tzText: String get() = tz.decodeToString()

    companion object {
        private const val TZ_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_-+"

        /** The defaults for a new teen (§5.5). */
        val DEFAULT = Rules(1, 1, 0, 0, 7, 60, ByteArray(0), emptyList())

        fun read(r: Reader): Rules {
            val pauseMode = r.u8()
            val approxMode = r.u8()
            val speed = r.u16()
            val phoneUse = r.u8()
            val history = r.u8()
            val silence = r.u16()
            val tz = r.vec16()
            val raw = r.vec16()
            if (raw.size % 6 != 0) malformed()
            val windows = readAll(raw) { List(raw.size / 6) { Window(u8(), u8(), u16(), u16()) } }
            return Rules(pauseMode, approxMode, speed, phoneUse, history, silence, tz, windows)
        }
    }
}

enum class Role(val code: Int) {
    ADULT(1),
    TEEN(2),
}

/** What a new member is asked to accept (§5.5, §9). [role] is the byte as written; only 1 and 2 are valid. */
class MemberTerms(val role: Int, val teenUntil: ULong, val guardians: List<Bytes>, val rules: Rules) {
    fun encode(): ByteArray = encode {
        u8(role)
        u64(teenUntil)
        ids(guardians)
        bytes(rules.encode())
    }

    companion object {
        fun read(r: Reader): MemberTerms = MemberTerms(r.u8(), r.u64(), r.ids(), Rules.read(r))
    }
}

/** The plaintext inside a `POLICY` entry's details (§5.5). */
sealed class PolicyChange {
    class SetRules(val target: Bytes, val rules: Rules) : PolicyChange()

    class SetGuardians(val target: Bytes, val guardians: List<Bytes>) : PolicyChange()

    class GrantPause(val target: Bytes, val pauseId: Bytes, val kind: Int, val start: ULong, val end: ULong) : PolicyChange()

    class RevokePause(val target: Bytes, val pauseId: Bytes) : PolicyChange()

    class EndTeen(val target: Bytes) : PolicyChange()

    class SetCircleName(val name: ByteArray) : PolicyChange()

    /** A subtype outside §16.2, which is not parsed further. */
    class Unknown(val subtype: Int) : PolicyChange()

    fun encode(): ByteArray = encode {
        when (val c = this@PolicyChange) {
            is SetRules -> u8(SET_RULES).bytes(c.target).bytes(c.rules.encode())
            is SetGuardians -> u8(SET_GUARDIANS).bytes(c.target).ids(c.guardians)
            is GrantPause -> u8(GRANT_PAUSE).bytes(c.target).bytes(c.pauseId).u8(c.kind).u64(c.start).u64(c.end)
            is RevokePause -> u8(REVOKE_PAUSE).bytes(c.target).bytes(c.pauseId)
            is EndTeen -> u8(END_TEEN).bytes(c.target)
            is SetCircleName -> u8(SET_CIRCLE_NAME).vec16(c.name)
            is Unknown -> u8(c.subtype)
        }
    }

    companion object {
        const val SET_RULES = 0x01
        const val SET_GUARDIANS = 0x02
        const val GRANT_PAUSE = 0x03
        const val REVOKE_PAUSE = 0x04
        const val END_TEEN = 0x05
        const val SET_CIRCLE_NAME = 0x06

        /** A known subtype must be exactly as listed; `malformed` otherwise. */
        fun parse(bytes: ByteArray): PolicyChange {
            val r = Reader(bytes)
            val change = when (val subtype = r.u8()) {
                SET_RULES -> SetRules(Bytes.of(r.bytes(16)), Rules.read(r))
                SET_GUARDIANS -> SetGuardians(Bytes.of(r.bytes(16)), r.ids())
                GRANT_PAUSE -> GrantPause(Bytes.of(r.bytes(16)), Bytes.of(r.bytes(8)), r.u8(), r.u64(), r.u64())
                REVOKE_PAUSE -> RevokePause(Bytes.of(r.bytes(16)), Bytes.of(r.bytes(8)))
                END_TEEN -> EndTeen(Bytes.of(r.bytes(16)))
                SET_CIRCLE_NAME -> SetCircleName(r.vec16())
                else -> return Unknown(subtype)
            }
            r.finish()
            return change
        }
    }
}

/** The encrypted part of a log entry (§5.4) and the private structures inside it. */
object Details {
    const val SIZE = 540

    /** Every plaintext is padded to this before it is sealed. */
    const val PADDED = 512

    suspend fun logKey(p: Primitives, epochSecret: ByteArray): ByteArray = p.kdf(epochSecret, Label.LOG_KEY, 32)

    /** nonce ‖ AEAD-Seal(log_key, nonce, PadTo(plaintext, 512), aad = the entry's header): always 540 bytes. */
    suspend fun seal(p: Primitives, epochSecret: ByteArray, header: ByteArray, plaintext: ByteArray, nonce: ByteArray = p.random(12)): ByteArray =
        nonce + p.crypto.aesGcmSeal(logKey(p, epochSecret), nonce, Padding.padTo(plaintext, PADDED), header)

    /** The plaintext, or null if the ciphertext doesn't open or its padding is bad. */
    suspend fun open(p: Primitives, epochSecret: ByteArray, header: ByteArray, details: ByteArray): ByteArray? {
        if (details.size != SIZE) return null
        val padded = p.crypto.aesGcmOpen(logKey(p, epochSecret), details.copyOf(12), details.copyOfRange(12, SIZE), header)
        return padded?.let { Padding.unpadExact(it, PADDED) }
    }

    /** A circle name (§5.5): 1 to 128 bytes of valid UTF-8; null otherwise. */
    fun name(bytes: ByteArray): String? {
        if (bytes.size !in 1..128) return null
        return try {
            bytes.decodeToString(throwOnInvalidSequence = true)
        } catch (_: CharacterCodingException) {
            null
        }
    }

    /** GenesisDetails: the circle's name inside a `vec16`, and nothing else; null if it doesn't parse. */
    fun genesisName(plaintext: ByteArray): ByteArray? = parsed { readAll(plaintext) { vec16() } }

    /** MemberDetails: the terms salt and the terms, and the terms' own bytes; null if it doesn't parse. */
    fun memberDetails(plaintext: ByteArray): Triple<ByteArray, MemberTerms, ByteArray>? = parsed {
        readAll(plaintext) { Triple(bytes(16), MemberTerms.read(this), plaintext.copyOfRange(16, plaintext.size)) }
    }

    fun encodeGenesis(name: String): ByteArray = encode { vec16(name.encodeToByteArray()) }

    fun encodeMember(termsSalt: ByteArray, terms: MemberTerms): ByteArray = termsSalt + terms.encode()

    /** terms_commit = H("member-terms", terms_salt ‖ MemberTerms). */
    suspend fun termsCommit(p: Primitives, termsSalt: ByteArray, terms: ByteArray): Bytes =
        Bytes.of(p.h(Label.MEMBER_TERMS, termsSalt, terms))

    /** epoch_commit = H("epoch-commit", u32(epoch) ‖ epoch_secret) (§5.6). */
    suspend fun epochCommit(p: Primitives, epoch: Long, secret: ByteArray): Bytes =
        Bytes.of(p.h(Label.EPOCH_COMMIT, encode { u32(epoch) }, secret))

    private inline fun <T> parsed(read: () -> T): T? = try {
        read()
    } catch (_: ProtocolException) {
        null
    }
}
