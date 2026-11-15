// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.log

import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.identity.DeviceCert
import ca.gureet.kinfold.core.identity.IdentityChain
import ca.gureet.kinfold.core.identity.IdentityLink
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.identity.Wrap
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.readAll

/** Log entry types (PROTOCOL.md §16.1). */
enum class EntryType(val code: Int) {
    GENESIS(0x01),
    ADD_MEMBER(0x02),
    REMOVE_MEMBER(0x03),
    ADD_DEVICE(0x04),
    REMOVE_DEVICE(0x05),
    UPDATE_KEY(0x06),
    POLICY(0x07),
    REKEY(0x08),
    SET_ADMIN(0x09),
    ADD_RECOVERY(0x0A),
    SET_OPTIONS(0x0B),
    ROTATE_IDENTITY(0x0C),
    ;

    /** The types whose `details` need their epoch's secret (§6.5). */
    val hasDetails: Boolean get() = this == GENESIS || this == ADD_MEMBER || this == POLICY

    companion object {
        fun of(code: Int): EntryType? = entries.firstOrNull { it.code == code }
    }
}

/** The 88-byte header of a log entry (§5.2). */
class EntryHeader(
    val version: Int,
    val suite: Int,
    val typeCode: Int,
    val circleId: Bytes,
    val seq: ULong,
    val prevHash: Bytes,
    val createdAt: ULong,
    val author: Bytes,
    val epoch: Long,
) {
    fun encode(): ByteArray = encode {
        u8(version)
        u16(suite)
        u8(typeCode)
        bytes(circleId)
        u64(seq)
        bytes(prevHash)
        u64(createdAt)
        bytes(author)
        u32(epoch)
    }

    companion object {
        const val SIZE = 88

        fun read(r: Reader): EntryHeader = EntryHeader(
            version = r.u8(),
            suite = r.u16(),
            typeCode = r.u8(),
            circleId = Bytes.of(r.bytes(16)),
            seq = r.u64(),
            prevHash = Bytes.of(r.bytes(32)),
            createdAt = r.u64(),
            author = Bytes.of(r.bytes(16)),
            epoch = r.u32(),
        )
    }
}

/** A log entry's framing (§5.2): header, `vec32 body`, signature. The body is parsed by [Body.parse]. */
class LogEntry private constructor(val raw: ByteArray, val header: EntryHeader, val body: ByteArray, val sig: ByteArray) {
    val headerBytes: ByteArray get() = raw.copyOf(EntryHeader.SIZE)

    /** Everything before the signature, which the signature covers. */
    val signedPart: ByteArray get() = raw.copyOf(raw.size - 64)

    companion object {
        const val MAX_SIZE = 65536

        /** The framing of [raw]; `malformed` if anything is short or left over. */
        fun parse(raw: ByteArray): LogEntry = readAll(raw) {
            val header = EntryHeader.read(this)
            val body = vec32()
            LogEntry(raw.copyOf(), header, body, bytes(64))
        }

        /** An entry signed by its author's device key. */
        suspend fun build(p: Primitives, author: SigningKey, header: EntryHeader, body: ByteArray): ByteArray {
            val unsigned = encode {
                bytes(header.encode())
                vec32(body)
            }
            return unsigned + p.sign(author, Label.LOG_ENTRY, unsigned)
        }

        /** entry_hash = H("log-hash", the whole entry). */
        suspend fun hash(p: Primitives, raw: ByteArray): Bytes = Bytes.of(p.h(Label.LOG_HASH, raw))

        /** circle_id = H("circle-id", the whole GENESIS entry)[0:16]. */
        suspend fun circleId(p: Primitives, genesis: ByteArray): Bytes = Bytes.of(p.h(Label.CIRCLE_ID, genesis).copyOf(16))
    }
}

/** The body of each entry type (§5.3). Every body must be exactly as listed, or it is `malformed`. */
sealed class Body {
    abstract fun encode(): ByteArray

    class Genesis(
        val cert: DeviceCert,
        val chain: IdentityChain,
        val bundle: KeyBundle,
        val epochCommit: Bytes,
        val details: ByteArray,
    ) : Body() {
        override fun encode() = encode {
            bytes(cert.encode())
            vec16(chain.encode())
            bytes(bundle.encode())
            bytes(epochCommit)
            bytes(details)
        }
    }

    class AddMember(
        val cert: DeviceCert,
        val chain: IdentityChain,
        val bundle: KeyBundle,
        val inviteId: Bytes,
        val termsCommit: Bytes,
        val consentSig: Bytes,
        val admin: Boolean,
        val details: ByteArray,
    ) : Body() {
        override fun encode() = encode {
            bytes(cert.encode())
            vec16(chain.encode())
            bytes(bundle.encode())
            bytes(inviteId)
            bytes(termsCommit)
            bytes(consentSig)
            flag(admin)
            bytes(details)
        }
    }

    class RemoveMember(val accountId: Bytes, val epochCommit: Bytes, val wraps: List<Wrap>) : Body() {
        override fun encode() = encode {
            bytes(accountId)
            bytes(epochCommit)
            vec32(Wrap.encodeList(wraps))
        }
    }

    class AddDevice(val cert: DeviceCert, val bundle: KeyBundle) : Body() {
        override fun encode() = encode {
            bytes(cert.encode())
            bytes(bundle.encode())
        }
    }

    class RemoveDevice(val deviceId: Bytes, val epochCommit: Bytes, val wraps: List<Wrap>) : Body() {
        override fun encode() = encode {
            bytes(deviceId)
            bytes(epochCommit)
            vec32(Wrap.encodeList(wraps))
        }
    }

    class UpdateKey(val bundle: KeyBundle) : Body() {
        override fun encode() = bundle.encode()
    }

    class Policy(val details: ByteArray) : Body() {
        override fun encode() = details.copyOf()
    }

    class Rekey(val epochCommit: Bytes, val wraps: List<Wrap>) : Body() {
        override fun encode() = encode {
            bytes(epochCommit)
            vec32(Wrap.encodeList(wraps))
        }
    }

    class SetAdmin(val accountId: Bytes, val admin: Boolean) : Body() {
        override fun encode() = encode {
            bytes(accountId)
            flag(admin)
        }
    }

    class AddRecovery(val cert: DeviceCert) : Body() {
        override fun encode() = cert.encode()
    }

    class SetOptions(val options: Long) : Body() {
        override fun encode() = encode { u32(options) }
    }

    class RotateIdentity(val link: IdentityLink) : Body() {
        override fun encode() = link.encode()
    }

    companion object {
        const val DETAILS_SIZE = 540

        fun parse(type: EntryType, bytes: ByteArray): Body = readAll(bytes) {
            when (type) {
                EntryType.GENESIS -> Genesis(
                    DeviceCert.read(this), IdentityChain.parse(vec16()), KeyBundle.read(this),
                    Bytes.of(bytes(32)), bytes(DETAILS_SIZE),
                )
                EntryType.ADD_MEMBER -> AddMember(
                    DeviceCert.read(this), IdentityChain.parse(vec16()), KeyBundle.read(this),
                    Bytes.of(bytes(16)), Bytes.of(bytes(32)), Bytes.of(bytes(64)), flag(), bytes(DETAILS_SIZE),
                )
                EntryType.REMOVE_MEMBER -> RemoveMember(Bytes.of(bytes(16)), Bytes.of(bytes(32)), Wrap.parseList(vec32()))
                EntryType.ADD_DEVICE -> AddDevice(DeviceCert.read(this), KeyBundle.read(this))
                EntryType.REMOVE_DEVICE -> RemoveDevice(Bytes.of(bytes(16)), Bytes.of(bytes(32)), Wrap.parseList(vec32()))
                EntryType.UPDATE_KEY -> UpdateKey(KeyBundle.read(this))
                EntryType.POLICY -> Policy(bytes(DETAILS_SIZE))
                EntryType.REKEY -> Rekey(Bytes.of(bytes(32)), Wrap.parseList(vec32()))
                EntryType.SET_ADMIN -> SetAdmin(Bytes.of(bytes(16)), flag())
                EntryType.ADD_RECOVERY -> AddRecovery(DeviceCert.read(this))
                EntryType.SET_OPTIONS -> SetOptions(u32())
                EntryType.ROTATE_IDENTITY -> RotateIdentity(IdentityLink.read(this))
            }
        }
    }
}
