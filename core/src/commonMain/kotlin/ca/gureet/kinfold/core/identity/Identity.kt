// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.identity

import ca.gureet.kinfold.core.Protocol.SUITE
import ca.gureet.kinfold.core.Protocol.VERSION
import ca.gureet.kinfold.core.crypto.Ed25519Checks
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.crypto.X25519Checks
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed
import ca.gureet.kinfold.core.wire.readAll

/** Device kinds (PROTOCOL.md §16.3). */
enum class DeviceKind(val code: Int) {
    PHONE(1),
    TABLET(2),
    WEB(3),
    HOME_ASSISTANT(4),
    RECOVERY(5),
    ;

    /** Kinds 1–4 receive envelopes and epoch wraps; a recovery device receives nothing. */
    val receives: Boolean get() = this != RECOVERY

    /** Phones and tablets hold the identity key and may author every entry type (§6.3). */
    val isPhoneOrTablet: Boolean get() = this == PHONE || this == TABLET

    companion object {
        fun of(code: Int): DeviceKind? = entries.firstOrNull { it.code == code }
    }
}

/** The identifiers of PROTOCOL.md §4.2. */
object Ids {
    /** account_id = H("account-id", ik_pub)[0:16], of the account's first identity key. */
    suspend fun account(p: Primitives, ikPub: ByteArray): Bytes = Bytes.of(p.h(Label.ACCOUNT_ID, ikPub).copyOf(16))

    /** device_id = H("device-id", dsk_pub)[0:16]. */
    suspend fun device(p: Primitives, dskPub: ByteArray): Bytes = Bytes.of(p.h(Label.DEVICE_ID, dskPub).copyOf(16))

    /** key_id = H("key-id", dek_pub)[0:8]. */
    suspend fun key(p: Primitives, dekPub: ByteArray): Bytes = Bytes.of(p.h(Label.KEY_ID, dekPub).copyOf(8))
}

/** A device certificate (§4.3): the account's identity key states that a signing key is one of its devices. */
class DeviceCert(
    val version: Int,
    val suite: Int,
    val accountId: Bytes,
    val dskPub: Bytes,
    val kindCode: Int,
    val issuedAt: ULong,
    val ikPub: Bytes,
    val sig: Bytes,
) {
    val kind: DeviceKind? get() = DeviceKind.of(kindCode)

    /** The first 60 bytes, which `sig` covers. */
    fun signedPart(): ByteArray = encode {
        u8(version)
        u16(suite)
        bytes(accountId)
        bytes(dskPub)
        u8(kindCode)
        u64(issuedAt)
    }

    fun encode(): ByteArray = encode {
        bytes(signedPart())
        bytes(ikPub)
        bytes(sig)
    }

    suspend fun deviceId(p: Primitives): Bytes = Ids.device(p, dskPub.toByteArray())

    /**
     * Well-formed (§4.3): version and suite as shown, a kind in the registry, neither key an
     * invalid key, and `sig` valid under `ik_pub`.
     */
    suspend fun isWellFormed(p: Primitives): Boolean =
        version == VERSION &&
            suite == SUITE &&
            kind != null &&
            !Ed25519Checks.isInvalidKey(ikPub.toByteArray()) &&
            !Ed25519Checks.isInvalidKey(dskPub.toByteArray()) &&
            p.verify(ikPub.toByteArray(), Label.DEVICE_CERT, signedPart(), sig.toByteArray())

    companion object {
        const val SIZE = 156

        fun read(r: Reader): DeviceCert = DeviceCert(
            version = r.u8(),
            suite = r.u16(),
            accountId = Bytes.of(r.bytes(16)),
            dskPub = Bytes.of(r.bytes(32)),
            kindCode = r.u8(),
            issuedAt = r.u64(),
            ikPub = Bytes.of(r.bytes(32)),
            sig = Bytes.of(r.bytes(64)),
        )

        fun parse(bytes: ByteArray): DeviceCert = readAll(bytes) { read(this) }

        /** A certificate for [dskPub], signed by the identity key [ik]. */
        suspend fun issue(
            p: Primitives,
            ik: SigningKey,
            accountId: Bytes,
            dskPub: ByteArray,
            kind: DeviceKind,
            issuedAt: ULong,
        ): DeviceCert {
            val unsigned = DeviceCert(VERSION, SUITE, accountId, Bytes.of(dskPub), kind.code, issuedAt, Bytes.of(ik.publicKey), Bytes.zero(64))
            return DeviceCert(
                VERSION, SUITE, accountId, Bytes.of(dskPub), kind.code, issuedAt, Bytes.of(ik.publicKey),
                Bytes.of(p.sign(ik, Label.DEVICE_CERT, unsigned.signedPart())),
            )
        }
    }
}

/** One rotation of an identity key (§4.3), signed by the old key and the new one. */
class IdentityLink(val oldIkPub: Bytes, val newIkPub: Bytes, val oldSig: Bytes, val newSig: Bytes) {
    fun encode(): ByteArray = encode {
        bytes(oldIkPub)
        bytes(newIkPub)
        bytes(oldSig)
        bytes(newSig)
    }

    /** Both signatures, over account_id ‖ old_ik_pub ‖ new_ik_pub, with the account's ID. */
    suspend fun signaturesVerify(p: Primitives, accountId: Bytes): Boolean {
        val message = signedPart(accountId)
        return p.verify(oldIkPub.toByteArray(), Label.IDENTITY_ROTATE, message, oldSig.toByteArray()) &&
            p.verify(newIkPub.toByteArray(), Label.IDENTITY_ROTATE, message, newSig.toByteArray())
    }

    private fun signedPart(accountId: Bytes): ByteArray = encode {
        bytes(accountId)
        bytes(oldIkPub)
        bytes(newIkPub)
    }

    companion object {
        const val SIZE = 192

        fun read(r: Reader): IdentityLink =
            IdentityLink(Bytes.of(r.bytes(32)), Bytes.of(r.bytes(32)), Bytes.of(r.bytes(64)), Bytes.of(r.bytes(64)))

        fun parse(bytes: ByteArray): IdentityLink = readAll(bytes) { read(this) }

        /** The link from [old] to [new] for [accountId], signed by both. */
        suspend fun create(p: Primitives, accountId: Bytes, old: SigningKey, new: SigningKey): IdentityLink {
            val bare = IdentityLink(Bytes.of(old.publicKey), Bytes.of(new.publicKey), Bytes.zero(64), Bytes.zero(64))
            val message = bare.signedPart(accountId)
            return IdentityLink(
                bare.oldIkPub, bare.newIkPub,
                Bytes.of(p.sign(old, Label.IDENTITY_ROTATE, message)),
                Bytes.of(p.sign(new, Label.IDENTITY_ROTATE, message)),
            )
        }
    }
}

/** An identity chain (§4.3): the links of every rotation of an account's identity key, oldest first. */
class IdentityChain(val links: List<IdentityLink>) {
    init {
        require(links.size <= MAX_LINKS) { "at most 8 links" }
    }

    /** The bytes inside the `vec16`: the links, one after another. */
    fun encode(): ByteArray = encode { links.forEach { bytes(it.encode()) } }

    /**
     * Whether the chain proves the account of [cert]: empty, and the certificate's key is the
     * account's first; or a chain of valid links from the account's first key to the
     * certificate's, every signature verifying with the account ID.
     */
    suspend fun provesAccountOf(p: Primitives, cert: DeviceCert): Boolean {
        if (links.isEmpty()) return Ids.account(p, cert.ikPub.toByteArray()) == cert.accountId
        if (Ids.account(p, links.first().oldIkPub.toByteArray()) != cert.accountId) return false
        for (i in 1 until links.size) if (links[i].oldIkPub != links[i - 1].newIkPub) return false
        if (links.last().newIkPub != cert.ikPub) return false
        for (link in links) {
            if (Ed25519Checks.isInvalidKey(link.oldIkPub.toByteArray()) || Ed25519Checks.isInvalidKey(link.newIkPub.toByteArray())) {
                return false
            }
            if (!link.signaturesVerify(p, cert.accountId)) return false
        }
        return true
    }

    companion object {
        const val MAX_LINKS = 8

        val EMPTY = IdentityChain(emptyList())

        /** The chain inside a `vec16`: a multiple of 192 bytes, at most 1,536; `malformed` otherwise. */
        fun parse(bytes: ByteArray): IdentityChain {
            if (bytes.size % IdentityLink.SIZE != 0 || bytes.size > MAX_LINKS * IdentityLink.SIZE) malformed()
            return IdentityChain(
                List(bytes.size / IdentityLink.SIZE) { i ->
                    IdentityLink.parse(bytes.copyOfRange(i * IdentityLink.SIZE, (i + 1) * IdentityLink.SIZE))
                },
            )
        }
    }
}

/** A device's published encryption key and what its software supports (§4.4). */
class KeyBundle(
    val version: Int,
    val suite: Int,
    val accountId: Bytes,
    val deviceId: Bytes,
    val dekPub: Bytes,
    val notBefore: ULong,
    val notAfter: ULong,
    val protoMax: Int,
    val features: Long,
    val sig: Bytes,
) {
    /** The first 88 bytes, which `sig` covers. */
    fun signedPart(): ByteArray = encode {
        u8(version)
        u16(suite)
        bytes(accountId)
        bytes(deviceId)
        bytes(dekPub)
        u64(notBefore)
        u64(notAfter)
        u8(protoMax)
        u32(features)
    }

    fun encode(): ByteArray = encode {
        bytes(signedPart())
        bytes(sig)
    }

    suspend fun keyId(p: Primitives): Bytes = Ids.key(p, dekPub.toByteArray())

    /**
     * Valid for the device with [dskPub] in [accountId] (§4.4): version and suite as shown, the
     * device ID of that key, that account, an encryption key that isn't an invalid key, a life
     * of at most 35 days, and `sig` valid under the device's key. `proto_max` and `features`
     * never matter.
     */
    suspend fun isValidFor(p: Primitives, dskPub: Bytes, accountId: Bytes): Boolean =
        version == VERSION &&
            suite == SUITE &&
            deviceId == Ids.device(p, dskPub.toByteArray()) &&
            this.accountId == accountId &&
            !X25519Checks.isInvalidKey(dekPub.toByteArray()) &&
            notBefore < notAfter &&
            notAfter - notBefore <= MAX_LIFE_MS &&
            p.verify(dskPub.toByteArray(), Label.KEY_BUNDLE, signedPart(), sig.toByteArray())

    /** Current at [t]: `not_before ≤ t + 600,000` and `t < not_after`, written without sums (Appendix C). */
    fun isCurrentAt(t: ULong): Boolean = (notBefore <= t || notBefore - t <= SKEW_MS) && t < notAfter

    companion object {
        const val SIZE = 152

        /** 35 days, the longest a bundle may last. */
        const val MAX_LIFE_MS: ULong = 3_024_000_000UL

        /** How far ahead of a clock a bundle's start may be and still be current. */
        const val SKEW_MS: ULong = 600_000UL

        fun read(r: Reader): KeyBundle = KeyBundle(
            version = r.u8(),
            suite = r.u16(),
            accountId = Bytes.of(r.bytes(16)),
            deviceId = Bytes.of(r.bytes(16)),
            dekPub = Bytes.of(r.bytes(32)),
            notBefore = r.u64(),
            notAfter = r.u64(),
            protoMax = r.u8(),
            features = r.u32(),
            sig = Bytes.of(r.bytes(64)),
        )

        fun parse(bytes: ByteArray): KeyBundle = readAll(bytes) { read(this) }

        /** A bundle for [dekPub], signed by the device's key [dsk]. */
        suspend fun sign(
            p: Primitives,
            dsk: SigningKey,
            accountId: Bytes,
            dekPub: ByteArray,
            notBefore: ULong,
            notAfter: ULong,
            protoMax: Int = 0,
            features: Long = 0,
        ): KeyBundle {
            val deviceId = Ids.device(p, dsk.publicKey)
            val bare = KeyBundle(VERSION, SUITE, accountId, deviceId, Bytes.of(dekPub), notBefore, notAfter, protoMax, features, Bytes.zero(64))
            return KeyBundle(
                VERSION, SUITE, accountId, deviceId, Bytes.of(dekPub), notBefore, notAfter, protoMax, features,
                Bytes.of(p.sign(dsk, Label.KEY_BUNDLE, bare.signedPart())),
            )
        }
    }
}
