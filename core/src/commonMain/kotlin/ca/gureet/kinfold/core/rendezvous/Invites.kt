// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.rendezvous

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.identity.DeviceCert
import ca.gureet.kinfold.core.identity.IdentityChain
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.log.Details
import ca.gureet.kinfold.core.log.MemberTerms
import ca.gureet.kinfold.core.rendezvous.RendezvousException.Failure
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Codes
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed
import ca.gureet.kinfold.core.wire.readAll

/**
 * An invite (PROTOCOL.md §9.1): what an admin's phone shows as a QR code for one new member. The
 * names at the end are hints for the join screen that nothing verifies.
 */
class Invite(
    val serverUrl: String,
    val serverKey: Bytes,
    val circleId: Bytes,
    val secret: Bytes,
    val inviterIkPub: Bytes,
    val expiresAt: ULong,
    val regToken: Bytes,
    val termsSalt: Bytes,
    /** The terms' own bytes, which `terms_commit` covers. */
    val termsBytes: Bytes,
    val circleName: String,
    val inviterName: String,
    val guardianNames: List<String>,
) {
    /** [termsBytes], parsed. */
    val terms: MemberTerms get() = readAll(termsBytes.toByteArray()) { MemberTerms.read(this) }

    fun encode(): ByteArray = encode {
        u8(Protocol.VERSION)
        vec16(serverUrl.encodeToByteArray())
        bytes(serverKey)
        bytes(circleId)
        bytes(secret)
        bytes(inviterIkPub)
        u64(expiresAt)
        vec16(regToken.toByteArray())
        bytes(termsSalt)
        bytes(termsBytes)
        vec16(circleName.encodeToByteArray())
        vec16(inviterName.encodeToByteArray())
        vec16(guardianNames.joinToString("\n").encodeToByteArray())
    }

    /** The QR code's text: `KFI0` and the invite in base64url. */
    val code: String get() = Codes.write(Codes.INVITE, encode())

    /** A link through [linkBase], the one origin the app was built with; the invite stays after `#`. */
    fun link(linkBase: String): String = "$linkBase/join#" + Base64Url.encode(encode())

    suspend fun inviteId(p: Primitives): Bytes = Joining.inviteId(p, secret)

    suspend fun termsCommit(p: Primitives): Bytes = Details.termsCommit(p, termsSalt.toByteArray(), termsBytes.toByteArray())

    companion object {
        /** The invite in [data], or `malformed`. */
        fun parse(data: ByteArray): Invite = readAll(data) {
            if (u8() != Protocol.VERSION) malformed()
            val serverUrl = utf8()
            val serverKey = Bytes.of(bytes(32))
            val circleId = Bytes.of(bytes(16))
            val secret = Bytes.of(bytes(16))
            val inviter = Bytes.of(bytes(32))
            val expiresAt = u64()
            val regToken = Bytes.of(vec16())
            val salt = Bytes.of(bytes(16))
            val start = position
            MemberTerms.read(this)
            val terms = Bytes.of(data.copyOfRange(start, position))
            val circleName = utf8()
            val inviterName = utf8()
            val names = utf8()
            Invite(
                serverUrl, serverKey, circleId, secret, inviter, expiresAt, regToken, salt, terms, circleName, inviterName,
                if (names.isEmpty()) emptyList() else names.split("\n"),
            )
        }

        /** The invite in a scanned `KFI0` code, or `malformed`. */
        fun fromCode(text: String): Invite = parse(Codes.read(Codes.INVITE, text) ?: malformed())
    }
}

/** What an inviter's device found in a join request it opened (§9.2). */
class JoinRequestContents(
    val cert: DeviceCert,
    val chain: IdentityChain,
    val bundle: KeyBundle,
    val termsCommit: Bytes,
    val consent: Bytes,
    val name: String,
)

/** Joining a circle (§9.2, §9.3): the join request the invitee posts, and the result the inviter posts back. */
object Joining {
    const val ADDED = 1
    const val DECLINED = 2

    suspend fun inviteId(p: Primitives, secret: Bytes): Bytes = Bytes.of(p.h(Label.INVITE_ID, secret.toByteArray()).copyOf(16))

    suspend fun joinKey(p: Primitives, secret: Bytes): ByteArray = p.kdf(secret.toByteArray(), Label.JOIN_KEY, 32)

    suspend fun joinResultKey(p: Primitives, secret: Bytes): ByteArray = p.kdf(secret.toByteArray(), Label.JOIN_RESULT_KEY, 32)

    /** What a join consent signs: `circle_id ‖ invite_id ‖ cert ‖ bundle ‖ terms_commit` (§5.3). */
    fun consentSigned(circleId: Bytes, inviteId: Bytes, cert: DeviceCert, bundle: KeyBundle, termsCommit: Bytes): ByteArray =
        concat(circleId.toByteArray(), inviteId.toByteArray(), cert.encode(), bundle.encode(), termsCommit.toByteArray())

    /** The invitee's consent, signed with its identity key [ik]. */
    suspend fun consent(
        p: Primitives,
        ik: SigningKey,
        circleId: Bytes,
        inviteId: Bytes,
        cert: DeviceCert,
        bundle: KeyBundle,
        termsCommit: Bytes,
    ): Bytes = Bytes.of(p.sign(ik, Label.JOIN_CONSENT, consentSigned(circleId, inviteId, cert, bundle, termsCommit)))

    /** A join request for the invite with [secret], sealed under its join key with [nonce]. */
    suspend fun request(
        p: Primitives,
        secret: Bytes,
        cert: DeviceCert,
        chain: IdentityChain,
        bundle: KeyBundle,
        termsCommit: Bytes,
        consent: Bytes,
        name: String,
        nonce: ByteArray = p.random(12),
    ): ByteArray {
        val plaintext = encode {
            bytes(cert.encode())
            vec16(chain.encode())
            bytes(bundle.encode())
            bytes(termsCommit)
            bytes(consent)
            vec16(name.encodeToByteArray())
        }
        return Sealed.seal(p, joinKey(p, secret), head(inviteId(p, secret)), nonce, plaintext)
    }

    /**
     * Opens a join request for [invite] at the time [now] and checks it as §9.2 and §6.4 require:
     * the certificate, its chain and kind, the bundle, the terms it commits to, and the consent.
     */
    suspend fun openRequest(p: Primitives, invite: Invite, msg: ByteArray, now: ULong): JoinRequestContents {
        val iid = invite.inviteId(p)
        val plaintext = Sealed.open(p, joinKey(p, invite.secret), msg, HEAD_SIZE) { checkHead(it, iid) }
        val c = parsing {
            readAll(plaintext) {
                JoinRequestContents(
                    cert = DeviceCert.read(this),
                    chain = IdentityChain.parse(vec16()),
                    bundle = KeyBundle.read(this),
                    termsCommit = Bytes.of(bytes(32)),
                    consent = Bytes.of(bytes(64)),
                    name = utf8(),
                )
            }
        }
        if (!c.cert.isWellFormed(p) || !c.chain.provesAccountOf(p, c.cert) || c.cert.kind?.isPhoneOrTablet != true) {
            refuse(Failure.BAD_CERT)
        }
        if (!c.bundle.isValidFor(p, c.cert.dskPub, c.cert.accountId) || !c.bundle.isCurrentAt(now)) refuse(Failure.BAD_BUNDLE)
        if (c.termsCommit != invite.termsCommit(p)) refuse(Failure.BAD_TERMS) // the invitee agreed to something else
        val signed = consentSigned(invite.circleId, iid, c.cert, c.bundle, c.termsCommit)
        if (!p.verify(c.cert.ikPub.toByteArray(), Label.JOIN_CONSENT, signed, c.consent.toByteArray())) refuse(Failure.BAD_CONSENT)
        return c
    }

    /** A join result: [ADDED] with the hash of the `ADD_MEMBER` entry, or [DECLINED] with 32 zero bytes. */
    suspend fun result(p: Primitives, secret: Bytes, outcome: Int, head: Bytes, nonce: ByteArray = p.random(12)): ByteArray {
        require(outcome == ADDED || (outcome == DECLINED && head.isAllZero())) { "declined carries a zero head" }
        require(head.size == 32)
        return Sealed.seal(p, joinResultKey(p, secret), head(inviteId(p, secret)), nonce, concat(byteArrayOf(outcome.toByte()), head.toByteArray()))
    }

    /** The outcome and head of a join result for the invite with [secret]. */
    suspend fun openResult(p: Primitives, secret: Bytes, msg: ByteArray): Pair<Int, Bytes> {
        val iid = inviteId(p, secret)
        val pt = Sealed.open(p, joinResultKey(p, secret), msg, HEAD_SIZE) { checkHead(it, iid) }
        val outcome = pt.firstOrNull()?.toInt()
        val head = Bytes.of(pt.copyOfRange(minOf(1, pt.size), pt.size))
        if (pt.size != 33 || (outcome != ADDED && outcome != DECLINED) || (outcome == DECLINED && !head.isAllZero())) {
            refuse(Failure.MALFORMED)
        }
        return outcome to head
    }

    /** `u8 version ‖ invite_id[16]`, the associated data of both messages. */
    private const val HEAD_SIZE = 17

    private fun head(iid: Bytes): ByteArray = concat(byteArrayOf(Protocol.VERSION.toByte()), iid.toByteArray())

    private fun checkHead(r: Reader, iid: Bytes) {
        if (r.u8() != Protocol.VERSION || Bytes.of(r.bytes(16)) != iid) refuse(Failure.WRONG_INVITE)
    }
}
