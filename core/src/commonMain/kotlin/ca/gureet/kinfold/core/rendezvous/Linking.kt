// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.rendezvous

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.crypto.HpkeKey
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.identity.DeviceCert
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.identity.IdentityChain
import ca.gureet.kinfold.core.identity.Ids
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.payload.Json
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
 * A link code (PROTOCOL.md §10.1): shown by an existing phone or tablet (direction 1, with its
 * account and identity key) or by a new web or Home Assistant device (direction 2). An app reads one
 * only from its own scanner, never from a link.
 */
class LinkCode(
    val direction: Int,
    val serverUrl: String,
    val serverKey: Bytes,
    val secret: Bytes,
    val expiresAt: ULong,
    /** Direction 1 only. */
    val accountId: Bytes? = null,
    /** Direction 1 only. */
    val ikPub: Bytes? = null,
) {
    init {
        require((direction == Linking.FROM_EXISTING) == (accountId != null && ikPub != null)) { "only direction 1 names the account" }
    }

    fun encode(): ByteArray = encode {
        u8(Protocol.VERSION)
        u8(direction)
        vec16(serverUrl.encodeToByteArray())
        bytes(serverKey)
        bytes(secret)
        u64(expiresAt)
        if (direction == Linking.FROM_EXISTING) {
            bytes(checkNotNull(accountId))
            bytes(checkNotNull(ikPub))
        }
    }

    /** The QR code's text: `KFL0` and the link in base64url. */
    val code: String get() = Codes.write(Codes.LINK, encode())

    companion object {
        /** The link in [data], or `malformed`. */
        fun parse(data: ByteArray): LinkCode = readAll(data) {
            if (u8() != Protocol.VERSION) malformed()
            val direction = u8()
            val url = utf8()
            val key = Bytes.of(bytes(32))
            val secret = Bytes.of(bytes(16))
            val expires = u64()
            when (direction) {
                Linking.FROM_EXISTING -> LinkCode(direction, url, key, secret, expires, Bytes.of(bytes(16)), Bytes.of(bytes(32)))
                Linking.FROM_NEW -> LinkCode(direction, url, key, secret, expires)
                else -> malformed()
            }
        }

        /** The link in a scanned `KFL0` code, or `malformed`. */
        fun fromCode(text: String): LinkCode = parse(Codes.read(Codes.LINK, text) ?: malformed())
    }
}

/** What an existing device found in a new device's request (§10.2 step 5). */
class LinkRequest(val dskPub: Bytes, val kind: DeviceKind, val bundle: KeyBundle, val name: String, val code: String)

/** Linking a device (§10.2, §10.3): the messages through the link's mailbox, and the response. */
object Linking {
    const val FROM_EXISTING = 1
    const val FROM_NEW = 2

    const val OFFER = 1
    const val REQUEST = 2
    const val COMMIT = 3
    const val NONCE = 4

    suspend fun linkId(p: Primitives, secret: Bytes): Bytes = Bytes.of(p.h(Label.LINK_ID, secret.toByteArray()).copyOf(16))

    suspend fun linkKey(p: Primitives, secret: Bytes): ByteArray = p.kdf(secret.toByteArray(), Label.LINK_KEY, 32)

    suspend fun linkConfirm(p: Primitives, secret: Bytes): ByteArray = p.kdf(secret.toByteArray(), Label.LINK_CONFIRM, 16)

    /** The kinds a new device may be in each direction. */
    fun kindFits(direction: Int, kind: DeviceKind): Boolean = when (direction) {
        FROM_EXISTING -> kind == DeviceKind.PHONE || kind == DeviceKind.TABLET
        FROM_NEW -> kind == DeviceKind.WEB || kind == DeviceKind.HOME_ASSISTANT
        else -> false
    }

    /** A LinkMessage of [type] carrying [plaintext], sealed under the link key with [nonce]. */
    suspend fun seal(p: Primitives, secret: Bytes, type: Int, plaintext: ByteArray, nonce: ByteArray = p.random(12)): ByteArray =
        Sealed.seal(p, linkKey(p, secret), head(linkId(p, secret), type), nonce, plaintext)

    /** The plaintext of a LinkMessage that must be of [type]. */
    suspend fun open(p: Primitives, secret: Bytes, type: Int, msg: ByteArray): ByteArray {
        val lid = linkId(p, secret)
        return Sealed.open(p, linkKey(p, secret), msg, HEAD_SIZE) { r ->
            if (r.u8() != Protocol.VERSION || Bytes.of(r.bytes(16)) != lid || r.u8() != type) refuse(Failure.WRONG_LINK)
        }
    }

    /** Direction 2: the account ID and identity key that the existing phone's offer names. */
    suspend fun openOffer(p: Primitives, secret: Bytes, msg: ByteArray): Pair<Bytes, Bytes> {
        val pt = open(p, secret, OFFER, msg)
        if (pt.size != 48) refuse(Failure.MALFORMED)
        return Bytes.of(pt.copyOf(16)) to Bytes.of(pt.copyOfRange(16, 48))
    }

    /** What the new device asks for: `dsk_pub ‖ u8 kind ‖ KeyBundle ‖ vec16 name`. */
    fun requestBody(dskPub: Bytes, kind: DeviceKind, bundle: KeyBundle, name: String): ByteArray = encode {
        bytes(dskPub)
        u8(kind.code)
        bytes(bundle.encode())
        vec16(name.encodeToByteArray())
    }

    /** What the new device posts first, fixing its request before it sees `r_old`. */
    suspend fun commit(p: Primitives, secret: Bytes, rNew: ByteArray, body: ByteArray): ByteArray =
        p.h(Label.LINK_COMMIT, linkId(p, secret).toByteArray(), rNew, body)

    /** The 6-digit code both screens show. */
    suspend fun code(p: Primitives, secret: Bytes, rOld: ByteArray, rNew: ByteArray, body: ByteArray): String {
        val h = p.h(Label.LINK_CODE, linkId(p, secret).toByteArray(), rOld, rNew, body)
        var v = 0L
        for (i in 0 until 4) v = (v shl 8) or (h[i].toLong() and 0xff)
        return (v % 1_000_000).toString().padStart(6, '0')
    }

    /**
     * Step 5 of §10.2, run by the existing device once it holds the commit and the request: the
     * request must be the one committed to, of a kind the [direction] allows, with a bundle valid in
     * the account [accountId] and current at [now]. Gives the code to show.
     */
    suspend fun openRequest(
        p: Primitives,
        secret: Bytes,
        direction: Int,
        accountId: Bytes,
        commitMsg: ByteArray,
        rOld: ByteArray,
        requestMsg: ByteArray,
        now: ULong,
    ): LinkRequest {
        val committed = open(p, secret, COMMIT, commitMsg)
        val pt = open(p, secret, REQUEST, requestMsg)
        if (committed.size != 32 || pt.size < 32) refuse(Failure.MALFORMED)
        val rNew = pt.copyOf(32)
        val body = pt.copyOfRange(32, pt.size)
        if (!commit(p, secret, rNew, body).contentEquals(committed)) refuse(Failure.BAD_COMMIT)
        val (dskPub, kindCode, bundle, name) = parsing {
            readAll(body) { Parsed(Bytes.of(bytes(32)), u8(), KeyBundle.read(this), utf8()) }
        }
        val kind = DeviceKind.of(kindCode)?.takeIf { kindFits(direction, it) } ?: refuse(Failure.KIND_NOT_ALLOWED)
        if (!bundle.isValidFor(p, dskPub, accountId) || !bundle.isCurrentAt(now)) refuse(Failure.BAD_BUNDLE)
        return LinkRequest(dskPub, kind, bundle, name, code(p, secret, rOld, rNew, body))
    }

    /**
     * The response (§10.3): [payload], the JSON of §10.3, sealed to the new device's key [newDekPub]
     * and signed by the existing device, whose certificate is [senderCert].
     */
    suspend fun response(
        p: Primitives,
        secret: Bytes,
        sender: SigningKey,
        senderCert: DeviceCert,
        newDekPub: ByteArray,
        newDeviceId: Bytes,
        payload: ByteArray,
    ): ByteArray {
        val lid = linkId(p, secret)
        val sealed = p.seal(newDekPub, responseInfo(p, lid, newDeviceId), payload)
        val body = encode {
            u8(Protocol.VERSION)
            bytes(lid)
            bytes(senderCert.encode())
            bytes(sealed.enc)
            vec32(sealed.ciphertext)
        }
        return concat(body, p.sign(sender, Label.LINK_RESPONSE, body))
    }

    /**
     * Opens and checks a response as the new device (§10.3). [account] and [ikPub] are what the
     * code (direction 1) or the offer (direction 2) named; [dek], [dskPub] and [kind] are the new
     * device's own. Returns the response's JSON.
     */
    suspend fun openResponse(
        p: Primitives,
        secret: Bytes,
        account: Bytes,
        ikPub: Bytes,
        msg: ByteArray,
        dek: HpkeKey,
        dskPub: Bytes,
        kind: DeviceKind,
    ): Json.Obj {
        val lid = linkId(p, secret)
        val parsed = parsing {
            readAll(msg) {
                val version = u8()
                val id = Bytes.of(bytes(16))
                val sender = DeviceCert.read(this)
                val enc = bytes(32)
                val ct = vec32()
                bytes(64)
                Response(version, id, sender, enc, ct)
            }
        }
        if (parsed.version != Protocol.VERSION || parsed.linkId != lid) refuse(Failure.WRONG_LINK)
        val sender = parsed.sender
        if (!sender.isWellFormed(p) || sender.kind?.isPhoneOrTablet != true || sender.accountId != account || sender.ikPub != ikPub) {
            refuse(Failure.BAD_CERT)
        }
        if (!p.verify(sender.dskPub.toByteArray(), Label.LINK_RESPONSE, msg.copyOf(msg.size - 64), msg.copyOfRange(msg.size - 64, msg.size))) {
            refuse(Failure.BAD_SIGNATURE)
        }
        val myId = Ids.device(p, dskPub.toByteArray())
        val pt = dek.open(parsed.enc, responseInfo(p, lid, myId), parsed.ct) ?: refuse(Failure.BAD_CIPHERTEXT)
        val obj = Json.parseObject(pt, Json.Limits.MESSAGE) ?: refuse(Failure.MALFORMED)
        if (obj.string("confirm") != Base64Url.encode(linkConfirm(p, secret))) refuse(Failure.BAD_CONFIRM)
        val mine = parsing { DeviceCert.parse(field(obj, "cert") ?: malformed()) }
        if (!mine.isWellFormed(p) || mine.dskPub != dskPub || mine.kind != kind || mine.accountId != account || mine.ikPub != ikPub) {
            refuse(Failure.BAD_CERT)
        }
        if ("ik" in obj.fields) { // direction 1 only: the identity key and its chain
            val seed = field(obj, "ik")?.takeIf { it.size == 32 } ?: refuse(Failure.MALFORMED)
            val chain = parsing { IdentityChain.parse(if ("chain" in obj.fields) field(obj, "chain") ?: malformed() else ByteArray(0)) }
            if (Bytes.of(p.crypto.ed25519(seed).publicKey) != ikPub || !chain.provesAccountOf(p, mine)) refuse(Failure.BAD_IDENTITY)
        }
        return obj
    }

    private suspend fun responseInfo(p: Primitives, lid: Bytes, deviceId: Bytes): ByteArray =
        p.h(Label.LINK_INFO, lid.toByteArray(), deviceId.toByteArray())

    /** A base64url string field, decoded; null if it is missing, not a string or not base64url. */
    private fun field(obj: Json.Obj, name: String): ByteArray? = obj.string(name)?.let { Base64Url.decode(it) }

    /** `u8 version ‖ link_id[16] ‖ u8 msg_type`, a LinkMessage's associated data. */
    private const val HEAD_SIZE = 18

    private fun head(lid: Bytes, type: Int): ByteArray = encode {
        u8(Protocol.VERSION)
        bytes(lid)
        u8(type)
    }

    private data class Parsed(val dskPub: Bytes, val kind: Int, val bundle: KeyBundle, val name: String)

    private class Response(val version: Int, val linkId: Bytes, val sender: DeviceCert, val enc: ByteArray, val ct: ByteArray)
}
