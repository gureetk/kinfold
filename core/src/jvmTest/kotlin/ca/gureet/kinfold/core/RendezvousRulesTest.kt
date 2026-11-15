// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.JvmCrypto
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.identity.DeviceCert
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.identity.IdentityChain
import ca.gureet.kinfold.core.identity.Ids
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.core.rendezvous.Joining
import ca.gureet.kinfold.core.rendezvous.LinkCode
import ca.gureet.kinfold.core.rendezvous.Linking
import ca.gureet.kinfold.core.rendezvous.RecoveryKit
import ca.gureet.kinfold.core.rendezvous.RendezvousException
import ca.gureet.kinfold.core.rendezvous.RendezvousException.Failure
import ca.gureet.kinfold.core.rendezvous.Sealed
import ca.gureet.kinfold.core.rendezvous.ShareLinks
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.encode
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.fail

/**
 * Each check of PROTOCOL.md §9, §10 and §12 by hand, with a message that breaks it and nothing
 * else; the vector file holds only two refusals. Built from the vectors' people and devices.
 */
class RendezvousRulesTest {
    private val crypto = JvmCrypto()
    private val p = Primitives(crypto)
    private val people = Vectors.group("identities")
    private val devices: Map<String, JsonObject> = people.entrySet()
        .flatMap { (_, person) -> person.asJsonObject.getAsJsonObject("devices").entrySet().map { it.value.asJsonObject } }
        .associateBy { it.str("label") }
    private val iv = Vectors.group("invite")
    private val invite = Invite.parse(iv.hex("invite"))
    private val jr = iv.getAsJsonObject("join_request")
    private val now = jr.get("now").asLong.toULong()

    private suspend fun ik(person: String) = crypto.ed25519(people.getAsJsonObject(person).hex("ik_seed"))

    /** A join request for [invite] from Maya's phone, with any part replaced. */
    private suspend fun request(
        cert: DeviceCert = DeviceCert.parse(jr.hex("cert")),
        chain: IdentityChain = IdentityChain.parse(jr.hex("chain")),
        bundle: KeyBundle = KeyBundle.parse(jr.hex("bundle")),
        commit: Bytes? = null,
        signer: String = "maya",
        secret: Bytes = invite.secret,
    ): ByteArray {
        val c = commit ?: invite.termsCommit(p)
        val consent = Joining.consent(p, ik(signer), invite.circleId, invite.inviteId(p), cert, bundle, c)
        return Joining.request(p, secret, cert, chain, bundle, c, consent, "Maya")
    }

    @Test
    fun joinRequests() = sync {
        Joining.openRequest(p, invite, request(), now) // the unchanged request opens
        val maya = DeviceCert.parse(jr.hex("cert"))
        val bundle = KeyBundle.parse(jr.hex("bundle"))
        val web = DeviceCert.issue(p, ik("maya"), maya.accountId, maya.dskPub.toByteArray(), DeviceKind.WEB, 0UL)
        val wrongAccount = DeviceCert.issue(p, ik("maya"), Bytes.of(ByteArray(16) { 1 }), maya.dskPub.toByteArray(), DeviceKind.PHONE, 0UL)
        val otherTerms = Bytes.of(p.h(Label.MEMBER_TERMS, invite.termsSalt.toByteArray(), byteArrayOf(1)))
        val cases = listOf(
            Failure.BAD_CERT to request(cert = web),
            Failure.BAD_CERT to request(cert = wrongAccount),
            Failure.BAD_CERT to request(cert = DeviceCert.parse(flip(jr.hex("cert"), DeviceCert.SIZE - 40))), // its signature
            Failure.BAD_BUNDLE to request(bundle = KeyBundle.parse(flip(jr.hex("bundle"), KeyBundle.SIZE - 40))),
            Failure.BAD_TERMS to request(commit = otherTerms),
            Failure.BAD_CONSENT to request(signer = "jordan"),
            Failure.WRONG_INVITE to request(secret = Bytes.of(ByteArray(16) { 9 })),
        )
        for ((want, msg) in cases) assertEquals(want, refusal { Joining.openRequest(p, invite, msg, now) })
        val ok = request()
        assertEquals(Failure.BAD_BUNDLE, refusal { Joining.openRequest(p, invite, ok, bundle.notAfter) }, "a bundle no longer current")
        assertEquals(Failure.BAD_CIPHERTEXT, refusal { Joining.openRequest(p, invite, flipLast(ok), now) })
        assertEquals(Failure.MALFORMED, refusal { Joining.openRequest(p, invite, ok.copyOf(ok.size - 1), now) })
        assertEquals(Failure.MALFORMED, refusal { Joining.openRequest(p, invite, ok + byteArrayOf(0), now) }, "bytes left over")
    }

    @Test
    fun joinResults() = sync {
        val s = invite.secret
        val key = Joining.joinResultKey(p, s)
        val head = encode {
            u8(0)
            bytes(invite.inviteId(p))
        }
        suspend fun result(pt: ByteArray) = Sealed.seal(p, key, head, ByteArray(12), pt)
        assertEquals(Failure.MALFORMED, refusal { Joining.openResult(p, s, result(byteArrayOf(3) + ByteArray(32))) }, "outcome 3")
        assertEquals(Failure.MALFORMED, refusal { Joining.openResult(p, s, result(byteArrayOf(2) + ByteArray(32) { 1 })) }, "declined, with a head")
        assertEquals(Failure.MALFORMED, refusal { Joining.openResult(p, s, result(byteArrayOf(1) + ByteArray(31))) }, "a short head")
        assertEquals(Failure.WRONG_INVITE, refusal { Joining.openResult(p, Bytes.of(ByteArray(16)), result(byteArrayOf(1) + ByteArray(32))) })
        assertEquals(1, Joining.openResult(p, s, result(byteArrayOf(1) + ByteArray(32) { 1 })).first)
    }

    private val link = Vectors.group("device_link").getAsJsonObject("from_existing")
    private val code = LinkCode.parse(link.hex("link"))
    private val tablet = devices.getValue(link.str("new_device"))
    private val phone = devices.getValue(link.str("existing_device"))

    /** The vector's response payload, with any fields replaced. */
    private fun payload(vararg changes: Pair<String, Json?>): ByteArray {
        val base = objOf(JsonParser.parseString(link.str("response_payload")).asJsonObject).fields.toMutableMap()
        for ((k, v) in changes) if (v == null) base.remove(k) else base[k] = v
        return Json.Obj(base).encode()
    }

    private suspend fun response(
        body: ByteArray = payload(),
        sender: JsonObject = phone,
        secret: Bytes = code.secret,
        senderCert: DeviceCert = DeviceCert.parse(sender.hex("cert")),
    ): ByteArray {
        val dek = crypto.x25519(link.hex("new_device_dek_sk"))
        return Linking.response(
            p, secret, crypto.ed25519(sender.hex("dsk_seed")), senderCert, dek.publicKey, Ids.device(p, tablet.hex("dsk_pub")), body,
        )
    }

    /** A certificate for the existing phone's key, issued by [person]'s identity key with any account and kind. */
    private suspend fun phoneCert(person: String, account: Bytes = checkNotNull(code.accountId), kind: DeviceKind = DeviceKind.PHONE) =
        DeviceCert.issue(p, ik(person), account, phone.hex("dsk_pub"), kind, 0UL)

    private suspend fun openResponse(msg: ByteArray) = Linking.openResponse(
        p, code.secret, checkNotNull(code.accountId), checkNotNull(code.ikPub), msg, crypto.x25519(link.hex("new_device_dek_sk")),
        Bytes.of(tablet.hex("dsk_pub")), DeviceKind.TABLET,
    )

    @Test
    fun linkResponses() = sync {
        openResponse(response()) // the unchanged response opens
        val b64 = { b: ByteArray -> Json.Str(Base64Url.encode(b)) }
        val owner = phone.str("label").substringBefore('/')
        openResponse(response(senderCert = phoneCert(owner))) // a certificate made here opens too
        // The new device's own certificate, issued here with any part replaced.
        suspend fun cert(
            person: String = owner,
            dsk: ByteArray = tablet.hex("dsk_pub"),
            kind: DeviceKind = DeviceKind.TABLET,
            account: Bytes = checkNotNull(code.accountId),
        ) = b64(DeviceCert.issue(p, ik(person), account, dsk, kind, 0UL).encode())
        openResponse(response(payload("cert" to cert())))
        val cases = listOf(
            Failure.BAD_CERT to response(sender = devices.getValue("alex/phone")), // another account
            Failure.BAD_CERT to response(sender = devices.getValue("jordan/web")), // not a phone or tablet
            Failure.BAD_CERT to response(senderCert = DeviceCert.parse(flip(phone.hex("cert"), DeviceCert.SIZE - 40))), // its signature
            Failure.BAD_CERT to response(senderCert = phoneCert(owner, account = Bytes.of(ByteArray(16) { 7 }))),
            Failure.BAD_CERT to response(senderCert = phoneCert("alex")), // the account's ID under another identity key
            Failure.BAD_CONFIRM to response(payload("confirm" to b64(ByteArray(16)))),
            Failure.BAD_CONFIRM to response(payload("confirm" to null)),
            Failure.BAD_CERT to response(payload("cert" to b64(devices.getValue("jordan/web").hex("cert")))), // another device's
            Failure.BAD_CERT to response(payload("cert" to b64(flip(tablet.hex("cert"), DeviceCert.SIZE - 40)))), // its signature
            Failure.BAD_CERT to response(payload("cert" to cert(dsk = phone.hex("dsk_pub")))), // for another key
            Failure.BAD_CERT to response(payload("cert" to cert(kind = DeviceKind.PHONE))),
            Failure.BAD_CERT to response(payload("cert" to cert(account = Bytes.of(ByteArray(16) { 7 })))),
            Failure.BAD_CERT to response(payload("cert" to cert(person = "alex"))), // under another identity key
            Failure.MALFORMED to response(payload("cert" to null)),
            Failure.BAD_IDENTITY to response(payload("ik" to b64(people.getAsJsonObject("alex").hex("ik_seed")))),
            Failure.BAD_IDENTITY to response(payload("chain" to b64(people.getAsJsonObject("alex").hex("chain")))),
            Failure.MALFORMED to response(payload("ik" to Json.Num(1))),
            Failure.MALFORMED to response(payload("ik" to b64(ByteArray(31)))),
            Failure.MALFORMED to response("not JSON".encodeToByteArray()),
            Failure.WRONG_LINK to response(secret = Bytes.of(ByteArray(16) { 3 })),
            Failure.BAD_SIGNATURE to flipLast(response()),
        )
        for ((want, msg) in cases) assertEquals(want, refusal { openResponse(msg) })
        // A response isn't a payload: a circle may have more than 256 epochs to hand over.
        val epochs = Json.Arr(List(300) { b64(ByteArray(32) { i -> it.toByte() }) })
        val circles = Json.Arr(listOf(Json.Obj(mapOf("id" to b64(ByteArray(16)), "epochs" to epochs))))
        assertEquals(epochs, ((openResponse(response(payload("circles" to circles)))["circles"] as Json.Arr).items[0] as Json.Obj)["epochs"])
    }

    @Test
    fun linkMessages() = sync {
        val s = code.secret
        val offer = Linking.seal(p, s, Linking.OFFER, ByteArray(48))
        assertEquals(Failure.WRONG_LINK, refusal { Linking.open(p, s, Linking.REQUEST, offer) }, "another type")
        assertEquals(Failure.WRONG_LINK, refusal { Linking.open(p, Bytes.of(ByteArray(16)), Linking.OFFER, offer) }, "another link")
        assertEquals(Failure.MALFORMED, refusal { Linking.openOffer(p, s, Linking.seal(p, s, Linking.OFFER, ByteArray(47))) })
        assertEquals(Failure.BAD_CIPHERTEXT, refusal { Linking.open(p, s, Linking.OFFER, flipLast(offer)) })
        // A request whose bundle isn't current when the existing device checks it.
        val bundle = KeyBundle.parse(link.hex("request_body").copyOfRange(33, 33 + KeyBundle.SIZE))
        assertEquals(Failure.BAD_BUNDLE, refusal {
            Linking.openRequest(p, s, code.direction, checkNotNull(code.accountId), link.hex("commit_message"), link.hex("r_old"), link.hex("request"), bundle.notAfter)
        })
        assertEquals(Failure.BAD_BUNDLE, refusal {
            Linking.openRequest(p, s, code.direction, Bytes.of(ByteArray(16)), link.hex("commit_message"), link.hex("r_old"), link.hex("request"), link.get("now").asLong.toULong())
        }, "a bundle for another account")
    }

    @Test
    fun shareUpdates() = sync {
        val v = Vectors.group("share_link")
        val s = Bytes.of(v.hex("secret"))
        val msg = v.getAsJsonObject("update").hex("message")
        assertEquals(Failure.WRONG_LINK, refusal { ShareLinks.open(p, Bytes.of(ByteArray(16)), msg) })
        assertEquals(Failure.BAD_CIPHERTEXT, refusal { ShareLinks.open(p, s, flipLast(msg)) })
        val head = msg.copyOf(33)
        val key = ShareLinks.shareKey(p, s)
        assertEquals(Failure.BAD_PADDING, refusal { ShareLinks.open(p, s, Sealed.seal(p, key, head, ByteArray(12), ByteArray(256))) })
        assertEquals(Failure.BAD_PADDING, refusal { ShareLinks.open(p, s, Sealed.seal(p, key, head, ByteArray(12), byteArrayOf(0x7b, 0x7d, -128) + ByteArray(297))) }, "300 bytes")
        assertEquals(Failure.BAD_PAYLOAD, refusal { ShareLinks.open(p, s, ShareLinks.update(p, s, 2UL, 3UL, "[1]".encodeToByteArray())) })
        assertEquals(Failure.BAD_PAYLOAD, refusal { ShareLinks.open(p, s, ShareLinks.update(p, s, 2UL, 3UL, "{}".encodeToByteArray())) }, "no t")
    }

    @Test
    fun codesThatDontParse() {
        val inviteBytes = iv.hex("invite")
        assertFailsWith<ProtocolException> { Invite.parse(byteArrayOf(1) + inviteBytes.copyOfRange(1, inviteBytes.size)) }
        assertFailsWith<ProtocolException> { Invite.parse(inviteBytes + byteArrayOf(0)) }
        assertFailsWith<ProtocolException> { Invite.fromCode("KFL0" + iv.str("code").substring(4)) }
        val linkBytes = link.hex("link")
        assertFailsWith<ProtocolException> { LinkCode.parse(byteArrayOf(1) + linkBytes.copyOfRange(1, linkBytes.size)) }
        assertFailsWith<ProtocolException> { LinkCode.parse(byteArrayOf(0, 3) + linkBytes.copyOfRange(2, linkBytes.size)) }
        assertFailsWith<ProtocolException> { LinkCode.parse(byteArrayOf(0, 2) + linkBytes.copyOfRange(2, linkBytes.size)) }
        val kit = Vectors.root.getAsJsonArray("recovery_kits").first().asJsonObject.hex("kit")
        assertFailsWith<ProtocolException> { RecoveryKit.parse(kit.copyOf(kit.size - 1)) }
        assertFailsWith<ProtocolException> { RecoveryKit.parse(byteArrayOf(1) + kit.copyOfRange(1, kit.size)) }
        // A server URL that isn't UTF-8.
        assertFailsWith<ProtocolException> { RecoveryKit.parse(byteArrayOf(0, 0, 1, -1) + kit.copyOfRange(3 + 22, kit.size)) }
    }

    private fun flip(b: ByteArray, i: Int): ByteArray = b.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }

    private fun flipLast(b: ByteArray): ByteArray = flip(b, b.size - 1)

    private suspend fun refusal(block: suspend () -> Unit): Failure {
        try {
            block()
        } catch (e: RendezvousException) {
            return e.failure
        }
        fail("not refused")
    }
}
