// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.JvmCrypto
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.identity.DeviceCert
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.identity.Ids
import ca.gureet.kinfold.core.identity.SafetyCode
import ca.gureet.kinfold.core.log.Body
import ca.gureet.kinfold.core.log.EntryType
import ca.gureet.kinfold.core.log.LogEntry
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.core.rendezvous.Joining
import ca.gureet.kinfold.core.rendezvous.LinkCode
import ca.gureet.kinfold.core.rendezvous.Linking
import ca.gureet.kinfold.core.rendezvous.RecoveryKit
import ca.gureet.kinfold.core.rendezvous.RendezvousException
import ca.gureet.kinfold.core.rendezvous.RendezvousException.Failure
import ca.gureet.kinfold.core.rendezvous.ShareLinks
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Codes
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.toHex
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The `safety_codes`, `invite`, `device_link`, `recovery_kits` and `share_link` vectors
 * (PROTOCOL.md §9 to §12): every structure parsed and written again byte for byte, every message
 * opened and checked, and every message sealed again from its nonce. Link responses, which use HPKE,
 * are opened, and sealed here and opened again.
 */
class RendezvousTest {
    private val crypto = JvmCrypto()
    private val p = Primitives(crypto)
    private val devices: Map<String, JsonObject> = Vectors.group("identities").entrySet()
        .flatMap { (_, person) -> person.asJsonObject.getAsJsonObject("devices").entrySet().map { it.value.asJsonObject } }
        .associateBy { it.str("label") }

    @Test
    fun safetyCodes() = sync {
        val cases = Vectors.root.getAsJsonArray("safety_codes").map { it.asJsonObject }
        assertTrue(cases.isNotEmpty())
        for (t in cases) {
            val a = t.hex("ik_pub_a")
            val b = t.hex("ik_pub_b")
            assertEquals(t.str("half_a"), SafetyCode.half(p, a))
            assertEquals(t.str("half_b"), SafetyCode.half(p, b))
            assertEquals(t.str("code"), SafetyCode.code(p, a, b))
            assertEquals(t.str("code"), SafetyCode.code(p, b, a), "the same whichever key is a")
            assertEquals(12, t.str("code").split(" ").size)
            assertEquals(t.str("qr"), SafetyCode.qr(a, b))
            assertEquals(t.str("qr"), SafetyCode.qr(b, a))
        }
    }

    @Test
    fun invite() = sync {
        val v = Vectors.group("invite")
        val bytes = v.hex("invite")
        val inv = Invite.parse(bytes)
        val f = v.getAsJsonObject("fields")
        assertEquals(f.str("server_url"), inv.serverUrl)
        assertEquals(f.str("server_key"), inv.serverKey.hex)
        assertEquals(f.str("circle_id"), inv.circleId.hex)
        assertEquals(f.str("secret"), inv.secret.hex)
        assertEquals(f.str("inviter_ik_pub"), inv.inviterIkPub.hex)
        assertEquals(f.get("expires_at").asLong.toULong(), inv.expiresAt)
        assertEquals(f.str("reg_token"), inv.regToken.hex)
        assertEquals(f.str("terms_salt"), inv.termsSalt.hex)
        assertEquals(f.str("terms"), inv.termsBytes.hex)
        assertEquals(f.str("circle_name"), inv.circleName)
        assertEquals(f.str("inviter_name"), inv.inviterName)
        assertEquals(f.getAsJsonArray("guardian_names").map { it.asString }, inv.guardianNames)
        val terms = v.getAsJsonObject("terms")
        assertEquals(terms.int("role"), inv.terms.role)
        assertEquals(terms.get("teen_until").asLong.toULong(), inv.terms.teenUntil)
        assertEquals(terms.getAsJsonArray("guardians").map { it.asString }, inv.terms.guardians.map { it.hex })
        assertEquals(terms.getAsJsonObject("rules").get("history_days").asInt, inv.terms.rules.historyDays)
        assertContentEquals(bytes, inv.encode(), "written again byte for byte")
        assertEquals(v.str("code"), inv.code)
        assertEquals(v.str("link"), inv.link(v.str("link_base")))
        assertContentEquals(bytes, Invite.fromCode(v.str("code")).encode())
        assertEquals(v.str("invite_id"), inv.inviteId(p).hex)
        assertEquals(v.str("join_key"), Joining.joinKey(p, inv.secret).toHex())
        assertEquals(v.str("join_result_key"), Joining.joinResultKey(p, inv.secret).toHex())
        assertEquals(v.str("terms_commit"), inv.termsCommit(p).hex)
    }

    @Test
    fun joinRequest() = sync {
        val v = Vectors.group("invite")
        val inv = Invite.parse(v.hex("invite"))
        val jr = v.getAsJsonObject("join_request")
        val msg = jr.hex("message")
        val got = Joining.openRequest(p, inv, msg, jr.get("now").asLong.toULong())
        assertEquals(jr.str("name"), got.name)
        assertEquals(jr.str("cert"), got.cert.encode().toHex())
        assertEquals(jr.str("chain"), got.chain.encode().toHex())
        assertEquals(jr.str("bundle"), got.bundle.encode().toHex())
        assertEquals(jr.str("consent"), got.consent.hex)
        assertEquals(v.str("terms_commit"), got.termsCommit.hex)
        val again = Joining.request(p, inv.secret, got.cert, got.chain, got.bundle, got.termsCommit, got.consent, got.name, jr.hex("nonce"))
        assertContentEquals(msg, again, "sealed again from its nonce")
        // The ADD_MEMBER entry that answers it carries the same invite, terms and consent.
        val entry = LogEntry.parse(Vectors.group("log").list("entries")[v.int("log_entry_seq")].hex("raw"))
        val body = Body.parse(EntryType.ADD_MEMBER, entry.body) as Body.AddMember
        assertEquals(v.str("invite_id"), body.inviteId.hex)
        assertEquals(got.consent, body.consentSig)
        assertEquals(got.termsCommit, body.termsCommit)
    }

    @Test
    fun joinResults() = sync {
        val v = Vectors.group("invite")
        val secret = Invite.parse(v.hex("invite")).secret
        val results = v.getAsJsonObject("join_result")
        assertEquals(setOf("added", "declined"), results.keySet())
        for ((name, r) in results.entrySet()) {
            val o = r.asJsonObject
            val (outcome, head) = Joining.openResult(p, secret, o.hex("message"))
            assertEquals(o.int("outcome"), outcome, name)
            assertEquals(o.str("head"), head.hex, name)
            assertContentEquals(o.hex("message"), Joining.result(p, secret, outcome, head, o.hex("nonce")), name)
        }
    }

    @Test
    fun deviceLinks() = sync {
        val v = Vectors.group("device_link")
        for (name in listOf("from_existing", "from_new", "from_existing_rotated")) {
            val d = v.getAsJsonObject(name)
            val link = LinkCode.parse(d.hex("link"))
            val secret = link.secret
            assertEquals(d.int("direction"), link.direction, name)
            assertContentEquals(d.hex("link"), link.encode(), "$name: written again")
            assertEquals(d.str("code_text"), link.code, name)
            assertContentEquals(d.hex("link"), LinkCode.fromCode(d.str("code_text")).encode(), name)
            assertEquals(d.str("link_id"), Linking.linkId(p, secret).hex, name)
            assertEquals(d.str("link_key"), Linking.linkKey(p, secret).toHex(), name)
            assertEquals(d.str("confirm"), Linking.linkConfirm(p, secret).toHex(), name)
            // Whose account: from the code in direction 1, from the existing phone's offer in direction 2.
            val (account, ikPub) = if (link.direction == Linking.FROM_NEW) {
                val offer = d.hex("offer")
                val got = Linking.openOffer(p, secret, offer)
                assertContentEquals(offer, Linking.seal(p, secret, Linking.OFFER, concat(got.first.toByteArray(), got.second.toByteArray()), d.hex("offer_nonce")))
                got
            } else {
                checkNotNull(link.accountId) to checkNotNull(link.ikPub)
            }
            assertEquals(d.str("account_id"), account.hex, name)
            assertEquals(d.str("ik_pub"), ikPub.hex, name)
            // The commit, the nonce and the request, each sealed again from its nonce.
            val rOld = Linking.open(p, secret, Linking.NONCE, d.hex("nonce_message"))
            assertEquals(d.str("r_old"), rOld.toHex(), name)
            assertContentEquals(d.hex("nonce_message"), Linking.seal(p, secret, Linking.NONCE, rOld, d.hex("nonce_nonce")), name)
            val rNew = d.hex("r_new")
            val body = d.hex("request_body")
            assertEquals(d.str("commit"), Linking.commit(p, secret, rNew, body).toHex(), name)
            assertContentEquals(d.hex("commit_message"), Linking.seal(p, secret, Linking.COMMIT, Linking.commit(p, secret, rNew, body), d.hex("commit_nonce")), name)
            assertContentEquals(d.hex("request"), Linking.seal(p, secret, Linking.REQUEST, concat(rNew, body), d.hex("request_nonce")), name)
            val req = Linking.openRequest(p, secret, link.direction, account, d.hex("commit_message"), rOld, d.hex("request"), d.get("now").asLong.toULong())
            assertEquals(d.str("code"), req.code, name)
            assertEquals(d.str("device_name"), req.name, name)
            assertEquals(d.str("code"), Linking.code(p, secret, rOld, rNew, body), name)
            assertContentEquals(body, Linking.requestBody(req.dskPub, req.kind, req.bundle, req.name), name)
            // The response, as the new device opens it.
            val nd = devices.getValue(d.str("new_device"))
            val kind = checkNotNull(DeviceKind.of(nd.int("kind")))
            val dek = crypto.x25519(d.hex("new_device_dek_sk"))
            val want = objOf(JsonParser.parseString(d.str("response_payload")).asJsonObject)
            val resp = Linking.openResponse(p, secret, account, ikPub, d.hex("response"), dek, Bytes.of(nd.hex("dsk_pub")), kind)
            assertEquals(want, resp, name)
            assertEquals(nd.str("cert"), Base64Url.decode(checkNotNull(resp.string("cert")))?.toHex(), name)
            assertEquals(link.direction == Linking.FROM_EXISTING, "ik" in resp.fields, "$name: the identity key moves in direction 1 only")
            // A response sealed here, by the existing device, opens the same way.
            val ed = devices.getValue(d.str("existing_device"))
            val sealed = Linking.response(
                p, secret, crypto.ed25519(ed.hex("dsk_seed")), DeviceCert.parse(ed.hex("cert")), dek.publicKey,
                Ids.device(p, nd.hex("dsk_pub")), d.str("response_payload").encodeToByteArray(),
            )
            assertEquals(want, Linking.openResponse(p, secret, account, ikPub, sealed, dek, Bytes.of(nd.hex("dsk_pub")), kind), name)
        }
    }

    @Test
    fun refusedLinkRequests() = sync {
        val expected = mapOf("request_not_committed" to Failure.BAD_COMMIT, "kind_does_not_fit_direction" to Failure.KIND_NOT_ALLOWED)
        val cases = Vectors.group("device_link").list("refused")
        assertEquals(expected.keys, cases.map { it.str("name") }.toSet())
        for (t in cases) {
            val failure = refusal {
                Linking.openRequest(
                    p, Bytes.of(t.hex("secret")), t.int("direction"), Bytes.of(t.hex("account_id")), t.hex("commit_message"),
                    t.hex("r_old"), t.hex("request"), t.get("now").asLong.toULong(),
                )
            }
            assertEquals(expected[t.str("name")], failure, t.str("name"))
        }
    }

    @Test
    fun recoveryKits() = sync {
        val cases = Vectors.root.getAsJsonArray("recovery_kits").map { it.asJsonObject }
        assertEquals(listOf("jordan", "alex"), cases.map { it.str("owner") })
        for (t in cases) {
            val owner = t.str("owner")
            val kit = RecoveryKit.fromCode(t.str("code"))
            assertContentEquals(t.hex("kit"), kit.encode(), owner)
            assertContentEquals(t.hex("kit"), Codes.read(Codes.RECOVERY_KIT, t.str("code")), owner)
            assertEquals(t.str("code"), kit.code, owner)
            assertEquals(t.str("account_id"), kit.accountId.hex, owner)
            assertEquals(t.str("ik_seed"), kit.ikSeed.hex, owner)
            assertEquals(t.str("chain"), kit.chain.encode().toHex(), owner)
            assertEquals(t.str("recovery_dsk_seed"), kit.recoveryDskSeed.hex, owner)
            assertEquals(t.get("created_at").asLong.toULong(), kit.createdAt, owner)
            val recovery = crypto.ed25519(kit.recoveryDskSeed.toByteArray())
            assertEquals(t.str("recovery_device_id"), Ids.device(p, recovery.publicKey).hex, owner)
            // The kit's identity key and chain can certify the recovery device for the account.
            val ik = crypto.ed25519(kit.ikSeed.toByteArray())
            val cert = DeviceCert.issue(p, ik, kit.accountId, recovery.publicKey, DeviceKind.RECOVERY, 0UL)
            assertTrue(cert.isWellFormed(p) && kit.chain.provesAccountOf(p, cert), owner)
        }
    }

    @Test
    fun shareLink() = sync {
        val v = Vectors.group("share_link")
        val secret = Bytes.of(v.hex("secret"))
        assertEquals(v.str("link_id"), ShareLinks.linkId(p, secret).hex)
        assertEquals(v.str("share_key"), ShareLinks.shareKey(p, secret).toHex())
        assertEquals(v.str("url"), ShareLinks.url(p, v.str("server_url"), secret))
        val u = v.getAsJsonObject("update")
        val got = ShareLinks.open(p, secret, u.hex("message"))
        assertEquals(u.get("seq").asLong.toULong(), got.seq)
        assertEquals(u.get("expires_at").asLong.toULong(), got.expiresAt)
        assertEquals(objOf(u.getAsJsonObject("payload")), got.payload)
        assertEquals(got.payload, Json.parsePayload(v.hex("payload_bytes")))
        val again = ShareLinks.update(p, secret, got.seq, got.expiresAt, v.hex("payload_bytes"), u.hex("nonce"))
        assertContentEquals(u.hex("message"), again, "sealed again from its nonce")
    }

    private suspend fun refusal(block: suspend () -> Unit): Failure {
        try {
            block()
        } catch (e: RendezvousException) {
            return e.failure
        }
        fail("not refused")
    }
}
