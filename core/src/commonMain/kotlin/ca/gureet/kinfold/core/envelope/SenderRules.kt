// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.envelope

import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.log.CircleState
import ca.gureet.kinfold.core.log.Device
import ca.gureet.kinfold.core.log.Role
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.push.WatchGrant
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes

/** Who may send what (PROTOCOL.md §8.2), as step 15 of §7.6 checks it. */
object SenderRules {
    enum class Verdict { ALLOWED, NOT_ALLOWED, HELD }

    /** Types that travel only in circle envelopes. */
    val CIRCLE_TYPES: Set<String> = setOf(
        "loc", "hb", "evt", "checkin", "sos", "place", "profile", "chat", "pause_req", "pause_deny", "watch_grant",
        "refresh_req", "refresh",
    )

    /** Types that travel only in direct envelopes. */
    val DIRECT_TYPES: Set<String> = setOf("sig", "welcome", "ik")

    /** The only types a web or Home Assistant device may send. Phones and tablets may send every type. */
    private val LIMITED_KINDS: Map<DeviceKind, Set<String>> = mapOf(
        DeviceKind.WEB to setOf("sig", "refresh_req"),
        DeviceKind.HOME_ASSISTANT to setOf("refresh_req"),
    )

    /** Types whose rule depends on roles or guardians, which a frozen device doesn't know (§6.5). */
    private val NEED_ROLES: Set<String> = setOf("pause_req", "pause_deny", "place")

    /**
     * Whether [sender] may send [payload] in an envelope of [kind] to device [me], given the
     * receiver's log [state]. [Verdict.HELD] when the answer needs roles and the receiver's private
     * state is frozen. A type this version doesn't define passes from a phone or tablet in either
     * kind of envelope; the app then ignores it (§8.1).
     */
    suspend fun verdict(p: Primitives, payload: Json.Obj, kind: Int, sender: Device, state: CircleState, me: Bytes): Verdict {
        val t = payload.string("t") ?: return Verdict.NOT_ALLOWED
        LIMITED_KINDS[sender.kind]?.let { if (t !in it) return Verdict.NOT_ALLOWED }
        if ((t in CIRCLE_TYPES && kind != EnvelopeHeader.CIRCLE) || (t in DIRECT_TYPES && kind != EnvelopeHeader.DIRECT)) {
            return Verdict.NOT_ALLOWED
        }
        if (t in NEED_ROLES && state.privateUnknownFrom != null) return Verdict.HELD
        val member = state.members.getValue(sender.accountId)
        val ok = when (t) {
            // from a device of a teen, about that teen
            "pause_req" -> member.role == Role.TEEN
            // from a guardian of the teen it names
            "pause_deny" -> {
                val teen = bytesField(payload, "teen", 16)?.let { state.members[it] }
                teen != null && teen.role == Role.TEEN && sender.accountId in teen.guardians
            }
            // from a device of the account that authored the entry adding the receiver
            "welcome" -> state.device(me)?.addedBy == sender.accountId
            // from the device the grant names as watched
            "watch_grant" -> bytesField(payload, "grant", WatchGrant.SIZE)
                ?.let { WatchGrant.parse(it.toByteArray()).watchedDevice == sender.id } == true
            // from the receiver's own account, with a seed for the identity key the log now shows
            "ik" -> {
                val seed = bytesField(payload, "ik", 32)
                state.device(me)?.accountId == sender.accountId && seed != null &&
                    Bytes.of(p.crypto.ed25519(seed.toByteArray()).publicKey) == member.ikPub
            }
            // a well-formed ID; a teen changes only places of their own
            "place" -> {
                val creator = bytesField(payload, "creator", 16)
                val n = bytesField(payload, "n", 8)
                creator != null && n != null && bytesField(payload, "id", 8) == placeId(p, creator, n) &&
                    (member.role != Role.TEEN || creator == sender.accountId)
            }
            else -> true
        }
        return if (ok) Verdict.ALLOWED else Verdict.NOT_ALLOWED
    }

    /** A place's ID: H("place-id", creator ‖ n)[0:8] (§8.2). */
    suspend fun placeId(p: Primitives, creator: Bytes, n: Bytes): Bytes =
        Bytes.of(p.h(Label.PLACE_ID, creator.toByteArray(), n.toByteArray()).copyOf(8))

    /** The field [name] if it is a base64url string of exactly [size] bytes, else null (§8.2). */
    fun bytesField(payload: Json.Obj, name: String, size: Int): Bytes? =
        payload.string(name)?.let { Base64Url.decode(it) }?.takeIf { it.size == size }?.let { Bytes.of(it) }
}
