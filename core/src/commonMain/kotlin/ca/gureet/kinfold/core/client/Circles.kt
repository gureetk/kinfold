// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.identity.IdentityChain
import ca.gureet.kinfold.core.log.Body
import ca.gureet.kinfold.core.log.Details
import ca.gureet.kinfold.core.log.EntryHeader
import ca.gureet.kinfold.core.log.EntryType
import ca.gureet.kinfold.core.log.LogEntry
import ca.gureet.kinfold.core.log.MemberLog
import ca.gureet.kinfold.core.log.MemberTerms
import ca.gureet.kinfold.core.log.Role
import ca.gureet.kinfold.core.log.Rules
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.push.WatchGrant
import ca.gureet.kinfold.core.rendezvous.Invite
import ca.gureet.kinfold.core.rendezvous.Joining
import ca.gureet.kinfold.core.rendezvous.RendezvousException
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.withLock

/** An invite this device made and keeps until someone joins with it or it ends (PROTOCOL.md §9.1). */
class PendingInvite(val invite: Invite, val inviteId: Bytes) {
    /** What the invitee scans or pastes: `KFI0` and the invite. */
    val code: String get() = invite.code
}

/** Someone admitted to a circle through an invite. [name] is what they typed; nothing verifies it. */
class Admitted(val accountId: Bytes, val deviceId: Bytes, val name: String)

/**
 * A circle this device joined. [detailsMatched] is false when the entry that added it carries
 * details that didn't open to the terms it accepted: it has then joined as an adult (§9.4).
 */
class Joined(val circleId: Bytes, val detailsMatched: Boolean)

/** The terms for an adult (§5.5): no guardians, and the rules a teen would have, which don't apply. */
fun adultTerms(): MemberTerms = MemberTerms(Role.ADULT.code, 0UL, emptyList(), Rules.DEFAULT)

/**
 * Creates a circle with this device as its founder and only admin (PROTOCOL.md §5.3): a `GENESIS`
 * entry under a fresh epoch secret, with [name] in its encrypted details. The circle's ID.
 */
suspend fun Client.createCircle(name: String): Bytes {
    val nameBytes = name.encodeToByteArray()
    require(nameBytes.size in 1..128) { "a circle's name is 1 to 128 bytes" }
    val secret = p.random(32)
    val header = EntryHeader(
        Protocol.VERSION, Protocol.SUITE, EntryType.GENESIS.code, Bytes.zero(16), 0UL, Bytes.zero(32), clock.now(), keys.deviceId, 0,
    )
    val details = Details.seal(p, secret, header.encode(), Details.encodeGenesis(name))
    val body = Body.Genesis(keys.cert, IdentityChain(emptyList()), keys.bundle, Details.epochCommit(p, 0, secret), details)
    val genesis = LogEntry.build(p, keys.signing, header, body.encode())
    val circleId = LogEntry.circleId(p, genesis)
    // The secret is kept before the circle exists on the server, so that a crash can't leave a circle nobody can read.
    addCircle(circleId, mapOf(0L to secret))
    try {
        val created = authed { api.createCircle(genesis) }
        if (created != circleId) throw ClientException("the server named the new circle wrongly")
        sync(circleId)
    } catch (e: Exception) {
        dropCircle(circleId)
        throw e
    }
    return circleId
}

/**
 * Makes an invite to [circleId] (§9.1) offering [terms], and registers it with the server, which
 * mints a registration token with it where the operator allows that. [circleName] and
 * [inviterName] are hints for the join screen. The invite is kept until it is used or ends.
 */
suspend fun Client.invite(
    circleId: Bytes,
    circleName: String,
    inviterName: String,
    validForMs: ULong = 86_400_000UL,
    terms: MemberTerms = adultTerms(),
): PendingInvite {
    val secret = Bytes.of(p.random(16))
    val salt = Bytes.of(p.random(16))
    val inviteId = Joining.inviteId(p, secret)
    val expiresAt = clock.now() + validForMs
    val token = authed { api.createInvite(circleId, inviteId, expiresAt, regToken = true) } ?: Bytes.of(ByteArray(0))
    val invite = Invite(
        serverUrl, serverKey, circleId, secret, Bytes.of(keys.identity.publicKey), expiresAt, token, salt,
        Bytes.of(terms.encode()), circleName, inviterName, emptyList(),
    )
    lock.withLock {
        storageWrite(Names.invite(inviteId), invite.encode())
        storageWrite(Names.INVITES, frames(*(pendingInviteIds() + inviteId).map { it.toByteArray() }.toTypedArray()))
    }
    return PendingInvite(invite, inviteId)
}

/** The invites this device made that haven't been used and haven't ended. */
suspend fun Client.pendingInvites(): List<PendingInvite> = lock.withLock {
    val now = clock.now()
    pendingInviteIds().mapNotNull { id ->
        val invite = storageRead(Names.invite(id))?.let {
            try {
                Invite.parse(it)
            } catch (_: ProtocolException) {
                null
            }
        }
        invite?.takeIf { it.expiresAt > now }?.let { PendingInvite(it, id) }
    }
}

/**
 * Admits the first person waiting on [pending] whose request checks out (§9.2): opens the request,
 * appends `ADD_MEMBER` with exactly the invite's salt and terms, sends `welcome` to the new device
 * and posts the result. An app shows the name and the safety code and waits for the person to tap
 * Allow before calling this; a test harness calls it at once. Null when nobody is waiting.
 */
suspend fun Client.admit(pending: PendingInvite, asAdmin: Boolean = false): Admitted? {
    val invite = pending.invite
    val requests = try {
        authed { api.joinRequests(pending.inviteId) }
    } catch (e: ApiException) {
        if (e.status == 410) forgetInvite(pending.inviteId)
        throw e
    }
    for (msg in requests) {
        val req = try {
            Joining.openRequest(p, invite, msg, clock.now())
        } catch (e: RendezvousException) {
            listener.failed("opening a join request", e)
            continue
        }
        val deviceId = req.cert.deviceId(p)
        val entry = appendEntry(invite.circleId) { state, secrets ->
            val secret = secrets[state.epoch] ?: throw ClientException("this device lacks the circle's current epoch secret")
            val header = EntryHeader(
                Protocol.VERSION, Protocol.SUITE, EntryType.ADD_MEMBER.code, invite.circleId, (state.seq + 1).toULong(), state.head,
                clock.now(), keys.deviceId, state.epoch,
            )
            val details = Details.seal(p, secret, header.encode(), Details.encodeMember(invite.termsSalt.toByteArray(), invite.terms))
            val body = Body.AddMember(req.cert, req.chain, req.bundle, pending.inviteId, req.termsCommit, req.consent, asAdmin, details)
            LogEntry.build(p, keys.signing, header, body.encode())
        }
        val head = LogEntry.hash(p, entry)
        send(invite.circleId, Payloads.welcome(secrets(invite.circleId), head), to = listOf(deviceId), wake = Wake.NOTIFY)
        authed { api.putJoinResult(pending.inviteId, Joining.result(p, invite.secret, Joining.ADDED, head)) }
        forgetInvite(pending.inviteId)
        return Admitted(req.cert.accountId, deviceId, req.name)
    }
    return null
}

/**
 * Joins the circle of [invite] (§9.2–9.4): posts a join request, waits for the inviter's answer,
 * fetches and verifies the log, checks the entry that added this device, and takes the welcome.
 * The app shows the invite's terms and gets the person's agreement before calling this.
 */
suspend fun Client.join(invite: Invite, name: String, timeoutMs: Long = 600_000L): Joined {
    if (invite.serverUrl != serverUrl || invite.serverKey != serverKey) throw ClientException("the invite is for another server")
    val circleId = invite.circleId
    val inviteId = invite.inviteId(p)
    val termsCommit = invite.termsCommit(p)
    val consent = Joining.consent(p, keys.identity, circleId, inviteId, keys.cert, keys.bundle, termsCommit)
    val request = Joining.request(p, invite.secret, keys.cert, IdentityChain(emptyList()), keys.bundle, termsCommit, consent, name)
    val deadline = monotonicMillis() + timeoutMs
    // Kept from the start, so that the welcome, which can come on the stream at any moment, finds the circle.
    addCircle(circleId)
    val head: Bytes
    try {
        authed { api.postJoinRequest(inviteId, request) }
        var result: ByteArray? = null
        while (result == null) {
            if (monotonicMillis() > deadline) throw ClientException("no answer to the join request in time")
            result = authed { api.joinResult(inviteId, RESULT_WAIT_S) }
        }
        val (outcome, h) = Joining.openResult(p, invite.secret, result)
        if (outcome != Joining.ADDED) throw ClientException("the inviter declined")
        head = h
        sync(circleId)
        checkAdded(invite, inviteId, termsCommit, consent, head)
    } catch (e: Exception) {
        // Not added, or not by the entry this device asked for: it isn't a member (§9.4).
        dropCircle(circleId)
        throw e
    }
    while (true) {
        val state = state(circleId) ?: throw ClientException("this device left the circle while joining")
        if (state.epoch in secrets(circleId)) {
            val seq = state.hashes.indexOf(head).toLong()
            return Joined(circleId, state.flags.none { it.first == seq && it.second == Reason.BAD_DETAILS })
        }
        if (monotonicMillis() > deadline) throw ClientException("no welcome in time")
        if (fetchInbox() == 0) delay(WELCOME_POLL_MS)
    }
}

/**
 * What §9.4 asks of a new member: the log is the invite's circle, and the entry the result names
 * adds this device with its own invite ID, terms commitment and consent, authored by a device of
 * the account whose identity key is in the invite, as the log stood before that entry.
 */
private suspend fun Client.checkAdded(invite: Invite, inviteId: Bytes, termsCommit: Bytes, consent: Bytes, head: Bytes) {
    val state = state(invite.circleId) ?: throw ClientException("not in the circle")
    if (state.circleId != invite.circleId) throw ClientException("the log isn't the invite's circle")
    val seq = state.hashes.indexOf(head)
    if (seq < 0) throw ClientException("the log doesn't hold the entry the inviter named")
    val all = entries(invite.circleId)
    val entry = LogEntry.parse(all[seq])
    val body = if (entry.header.typeCode == EntryType.ADD_MEMBER.code) Body.parse(EntryType.ADD_MEMBER, entry.body) as? Body.AddMember else null
    if (body == null || body.cert.deviceId(p) != keys.deviceId || body.inviteId != inviteId || body.termsCommit != termsCommit || body.consentSig != consent) {
        throw ClientException("the entry the inviter named doesn't answer this device's request")
    }
    val before = MemberLog.replay(p, all.subList(0, seq), null).first
    val author = before.device(entry.header.author)
    if (author == null || before.members[author.accountId]?.ikPub != invite.inviterIkPub) {
        throw ClientException("the entry adding this device wasn't made by the inviter")
    }
}

private suspend fun Client.forgetInvite(inviteId: Bytes) {
    lock.withLock {
        storageDelete(Names.invite(inviteId))
        storageWrite(Names.INVITES, frames(*pendingInviteIds().filter { it != inviteId }.map { it.toByteArray() }.toTypedArray()))
    }
}

private fun Client.pendingInviteIds(): List<Bytes> =
    storageRead(Names.INVITES)?.let { framesLenient(it) }?.filter { it.size == 16 }?.map { Bytes.of(it) } ?: emptyList()

/**
 * Issues a silence-watch grant (§14.1) from this device to [watcher]'s account, telling it after
 * [afterMin] minutes of silence, for [validForMs], and sends it to the circle as `watch_grant`.
 * A phone issues one only with its person's agreement, or under a teen's rules.
 */
suspend fun Client.grantWatch(circleId: Bytes, watcher: Bytes, afterMin: Int, validForMs: ULong = WEEK_MS): WatchGrant {
    val now = clock.now()
    val grant = WatchGrant.issue(p, keys.signing, circleId, keys.deviceId, watcher, afterMin, now, now + validForMs)
    send(circleId, Payloads.watchGrant(grant))
    return grant
}

/**
 * Registers a grant this account was given (API.md §8), once it checks out as the server will
 * check it. It is put again after every login, until it ends.
 */
suspend fun Client.registerWatch(grant: WatchGrant) {
    val state = state(grant.circleId) ?: throw ClientException("not a member of the grant's circle")
    if (grant.watcherAccount != keys.accountId || !grant.isValidAt(p, state, clock.now())) {
        throw ClientException("the grant isn't a valid one for this account")
    }
    authed { api.putWatch(grant.circleId, grant.watchedDevice, grant.encode()) }
    lock.withLock { keepGrant(grant) }
}

/** The watches this account holds in [circleId], and those on its devices (API.md §8). */
suspend fun Client.watches(circleId: Bytes): List<WatchInfo> = authed { api.watches(circleId) }

/** The grant a `watch_grant` payload carries, or null if it carries none that parses. */
fun grantOf(payload: Json.Obj): WatchGrant? {
    if (payload.string("t") != "watch_grant") return null
    val raw = payload.string("grant")?.let { Base64Url.decode(it) } ?: return null
    return try {
        WatchGrant.parse(raw)
    } catch (_: ProtocolException) {
        null
    }
}

/** A push registration for an app the family builds itself, which its server reaches through Apple directly (API.md §12). */
fun apnsRegistration(notifyToken: ByteArray, locateToken: ByteArray?, environment: String): Json.Obj {
    val fields = LinkedHashMap<String, Json>()
    fields["kind"] = Json.Str("apns")
    fields["notify"] = Json.Str(Base64Url.encode(notifyToken))
    locateToken?.let { fields["locate"] = Json.Str(Base64Url.encode(it)) }
    fields["environment"] = Json.Str(environment)
    return Json.Obj(fields)
}

/** How long a join waits for the inviter's answer in one call (API.md §9). */
private const val RESULT_WAIT_S = 25

private const val WELCOME_POLL_MS = 2_000L

private const val WEEK_MS: ULong = 604_800_000UL

