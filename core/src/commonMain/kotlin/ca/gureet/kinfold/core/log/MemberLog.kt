// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.log

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.crypto.Ed25519Checks
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.identity.DeviceCert
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.identity.Wrap
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.concat

/** The outcome of one entry (PROTOCOL.md §6.2). */
sealed class Outcome {
    /** The log is broken at this entry: nothing is applied, and nothing after it may be. */
    class Fatal(val reason: Reason) : Outcome()

    /** Applied: the new [state], and whether the entry was accepted, rejected or deferred. */
    class Applied(val state: CircleState, val result: Result, val reason: Reason?) : Outcome()
}

enum class Result {
    /** Applied; [Outcome.Applied.reason] is `bad_details` when the details were unreadable. */
    ACCEPTED,

    /** A `POLICY` entry that changes nothing but stays in the chain, flagged. */
    REJECTED,

    /** Public effects applied; the private rules wait for an epoch secret (§6.5). */
    DEFERRED,
}

/** Circle options (§16.7). */
object Options {
    const val WEB: Long = 0x1
    const val HOME_ASSISTANT: Long = 0x2
    const val DEFINED: Long = WEB or HOME_ASSISTANT
}

/**
 * Validation of the member log (§6.3): the checks in order, the public rules a server makes,
 * and, for a client, the private rules on the encrypted details and guardian repair.
 */
object MemberLog {
    const val MAX_MEMBERS = 32
    const val MAX_DEVICES = 8
    const val MAX_GUARDIANS = 8
    const val MAX_PAUSES = 16
    const val PAUSE_MAX_MS: ULong = 86_400_000UL

    /**
     * Processes one entry against [state], which is never changed. [secrets] maps epochs to the
     * epoch secrets this client holds; a secret that doesn't match the log's commitment is
     * ignored. Null runs the server's public mode: steps 1–9 and the public effects, every
     * outcome fatal or accepted.
     */
    suspend fun apply(p: Primitives, state: CircleState, raw: ByteArray, secrets: Map<Long, ByteArray>?): Outcome = try {
        process(p, state, raw, secrets)
    } catch (e: ProtocolException) {
        Outcome.Fatal(e.reason)
    }

    /** Applies [entries] in order from an empty log, stopping at the first fatal one. */
    suspend fun replay(p: Primitives, entries: List<ByteArray>, secrets: Map<Long, ByteArray>?): Pair<CircleState, List<Outcome>> {
        var state = CircleState()
        val outcomes = mutableListOf<Outcome>()
        for (raw in entries) {
            val o = apply(p, state, raw, secrets)
            outcomes.add(o)
            if (o is Outcome.Applied) state = o.state else break
        }
        return state to outcomes
    }

    private class Rejected(val reason: Reason) : Exception(reason.code)

    private fun fatal(reason: Reason): Nothing = throw ProtocolException(reason)

    private fun reject(reason: Reason): Nothing = throw Rejected(reason)

    private suspend fun process(p: Primitives, st: CircleState, raw: ByteArray, secrets: Map<Long, ByteArray>?): Outcome {
        if (raw.size > LogEntry.MAX_SIZE) fatal(Reason.TOO_LARGE) // step 1
        val e = LogEntry.parse(raw)
        val h = e.header
        if (h.version != Protocol.VERSION || h.suite != Protocol.SUITE) fatal(Reason.BAD_VERSION) // step 2
        val type = EntryType.of(h.typeCode) ?: fatal(Reason.UNKNOWN_ENTRY_TYPE) // step 3
        val body = Body.parse(type, e.body) // step 4

        val circleId = st.circleId // step 5
        if (circleId == null) {
            if (type != EntryType.GENESIS || h.seq != 0UL) fatal(Reason.BAD_SEQ)
            if (!h.prevHash.isAllZero()) fatal(Reason.BAD_PREV_HASH)
            if (!h.circleId.isAllZero()) fatal(Reason.BAD_CIRCLE_ID)
            if (h.epoch != 0L) fatal(Reason.BAD_EPOCH)
        } else {
            if (type == EntryType.GENESIS) fatal(Reason.UNEXPECTED_GENESIS)
            if (h.seq != (st.seq + 1).toULong()) fatal(Reason.BAD_SEQ)
            if (h.prevHash != st.head) fatal(Reason.BAD_PREV_HASH)
            if (h.circleId != circleId) fatal(Reason.BAD_CIRCLE_ID)
            if (h.epoch != st.epoch) fatal(Reason.BAD_EPOCH)
        }

        val author: Author // step 6
        if (body is Body.Genesis) {
            if (h.author != body.cert.deviceId(p)) fatal(Reason.BAD_AUTHOR)
            author = Author(body.cert.dskPub, body.cert.accountId, body.cert.kindCode)
        } else {
            val d = st.device(h.author) ?: fatal(Reason.AUTHOR_NOT_ACTIVE)
            author = Author(d.dskPub, d.accountId, d.kind.code)
        }
        if (!p.verify(author.dskPub.toByteArray(), Label.LOG_ENTRY, e.signedPart, e.sig)) fatal(Reason.BAD_SIGNATURE) // step 7
        if (!kindMayAuthor(st, h, body, author)) fatal(Reason.KIND_NOT_ALLOWED) // step 8

        val s = st.copy() // steps 9 to 11, on a copy
        val seq = h.seq.toLong()
        s.seq = seq
        s.head = LogEntry.hash(p, raw)
        s.addHash(s.head)
        var private = secrets != null && s.privateUnknownFrom == null
        if (private && type.hasDetails && !hasSecret(p, st, h, body, secrets!!)) {
            s.privateUnknownFrom = seq // §6.5: frozen until the secret arrives
            private = false
        }
        val before = st.receivingDevices().map { it.id }.toSet()
        val ctx = Context(p, s, e, author.accountId, if (private) secrets else null)
        var result = Result.ACCEPTED
        var reason: Reason? = null
        try {
            ctx.handle(body)
        } catch (r: Rejected) {
            result = Result.REJECTED
            reason = r.reason
            s.flags.add(seq to r.reason)
        }
        if (type == EntryType.GENESIS || before != s.receivingDevices().map { it.id }.toSet()) s.receivingChangedSeq = seq
        if (private) {
            repairGuardians(s)
            if (result == Result.ACCEPTED) reason = s.flags.firstOrNull { it.first == seq }?.second
        } else if (secrets != null) {
            result = Result.DEFERRED
        }
        return Outcome.Applied(s, result, reason)
    }

    private class Author(val dskPub: Bytes, val accountId: Bytes, val kindCode: Int)

    /** The table of §6.3: what a device may write depends on its kind. */
    private fun kindMayAuthor(st: CircleState, h: EntryHeader, body: Body, author: Author): Boolean = when (DeviceKind.of(author.kindCode)) {
        DeviceKind.PHONE, DeviceKind.TABLET -> true
        DeviceKind.WEB, DeviceKind.HOME_ASSISTANT -> body is Body.UpdateKey || (body is Body.RemoveDevice && body.deviceId == h.author)
        DeviceKind.RECOVERY -> body is Body.AddDevice || (body is Body.RemoveDevice && st.device(body.deviceId)?.accountId == author.accountId)
        null -> false
    }

    /** A secret counts only if it matches the log's commitment for its epoch (§6.5). */
    private suspend fun hasSecret(p: Primitives, st: CircleState, h: EntryHeader, body: Body, secrets: Map<Long, ByteArray>): Boolean {
        val secret = secrets[h.epoch] ?: return false
        val commit = if (body is Body.Genesis) body.epochCommit else st.commits[h.epoch] ?: return false
        return Details.epochCommit(p, h.epoch, secret) == commit
    }

    /** Guardian repair (§6.6): every teen keeps at least one adult guardian, judged against one snapshot. */
    private fun repairGuardians(s: CircleState) {
        val adults = s.members.values.filter { it.role == Role.ADULT }.map { it.accountId }.sorted()
        val adultSet = adults.toSet()
        val admins = adults.filter { s.members.getValue(it).admin }
        val ending = mutableListOf<Member>()
        for (m in s.members.values) {
            if (m.role != Role.TEEN) continue
            val kept = m.guardians.filter { it in adultSet }
            val g = kept.ifEmpty { admins.take(MAX_GUARDIANS) }.ifEmpty { adults.take(MAX_GUARDIANS) }
            if (g.isEmpty()) ending.add(m) else m.guardians = g
        }
        ending.forEach { it.endTeen() }
    }

    /** One entry's public rules (§6.4), and with [secrets] its private rules (§6.5). */
    private class Context(
        val p: Primitives,
        val s: CircleState,
        val e: LogEntry,
        val authorAccount: Bytes,
        val secrets: Map<Long, ByteArray>?,
    ) {
        val h: EntryHeader get() = e.header
        val authorMember: Member get() = s.members.getValue(authorAccount)

        suspend fun handle(body: Body) {
            when (body) {
                is Body.Genesis -> genesis(body)
                is Body.AddMember -> addMember(body)
                is Body.RemoveMember -> removeMember(body)
                is Body.AddDevice -> addDevice(body)
                is Body.RemoveDevice -> removeDevice(body)
                is Body.UpdateKey -> updateKey(body)
                is Body.Policy -> policy(body)
                is Body.Rekey -> rekey(body)
                is Body.SetAdmin -> setAdmin(body)
                is Body.AddRecovery -> addRecovery(body)
                is Body.SetOptions -> setOptions(body)
                is Body.RotateIdentity -> rotateIdentity(body)
            }
        }

        suspend fun newDevice(cert: DeviceCert, bundle: KeyBundle?, addedBy: Bytes): Device =
            Device(cert.deviceId(p), cert.accountId, cert.dskPub, checkNotNull(cert.kind), bundle, bundle?.keyId(p), addedBy)

        suspend fun bundleOk(bundle: KeyBundle, cert: DeviceCert): Boolean =
            bundle.isValidFor(p, cert.dskPub, cert.accountId) && bundle.isCurrentAt(h.createdAt)

        suspend fun genesis(b: Body.Genesis) {
            if (!b.cert.isWellFormed(p) || !b.chain.provesAccountOf(p, b.cert)) fatal(Reason.BAD_CERT)
            if (!bundleOk(b.bundle, b.cert)) fatal(Reason.BAD_BUNDLE)
            s.circleId = LogEntry.circleId(p, e.raw)
            s.commits.clear()
            s.commits[0] = b.epochCommit
            val m = Member(b.cert.accountId, b.cert.ikPub, admin = true)
            val d = newDevice(b.cert, b.bundle, b.cert.accountId)
            m.devices[d.id] = d
            s.members[m.accountId] = m
            val secrets = secrets ?: return
            val name = Details.open(p, secrets.getValue(0L), e.headerBytes, b.details)
                ?.let { Details.genesisName(it) }
                ?.let { Details.name(it) }
            if (name == null) s.flags.add(s.seq to Reason.BAD_DETAILS)
            s.name = name ?: ""
        }

        suspend fun addMember(b: Body.AddMember) {
            if (!authorMember.admin) fatal(Reason.NOT_ADMIN)
            if (s.rekeyPending) fatal(Reason.REKEY_PENDING)
            if (s.members.size >= MAX_MEMBERS) fatal(Reason.TOO_MANY_MEMBERS)
            val c = b.cert
            if (!c.isWellFormed(p) || !b.chain.provesAccountOf(p, c)) fatal(Reason.BAD_CERT)
            if (c.kind != DeviceKind.PHONE && c.kind != DeviceKind.TABLET) fatal(Reason.KIND_NOT_ALLOWED)
            if (!bundleOk(b.bundle, c)) fatal(Reason.BAD_BUNDLE)
            if (c.accountId in s.members || s.members.values.any { it.ikPub == c.ikPub }) fatal(Reason.ALREADY_MEMBER)
            if (s.device(c.deviceId(p)) != null) fatal(Reason.DEVICE_ACTIVE)
            if (b.inviteId in s.usedInvites) fatal(Reason.INVITE_REUSED)
            val consent = concat(
                checkNotNull(s.circleId).toByteArray(), b.inviteId.toByteArray(), c.encode(), b.bundle.encode(), b.termsCommit.toByteArray(),
            )
            if (!p.verify(c.ikPub.toByteArray(), Label.JOIN_CONSENT, consent, b.consentSig.toByteArray())) fatal(Reason.BAD_CONSENT)
            val m = Member(c.accountId, c.ikPub, admin = b.admin)
            val d = newDevice(c, b.bundle, authorAccount)
            m.devices[d.id] = d
            s.usedInvites.add(b.inviteId)
            val secrets = secrets
            if (secrets != null && !applyTerms(m, b, secrets.getValue(s.epoch))) s.flags.add(s.seq to Reason.BAD_DETAILS)
            s.members[m.accountId] = m
        }

        /** §6.5 for ADD_MEMBER: the terms the new member signed, if they are valid; false otherwise. */
        suspend fun applyTerms(m: Member, b: Body.AddMember, secret: ByteArray): Boolean {
            val plain = Details.open(p, secret, e.headerBytes, b.details) ?: return false
            val (salt, terms, termsBytes) = Details.memberDetails(plain) ?: return false
            if (Details.termsCommit(p, salt, termsBytes) != b.termsCommit) return false
            val g = terms.guardians
            return when {
                terms.role == Role.ADULT.code && terms.teenUntil == 0UL && g.isEmpty() && terms.rules.isValid -> true
                terms.role == Role.TEEN.code &&
                    terms.teenUntil > h.createdAt &&
                    g.size in 1..MAX_GUARDIANS &&
                    terms.rules.isValid &&
                    g.all { s.members[it]?.role == Role.ADULT } -> {
                    m.role = Role.TEEN
                    m.teenUntil = terms.teenUntil
                    m.guardians = g
                    m.rules = terms.rules
                    true
                }
                else -> false
            }
        }

        suspend fun removeMember(b: Body.RemoveMember) {
            val target = b.accountId
            val targetMember = s.members[target] ?: fatal(Reason.NOT_MEMBER)
            if (!(authorMember.admin || authorAccount == target)) fatal(Reason.NOT_ADMIN)
            if (targetMember.admin && s.admins().size == 1 && s.members.size > 1) fatal(Reason.LAST_ADMIN)
            val fresh = authorMember.admin && authorAccount != target
            epochBody(b.epochCommit, b.wraps, s.receivingDevices().filter { it.accountId != target }, fresh)
            s.members.remove(target)
            advance(b.epochCommit, fresh)
        }

        /** The certificate is the author's own, under its current identity key (§6.4). */
        suspend fun ownCert(c: DeviceCert) {
            if (!c.isWellFormed(p)) fatal(Reason.BAD_CERT)
            if (c.accountId != authorAccount || c.ikPub != authorMember.ikPub) fatal(Reason.WRONG_ACCOUNT)
        }

        suspend fun addDevice(b: Body.AddDevice) {
            val c = b.cert
            ownCert(c)
            val allowed = when (c.kind) {
                DeviceKind.PHONE, DeviceKind.TABLET -> true
                DeviceKind.WEB -> s.options and Options.WEB != 0L
                DeviceKind.HOME_ASSISTANT -> s.options and Options.HOME_ASSISTANT != 0L
                else -> false
            }
            if (!allowed) fatal(Reason.KIND_NOT_ALLOWED)
            if (authorMember.devices.size >= MAX_DEVICES) fatal(Reason.TOO_MANY_DEVICES)
            if (!bundleOk(b.bundle, c)) fatal(Reason.BAD_BUNDLE)
            if (s.device(c.deviceId(p)) != null) fatal(Reason.DEVICE_ACTIVE)
            val d = newDevice(c, b.bundle, authorAccount)
            authorMember.devices[d.id] = d
        }

        suspend fun addRecovery(b: Body.AddRecovery) {
            val c = b.cert
            ownCert(c)
            if (c.kind != DeviceKind.RECOVERY) fatal(Reason.KIND_NOT_ALLOWED)
            val devices = authorMember.devices
            if (devices.values.any { it.kind == DeviceKind.RECOVERY } || devices.size >= MAX_DEVICES) fatal(Reason.TOO_MANY_DEVICES)
            if (s.device(c.deviceId(p)) != null) fatal(Reason.DEVICE_ACTIVE)
            val d = newDevice(c, null, authorAccount)
            devices[d.id] = d
        }

        fun removeDevice(b: Body.RemoveDevice) {
            val target = s.device(b.deviceId) ?: fatal(Reason.UNKNOWN_DEVICE)
            if (!(target.accountId == authorAccount || authorMember.admin)) fatal(Reason.NOT_ADMIN)
            val owner = s.members.getValue(target.accountId)
            if (owner.devices.size == 1) fatal(Reason.LAST_DEVICE)
            if (target.kind == DeviceKind.RECOVERY) {
                noEpoch(b.epochCommit, b.wraps) // it never held an epoch secret, so nothing else changes
                owner.devices.remove(target.id)
                return
            }
            val fresh = authorMember.admin && h.author != target.id
            epochBody(b.epochCommit, b.wraps, s.receivingDevices().filter { it.id != target.id }, fresh)
            owner.devices.remove(target.id)
            advance(b.epochCommit, fresh)
        }

        suspend fun updateKey(b: Body.UpdateKey) {
            val d = checkNotNull(s.device(h.author))
            val bundle = b.bundle
            if (!bundle.isValidFor(p, d.dskPub, d.accountId) || !bundle.isCurrentAt(h.createdAt) || bundle.keyId(p) == d.keyId) {
                fatal(Reason.BAD_BUNDLE)
            }
            s.members.getValue(d.accountId).devices[d.id] = Device(d.id, d.accountId, d.dskPub, d.kind, bundle, bundle.keyId(p), d.addedBy)
        }

        fun rekey(b: Body.Rekey) {
            if (!authorMember.admin) fatal(Reason.NOT_ADMIN)
            checkWraps(b.wraps, s.receivingDevices())
            newEpoch(b.epochCommit)
            s.rekeyPending = false
        }

        fun setAdmin(b: Body.SetAdmin) {
            if (!authorMember.admin) fatal(Reason.NOT_ADMIN)
            val target = s.members[b.accountId] ?: fatal(Reason.NOT_MEMBER)
            if (!b.admin && target.admin && s.admins().size == 1) fatal(Reason.LAST_ADMIN)
            target.admin = b.admin
        }

        fun setOptions(b: Body.SetOptions) {
            if (!authorMember.admin) fatal(Reason.NOT_ADMIN)
            if (b.options and Options.DEFINED.inv() != 0L) fatal(Reason.BAD_OPTIONS)
            s.options = b.options
        }

        suspend fun rotateIdentity(b: Body.RotateIdentity) {
            val link = b.link
            val m = authorMember
            if (link.oldIkPub != m.ikPub ||
                Ed25519Checks.isInvalidKey(link.newIkPub.toByteArray()) ||
                link.newIkPub == link.oldIkPub ||
                s.members.values.any { it.ikPub == link.newIkPub } ||
                !link.signaturesVerify(p, authorAccount)
            ) {
                fatal(Reason.BAD_ROTATION)
            }
            m.ikPub = link.newIkPub
        }

        suspend fun policy(b: Body.Policy) {
            if (s.rekeyPending) fatal(Reason.REKEY_PENDING)
            val secrets = secrets ?: return // opaque to servers
            val plain = Details.open(p, secrets.getValue(s.epoch), e.headerBytes, b.details) ?: reject(Reason.BAD_DETAILS)
            val change = try {
                PolicyChange.parse(plain)
            } catch (_: ProtocolException) {
                reject(Reason.BAD_DETAILS)
            }
            when (change) {
                is PolicyChange.Unknown -> reject(Reason.UNKNOWN_POLICY)
                is PolicyChange.SetCircleName -> {
                    if (!authorMember.admin) reject(Reason.NOT_ADMIN)
                    s.name = Details.name(change.name) ?: reject(Reason.BAD_DETAILS)
                    return
                }
                else -> Unit
            }
            val targetId = when (change) {
                is PolicyChange.SetRules -> change.target
                is PolicyChange.SetGuardians -> change.target
                is PolicyChange.GrantPause -> change.target
                is PolicyChange.RevokePause -> change.target
                is PolicyChange.EndTeen -> change.target
            }
            val target = s.members[targetId] ?: reject(Reason.NOT_MEMBER)
            if (target.role != Role.TEEN) reject(Reason.NOT_TEEN)
            val isGuardian = authorAccount in target.guardians
            if (change is PolicyChange.EndTeen) {
                if (!isGuardian) {
                    if (authorAccount != targetId) reject(Reason.NOT_GUARDIAN)
                    if (h.createdAt < target.teenUntil) reject(Reason.TEEN_UNTIL_NOT_REACHED)
                }
                target.endTeen()
                return
            }
            if (!isGuardian) reject(Reason.NOT_GUARDIAN)
            when (change) {
                is PolicyChange.SetRules -> {
                    if (!change.rules.isValid) reject(Reason.BAD_RULES)
                    target.rules = change.rules
                }
                is PolicyChange.SetGuardians -> {
                    val g = change.guardians
                    if (g.size !in 1..MAX_GUARDIANS || g.any { s.members[it]?.role != Role.ADULT }) reject(Reason.BAD_GUARDIANS)
                    target.guardians = g
                }
                is PolicyChange.GrantPause -> {
                    if ((change.kind != 1 && change.kind != 2) ||
                        change.start >= change.end ||
                        change.end - change.start > PAUSE_MAX_MS ||
                        change.pauseId in target.pauses
                    ) {
                        reject(Reason.BAD_PAUSE)
                    }
                    if (target.pauses.size >= MAX_PAUSES) {
                        val earliest = target.pauses.entries.minWith(compareBy<Map.Entry<Bytes, Pause>> { it.value.end }.thenBy { it.key })
                        target.pauses.remove(earliest.key)
                    }
                    target.pauses[change.pauseId] = Pause(change.kind, change.start, change.end)
                }
                is PolicyChange.RevokePause -> {
                    if (target.pauses.remove(change.pauseId) == null) reject(Reason.UNKNOWN_PAUSE)
                }
            }
        }

        /** Wrap coverage (§6.4): one wrap per device of the set, ascending, each to its current key. */
        fun checkWraps(wraps: List<Wrap>, devices: List<Device>) {
            val expected = devices.associate { it.id to it.keyId }
            val ids = wraps.map { it.recipient }
            val ascending = ids.zipWithNext().all { (a, b) -> a < b }
            if (!ascending || ids.size != expected.size || wraps.any { expected[it.recipient] != it.keyId }) fatal(Reason.BAD_WRAPS)
        }

        fun noEpoch(commit: Bytes, wraps: List<Wrap>) {
            if (!commit.isAllZero() || wraps.isNotEmpty()) fatal(Reason.BAD_WRAPS)
        }

        /** A removal by an admin who stays starts an epoch; any other carries no secret (§6.4). */
        fun epochBody(commit: Bytes, wraps: List<Wrap>, devices: List<Device>, fresh: Boolean) {
            if (fresh) checkWraps(wraps, devices) else noEpoch(commit, wraps)
        }

        fun advance(commit: Bytes, fresh: Boolean) {
            if (fresh) {
                newEpoch(commit)
                s.rekeyPending = false
            } else {
                s.rekeyPending = true
            }
        }

        fun newEpoch(commit: Bytes) {
            s.epoch += 1
            s.commits[s.epoch] = commit
        }
    }
}
