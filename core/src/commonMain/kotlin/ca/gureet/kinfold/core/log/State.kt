// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.log

import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.encode

/** A device of a current member (PROTOCOL.md §6.1). A recovery device has no bundle and no key ID. */
class Device(
    val id: Bytes,
    val accountId: Bytes,
    val dskPub: Bytes,
    val kind: DeviceKind,
    val bundle: KeyBundle?,
    val keyId: Bytes?,
    /** The account that authored the entry adding this device; `welcome` is checked against it (§8.2). */
    val addedBy: Bytes,
)

/** A stored pause of a teen (§5.5): kind 1 pauses sharing, kind 2 allows approximate location. */
class Pause(val kind: Int, val start: ULong, val end: ULong)

/** A member: the public part every server knows, and the private part only members can read. */
class Member(
    val accountId: Bytes,
    var ikPub: Bytes,
    var admin: Boolean,
    val devices: MutableMap<Bytes, Device> = mutableMapOf(),
    var role: Role = Role.ADULT,
    var teenUntil: ULong = 0UL,
    var guardians: List<Bytes> = emptyList(),
    var rules: Rules? = null,
    val pauses: MutableMap<Bytes, Pause> = mutableMapOf(),
) {
    fun copy(): Member = Member(accountId, ikPub, admin, devices.toMutableMap(), role, teenUntil, guardians, rules, pauses.toMutableMap())

    /** Teen settings end (§6.5, `END_TEEN`): an adult again, with nothing left of the rules. */
    fun endTeen() {
        role = Role.ADULT
        teenUntil = 0UL
        guardians = emptyList()
        rules = null
        pauses.clear()
    }
}

/** A circle's state after an entry (§6.1). A client holds all of it; a server, the public part. */
class CircleState {
    var circleId: Bytes? = null
    var seq: Long = -1
    var head: Bytes = Bytes.zero(32)
    var epoch: Long = 0
    val commits: MutableMap<Long, Bytes> = mutableMapOf()
    var name: String = ""
    val members: MutableMap<Bytes, Member> = mutableMapOf()

    /** Every entry hash, in order: `hashes[seq]`. */
    val hashes: MutableList<Bytes> = mutableListOf()
    private val hashSet: MutableSet<Bytes> = mutableSetOf()

    /** `(seq, reason)` for every rejected entry and every one accepted with unreadable details. */
    val flags: MutableList<Pair<Long, Reason>> = mutableListOf()
    var rekeyPending: Boolean = false

    /** The `seq` from which this client couldn't run the private rules (§6.5), or null. */
    var privateUnknownFrom: Long? = null
    var options: Long = 0
    val usedInvites: MutableSet<Bytes> = mutableSetOf()

    /** The last entry that changed the set of receiving devices; circle envelopes must be at or after it (§7.5). */
    var receivingChangedSeq: Long = -1

    fun addHash(hash: Bytes) {
        hashes.add(hash)
        hashSet.add(hash)
    }

    fun hasEntry(hash: Bytes): Boolean = hash in hashSet

    fun device(id: Bytes): Device? = members.values.firstNotNullOfOrNull { it.devices[id] }

    /** Devices of current members, by device ID. */
    fun activeDevices(): List<Device> = members.values.flatMap { it.devices.values }.sortedBy { it.id }

    /** Active devices of kinds 1–4, by device ID. */
    fun receivingDevices(): List<Device> = activeDevices().filter { it.kind.receives }

    /** Admins' account IDs, ascending. */
    fun admins(): List<Bytes> = members.values.filter { it.admin }.map { it.accountId }.sorted()

    fun copy(): CircleState {
        val s = CircleState()
        s.circleId = circleId
        s.seq = seq
        s.head = head
        s.epoch = epoch
        s.commits.putAll(commits)
        s.name = name
        for ((id, m) in members) s.members[id] = m.copy()
        for (h in hashes) s.addHash(h)
        s.flags.addAll(flags)
        s.rekeyPending = rekeyPending
        s.privateUnknownFrom = privateUnknownFrom
        s.options = options
        s.usedInvites.addAll(usedInvites)
        s.receivingChangedSeq = receivingChangedSeq
        return s
    }

    /** StateBytes of §6.9. */
    fun stateBytes(): ByteArray = encode {
        bytes(checkNotNull(circleId) { "no circle yet" })
        u64(seq.toULong())
        bytes(head)
        u32(epoch)
        flag(rekeyPending)
        u32(options)
        vec16(name.encodeToByteArray())
        u16(members.size)
        for (m in members.values.sortedBy { it.accountId }) {
            bytes(m.accountId)
            bytes(m.ikPub)
            flag(m.admin)
            u8(m.role.code)
            u64(m.teenUntil)
            ids(m.guardians)
            vec16(if (m.role == Role.TEEN) checkNotNull(m.rules).encode() else ByteArray(0))
            u16(m.pauses.size)
            for ((id, pause) in m.pauses.entries.sortedBy { it.key }) {
                bytes(id)
                u8(pause.kind)
                u64(pause.start)
                u64(pause.end)
            }
            u16(m.devices.size)
            for (d in m.devices.values.sortedBy { it.id }) {
                bytes(d.id)
                u8(d.kind.code)
                bytes(d.keyId ?: Bytes.zero(8))
            }
        }
    }

    /** state_hash = H("state-hash", StateBytes)[0:8], or null while the private state is frozen. */
    suspend fun stateHash(p: Primitives): Bytes? =
        if (privateUnknownFrom != null || circleId == null) null else Bytes.of(p.h(Label.STATE_HASH, stateBytes()).copyOf(8))
}
