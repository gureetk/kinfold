// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import ca.gureet.kinfold.core.crypto.HpkeKey
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.crypto.SigningKey
import ca.gureet.kinfold.core.identity.DeviceCert
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.identity.Ids
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed

/**
 * A device's keys and the documents made from them (PROTOCOL.md §4): its account's identity key,
 * its own signing and encryption keys, its certificate and its key bundle, and the encryption keys
 * its earlier bundles published, which it keeps for a while to open what was wrapped to them
 * (§4.5). The private keys are seeds the platform turns into keys (`Crypto.ed25519`,
 * `Crypto.x25519`); [encode] holds them, so whatever stores it must protect it like the keys
 * themselves.
 */
class DeviceKeys private constructor(
    val kind: DeviceKind,
    private val ikSeed: ByteArray,
    private val dskSeed: ByteArray,
    private val dekPrivate: ByteArray,
    val cert: DeviceCert,
    val bundle: KeyBundle,
    /** The account's identity key, which signs certificates and join consents. */
    val identity: SigningKey,
    /** The device's signing key (DSK). */
    val signing: SigningKey,
    /** The device's encryption key (DEK), the one its bundle publishes. */
    val encryption: HpkeKey,
    val accountId: Bytes,
    val deviceId: Bytes,
    val keyId: Bytes,
    /** The encryption keys of earlier bundles, newest last. */
    val retired: List<Retired>,
) {
    /**
     * An encryption key an earlier bundle published: kept until every envelope that could be
     * wrapped to it has run out, 30 days at most after the last moment it was current in a log
     * this device holds, [lastCurrentAt] (§4.5).
     */
    class Retired internal constructor(internal val dekPrivate: ByteArray, val key: HpkeKey, val keyId: Bytes, val lastCurrentAt: ULong)

    /** The device's encryption keys by key ID, for opening envelopes and pushes: the current one and the retired ones. */
    val hpkeKeys: Map<Bytes, HpkeKey>
        get() = LinkedHashMap<Bytes, HpkeKey>().also { m ->
            m[keyId] = encryption
            for (r in retired) if (r.keyId !in m) m[r.keyId] = r.key
        }

    /** Everything, private keys included, in a form [decode] reads. */
    fun encode(): ByteArray = encode {
        u8(FORMAT)
        u8(kind.code)
        bytes(ikSeed)
        bytes(dskSeed)
        bytes(dekPrivate)
        bytes(cert.encode())
        bytes(bundle.encode())
        u8(retired.size)
        for (r in retired) {
            bytes(r.dekPrivate)
            u64(r.lastCurrentAt)
        }
    }

    /**
     * A new encryption key, and a bundle for it that starts at the trusted time [now] (an hour
     * back, for clocks) and lasts two weeks (§4.5). The current key is retired, last current
     * [now]. The device publishes the bundle with `UPDATE_KEY` in every circle it is in.
     */
    suspend fun rotated(p: Primitives, now: ULong): DeviceKeys {
        val dekPrivate = p.random(32)
        val dek = p.crypto.x25519(dekPrivate)
        val notBefore = if (now > BUNDLE_BACKDATE_MS) now - BUNDLE_BACKDATE_MS else 0UL
        val bundle = KeyBundle.sign(p, signing, accountId, dek.publicKey, notBefore, notBefore + ROTATED_LIFE_MS)
        val kept = retired + Retired(this.dekPrivate, encryption, keyId, now)
        return DeviceKeys(kind, ikSeed, dskSeed, dekPrivate, cert, bundle, identity, signing, dek, accountId, deviceId, bundle.keyId(p), kept.takeLast(MAX_RETIRED))
    }

    /**
     * These keys with each retired key whose ID is in [stillCurrent] marked current at [now] (to
     * the hour, so that a log that keeps an old key doesn't mean a write every round), and every
     * other one dropped once it was last current more than [KEEP_RETIRED_MS] before [now]. The
     * same object when nothing changes.
     */
    fun withRetired(stillCurrent: Set<Bytes>, now: ULong): DeviceKeys {
        var changed = false
        val kept = ArrayList<Retired>()
        for (r in retired) {
            when {
                r.keyId in stillCurrent -> if (now > r.lastCurrentAt && now - r.lastCurrentAt >= MARK_EVERY_MS) {
                    changed = true
                    kept.add(Retired(r.dekPrivate, r.key, r.keyId, now))
                } else {
                    kept.add(r)
                }
                now > r.lastCurrentAt && now - r.lastCurrentAt > KEEP_RETIRED_MS -> changed = true
                else -> kept.add(r)
            }
        }
        if (!changed) return this
        return DeviceKeys(kind, ikSeed, dskSeed, dekPrivate, cert, bundle, identity, signing, encryption, accountId, deviceId, keyId, kept)
    }

    companion object {
        /** 2 since retired keys are kept; 1 held none. */
        private const val FORMAT = 2
        private const val FORMAT_WITHOUT_RETIRED = 1

        /** A rotated bundle lasts two weeks (§4.5); the device makes the next one after a week. */
        const val ROTATED_LIFE_MS: ULong = 1_209_600_000UL

        /** A retired key is kept this long after it was last current: the 30 days of the longest envelope, and a day either way for clocks. */
        const val KEEP_RETIRED_MS: ULong = 2_764_800_000UL

        /** Weekly rotation for 32 days needs five; the rest is room for a device that rotated more often. */
        private const val MAX_RETIRED = 16

        private const val MARK_EVERY_MS: ULong = 3_600_000UL

        /** How long a new bundle is good for: the most §4.4 allows, starting an hour back to allow for clocks. */
        private const val BUNDLE_LIFE_MS: ULong = KeyBundle.MAX_LIFE_MS
        private const val BUNDLE_BACKDATE_MS: ULong = 3_600_000UL

        /**
         * New keys for a device of [kind] in a new account, at the trusted time [now]: a fresh
         * identity key, signing key and encryption key, a certificate, and a bundle that lasts 35
         * days. A device that runs longer needs a new bundle in an `UPDATE_KEY` entry (§4.5).
         */
        suspend fun create(p: Primitives, kind: DeviceKind, now: ULong): DeviceKeys {
            val ikSeed = p.random(32)
            val dskSeed = p.random(32)
            val dekPrivate = p.random(32)
            val ik = p.crypto.ed25519(ikSeed)
            val dsk = p.crypto.ed25519(dskSeed)
            val dek = p.crypto.x25519(dekPrivate)
            val accountId = Ids.account(p, ik.publicKey)
            val cert = DeviceCert.issue(p, ik, accountId, dsk.publicKey, kind, now)
            val notBefore = if (now > BUNDLE_BACKDATE_MS) now - BUNDLE_BACKDATE_MS else 0UL
            val bundle = KeyBundle.sign(p, dsk, accountId, dek.publicKey, notBefore, notBefore + BUNDLE_LIFE_MS)
            return build(p, kind, ikSeed, dskSeed, dekPrivate, cert, bundle, emptyList())
        }

        /** Keys from [encode], or from the format before retired keys were kept; `malformed` if [data] isn't such a record. */
        suspend fun decode(p: Primitives, data: ByteArray): DeviceKeys {
            val r = Reader(data)
            val format = r.u8()
            if (format != FORMAT && format != FORMAT_WITHOUT_RETIRED) malformed()
            val kind = DeviceKind.of(r.u8()) ?: malformed()
            val ikSeed = r.bytes(32)
            val dskSeed = r.bytes(32)
            val dekPrivate = r.bytes(32)
            val cert = DeviceCert.read(r)
            val bundle = KeyBundle.read(r)
            val retired = ArrayList<Pair<ByteArray, ULong>>()
            if (format == FORMAT) repeat(r.u8()) { retired.add(r.bytes(32) to r.u64()) }
            r.finish()
            return build(p, kind, ikSeed, dskSeed, dekPrivate, cert, bundle, retired)
        }

        private suspend fun build(
            p: Primitives,
            kind: DeviceKind,
            ikSeed: ByteArray,
            dskSeed: ByteArray,
            dekPrivate: ByteArray,
            cert: DeviceCert,
            bundle: KeyBundle,
            retired: List<Pair<ByteArray, ULong>>,
        ): DeviceKeys {
            val ik = p.crypto.ed25519(ikSeed)
            val dsk = p.crypto.ed25519(dskSeed)
            val dek = p.crypto.x25519(dekPrivate)
            val accountId = Ids.account(p, ik.publicKey)
            val deviceId = Ids.device(p, dsk.publicKey)
            if (cert.accountId != accountId || cert.dskPub != Bytes.of(dsk.publicKey) || bundle.dekPub != Bytes.of(dek.publicKey)) {
                malformed()
            }
            val old = retired.map { (seed, at) ->
                val key = p.crypto.x25519(seed)
                Retired(seed, key, Ids.key(p, key.publicKey), at)
            }
            return DeviceKeys(kind, ikSeed, dskSeed, dekPrivate, cert, bundle, ik, dsk, dek, accountId, deviceId, bundle.keyId(p), old)
        }
    }
}
