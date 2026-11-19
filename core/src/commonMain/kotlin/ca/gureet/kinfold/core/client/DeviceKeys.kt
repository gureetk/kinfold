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
 * its own signing and encryption keys, its certificate and its key bundle. The private keys are
 * seeds the platform turns into keys (`Crypto.ed25519`, `Crypto.x25519`); [encode] holds them, so
 * whatever stores it must protect it like the keys themselves.
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
) {
    /** The device's encryption keys by key ID, for opening envelopes and pushes. */
    val hpkeKeys: Map<Bytes, HpkeKey> get() = mapOf(keyId to encryption)

    /** Everything, private keys included, in a form [decode] reads. */
    fun encode(): ByteArray = encode {
        u8(FORMAT)
        u8(kind.code)
        bytes(ikSeed)
        bytes(dskSeed)
        bytes(dekPrivate)
        bytes(cert.encode())
        bytes(bundle.encode())
    }

    companion object {
        private const val FORMAT = 1

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
            return build(p, kind, ikSeed, dskSeed, dekPrivate, cert, bundle)
        }

        /** Keys from [encode]; `malformed` if [data] isn't such a record. */
        suspend fun decode(p: Primitives, data: ByteArray): DeviceKeys {
            val r = Reader(data)
            if (r.u8() != FORMAT) malformed()
            val kind = DeviceKind.of(r.u8()) ?: malformed()
            val ikSeed = r.bytes(32)
            val dskSeed = r.bytes(32)
            val dekPrivate = r.bytes(32)
            val cert = DeviceCert.read(r)
            val bundle = KeyBundle.read(r)
            r.finish()
            return build(p, kind, ikSeed, dskSeed, dekPrivate, cert, bundle)
        }

        private suspend fun build(
            p: Primitives,
            kind: DeviceKind,
            ikSeed: ByteArray,
            dskSeed: ByteArray,
            dekPrivate: ByteArray,
            cert: DeviceCert,
            bundle: KeyBundle,
        ): DeviceKeys {
            val ik = p.crypto.ed25519(ikSeed)
            val dsk = p.crypto.ed25519(dskSeed)
            val dek = p.crypto.x25519(dekPrivate)
            val accountId = Ids.account(p, ik.publicKey)
            val deviceId = Ids.device(p, dsk.publicKey)
            if (cert.accountId != accountId || cert.dskPub != Bytes.of(dsk.publicKey) || bundle.dekPub != Bytes.of(dek.publicKey)) {
                malformed()
            }
            return DeviceKeys(kind, ikSeed, dskSeed, dekPrivate, cert, bundle, ik, dsk, dek, accountId, deviceId, bundle.keyId(p))
        }
    }
}
