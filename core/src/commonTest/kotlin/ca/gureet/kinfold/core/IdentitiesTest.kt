// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.identity.DeviceCert
import ca.gureet.kinfold.core.identity.DeviceKind
import ca.gureet.kinfold.core.identity.IdentityChain
import ca.gureet.kinfold.core.identity.IdentityLink
import ca.gureet.kinfold.core.identity.Ids
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.hexBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The `identities` vectors (PROTOCOL.md §4): IDs, certificates, chains and key bundles. */
class IdentitiesTest {
    private val crypto = platformCrypto()
    private val p = Primitives(crypto)
    private val people: List<Pair<String, JsonObject>> =
        Vectors.group("identities").entrySet().map { it.key to it.value.asJsonObject }

    private fun JsonObject.hexList(key: String): List<ByteArray> = getAsJsonArray(key).map { hexBytes(it.asString) }

    private fun JsonObject.devices(): List<JsonObject> = getAsJsonObject("devices").entrySet().map { it.value.asJsonObject }

    private fun person(name: String): JsonObject = people.first { it.first == name }.second

    @Test
    fun accountsAndChains() = sync {
        assertEquals(listOf("jordan", "alex", "maya", "sam", "riley"), people.map { it.first })
        var rotations = 0
        for ((name, person) in people) {
            val seeds = person.hexList("ik_seeds")
            val pubs = person.hexList("ik_pubs")
            for ((seed, pub) in seeds.zip(pubs)) assertContentEquals(pub, crypto.ed25519(seed).publicKey, name)
            assertContentEquals(pubs.last(), person.hex("ik_pub"))
            assertContentEquals(seeds.last(), person.hex("ik_seed"))
            val account = Ids.account(p, pubs.first())
            assertEquals(Bytes.of(person.hex("account_id")), account, name)
            val chain = IdentityChain.parse(person.hex("chain"))
            assertEquals(pubs.size - 1, chain.links.size, name)
            assertContentEquals(person.hex("chain"), chain.encode())
            for ((i, link) in chain.links.withIndex()) {
                val rebuilt = IdentityLink.create(p, account, crypto.ed25519(seeds[i]), crypto.ed25519(seeds[i + 1]))
                assertContentEquals(rebuilt.encode(), link.encode(), "$name link $i")
                assertTrue(link.signaturesVerify(p, account))
            }
            rotations += chain.links.size
        }
        assertTrue(rotations >= 2, "the vectors include rotated identities")
    }

    @Test
    fun devices() = sync {
        var bundles = 0
        for ((name, person) in people) {
            val account = Bytes.of(person.hex("account_id"))
            val ik = crypto.ed25519(person.hex("ik_seed"))
            val chain = IdentityChain.parse(person.hex("chain"))
            for (d in person.devices()) {
                val label = d.str("label")
                val dsk = crypto.ed25519(d.hex("dsk_seed"))
                assertContentEquals(d.hex("dsk_pub"), dsk.publicKey, label)
                assertEquals(Bytes.of(d.hex("device_id")), Ids.device(p, dsk.publicKey), label)

                val cert = DeviceCert.parse(d.hex("cert"))
                assertContentEquals(d.hex("cert"), cert.encode(), label)
                assertTrue(cert.isWellFormed(p), label)
                assertEquals(account, cert.accountId)
                assertEquals(Bytes.of(dsk.publicKey), cert.dskPub)
                assertEquals(DeviceKind.of(d.int("kind")), cert.kind)
                assertEquals(Bytes.of(person.hex("ik_pub")), cert.ikPub)
                assertEquals(Bytes.of(d.hex("device_id")), cert.deviceId(p))
                assertTrue(chain.provesAccountOf(p, cert), label)
                val reissued = DeviceCert.issue(p, ik, account, dsk.publicKey, checkNotNull(cert.kind), cert.issuedAt)
                assertContentEquals(d.hex("cert"), reissued.encode(), label)

                val deks = d.list("deks")
                val raw = d.hexList("bundles")
                assertEquals(deks.size, raw.size, label)
                if (cert.kind == DeviceKind.RECOVERY) assertTrue(deks.isEmpty(), "a recovery device has no keys")
                for ((dek, bytes) in deks.zip(raw)) {
                    val key = crypto.x25519(dek.hex("sk"))
                    assertContentEquals(dek.hex("pub"), key.publicKey)
                    assertEquals(Bytes.of(dek.hex("key_id")), Ids.key(p, key.publicKey))
                    val bundle = KeyBundle.parse(bytes)
                    assertContentEquals(bytes, bundle.encode())
                    assertTrue(bundle.isValidFor(p, Bytes.of(dsk.publicKey), account), label)
                    assertEquals(Bytes.of(dek.hex("pub")), bundle.dekPub)
                    assertEquals(Bytes.of(dek.hex("key_id")), bundle.keyId(p))
                    val resigned = KeyBundle.sign(
                        p, dsk, account, key.publicKey, bundle.notBefore, bundle.notAfter, bundle.protoMax, bundle.features,
                    )
                    assertContentEquals(bytes, resigned.encode(), label)
                    bundles++
                }
            }
            assertTrue(person.devices().isNotEmpty(), name)
        }
        assertTrue(bundles >= 10)
    }

    @Test
    fun certificatesRefused() = sync {
        val jordan = person("jordan")
        val d = jordan.devices().first()
        val good = DeviceCert.parse(d.hex("cert"))
        val ik = crypto.ed25519(jordan.hex("ik_seed"))
        suspend fun withBytes(at: Int, value: Int) =
            DeviceCert.parse(good.encode().also { it[at] = value.toByte() }).isWellFormed(p)
        assertFalse(withBytes(0, 1), "version 1")
        assertFalse(withBytes(2, 2), "suite 2")
        assertFalse(withBytes(51, 0), "kind 0")
        assertFalse(withBytes(51, 6), "kind 6")
        assertFalse(withBytes(100, good.encode()[100].toInt() xor 1), "a flipped signature bit")
        assertFalse(withBytes(10, good.encode()[10].toInt() xor 1), "a changed account ID")
        val small = hexBytes("0100000000000000000000000000000000000000000000000000000000000000")
        val withSmallDsk = DeviceCert.issue(p, ik, good.accountId, small, DeviceKind.PHONE, good.issuedAt)
        assertFalse(withSmallDsk.isWellFormed(p), "a small-order device key, though correctly signed")
        val other = crypto.ed25519(ByteArray(32) { 5 })
        val wrongSigner = DeviceCert.issue(p, other, good.accountId, good.dskPub.toByteArray(), DeviceKind.PHONE, good.issuedAt)
        assertTrue(wrongSigner.isWellFormed(p), "well-formed: it names the key that signed it")
        assertFalse(IdentityChain.EMPTY.provesAccountOf(p, wrongSigner), "but nothing ties that key to the account")
        // The same changes, signed again, so that only the field's own rule can refuse them
        suspend fun signed(version: Int = 0, suite: Int = 1, kind: Int = 1): DeviceCert {
            val bare = DeviceCert(version, suite, good.accountId, good.dskPub, kind, good.issuedAt, Bytes.of(ik.publicKey), Bytes.zero(64))
            return DeviceCert(
                version, suite, good.accountId, good.dskPub, kind, good.issuedAt, Bytes.of(ik.publicKey),
                Bytes.of(p.sign(ik, Label.DEVICE_CERT, bare.signedPart())),
            )
        }
        assertTrue(signed().isWellFormed(p))
        assertFalse(signed(version = 1).isWellFormed(p), "version 1, signed")
        assertFalse(signed(suite = 2).isWellFormed(p), "suite 2, signed")
        for (kind in listOf(0, 6, 255)) assertFalse(signed(kind = kind).isWellFormed(p), "kind $kind, signed")
        for (kind in 1..5) assertTrue(signed(kind = kind).isWellFormed(p), "kind $kind")
        assertFailsWith<ProtocolException> { DeviceCert.parse(good.encode().copyOf(155)) }
        assertFailsWith<ProtocolException> { DeviceCert.parse(good.encode() + byteArrayOf(0)) }
    }

    @Test
    fun chainsRefused() = sync {
        val (name, rotated) = people.first { (_, person) -> IdentityChain.parse(person.hex("chain")).links.isNotEmpty() }
        val cert = DeviceCert.parse(rotated.devices().first().hex("cert"))
        val chain = IdentityChain.parse(rotated.hex("chain"))
        assertTrue(chain.provesAccountOf(p, cert), name)
        assertFalse(IdentityChain.EMPTY.provesAccountOf(p, cert), "no chain for a rotated key")
        assertFalse(IdentityChain(chain.links.dropLast(1)).provesAccountOf(p, cert), "a link short")
        assertFalse(IdentityChain(chain.links + chain.links.last()).provesAccountOf(p, cert), "a link repeated")
        val link = chain.links.first()
        val badSig = IdentityLink(link.oldIkPub, link.newIkPub, link.newSig, link.newSig)
        assertFalse(IdentityChain(listOf(badSig) + chain.links.drop(1)).provesAccountOf(p, cert), "a bad old signature")
        val other = DeviceCert.parse(person("maya").devices().first().hex("cert"))
        assertFalse(chain.provesAccountOf(p, other), "another account's certificate")
        val firstKey = crypto.ed25519(rotated.hexList("ik_seeds").first())
        val oldCert = DeviceCert.issue(p, firstKey, cert.accountId, cert.dskPub.toByteArray(), DeviceKind.PHONE, cert.issuedAt)
        assertTrue(oldCert.isWellFormed(p))
        assertTrue(IdentityChain.EMPTY.provesAccountOf(p, oldCert), "a certificate under the first key needs no chain")
        assertFalse(chain.provesAccountOf(p, oldCert), "a chain that goes past the certificate's key")
        assertFailsWith<ProtocolException> { IdentityChain.parse(ByteArray(193)) }
        assertFailsWith<ProtocolException> { IdentityChain.parse(ByteArray(9 * 192)) }
        assertEquals(8, IdentityChain.parse(ByteArray(8 * 192)).links.size)
    }

    @Test
    fun bundlesRefused() = sync {
        val jordan = person("jordan")
        val d = jordan.devices().first()
        val account = Bytes.of(jordan.hex("account_id"))
        val dsk = crypto.ed25519(d.hex("dsk_seed"))
        val dskPub = Bytes.of(dsk.publicKey)
        val dek = d.list("deks").first().hex("pub")
        val start = 1_800_000_000_000UL
        suspend fun bundle(notBefore: ULong, notAfter: ULong, key: ByteArray = dek) =
            KeyBundle.sign(p, dsk, account, key, notBefore, notAfter)
        assertTrue(bundle(start, start + KeyBundle.MAX_LIFE_MS).isValidFor(p, dskPub, account), "exactly 35 days")
        assertFalse(bundle(start, start + KeyBundle.MAX_LIFE_MS + 1UL).isValidFor(p, dskPub, account), "35 days and 1 ms")
        assertFalse(bundle(start, start).isValidFor(p, dskPub, account), "ends as it starts")
        assertFalse(bundle(start, start - 1UL).isValidFor(p, dskPub, account), "ends before it starts")
        assertTrue(bundle(ULong.MAX_VALUE - 1UL, ULong.MAX_VALUE).isValidFor(p, dskPub, account), "at the top of the range")
        val invalidKey = hexBytes("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
        assertFalse(bundle(start, start + 1UL, invalidKey).isValidFor(p, dskPub, account), "a low-order key")
        val good = bundle(start, start + 1000UL)
        assertFalse(good.isValidFor(p, dskPub, Bytes.of(person("alex").hex("account_id"))), "another account")
        val otherDevice = Bytes.of(crypto.ed25519(ByteArray(32) { 3 }).publicKey)
        assertFalse(good.isValidFor(p, otherDevice, account), "another device's key")
        val flipped = KeyBundle.parse(good.encode().also { it[150] = (it[150].toInt() xor 1).toByte() })
        assertFalse(flipped.isValidFor(p, dskPub, account), "a flipped signature bit")
        suspend fun signedAs(deviceId: Bytes, version: Int = 0, suite: Int = 1): KeyBundle {
            val bare = KeyBundle(version, suite, account, deviceId, Bytes.of(dek), start, start + 1000UL, 0, 0, Bytes.zero(64))
            return KeyBundle(
                version, suite, account, deviceId, Bytes.of(dek), start, start + 1000UL, 0, 0,
                Bytes.of(p.sign(dsk, Label.KEY_BUNDLE, bare.signedPart())),
            )
        }
        assertTrue(signedAs(good.deviceId).isValidFor(p, dskPub, account))
        assertFalse(signedAs(Ids.device(p, otherDevice.toByteArray())).isValidFor(p, dskPub, account), "another device's ID, signed")
        assertFalse(signedAs(good.deviceId, version = 1).isValidFor(p, dskPub, account), "version 1, signed")
        assertFalse(signedAs(good.deviceId, suite = 2).isValidFor(p, dskPub, account), "suite 2, signed")
        val version1 = KeyBundle.parse(good.encode().also { it[0] = 1 })
        assertFalse(version1.isValidFor(p, dskPub, account), "version 1")
        val withFeatures = KeyBundle.sign(p, dsk, account, dek, start, start + 1000UL, protoMax = 7, features = 0xffffffffL)
        assertTrue(withFeatures.isValidFor(p, dskPub, account), "proto_max and features never matter")
    }

    @Test
    fun currency() = sync {
        val jordan = person("jordan")
        val d = jordan.devices().first()
        val dsk = crypto.ed25519(d.hex("dsk_seed"))
        val account = Bytes.of(jordan.hex("account_id"))
        val dek = d.list("deks").first().hex("pub")
        val start = 1_800_000_000_000UL
        val b = KeyBundle.sign(p, dsk, account, dek, start, start + 1000UL)
        assertTrue(b.isCurrentAt(start - 600_000UL), "ten minutes early")
        assertFalse(b.isCurrentAt(start - 600_001UL), "ten minutes and 1 ms early")
        assertTrue(b.isCurrentAt(start + 999UL))
        assertFalse(b.isCurrentAt(start + 1000UL), "at not_after")
        val top = KeyBundle.sign(p, dsk, account, dek, ULong.MAX_VALUE - 10UL, ULong.MAX_VALUE)
        assertTrue(top.isCurrentAt(ULong.MAX_VALUE - 1UL), "t + 600,000 would wrap here")
        assertFalse(top.isCurrentAt(ULong.MAX_VALUE))
        assertTrue(top.isCurrentAt(ULong.MAX_VALUE - 600_010UL), "ten minutes early, near the top")
        assertFalse(top.isCurrentAt(ULong.MAX_VALUE - 600_011UL))
    }
}
