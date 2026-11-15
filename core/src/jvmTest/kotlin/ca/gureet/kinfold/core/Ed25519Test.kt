// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.Crypto
import ca.gureet.kinfold.core.crypto.Ed25519Checks
import ca.gureet.kinfold.core.crypto.JvmCrypto
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.wire.hexBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The `ed25519` vectors: the verdict PROTOCOL.md §3.3 requires on every edge case. */
class Ed25519Test {
    private val p = Primitives(JvmCrypto())
    private val v = Vectors.group("ed25519")

    @Test
    fun signatures() = sync {
        val signatures = v.list("signatures")
        assertEquals(28, signatures.size)
        for (s in signatures) {
            assertEquals(s.bool("valid"), p.verifyMessage(s.hex("pub"), s.hex("msg"), s.hex("sig")), s.str("name"))
        }
    }

    @Test
    fun keys() {
        val keys = v.list("keys")
        assertEquals(17, keys.size)
        for (k in keys) assertEquals(k.bool("invalid"), Ed25519Checks.isInvalidKey(k.hex("pub")), k.str("note"))
    }

    /** A platform that accepts every signature, to see what the byte checks refuse on their own. */
    private class AcceptsAll(inner: Crypto) : Crypto by inner {
        override suspend fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray) = true
    }

    /**
     * Where the equation holds, as for small-order and non-canonical keys and R, only the byte
     * checks can refuse the signature, whatever the platform says.
     */
    @Test
    fun byteChecksAlone() = sync {
        val permissive = Primitives(AcceptsAll(JvmCrypto()))
        var refused = 0
        for (s in v.list("signatures")) {
            val verdict = permissive.verifyMessage(s.hex("pub"), s.hex("msg"), s.hex("sig"))
            if (s.bool("valid")) {
                assertTrue(verdict, s.str("name"))
            } else if (s.bool("without_byte_checks")) {
                assertFalse(verdict, s.str("name"))
                refused++
            }
        }
        assertTrue(refused >= 15, "the vectors exercise the checks")
    }

    /** Each bound of §3.3, on either side. */
    @Test
    fun bounds() = sync {
        val permissive = Primitives(AcceptsAll(JvmCrypto()))
        val key = v.list("keys").first { it.str("note") == "an ordinary key" }.hex("pub")
        val msg = byteArrayOf(1, 2, 3)
        suspend fun accepts(pub: ByteArray, r: ByteArray, s: ByteArray) = permissive.verifyMessage(pub, msg, r + s)
        val l = hexBytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        val lMinusOne = l.copyOf().also { it[0] = 0xec.toByte() }
        val lPlusOne = l.copyOf().also { it[0] = 0xee.toByte() }
        assertTrue(accepts(key, key, lMinusOne), "S = L - 1")
        assertFalse(accepts(key, key, l), "S = L")
        assertFalse(accepts(key, key, lPlusOne), "S = L + 1")
        assertFalse(accepts(key, key, ByteArray(32) { -1 }), "S = 2^256 - 1")
        val pMinusTwo = hexBytes("ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        val p = hexBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        val pPlusOne = hexBytes("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        val pWithSign = hexBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        val zeroWithSign = hexBytes("0000000000000000000000000000000000000000000000000000000000000080")
        for ((name, point) in listOf("p" to p, "p + 1" to pPlusOne, "p, sign bit set" to pWithSign, "0, sign bit set" to zeroWithSign)) {
            assertFalse(accepts(key, point, lMinusOne), "R with y = $name")
            assertFalse(accepts(point, key, lMinusOne), "a key with y = $name")
        }
        assertTrue(accepts(key, pMinusTwo, lMinusOne), "R with y = p - 2")
        assertTrue(accepts(pMinusTwo, key, lMinusOne), "a key with y = p - 2")
        assertFalse(accepts(key.copyOf(31), key, lMinusOne), "a 31-byte key")
        assertFalse(permissive.verifyMessage(key, msg, key + lMinusOne + byteArrayOf(0)), "a 65-byte signature")
    }
}
