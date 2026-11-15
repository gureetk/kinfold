// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.identity

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.wire.Codes
import ca.gureet.kinfold.core.wire.compareUnsigned
import ca.gureet.kinfold.core.wire.concat

/**
 * Safety codes (PROTOCOL.md §11): 60 digits, or a QR code, that two people compare to confirm
 * that neither identity key was swapped.
 */
object SafetyCode {
    /** SHA-512 runs this many times for each half, so that matching a half costs a search. */
    const val ITERATIONS = 5200

    /** One person's 30 digits, from their current identity key. */
    suspend fun half(p: Primitives, ikPub: ByteArray): String = digits(p, Label.SAFETY, ikPub)

    /** Both people's halves, the lower key's first, in twelve groups of five: the same for both people. */
    suspend fun code(p: Primitives, a: ByteArray, b: ByteArray): String {
        val (lo, hi) = ordered(a, b)
        return (half(p, lo) + half(p, hi)).chunked(5).joinToString(" ")
    }

    /** The QR form, which compares the two full keys: `KFV0` and b64u(u8(0) ‖ lower key ‖ higher key). */
    fun qr(a: ByteArray, b: ByteArray): String {
        val (lo, hi) = ordered(a, b)
        return Codes.write(Codes.SAFETY, concat(byteArrayOf(Protocol.VERSION.toByte()), lo, hi))
    }

    /**
     * 30 digits from a public key: h = vec16(label) ‖ key, then [ITERATIONS] times h = SHA-512(h ‖ key);
     * each 5 bytes of h's first 30 as a big-endian integer, mod 100,000, as 5 digits. §13.1 uses the
     * same for the server key's fingerprint, under its own label.
     */
    internal suspend fun digits(p: Primitives, label: Label, key: ByteArray): String {
        var h = concat(label.prefix, key)
        repeat(ITERATIONS) { h = p.crypto.sha512(concat(h, key)) }
        return (0 until 30 step 5).joinToString("") { i ->
            var v = 0L
            for (j in i until i + 5) v = (v shl 8) or (h[j].toLong() and 0xff)
            (v % 100_000).toString().padStart(5, '0')
        }
    }

    private fun ordered(a: ByteArray, b: ByteArray): Pair<ByteArray, ByteArray> = if (compareUnsigned(a, b) <= 0) a to b else b to a
}
