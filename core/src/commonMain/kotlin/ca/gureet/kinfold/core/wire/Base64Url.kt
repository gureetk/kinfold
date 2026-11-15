// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.wire

/**
 * Base64url without padding (RFC 4648 §5), the text form of PROTOCOL.md §2. Decoding refuses
 * padding, characters outside `A–Z a–z 0–9 - _`, a length no encoding has, and non-canonical
 * input, whose leftover bits aren't zero and which would therefore encode differently.
 */
object Base64Url {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val VALUES = IntArray(128) { -1 }.also { table ->
        for (i in ALPHABET.indices) table[ALPHABET[i].code] = i
    }

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size * 4 + 2) / 3)
        var bits = 0
        var count = 0
        for (b in bytes) {
            bits = (bits shl 8) or (b.toInt() and 0xff)
            count += 8
            while (count >= 6) {
                count -= 6
                out.append(ALPHABET[(bits shr count) and 63])
            }
            bits = bits and ((1 shl count) - 1)
        }
        if (count > 0) out.append(ALPHABET[(bits shl (6 - count)) and 63])
        return out.toString()
    }

    /** The bytes [text] encodes, or null if it isn't canonical base64url without padding. */
    fun decode(text: String): ByteArray? {
        if (text.length % 4 == 1) return null
        val out = ByteArray(text.length * 3 / 4)
        var bits = 0
        var count = 0
        var at = 0
        for (c in text) {
            val v = if (c.code < 128) VALUES[c.code] else -1
            if (v < 0) return null
            bits = (bits shl 6) or v
            count += 6
            if (count >= 8) {
                count -= 8
                out[at++] = (bits shr count).toByte()
                bits = bits and ((1 shl count) - 1)
            }
        }
        return if (bits == 0) out else null
    }
}
