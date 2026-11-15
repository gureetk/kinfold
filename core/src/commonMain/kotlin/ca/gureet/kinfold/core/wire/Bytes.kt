// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.wire

/**
 * An immutable byte string: equal to another with the same bytes, and ordered bytewise as
 * unsigned values, the order PROTOCOL.md §2 gives IDs. For IDs, keys and hashes, which are
 * compared, sorted and kept in maps.
 */
class Bytes private constructor(private val data: ByteArray) : Comparable<Bytes> {
    val size: Int get() = data.size

    operator fun get(index: Int): Byte = data[index]

    fun toByteArray(): ByteArray = data.copyOf()

    fun isAllZero(): Boolean = data.all { it == 0.toByte() }

    val hex: String get() = data.toHex()

    override fun equals(other: Any?): Boolean = other is Bytes && data.contentEquals(other.data)

    override fun hashCode(): Int = data.contentHashCode()

    override fun compareTo(other: Bytes): Int = compareUnsigned(data, other.data)

    override fun toString(): String = hex

    companion object {
        fun of(bytes: ByteArray): Bytes = Bytes(bytes.copyOf())

        fun zero(size: Int): Bytes = Bytes(ByteArray(size))
    }
}

/** Compares two byte strings bytewise as unsigned values; a prefix sorts first. */
fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
    for (i in 0 until minOf(a.size, b.size)) {
        val c = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
        if (c != 0) return c
    }
    return a.size - b.size
}

fun ByteArray.toHex(): String {
    val digits = "0123456789abcdef"
    val out = CharArray(size * 2)
    for (i in indices) {
        val v = this[i].toInt() and 0xff
        out[2 * i] = digits[v ushr 4]
        out[2 * i + 1] = digits[v and 15]
    }
    return out.concatToString()
}

/** Lowercase or uppercase hex, two digits a byte. For constants and tests. */
fun hexBytes(text: String): ByteArray {
    require(text.length % 2 == 0) { "odd-length hex" }
    return ByteArray(text.length / 2) { i ->
        val hi = text[2 * i].digitToInt(16)
        val lo = text[2 * i + 1].digitToInt(16)
        ((hi shl 4) or lo).toByte()
    }
}

fun concat(vararg parts: ByteArray): ByteArray {
    val out = ByteArray(parts.sumOf { it.size })
    var at = 0
    for (p in parts) {
        p.copyInto(out, at)
        at += p.size
    }
    return out
}
