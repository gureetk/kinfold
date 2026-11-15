// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.wire

import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.Reason

/**
 * Reads the encoding of PROTOCOL.md §2. Input that ends before a field is complete, a length
 * that runs past the end, a `flag` other than 0 or 1 and an `ids` list that is not a multiple
 * of 16 bytes or not strictly ascending all throw [ProtocolException] with `malformed`, and so
 * does anything left over when [finish] is called.
 */
class Reader(private val data: ByteArray) {
    private var pos = 0

    val position: Int get() = pos

    val remaining: Int get() = data.size - pos

    fun u8(): Int {
        need(1)
        return data[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        need(2)
        val v = ((data[pos].toInt() and 0xff) shl 8) or (data[pos + 1].toInt() and 0xff)
        pos += 2
        return v
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        repeat(4) { v = (v shl 8) or (data[pos++].toLong() and 0xff) }
        return v
    }

    fun u64(): ULong {
        need(8)
        var v = 0UL
        repeat(8) { v = (v shl 8) or (data[pos++].toULong() and 0xffUL) }
        return v
    }

    fun bytes(n: Int): ByteArray {
        need(n)
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun vec16(): ByteArray = bytes(u16())

    /** A `vec16` holding strict UTF-8 text; anything else is `malformed`. */
    fun utf8(): String = try {
        vec16().decodeToString(throwOnInvalidSequence = true)
    } catch (_: CharacterCodingException) {
        malformed()
    }

    fun vec32(): ByteArray {
        val n = u32()
        if (n > remaining) malformed()
        return bytes(n.toInt())
    }

    fun flag(): Boolean = when (u8()) {
        0 -> false
        1 -> true
        else -> malformed()
    }

    /** A `vec16` of 16-byte IDs, strictly ascending bytewise. */
    fun ids(): List<Bytes> {
        val raw = vec16()
        if (raw.size % 16 != 0) malformed()
        val out = ArrayList<Bytes>(raw.size / 16)
        for (i in 0 until raw.size / 16) {
            val id = Bytes.of(raw.copyOfRange(16 * i, 16 * i + 16))
            if (out.isNotEmpty() && out.last() >= id) malformed()
            out.add(id)
        }
        return out
    }

    /** Fails unless every byte has been read. */
    fun finish() {
        if (pos != data.size) malformed()
    }

    private fun need(n: Int) {
        if (n < 0 || n > remaining) malformed()
    }
}

fun malformed(): Nothing = throw ProtocolException(Reason.MALFORMED)

/** Reads [data] with [read], which must use all of it; `malformed` otherwise. */
inline fun <T> readAll(data: ByteArray, read: Reader.() -> T): T {
    val r = Reader(data)
    val v = r.read()
    r.finish()
    return v
}
