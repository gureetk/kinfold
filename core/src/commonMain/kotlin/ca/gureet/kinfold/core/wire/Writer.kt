// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.wire

/** Writes the encoding of PROTOCOL.md §2: fields in order, big-endian, no padding or tags. */
class Writer(initialCapacity: Int = 64) {
    private var buf = ByteArray(maxOf(initialCapacity, 16))
    private var len = 0

    val size: Int get() = len

    fun u8(v: Int): Writer {
        require(v in 0..0xff) { "u8 out of range" }
        room(1)
        buf[len++] = v.toByte()
        return this
    }

    fun u16(v: Int): Writer {
        require(v in 0..0xffff) { "u16 out of range" }
        room(2)
        buf[len++] = (v shr 8).toByte()
        buf[len++] = v.toByte()
        return this
    }

    fun u32(v: Long): Writer {
        require(v in 0..0xffffffffL) { "u32 out of range" }
        room(4)
        for (shift in 24 downTo 0 step 8) buf[len++] = (v shr shift).toByte()
        return this
    }

    fun u64(v: ULong): Writer {
        room(8)
        for (shift in 56 downTo 0 step 8) buf[len++] = (v shr shift).toByte()
        return this
    }

    fun bytes(b: ByteArray): Writer {
        room(b.size)
        b.copyInto(buf, len)
        len += b.size
        return this
    }

    fun bytes(b: Bytes): Writer = bytes(b.toByteArray())

    fun vec16(b: ByteArray): Writer = u16(b.size).bytes(b)

    fun vec32(b: ByteArray): Writer = u32(b.size.toLong()).bytes(b)

    fun flag(v: Boolean): Writer = u8(if (v) 1 else 0)

    /** An `ids` list: the IDs sorted bytewise, each once. */
    fun ids(ids: Collection<Bytes>): Writer {
        val sorted = ids.sorted()
        require(sorted.all { it.size == 16 } && sorted.zipWithNext().all { (a, b) -> a < b }) {
            "ids must be distinct 16-byte IDs"
        }
        return vec16(concat(*sorted.map { it.toByteArray() }.toTypedArray()))
    }

    fun toByteArray(): ByteArray = buf.copyOf(len)

    private fun room(n: Int) {
        if (len + n > buf.size) buf = buf.copyOf(maxOf(buf.size * 2, len + n))
    }
}

inline fun encode(write: Writer.() -> Unit): ByteArray = Writer().apply(write).toByteArray()
