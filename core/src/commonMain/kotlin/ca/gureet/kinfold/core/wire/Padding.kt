// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.wire

/**
 * Padding (PROTOCOL.md §7.4): the payload, 0x80, then zero bytes to a fixed size, so that the
 * size says nothing about what was padded.
 */
object Padding {
    /** Envelope payloads and share updates pad to one of these. */
    val BUCKETS: List<Int> = listOf(256, 512, 1024, 2048, 4096, 8192, 16384, 65536)

    const val MAX_PAYLOAD: Int = 65535

    /** [payload], 0x80 and zero bytes, to exactly [size] bytes. */
    fun padTo(payload: ByteArray, size: Int): ByteArray {
        require(payload.size <= size - 1) { "payload doesn't fit" }
        val out = payload.copyOf(size)
        out[payload.size] = 0x80.toByte()
        return out
    }

    /** [payload] padded to the smallest bucket that holds it and the 0x80. */
    fun pad(payload: ByteArray): ByteArray {
        require(payload.size <= MAX_PAYLOAD) { "payload over 65,535 bytes" }
        return padTo(payload, BUCKETS.first { it >= payload.size + 1 })
    }

    /** The payload of an envelope or a share update, whose padded size must be a bucket. */
    fun unpadBucket(padded: ByteArray): ByteArray? = if (padded.size in BUCKETS) unpad(padded) else null

    /** The payload of log details (512 bytes) or a push (2,560), padded to exactly [size]. */
    fun unpadExact(padded: ByteArray, size: Int): ByteArray? = if (padded.size == size) unpad(padded) else null

    /**
     * Unpad of §7.4: trailing zero bytes stripped, then the 0x80 before them. Null if what is
     * left doesn't end in 0x80.
     */
    private fun unpad(padded: ByteArray): ByteArray? {
        var end = padded.size
        while (end > 0 && padded[end - 1] == 0.toByte()) end--
        if (end == 0 || padded[end - 1] != 0x80.toByte()) return null
        return padded.copyOf(end - 1)
    }
}
