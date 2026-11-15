// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Padding
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.concat
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.readAll
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The encoding of PROTOCOL.md §2 and the `padding` vectors (§7.4). */
class WireTest {
    private fun id(n: Int): Bytes = Bytes.of(ByteArray(16).also { it[15] = n.toByte() })

    @Test
    fun roundTrip() {
        val bytes = encode {
            u8(0xfe)
            u16(0xfedc)
            u32(0xfedcba98L)
            u64(ULong.MAX_VALUE)
            vec16(byteArrayOf(1, 2))
            vec32(byteArrayOf(3))
            flag(true)
            flag(false)
            ids(listOf(id(0x80), id(2)))
        }
        readAll(bytes) {
            assertEquals(0xfe, u8())
            assertEquals(0xfedc, u16())
            assertEquals(0xfedcba98L, u32())
            assertEquals(ULong.MAX_VALUE, u64())
            assertContentEquals(byteArrayOf(1, 2), vec16())
            assertContentEquals(byteArrayOf(3), vec32())
            assertTrue(flag())
            assertFalse(flag())
            assertEquals(listOf(id(2), id(0x80)), ids())
        }
    }

    @Test
    fun malformed() {
        fun refuses(why: String, bytes: ByteArray, read: Reader.() -> Unit) {
            val e = assertFailsWith<ProtocolException>(why) { readAll(bytes, read) }
            assertEquals(Reason.MALFORMED, e.reason, why)
        }
        refuses("ends early", byteArrayOf(0)) { u16() }
        refuses("a vec16 past the end", byteArrayOf(0, 2, 1)) { vec16() }
        refuses("a vec32 past the end", byteArrayOf(0, 0, 0, 1)) { vec32() }
        refuses("a 4 GB vec32", byteArrayOf(-1, -1, -1, -1)) { vec32() }
        refuses("a flag of 2", byteArrayOf(2)) { flag() }
        refuses("a byte left over", byteArrayOf(1, 2)) { u8() }
        refuses("ids not a multiple of 16", encode { vec16(ByteArray(15)) }) { ids() }
        refuses("ids out of order", encode { vec16(concat(id(2).toByteArray(), id(1).toByteArray())) }) { ids() }
        refuses("an id twice", encode { vec16(concat(id(1).toByteArray(), id(1).toByteArray())) }) { ids() }
    }

    @Test
    fun bytesOrderUnsigned() {
        assertTrue(id(0x7f) < id(0x80))
        assertTrue(Bytes.of(byteArrayOf(1)) < Bytes.of(byteArrayOf(1, 0)))
        assertEquals(Bytes.of(byteArrayOf(1, 2)), Bytes.of(byteArrayOf(1, 2)))
    }

    @Test
    fun paddingVectors() = sync {
        val v = Vectors.group("padding")
        val crypto = platformCrypto()
        suspend fun sha256(b: ByteArray) = crypto.sha256(b)
        for (c in v.list("valid")) {
            val payload = ByteArray(c.int("payload_length")) { c.hex("payload_byte")[0] }
            val padded = Padding.pad(payload)
            assertEquals(c.int("padded_length"), padded.size)
            assertContentEquals(c.hex("padded_sha256"), sha256(padded))
            assertContentEquals(payload, Padding.unpadBucket(padded))
        }
        for (c in v.list("pad_to")) {
            val payload = ByteArray(c.int("payload_length")) { c.hex("payload_byte")[0] }
            val padded = Padding.padTo(payload, c.int("to"))
            assertContentEquals(c.hex("padded_sha256"), sha256(padded))
            assertContentEquals(payload, Padding.unpadExact(padded, c.int("to")))
            assertNull(Padding.unpadExact(padded, c.int("to") + 1), "another size")
        }
        for (c in v.list("invalid")) assertNull(Padding.unpadBucket(c.hex("padded")), c.str("description"))
    }

    @Test
    fun paddingLimits() {
        assertEquals(65536, Padding.pad(ByteArray(65535)).size)
        assertFailsWith<IllegalArgumentException> { Padding.pad(ByteArray(65536)) }
        assertEquals(256, Padding.pad(ByteArray(255)).size)
        assertEquals(512, Padding.pad(ByteArray(256)).size)
        assertFailsWith<IllegalArgumentException> { Padding.padTo(ByteArray(512), 512) }
    }
}
