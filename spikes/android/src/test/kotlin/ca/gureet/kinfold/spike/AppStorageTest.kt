// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class AppStorageTest {
    @Test
    fun writesAppendsAndDeletes() {
        val dir = Files.createTempDirectory("storage").toFile()
        val s = AppStorage(dir)
        assertNull(s.read("device"))
        s.write("device", byteArrayOf(1, 2))
        s.write("device", byteArrayOf(3))
        assertContentEquals(byteArrayOf(3), s.read("device"))
        s.append("replay-ab", byteArrayOf(1))
        s.append("replay-ab", byteArrayOf(2))
        assertContentEquals(byteArrayOf(1, 2), s.read("replay-ab"))
        s.delete("device")
        assertNull(s.read("device"))
        assertEquals(listOf("replay-ab"), dir.list()!!.toList(), "no file is left half-written")
        assertFailsWith<IllegalArgumentException> { s.read("../device") }
    }
}
