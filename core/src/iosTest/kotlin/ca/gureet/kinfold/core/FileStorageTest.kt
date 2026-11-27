// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.app.FileStorage
import ca.gureet.kinfold.core.app.IosSealer
import ca.gureet.kinfold.core.crypto.toByteArray
import ca.gureet.kinfold.core.crypto.toNSData
import ca.gureet.kinfold.core.wire.encode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID
import platform.Foundation.create
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** The iOS app's files, which its extensions share from processes of their own. */
class FileStorageTest {
    /** Not a seal: the tests check the files, not the Keychain. */
    private object Plain : IosSealer {
        override fun seal(data: NSData, name: String): NSData = (byteArrayOf(7) + data.toByteArray()).toNSData()

        override fun open(data: NSData, name: String): NSData? = data.toByteArray().takeIf { it.firstOrNull() == 7.toByte() }?.copyOfRange(1, data.length.toInt())?.toNSData()
    }

    private fun dir(): String = NSTemporaryDirectory() + "kinfold-test-" + NSUUID().UUIDString

    /**
     * Two storages on one directory, as the app and an extension hold it, never hand out the same
     * number, even when they ask at once: each takes the lock on its own open file, as two
     * processes would.
     */
    @Test
    fun countersAreSharedAndNeverRepeat() {
        val d = dir()
        val app = FileStorage(d, Plain)
        val ext = FileStorage(d, Plain)
        app.write("seq", encode { u64(5UL) })
        val got = runBlocking(Dispatchers.Default) {
            (0 until 8).map { i -> async { (0 until 25).map { (if (i % 2 == 0) app else ext).next("seq", 1UL) } } }.awaitAll().flatten()
        }
        assertEquals((5UL until 205UL).toList(), got.sorted())
        assertContentEquals(encode { u64(205UL) }, ext.read("seq"))
        NSFileManager.defaultManager.removeItemAtPath(d, null)
    }

    @Test
    fun secretsAreSealedAndTheRestIsNot() {
        val d = dir()
        val s = FileStorage(d, Plain)
        s.write("device", byteArrayOf(1, 2))
        s.write("cursor", byteArrayOf(3))
        assertContentEquals(byteArrayOf(1, 2), s.read("device"))
        assertContentEquals(byteArrayOf(7, 1, 2), NSData.create(contentsOfFile = "$d/device")?.toByteArray())
        assertContentEquals(byteArrayOf(3), NSData.create(contentsOfFile = "$d/cursor")?.toByteArray())
        s.append("cursor", byteArrayOf(4))
        assertContentEquals(byteArrayOf(3, 4), s.read("cursor"))
        s.delete("cursor")
        assertNull(s.read("cursor"))
        NSFileManager.defaultManager.removeItemAtPath(d, null)
    }
}
