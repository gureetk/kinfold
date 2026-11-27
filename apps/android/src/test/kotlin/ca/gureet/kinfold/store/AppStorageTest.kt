// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.store

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

class AppStorageTest {
    /** The Keystore's AES-GCM, played by the JDK's, with the same file format. */
    private class JdkSealer : Sealer {
        private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

        override fun seal(plain: ByteArray, aad: ByteArray): ByteArray {
            val iv = ByteArray(Sealer.NONCE).also { SecureRandom().nextBytes(it) }
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(Sealer.TAG_BITS, iv)) }
            c.updateAAD(aad)
            return byteArrayOf(Sealer.FORMAT) + iv + c.doFinal(plain)
        }

        override fun open(sealed: ByteArray, aad: ByteArray): ByteArray {
            if (sealed.size < 1 + Sealer.NONCE + Sealer.TAG_BITS / 8 || sealed[0] != Sealer.FORMAT) throw IOException("not a sealed file")
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(Sealer.TAG_BITS, sealed, 1, Sealer.NONCE))
            c.updateAAD(aad)
            return try {
                c.doFinal(sealed, 1 + Sealer.NONCE, sealed.size - 1 - Sealer.NONCE)
            } catch (e: Exception) {
                throw IOException("doesn't open", e)
            }
        }
    }

    @Test
    fun writesAppendsAndDeletes() {
        val dir = Files.createTempDirectory("storage").toFile()
        val s = AppStorage(dir, JdkSealer())
        assertNull(s.read("device"))
        assertFalse(s.hasDevice())
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

    @Test
    fun sealsTheSecretFilesOnly() {
        val dir = Files.createTempDirectory("storage").toFile()
        val s = AppStorage(dir, JdkSealer())
        val secret = "the device's keys".encodeToByteArray()
        for (name in listOf("device", "secrets-00ff", "app-family")) {
            s.write(name, secret)
            val onDisk = File(dir, name).readBytes()
            assertFalse(onDisk.toList().windowed(secret.size).any { it == secret.toList() }, "$name is sealed on disk")
            assertContentEquals(secret, s.read(name))
        }
        s.write("cursor", secret)
        assertContentEquals(secret, File(dir, "cursor").readBytes(), "the inbox cursor isn't secret")
        assertFailsWith<IllegalArgumentException> { s.append("secrets-00ff", secret) }
    }

    @Test
    fun aSealedFileOpensOnlyUnderItsOwnName() {
        val dir = Files.createTempDirectory("storage").toFile()
        val s = AppStorage(dir, JdkSealer())
        s.write("secrets-aa", byteArrayOf(1))
        s.write("secrets-bb", byteArrayOf(2))
        File(dir, "secrets-aa").copyTo(File(dir, "secrets-bb"), overwrite = true)
        assertFailsWith<IOException> { s.read("secrets-bb") }
        File(dir, "secrets-aa").writeBytes(byteArrayOf(1, 2, 3))
        assertFailsWith<IOException> { s.read("secrets-aa") }
    }
}
