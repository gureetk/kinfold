// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike.harness

import ca.gureet.kinfold.core.client.Storage
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions

/**
 * A [Storage] in a directory only its owner can open: one file per name, each readable by the
 * owner alone. A write goes to a new file that replaces the old one once it is on disk.
 */
class FileStorage(private val dir: Path) : Storage {
    init {
        if (!Files.isDirectory(dir)) Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PRIVATE_DIR))
        Files.setPosixFilePermissions(dir, PRIVATE_DIR)
    }

    override fun read(name: String): ByteArray? = path(name).let { if (Files.exists(it)) Files.readAllBytes(it) else null }

    override fun write(name: String, data: ByteArray) {
        val tmp = dir.resolve(".$name.new")
        Files.deleteIfExists(tmp)
        Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PRIVATE_FILE))
        FileChannel.open(tmp, StandardOpenOption.WRITE).use { ch ->
            ch.write(ByteBuffer.wrap(data))
            ch.force(true)
        }
        Files.move(tmp, path(name), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    }

    override fun append(name: String, data: ByteArray) {
        val p = path(name)
        if (!Files.exists(p)) Files.createFile(p, PosixFilePermissions.asFileAttribute(PRIVATE_FILE))
        FileChannel.open(p, StandardOpenOption.WRITE, StandardOpenOption.APPEND).use { ch ->
            ch.write(ByteBuffer.wrap(data))
            ch.force(true)
        }
    }

    override fun delete(name: String) {
        Files.deleteIfExists(path(name))
    }

    private fun path(name: String): Path {
        require(NAME.matches(name)) { "a storage name is lower-case letters, digits and hyphens" }
        return dir.resolve(name)
    }

    private companion object {
        val NAME = Regex("[a-z0-9-]{1,80}")
        val PRIVATE_DIR = PosixFilePermissions.fromString("rwx------")
        val PRIVATE_FILE = PosixFilePermissions.fromString("rw-------")
    }
}
