// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.store

import ca.gureet.kinfold.core.client.Storage
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * The client's [Storage], and the app's own files, in the app's private files: no other app can
 * read them, and no backup or transfer to a new phone takes them (the manifest's backup rules).
 * One file per name; a write goes to a new file that replaces the old one once it is on disk.
 *
 * The files that hold secrets are sealed by [sealer]: the device's keys (`device`), each circle's
 * epoch secrets (`secrets-…`), and the app's own records (`app-…`), which hold names and the
 * family's latest positions. Copied off the phone, they are unreadable without the key in this
 * phone's Keystore (plan §8). The rest (the verified logs, the replay record, the inbox cursor,
 * the sequence number) are what the server already holds or could work out, and stay plain.
 */
class AppStorage(private val dir: File, private val sealer: Sealer) : Storage {
    init {
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("can't make $dir")
    }

    override fun read(name: String): ByteArray? {
        val f = file(name)
        if (!f.exists()) return null
        val data = f.readBytes()
        return if (sealed(name)) sealer.open(data, name.encodeToByteArray()) else data
    }

    override fun write(name: String, data: ByteArray) {
        val bytes = if (sealed(name)) sealer.seal(data, name.encodeToByteArray()) else data
        val tmp = File(dir, ".$name.new")
        FileOutputStream(tmp).use {
            it.write(bytes)
            it.fd.sync()
        }
        if (!tmp.renameTo(file(name))) throw IOException("can't replace $name")
    }

    override fun append(name: String, data: ByteArray) {
        // The client appends only to its logs and replay records, which aren't sealed.
        require(!sealed(name)) { "a sealed file is written whole" }
        FileOutputStream(file(name), true).use {
            it.write(data)
            it.fd.sync()
        }
    }

    override fun delete(name: String) {
        file(name).delete()
    }

    /** Whether a device has been set up here. */
    fun hasDevice(): Boolean = file(DEVICE).exists()

    private fun file(name: String): File {
        require(NAME.matches(name)) { "a storage name is lower-case letters, digits and hyphens" }
        return File(dir, name)
    }

    companion object {
        private val NAME = Regex("[a-z0-9-]{1,80}")
        private const val DEVICE = "device"

        /** The names whose content is secret. */
        fun sealed(name: String): Boolean = name == DEVICE || name.startsWith("secrets-") || name.startsWith("app-")
    }
}
