// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.spike

import ca.gureet.kinfold.core.client.Storage
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * The client's [Storage] in the app's private files, which no other app can read and which no
 * backup takes (the manifest's `no_backup` rules). One file per name; a write goes to a new file
 * that replaces the old one once it is on disk.
 *
 * The keys sit there unsealed, as the harness's do: the real app seals them with the Keystore
 * (plan §8). This is a test app on test keys.
 */
class AppStorage(private val dir: File) : Storage {
    init {
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("can't make $dir")
    }

    override fun read(name: String): ByteArray? = file(name).let { if (it.exists()) it.readBytes() else null }

    override fun write(name: String, data: ByteArray) {
        val tmp = File(dir, ".$name.new")
        FileOutputStream(tmp).use {
            it.write(data)
            it.fd.sync()
        }
        if (!tmp.renameTo(file(name))) throw IOException("can't replace $name")
    }

    override fun append(name: String, data: ByteArray) {
        FileOutputStream(file(name), true).use {
            it.write(data)
            it.fd.sync()
        }
    }

    override fun delete(name: String) {
        file(name).delete()
    }

    private fun file(name: String): File {
        require(NAME.matches(name)) { "a storage name is lower-case letters, digits and hyphens" }
        return File(dir, name)
    }

    private companion object {
        val NAME = Regex("[a-z0-9-]{1,80}")
    }
}
