// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.app

import ca.gureet.kinfold.core.client.Storage
import ca.gureet.kinfold.core.crypto.toByteArray
import ca.gureet.kinfold.core.crypto.toNSData
import platform.Foundation.NSData
import platform.Foundation.NSDataWritingAtomic
import platform.Foundation.NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication
import platform.Foundation.NSFileHandle
import platform.Foundation.NSFileManager
import platform.Foundation.NSFileProtectionCompleteUntilFirstUserAuthentication
import platform.Foundation.NSFileProtectionKey
import platform.Foundation.closeFile
import platform.Foundation.dataWithContentsOfFile
import platform.Foundation.fileHandleForWritingAtPath
import platform.Foundation.seekToEndOfFile
import platform.Foundation.synchronizeFile
import platform.Foundation.writeData
import platform.Foundation.writeToFile

/** Seals and opens what [FileStorage] keeps secret. The iOS app gives it: AES-GCM under a key in the Keychain. */
interface IosSealer {
    /** [data] sealed, bound to [name], or null if it can't be. */
    fun seal(data: NSData, name: String): NSData?

    /** [data] opened, or null if it wasn't sealed under this phone's key for [name]. */
    fun open(data: NSData, name: String): NSData?
}

/**
 * The client's [Storage] and the app's own records on iOS: one file per name in [dir], inside the
 * app's container, which no other app reads and iCloud and iTunes backups leave out (the app marks
 * the directory). Each file is protected until the phone is first unlocked after it starts, so
 * that sharing works while it is locked. A write replaces the file whole, atomically.
 *
 * The files that hold secrets are sealed by [sealer]: the device's keys (`device`), each circle's
 * epoch secrets (`secrets-…`), and the app's own records (`app-…`), which hold names and the
 * family's latest positions. The rest (the verified logs, the replay record, the inbox cursor, the
 * sequence number) are what the server already holds or could work out, and stay plain.
 */
class FileStorage(private val dir: String, private val sealer: IosSealer) : Storage {
    private val fm = NSFileManager.defaultManager

    init {
        fm.createDirectoryAtPath(dir, withIntermediateDirectories = true, attributes = PROTECTED, error = null)
    }

    override fun read(name: String): ByteArray? {
        val data = NSData.dataWithContentsOfFile(path(name)) ?: return null
        val plain = if (sealed(name)) sealer.open(data, name) ?: throw IllegalStateException("can't open $name") else data
        return plain.toByteArray()
    }

    override fun write(name: String, data: ByteArray) {
        val bytes = data.toNSData()
        val out = if (sealed(name)) sealer.seal(bytes, name) ?: throw IllegalStateException("can't seal $name") else bytes
        if (!out.writeToFile(path(name), NSDataWritingAtomic or NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication, null)) {
            throw IllegalStateException("can't write $name")
        }
    }

    override fun append(name: String, data: ByteArray) {
        // The client appends only to its logs and replay records, which aren't sealed.
        require(!sealed(name)) { "a sealed file is written whole" }
        val p = path(name)
        if (!fm.fileExistsAtPath(p) && !fm.createFileAtPath(p, null, PROTECTED)) throw IllegalStateException("can't create $name")
        val h = NSFileHandle.fileHandleForWritingAtPath(p) ?: throw IllegalStateException("can't open $name")
        try {
            h.seekToEndOfFile()
            h.writeData(data.toNSData())
            h.synchronizeFile()
        } finally {
            h.closeFile()
        }
    }

    override fun delete(name: String) {
        fm.removeItemAtPath(path(name), null)
    }

    /** Whether a device has been set up here. */
    fun hasDevice(): Boolean = fm.fileExistsAtPath(path(DEVICE))

    private fun path(name: String): String {
        require(NAME.matches(name)) { "a storage name is lower-case letters, digits and hyphens" }
        return "$dir/$name"
    }

    companion object {
        private val NAME = Regex("[a-z0-9-]{1,80}")
        private const val DEVICE = "device"
        private val PROTECTED: Map<Any?, *> = mapOf(NSFileProtectionKey to NSFileProtectionCompleteUntilFirstUserAuthentication)

        /** The names whose content is secret. */
        fun sealed(name: String): Boolean = name == DEVICE || name.startsWith("secrets-") || name.startsWith("app-")
    }
}
