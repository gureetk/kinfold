// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

/**
 * Where a [Client] keeps what a device knows between runs: its keys, the server it trusts, each
 * circle's verified log and epoch secrets, its place in the inbox. Each platform decides how the
 * files are protected; the keys must stay out of backups and off other devices.
 *
 * Names are short ASCII words. A client calls these one at a time, never two at once.
 */
interface Storage {
    /** The whole content of [name], or null if there is none. */
    fun read(name: String): ByteArray?

    /** Replaces [name]'s content: after a crash it holds the old content or the new, never part of either. */
    fun write(name: String, data: ByteArray)

    /**
     * Adds [data] at the end of [name], creating it if needed. After a crash the end may hold part
     * of the last addition, which readers of the name must notice.
     */
    fun append(name: String, data: ByteArray)

    fun delete(name: String)
}

/** A [Storage] in memory, for tests and for devices that keep nothing. */
class MemoryStorage : Storage {
    private val files = HashMap<String, ByteArray>()

    override fun read(name: String): ByteArray? = files[name]?.copyOf()

    override fun write(name: String, data: ByteArray) {
        files[name] = data.copyOf()
    }

    override fun append(name: String, data: ByteArray) {
        files[name] = (files[name] ?: ByteArray(0)) + data
    }

    override fun delete(name: String) {
        files.remove(name)
    }
}
