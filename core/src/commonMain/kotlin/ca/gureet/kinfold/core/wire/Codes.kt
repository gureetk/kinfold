// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.wire

/**
 * The text that people scan (PROTOCOL.md §2): a four-character prefix naming the structure, then
 * the structure in base64url. None of these is a URL.
 */
object Codes {
    const val INVITE = "KFI0"
    const val LINK = "KFL0"
    const val RECOVERY_KIT = "KFR0"
    const val SAFETY = "KFV0"
    const val SETUP = "KFS0"

    fun write(prefix: String, bytes: ByteArray): String = prefix + Base64Url.encode(bytes)

    /** The bytes inside [text] if it starts with [prefix] and the rest is strict base64url; null otherwise. */
    fun read(prefix: String, text: String): ByteArray? =
        if (text.startsWith(prefix)) Base64Url.decode(text.substring(prefix.length)) else null
}
