// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.server

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Codes
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed
import ca.gureet.kinfold.core.wire.readAll

/**
 * A setup code (PROTOCOL.md §13.1): what the server's command line prints for the first device on a
 * server, carrying the server's key and a registration token for the first account. A device that
 * scans it trusts the key without asking the server.
 */
class Setup(val serverUrl: String, val serverKey: Bytes, val regToken: Bytes, val expiresAt: ULong) {
    fun encode(): ByteArray = encode {
        u8(Protocol.VERSION)
        vec16(serverUrl.encodeToByteArray())
        bytes(serverKey)
        vec16(regToken.toByteArray())
        u64(expiresAt)
    }

    /** The QR code's text: `KFS0` and the setup in base64url. */
    val code: String get() = Codes.write(Codes.SETUP, encode())

    companion object {
        /** The setup in [data], or `malformed`. */
        fun parse(data: ByteArray): Setup = readAll(data) {
            if (u8() != Protocol.VERSION) malformed()
            Setup(utf8(), Bytes.of(bytes(32)), Bytes.of(vec16()), u64())
        }

        /** The setup in a scanned `KFS0` code, or `malformed`. */
        fun fromCode(text: String): Setup = parse(Codes.read(Codes.SETUP, text) ?: malformed())
    }
}
