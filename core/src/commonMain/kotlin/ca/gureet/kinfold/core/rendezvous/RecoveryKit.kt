// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.rendezvous

import ca.gureet.kinfold.core.Protocol
import ca.gureet.kinfold.core.identity.IdentityChain
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Codes
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.malformed
import ca.gureet.kinfold.core.wire.readAll

/**
 * A recovery kit (PROTOCOL.md §10.4): the identity key and a recovery signing key on paper, for
 * when every phone is gone. It is printed or written down, never kept on a phone, a server or a
 * cloud drive, so a device holds one only while it is using it.
 */
class RecoveryKit(
    val serverUrl: String,
    val serverKey: Bytes,
    val accountId: Bytes,
    val ikSeed: Bytes,
    val chain: IdentityChain,
    val recoveryDskSeed: Bytes,
    val createdAt: ULong,
) {
    fun encode(): ByteArray = encode {
        u8(Protocol.VERSION)
        vec16(serverUrl.encodeToByteArray())
        bytes(serverKey)
        bytes(accountId)
        bytes(ikSeed)
        vec16(chain.encode())
        bytes(recoveryDskSeed)
        u64(createdAt)
    }

    /** The code to print: `KFR0` and the kit in base64url. */
    val code: String get() = Codes.write(Codes.RECOVERY_KIT, encode())

    companion object {
        /** The kit in [data], or `malformed`. */
        fun parse(data: ByteArray): RecoveryKit = readAll(data) {
            if (u8() != Protocol.VERSION) malformed()
            RecoveryKit(
                serverUrl = utf8(),
                serverKey = Bytes.of(bytes(32)),
                accountId = Bytes.of(bytes(16)),
                ikSeed = Bytes.of(bytes(32)),
                chain = IdentityChain.parse(vec16()),
                recoveryDskSeed = Bytes.of(bytes(32)),
                createdAt = u64(),
            )
        }

        /** The kit in a scanned `KFR0` code, or `malformed`. */
        fun fromCode(text: String): RecoveryKit = parse(Codes.read(Codes.RECOVERY_KIT, text) ?: malformed())
    }
}
