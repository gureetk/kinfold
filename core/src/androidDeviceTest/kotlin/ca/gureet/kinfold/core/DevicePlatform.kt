// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.Crypto
import ca.gureet.kinfold.core.crypto.TinkCrypto

/** The vectors and the spec travel in the test APK as Java resources; the build copies them there. */
private fun resource(name: String): String =
    checkNotNull(TinkCrypto::class.java.classLoader?.getResourceAsStream(name)) { "$name isn't in the test APK" }
        .use { it.readBytes().decodeToString() }

actual fun platformCrypto(): Crypto = TinkCrypto()

actual fun vectorsText(): String = resource("kinfold-v0.json")

actual fun protocolText(): String = resource("PROTOCOL.md")
