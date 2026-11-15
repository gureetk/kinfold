// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.Crypto
import ca.gureet.kinfold.core.crypto.TinkCrypto
import java.io.File

/** spec/vectors/kinfold-v0.json, which the build names in the system property `kinfold.vectors`. */
private val vectorsFile: File by lazy { File(checkNotNull(System.getProperty("kinfold.vectors")) { "kinfold.vectors is not set" }) }

actual fun platformCrypto(): Crypto = TinkCrypto()

actual fun vectorsText(): String = vectorsFile.readText()

actual fun protocolText(): String = checkNotNull(vectorsFile.parentFile?.parentFile).resolve("PROTOCOL.md").readText()
