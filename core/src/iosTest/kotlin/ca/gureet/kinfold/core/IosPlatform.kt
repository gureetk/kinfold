// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.Crypto
import ca.gureet.kinfold.core.crypto.CryptoKitCrypto
import ca.gureet.kinfold.core.crypto.toByteArray
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import platform.Foundation.NSData
import platform.Foundation.create

actual fun platformCrypto(): Crypto = CryptoKitCrypto()

// The simulator runs the tests as a process on the Mac, so they read the files where the
// repository is; the build writes their paths into SpecFiles.kt (build.gradle.kts).
actual fun vectorsText(): String = read(SpecFiles.VECTORS)

actual fun protocolText(): String = read(SpecFiles.PROTOCOL)

private fun read(path: String): String =
    checkNotNull(NSData.create(contentsOfFile = path)) { "can't read $path" }.toByteArray().decodeToString()

// No transport on iOS yet.
actual fun testServer(): TestServer? = null

actual fun <T> blocking(block: suspend CoroutineScope.() -> T): T = runBlocking(block = block)

// kotlin.test has no skipping on Kotlin/Native: the test passes without running.
actual fun skip(why: String) = println("skipped: $why")
