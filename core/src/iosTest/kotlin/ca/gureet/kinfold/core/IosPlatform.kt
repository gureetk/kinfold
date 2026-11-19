// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.client.UrlSessionTransport
import ca.gureet.kinfold.core.crypto.Crypto
import ca.gureet.kinfold.core.crypto.CryptoKitCrypto
import ca.gureet.kinfold.core.crypto.toByteArray
import kotlinx.cinterop.toKString
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import platform.Foundation.NSBundle
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.getenv

actual fun platformCrypto(): Crypto = CryptoKitCrypto()

// On an iPhone the tests run inside an app (spikes/ios) that carries the files. The simulator runs
// them as a process on the Mac, so there they read the files where the repository is; the build
// writes their paths into SpecFiles.kt (build.gradle.kts).
actual fun vectorsText(): String = read(bundled("kinfold-v0", "json") ?: SpecFiles.VECTORS).decodeToString()

actual fun protocolText(): String = read(bundled("PROTOCOL", "md") ?: SpecFiles.PROTOCOL).decodeToString()

private fun bundled(name: String, type: String): String? = NSBundle.mainBundle.pathForResource(name, ofType = type)

private fun read(path: String): ByteArray =
    checkNotNull(NSData.create(contentsOfFile = path)) { "can't read $path" }.toByteArray()

// test-with-server.sh passes the server as Gradle properties, and the build hands them to the
// simulator's test process as these variables (build.gradle.kts).
actual fun testServer(): TestServer? {
    val url = env("KINFOLD_SERVER") ?: return null
    val code = env("KINFOLD_SETUP") ?: return null
    val cert = env("KINFOLD_CACERT") ?: return null
    return TestServer(url, code, UrlSessionTransport.trusting(read(cert)))
}

private fun env(name: String): String? = getenv(name)?.toKString()?.takeIf { it.isNotEmpty() }

actual fun <T> blocking(block: suspend CoroutineScope.() -> T): T = runBlocking(block = block)

// kotlin.test has no skipping on Kotlin/Native: the test passes without running.
actual fun skip(why: String) = println("skipped: $why")
