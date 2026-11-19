// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import androidx.test.platform.app.InstrumentationRegistry
import ca.gureet.kinfold.core.client.OkHttpTransport
import ca.gureet.kinfold.core.crypto.Crypto
import ca.gureet.kinfold.core.crypto.TinkCrypto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.Assume
import java.util.Base64

/** The vectors and the spec travel in the test APK as Java resources; the build copies them there. */
private fun resource(name: String): String =
    checkNotNull(TinkCrypto::class.java.classLoader?.getResourceAsStream(name)) { "$name isn't in the test APK" }
        .use { it.readBytes().decodeToString() }

actual fun platformCrypto(): Crypto = TinkCrypto()

actual fun vectorsText(): String = resource("kinfold-v0.json")

actual fun protocolText(): String = resource("PROTOCOL.md")

// The build passes the server's details as instrumentation arguments (build.gradle.kts).
actual fun testServer(): TestServer? {
    val args = InstrumentationRegistry.getArguments()
    val url = args.getString("kinfold.server") ?: return null
    val code = args.getString("kinfold.setup") ?: return null
    val cert = Base64.getUrlDecoder().decode(args.getString("kinfold.cacert") ?: return null)
    return TestServer(url, code, OkHttpTransport.trusting(cert))
}

actual fun <T> blocking(block: suspend CoroutineScope.() -> T): T = runBlocking(block = block)

actual fun skip(why: String) = Assume.assumeTrue(why, false)
