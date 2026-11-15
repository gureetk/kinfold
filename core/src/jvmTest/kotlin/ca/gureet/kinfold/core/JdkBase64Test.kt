// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.wire.Base64Url
import java.util.Base64
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/** Base64url (PROTOCOL.md §2) against the JDK's encoder, at every length up to 200 bytes. */
class JdkBase64Test {
    @Test
    fun againstTheJdk() {
        val jdk = Base64.getUrlEncoder().withoutPadding()
        val random = Random(1)
        for (n in 0..200) {
            val bytes = random.nextBytes(n)
            val text = jdk.encodeToString(bytes)
            assertEquals(text, Base64Url.encode(bytes))
            assertContentEquals(bytes, Base64Url.decode(text))
        }
    }
}
