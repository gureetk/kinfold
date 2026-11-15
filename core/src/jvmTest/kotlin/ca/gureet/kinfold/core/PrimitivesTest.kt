// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.JvmCrypto
import ca.gureet.kinfold.core.crypto.Label
import ca.gureet.kinfold.core.crypto.Primitives
import ca.gureet.kinfold.core.wire.Base64Url
import com.google.gson.JsonObject
import java.util.Base64
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The `primitives` vectors: H, KDF, labelled signatures and base64url (PROTOCOL.md §2, §3.3). */
class PrimitivesTest {
    private val p = Primitives(JvmCrypto())
    private val v = Vectors.group("primitives")

    private fun label(c: JsonObject): Label = checkNotNull(Label.ofText(c.str("label")))

    @Test
    fun hash() = sync {
        assertEquals("kinfold/v0/", v.str("label_prefix"))
        for (c in v.list("H")) assertContentEquals(c.hex("out"), p.h(label(c), c.hex("data")))
    }

    @Test
    fun kdf() = sync {
        for (c in v.list("kdf")) assertContentEquals(c.hex("out"), p.kdf(c.hex("ikm"), label(c), c.int("length")))
    }

    @Test
    fun sign() = sync {
        for (c in v.list("sign")) {
            val key = p.crypto.ed25519(c.hex("seed"))
            val sig = p.sign(key, label(c), c.hex("data"))
            assertContentEquals(c.hex("sig"), sig)
            assertTrue(p.verify(key.publicKey, label(c), c.hex("data"), sig))
            assertFalse(p.verify(key.publicKey, Label.LOG_HASH, c.hex("data"), sig), "another label")
            val flipped = sig.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }
            assertFalse(p.verify(key.publicKey, label(c), c.hex("data"), flipped), "a flipped bit")
        }
    }

    @Test
    fun base64url() {
        for (c in v.list("b64u")) {
            assertEquals(c.str("text"), Base64Url.encode(c.hex("bytes")))
            assertContentEquals(c.hex("bytes"), Base64Url.decode(c.str("text")))
        }
        for (bad in listOf("-w==", "-w=", "+w", "/w", "-x", "A", "AAAAA", "-w ", " -w", "é", "-_8\n")) {
            assertNull(Base64Url.decode(bad), "refuses \"$bad\"")
        }
        // Against the JDK's encoder, at every length up to 200 bytes
        val jdk = Base64.getUrlEncoder().withoutPadding()
        val random = Random(1)
        for (n in 0..200) {
            val bytes = random.nextBytes(n)
            val text = jdk.encodeToString(bytes)
            assertEquals(text, Base64Url.encode(bytes))
            assertContentEquals(bytes, Base64Url.decode(text))
        }
    }

    /** Every label in the table of §16.4, and no other. */
    @Test
    fun labelsMatchTheSpec() {
        val table = Vectors.spec.substringAfter("### 16.4 Labels").substringBefore("### 16.5")
        val names = table.lines()
            .filter { it.startsWith("| `") }
            .flatMap { row -> Regex("`([a-z0-9-]+)`").findAll(row.split("|")[1]).map { it.groupValues[1] } }
            .toSet()
        assertEquals(names, Label.entries.map { it.text.removePrefix("kinfold/v0/") }.toSet())
    }

    /** Every reason code in the table of §16.5, and no other. */
    @Test
    fun reasonsMatchTheSpec() {
        val table = Vectors.spec.substringAfter("### 16.5 Reason codes").substringBefore("### 16.6")
        val codes = Regex("`([a-z_]+)`").findAll(table).map { it.groupValues[1] }.toSet() - "deferred"
        assertEquals(codes, Reason.entries.map { it.code }.toSet())
    }
}
