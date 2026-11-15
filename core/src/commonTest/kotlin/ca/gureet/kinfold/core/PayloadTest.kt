// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.envelope.SenderRules
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.toHex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The limits of PROTOCOL.md §8.1 by hand, at both edges, and the JSON a sender writes. The vector
 * file holds only some of these edges, to stay small.
 */
class PayloadTest {
    private fun ok(text: String): Boolean = Json.parsePayload(text.encodeToByteArray()) != null

    private fun ok(bytes: ByteArray): Boolean = Json.parsePayload(bytes) != null

    private fun nested(levels: Int, open: String = """{"a":""", close: String = "}"): String {
        var out = "1"
        repeat(levels - 1) { out = open + out + close }
        return """{"t":"x","v":$out}"""
    }

    private fun str(s: String) = """{"t":"x","s":"$s"}"""

    @Test
    fun depth() {
        assertTrue(ok(nested(8)), "8 levels of objects")
        assertFalse(ok(nested(9)), "9 levels of objects")
        assertTrue(ok(nested(8, "[", "]")), "8 levels of arrays")
        assertFalse(ok(nested(9, "[", "]")), "9 levels of arrays")
        assertFalse(ok("""{"t":"x","v":""" + "[".repeat(100_000) + "]".repeat(100_000) + "}"), "deep nesting fails without recursing")
    }

    @Test
    fun strings() {
        assertTrue(ok(str("a".repeat(4096))))
        assertFalse(ok(str("a".repeat(4097))))
        assertTrue(ok(str("é".repeat(2048))), "counted in UTF-8 bytes")
        assertFalse(ok(str("é".repeat(2049))))
        assertTrue(ok(str("😀".repeat(1024))), "a character outside the BMP is 4 bytes")
        assertFalse(ok(str("😀".repeat(1025))))
        assertTrue(ok(str("\\u00e9".repeat(2048))), "an escape counts as the character it stands for")
        assertFalse(ok(str("\\u00e9".repeat(2049))))
        assertTrue(ok("""{"t":"x","${"k".repeat(4096)}":1}"""))
        assertFalse(ok("""{"t":"x","${"k".repeat(4097)}":1}"""), "keys have the same limit")
    }

    @Test
    fun avatar() {
        assertTrue(ok("""{"t":"profile","avatar":"${"A".repeat(43_700)}"}"""))
        assertFalse(ok("""{"t":"profile","avatar":"${"A".repeat(43_701)}"}"""))
        assertTrue(ok("""{"t":"profile","avatar":"${"é".repeat(21_850)}"}"""))
        assertFalse(ok("""{"t":"profile","avatar":"${"é".repeat(21_851)}"}"""))
        assertFalse(ok("""{"t":"profile","x":{"avatar":"${"A".repeat(4097)}"}}"""), "only the top-level field")
        assertFalse(ok("""{"t":"profile","avatar":["${"A".repeat(4097)}"]}"""), "only a string in that field")
        assertFalse(ok("""{"t":"profile","${"A".repeat(4097)}":"avatar"}"""))
    }

    @Test
    fun arrays() {
        assertTrue(ok("""{"t":"x","a":[${List(256) { "0" }.joinToString(",")}]}"""))
        assertFalse(ok("""{"t":"x","a":[${List(257) { "0" }.joinToString(",")}]}"""))
        assertTrue(ok("""{"t":"x","a":[]}"""))
    }

    @Test
    fun numbers() {
        for (n in listOf("9007199254740991", "-9007199254740991", "0", "-0", "1.0", "1e3", "1E+2", "0.0", "-0.0", "250e-1", "1.000e2")) {
            assertTrue(ok("""{"t":"x","n":$n}"""), n)
        }
        for (n in listOf("9007199254740992", "-9007199254740992", "1.5", "1e-1", "1e400", "-1e400", "01", "+1", ".5", "1.", "-", "1e", "1e+", "0x10", "NaN", "Infinity", "-Infinity")) {
            assertFalse(ok("""{"t":"x","n":$n}"""), n)
        }
        assertEquals(Json.Num(1000), Json.parsePayload("""{"t":"x","n":1e3}""".encodeToByteArray())?.get("n"))
        assertEquals(Json.Num(-9007199254740991), Json.parsePayload("""{"t":"x","n":-9007199254740991}""".encodeToByteArray())?.get("n"))
    }

    @Test
    fun literals() {
        assertTrue(ok("""{"t":"x","a":true,"b":false,"c":null}"""))
        for (v in listOf("tru", "True", "nul", "None", "undefined")) assertFalse(ok("""{"t":"x","v":$v}"""), v)
    }

    @Test
    fun surrogates() {
        assertFalse(ok(str("\\ud800")), "an unpaired high surrogate")
        assertFalse(ok(str("\\udc00")), "an unpaired low surrogate")
        assertFalse(ok(str("\\ud800\\u0041")))
        assertFalse(ok(str("\\udc00\\ud800")), "a pair the wrong way round")
        assertFalse(ok("""{"t":"x","\udc00":1}"""), "in a key")
        assertFalse(ok("""{"t":"profile","avatar":"\ud800"}"""), "in the avatar")
        assertEquals(Json.Str("😀"), Json.parsePayload(str("\\ud83d\\ude00").encodeToByteArray())?.get("s"))
    }

    @Test
    fun utf8() {
        val head = """{"t":"x","s":"""".encodeToByteArray()
        val tail = "\"}".encodeToByteArray()
        fun inString(vararg b: Int) = ok(head + ByteArray(b.size) { b[it].toByte() } + tail)
        assertFalse(inString(0xff), "a byte that never starts UTF-8")
        assertFalse(inString(0xc0, 0xaf), "an overlong encoding")
        assertFalse(inString(0xed, 0xa0, 0x80), "an encoded surrogate")
        assertFalse(inString(0xe2, 0x82), "a sequence cut short")
        assertTrue(inString(0xe2, 0x82, 0xac))
        assertFalse(ok(byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + """{"t":"x"}""".encodeToByteArray()), "a byte order mark")
    }

    @Test
    fun structure() {
        assertTrue(ok("""{"t":""}"""))
        assertTrue(ok(" \t\r\n{ \"t\" : \"x\" , \"a\" : [ 1 , 2 ] } \n"), "JSON whitespace anywhere")
        for (text in listOf("[1]", "\"x\"", "1", "null", "{}", """{"t":1}""", """{"t":null}""", """{"t":["x"]}""", "")) {
            assertFalse(ok(text), "not an object with a string t: $text")
        }
        assertFalse(ok("""{"t":"x"} {}"""), "something after the object")
        assertFalse(ok("""{"t":"x",}"""), "a trailing comma in an object")
        assertFalse(ok("""{"t":"x","a":[1,]}"""), "a trailing comma in an array")
        assertFalse(ok("""{"t":"x" "a":1}"""))
        assertFalse(ok("""{"t":"x","a":1"""), "cut short")
        assertFalse(ok("{'t':'x'}"))
        assertFalse(ok("""{"t":"x","s":"a${'\n'}b"}"""), "a control character must be escaped")
        assertTrue(ok("""{"t":"x","s":"a\nb\t\"\\\/\b\f\r\u0001"}"""))
        assertFalse(ok("""{"t":"x","s":"\x"}"""), "an escape JSON doesn't have")
        assertFalse(ok(" {\"t\":\"x\"}"), "whitespace JSON doesn't have")
    }

    @Test
    fun repeatedKeys() {
        assertFalse(ok("""{"t":"x","a":1,"a":2}"""), "a key twice: refused, as §8.1 allows")
        assertFalse(ok("""{"t":"x","t":"y"}"""))
        assertFalse(ok("""{"t":"x","o":{"a":1,"a":1}}"""), "at any depth")
        assertTrue(ok("""{"t":"x","o":{"a":1},"p":{"a":1}}"""), "the same key in different objects")
    }

    @Test
    fun writing() {
        val v = Json.Obj(
            linkedMapOf(
                "t" to Json.Str("chat"),
                "text" to Json.Str("a\"b\\c/\n\r\t\b\u000c\u0001\u001f é 😀  "),
                "n" to Json.Num(-9007199254740991),
                "a" to Json.Arr(listOf(Json.Bool(true), Json.Bool(false), Json.Null, Json.Obj(emptyMap()), Json.Arr(emptyList()))),
            ),
        )
        val text = """{"t":"chat","text":"a\"b\\c/\n\r\t\b\f\u0001\u001f é 😀 """ + " " + """","n":-9007199254740991,"a":[true,false,null,{},[]]}"""
        assertEquals(text, v.write())
        assertEquals(v, Json.parsePayload(v.encode()))
    }

    /**
     * Every vector payload survives writing and reading again, and those of the types §8.2 defines
     * are written byte for byte as their senders wrote them. (One vector writes `1.0` on purpose.)
     */
    @Test
    fun vectorsWriteBack() {
        for (t in Vectors.group("envelopes").list("valid")) {
            val bytes = t.hex("payload_bytes")
            val parsed = assertNotNull(Json.parsePayload(bytes), t.str("name"))
            assertEquals(parsed, Json.parsePayload(parsed.encode()), t.str("name"))
            if (parsed.string("t") in SenderRules.CIRCLE_TYPES + SenderRules.DIRECT_TYPES) {
                assertEquals(bytes.toHex(), parsed.encode().toHex(), t.str("name"))
            }
        }
    }
}
