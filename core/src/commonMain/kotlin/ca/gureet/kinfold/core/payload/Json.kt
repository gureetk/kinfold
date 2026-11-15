// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.payload

import kotlin.math.abs
import kotlin.math.floor

/**
 * A JSON value as a payload may hold it (PROTOCOL.md §8.1). Every number is whole and at most
 * 2^53 − 1 in magnitude, so numbers are [Long]s.
 */
sealed class Json {
    /** An object. Its fields keep the order they arrived in; no key appears twice. */
    data class Obj(val fields: Map<String, Json>) : Json() {
        operator fun get(key: String): Json? = fields[key]

        /** The field [key] if it is a string, else null. */
        fun string(key: String): String? = (fields[key] as? Str)?.value

        /** The field [key] if it is a number, else null. */
        fun long(key: String): Long? = (fields[key] as? Num)?.value
    }

    data class Arr(val items: List<Json>) : Json()

    data class Str(val value: String) : Json()

    data class Num(val value: Long) : Json()

    data class Bool(val value: Boolean) : Json()

    data object Null : Json()

    /** Compact JSON (§8.1): no spaces, non-ASCII characters as UTF-8, the escapes JSON requires and no others. */
    fun write(): String = StringBuilder().also { writeTo(it, this) }.toString()

    /** [write] as UTF-8 bytes: what a sender pads and encrypts. */
    fun encode(): ByteArray = write().encodeToByteArray()

    /**
     * The limits a parse applies as it reads: nesting depth, UTF-8 bytes in a string (and in a
     * top-level `avatar`), and items in an array.
     */
    data class Limits(val maxDepth: Int, val maxString: Int, val maxAvatar: Int, val maxArray: Int) {
        companion object {
            /** §8.1, for payloads. */
            val PAYLOAD = Limits(MAX_DEPTH, MAX_STRING, MAX_AVATAR, MAX_ARRAY)

            /**
             * For JSON that isn't a payload, such as a link response (§10.3): the payload limits,
             * except that arrays may be of any length, since a circle may have more than 256 epochs.
             */
            val MESSAGE = Limits(MAX_DEPTH, MAX_STRING, MAX_STRING, Int.MAX_VALUE)
        }
    }

    companion object {
        /** Objects and arrays nest at most this deep; the payload object itself is level 1. */
        const val MAX_DEPTH = 8

        /** The most UTF-8 bytes in a string, key or value. */
        const val MAX_STRING = 4096

        /** The most UTF-8 bytes in the top-level field `avatar`. */
        const val MAX_AVATAR = 43_700

        /** The most items in an array. */
        const val MAX_ARRAY = 256

        /** The largest magnitude of a number, 2^53 − 1. */
        const val MAX_INT = 9_007_199_254_740_991L

        /**
         * Step 14 of §7.6: [bytes] as a payload, that is UTF-8 JSON whose top level is an object
         * with a string `t`, within every limit of §8.1. Null for anything else (`bad_payload`).
         *
         * A payload that repeats a key within an object is refused, which §8.1 allows. That way
         * no two readers of one payload can disagree about which value counts.
         */
        fun parsePayload(bytes: ByteArray): Obj? = parseObject(bytes, Limits.PAYLOAD)?.takeIf { it["t"] is Str }

        /**
         * [bytes] as UTF-8 JSON whose top level is an object, within [limits]; null for anything
         * else. A key repeated within an object is refused here too.
         */
        fun parseObject(bytes: ByteArray, limits: Limits): Obj? {
            val text = try {
                bytes.decodeToString(throwOnInvalidSequence = true)
            } catch (_: CharacterCodingException) {
                return null
            }
            return try {
                Parser(text, limits).document()
            } catch (_: NotAPayload) {
                null
            }
        }

        private fun writeTo(out: StringBuilder, v: Json) {
            when (v) {
                is Obj -> {
                    out.append('{')
                    var first = true
                    for ((k, x) in v.fields) {
                        if (!first) out.append(',')
                        first = false
                        writeString(out, k)
                        out.append(':')
                        writeTo(out, x)
                    }
                    out.append('}')
                }
                is Arr -> {
                    out.append('[')
                    v.items.forEachIndexed { i, x ->
                        if (i > 0) out.append(',')
                        writeTo(out, x)
                    }
                    out.append(']')
                }
                is Str -> writeString(out, v.value)
                is Num -> out.append(v.value)
                is Bool -> out.append(v.value)
                Null -> out.append("null")
            }
        }

        private fun writeString(out: StringBuilder, s: String) {
            out.append('"')
            for (c in s) {
                when (c) {
                    '"' -> out.append("\\\"")
                    '\\' -> out.append("\\\\")
                    '\n' -> out.append("\\n")
                    '\r' -> out.append("\\r")
                    '\t' -> out.append("\\t")
                    '\b' -> out.append("\\b")
                    '\u000c' -> out.append("\\f")
                    else -> if (c < ' ') {
                        out.append("\\u00").append(HEX[c.code shr 4]).append(HEX[c.code and 15])
                    } else {
                        out.append(c)
                    }
                }
            }
            out.append('"')
        }

        private const val HEX = "0123456789abcdef"
    }
}

/** Thrown inside [Parser] for anything that isn't a payload; never escapes [Json.parsePayload]. */
private class NotAPayload : Exception()

/**
 * RFC 8259 JSON with [limits] (those of §8.1, for a payload) checked as the text is read, so that
 * nothing too deep or too large is ever built. The input is already valid UTF-8, decoded.
 */
private class Parser(private val s: String, private val limits: Json.Limits) {
    private var i = 0

    fun document(): Json.Obj {
        ws()
        if (peek() != '{') refuse()
        val obj = obj(1)
        ws()
        if (i != s.length) refuse()
        return obj
    }

    private fun value(depth: Int, limit: Int): Json {
        ws()
        return when (peek()) {
            '{' -> obj(depth)
            '[' -> arr(depth)
            '"' -> Json.Str(string(limit))
            't' -> literal("true", Json.Bool(true))
            'f' -> literal("false", Json.Bool(false))
            'n' -> literal("null", Json.Null)
            else -> number()
        }
    }

    private fun obj(depth: Int): Json.Obj {
        if (depth > limits.maxDepth) refuse()
        i++
        val fields = LinkedHashMap<String, Json>()
        ws()
        if (peek() == '}') {
            i++
            return Json.Obj(fields)
        }
        while (true) {
            ws()
            if (peek() != '"') refuse()
            val key = string(limits.maxString)
            if (key in fields) refuse()
            ws()
            if (next() != ':') refuse()
            // The one exception to the string limit: the payload's own `avatar` field.
            fields[key] = value(depth + 1, if (depth == 1 && key == "avatar") limits.maxAvatar else limits.maxString)
            ws()
            when (next()) {
                ',' -> continue
                '}' -> return Json.Obj(fields)
                else -> refuse()
            }
        }
    }

    private fun arr(depth: Int): Json.Arr {
        if (depth > limits.maxDepth) refuse()
        i++
        val items = ArrayList<Json>()
        ws()
        if (peek() == ']') {
            i++
            return Json.Arr(items)
        }
        while (true) {
            if (items.size == limits.maxArray) refuse()
            items.add(value(depth + 1, limits.maxString))
            ws()
            when (next()) {
                ',' -> continue
                ']' -> return Json.Arr(items)
                else -> refuse()
            }
        }
    }

    /** A string at [i] (the opening quote), at most [limit] bytes once encoded as UTF-8. */
    private fun string(limit: Int): String {
        i++
        val out = StringBuilder()
        var utf8 = 0
        while (true) {
            val c = next()
            val code: Int = when {
                c == '"' -> return out.toString()
                c == '\\' -> escape()
                c < ' ' -> refuse()                         // control characters must be escaped
                c.isHighSurrogate() -> {
                    // The text came from valid UTF-8, so a high surrogate is always followed by a low one.
                    val low = next()
                    0x10000 + ((c.code - 0xD800) shl 10) + (low.code - 0xDC00)
                }
                else -> c.code
            }
            utf8 += when {
                code < 0x80 -> 1
                code < 0x800 -> 2
                code < 0x10000 -> 3
                else -> 4
            }
            if (utf8 > limit) refuse()
            appendCodePoint(out, code)
        }
    }

    /** The code point of the escape after a backslash; a `\u` escape may not leave a surrogate unpaired. */
    private fun escape(): Int = when (next()) {
        '"' -> '"'.code
        '\\' -> '\\'.code
        '/' -> '/'.code
        'b' -> 8
        'f' -> 12
        'n' -> 10
        'r' -> 13
        't' -> 9
        'u' -> {
            val unit = hex4()
            when (unit) {
                in 0xD800..0xDBFF -> {
                    if (next() != '\\' || next() != 'u') refuse()
                    val low = hex4()
                    if (low !in 0xDC00..0xDFFF) refuse()
                    0x10000 + ((unit - 0xD800) shl 10) + (low - 0xDC00)
                }
                in 0xDC00..0xDFFF -> refuse()
                else -> unit
            }
        }
        else -> refuse()
    }

    private fun hex4(): Int {
        var v = 0
        repeat(4) {
            val d = when (val c = next()) {
                in '0'..'9' -> c - '0'
                in 'a'..'f' -> c - 'a' + 10
                in 'A'..'F' -> c - 'A' + 10
                else -> refuse()
            }
            v = (v shl 4) or d
        }
        return v
    }

    /**
     * A number, read as an IEEE 754 double as §8.1 says: it must be whole and within
     * ±(2^53 − 1), so `1.0` and `1e3` pass and `1.5` doesn't.
     */
    private fun number(): Json.Num {
        val start = i
        if (peek() == '-') i++
        when (peek()) {
            '0' -> i++
            in '1'..'9' -> digits()
            else -> refuse()
        }
        if (peek() == '.') {
            i++
            if (peek() !in '0'..'9') refuse()
            digits()
        }
        if (peek() == 'e' || peek() == 'E') {
            i++
            if (peek() == '+' || peek() == '-') i++
            if (peek() !in '0'..'9') refuse()
            digits()
        }
        val d = s.substring(start, i).toDouble()
        if (!d.isFinite() || d != floor(d) || abs(d) > Json.MAX_INT.toDouble()) refuse()
        return Json.Num(d.toLong())
    }

    private fun digits() {
        while (peek() in '0'..'9') i++
    }

    private fun literal(word: String, v: Json): Json {
        if (!s.startsWith(word, i)) refuse()
        i += word.length
        return v
    }

    private fun ws() {
        while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
    }

    /** The character at [i], or a NUL that matches nothing a caller looks for. */
    private fun peek(): Char = if (i < s.length) s[i] else '\u0000'

    private fun next(): Char = if (i < s.length) s[i++] else refuse()

    private fun refuse(): Nothing = throw NotAPayload()

    private fun appendCodePoint(out: StringBuilder, code: Int) {
        if (code < 0x10000) {
            out.append(code.toChar())
        } else {
            val v = code - 0x10000
            out.append((0xD800 + (v shr 10)).toChar()).append((0xDC00 + (v and 0x3FF)).toChar())
        }
    }
}
