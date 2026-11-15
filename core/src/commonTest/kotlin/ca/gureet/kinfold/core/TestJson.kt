// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

/**
 * A small JSON model for the tests, so that the vectors read the same on every platform. It reads
 * strict RFC 8259 JSON whose numbers are whole and fit a [Long], which is all the vector file
 * holds. Accessors that take a key fail when it is missing; the `opt` ones give null instead.
 */
sealed class JsonElement {
    val isJsonObject: Boolean get() = this is JsonObject
    val isJsonArray: Boolean get() = this is JsonArray
    val isJsonNull: Boolean get() = this is JsonNull
    val asJsonObject: JsonObject get() = this as? JsonObject ?: error("not an object: $this")
    val asJsonArray: JsonArray get() = this as? JsonArray ?: error("not an array: $this")
    val asJsonPrimitive: JsonPrimitive get() = this as? JsonPrimitive ?: error("not a primitive: $this")
    val asString: String get() = asJsonPrimitive.value as? String ?: error("not a string: $this")
    val asLong: Long get() = asJsonPrimitive.value as? Long ?: error("not a number: $this")
    val asInt: Int get() = asLong.also { require(it in Int.MIN_VALUE..Int.MAX_VALUE) { "not an Int: $it" } }.toInt()
    val asBoolean: Boolean get() = asJsonPrimitive.value as? Boolean ?: error("not a boolean: $this")

    abstract fun deepCopy(): JsonElement

    final override fun toString(): String = StringBuilder().also { write(it) }.toString()

    internal abstract fun write(out: StringBuilder)
}

class JsonObject : JsonElement() {
    private val members = LinkedHashMap<String, JsonElement>()

    operator fun get(key: String): JsonElement = members[key] ?: error("no \"$key\" in $this")

    fun opt(key: String): JsonElement? = members[key]

    fun getAsJsonObject(key: String): JsonObject = get(key).asJsonObject

    fun getAsJsonArray(key: String): JsonArray = get(key).asJsonArray

    fun optObject(key: String): JsonObject? = members[key]?.asJsonObject

    fun optArray(key: String): JsonArray? = members[key]?.asJsonArray

    fun has(key: String): Boolean = key in members

    fun entrySet(): Set<Map.Entry<String, JsonElement>> = members.entries

    fun keySet(): Set<String> = members.keys

    fun size(): Int = members.size

    fun add(key: String, value: JsonElement) {
        members[key] = value
    }

    fun addProperty(key: String, value: String) = add(key, JsonPrimitive(value))

    fun addProperty(key: String, value: Long) = add(key, JsonPrimitive(value))

    fun addProperty(key: String, value: Int) = add(key, JsonPrimitive(value))

    fun addProperty(key: String, value: Boolean) = add(key, JsonPrimitive(value))

    fun remove(key: String): JsonElement? = members.remove(key)

    override fun deepCopy(): JsonObject = JsonObject().also { copy -> members.forEach { (k, v) -> copy.add(k, v.deepCopy()) } }

    override fun equals(other: Any?): Boolean = other is JsonObject && other.members == members

    override fun hashCode(): Int = members.hashCode()

    override fun write(out: StringBuilder) {
        out.append('{')
        members.entries.forEachIndexed { i, (k, v) ->
            if (i > 0) out.append(',')
            writeString(out, k)
            out.append(':')
            v.write(out)
        }
        out.append('}')
    }
}

class JsonArray : JsonElement(), Iterable<JsonElement> {
    private val items = ArrayList<JsonElement>()

    override fun iterator(): Iterator<JsonElement> = items.iterator()

    operator fun get(i: Int): JsonElement = items[i]

    fun size(): Int = items.size

    fun add(value: JsonElement) {
        items.add(value)
    }

    fun add(value: String) = add(JsonPrimitive(value))

    override fun deepCopy(): JsonArray = JsonArray().also { copy -> items.forEach { copy.add(it.deepCopy()) } }

    override fun equals(other: Any?): Boolean = other is JsonArray && other.items == items

    override fun hashCode(): Int = items.hashCode()

    override fun write(out: StringBuilder) {
        out.append('[')
        items.forEachIndexed { i, v ->
            if (i > 0) out.append(',')
            v.write(out)
        }
        out.append(']')
    }
}

/** A string, a whole number or a boolean. */
class JsonPrimitive private constructor(internal val value: Any, private val kind: Kind) : JsonElement() {
    private enum class Kind { STRING, NUMBER, BOOLEAN }

    constructor(value: String) : this(value, Kind.STRING)
    constructor(value: Long) : this(value, Kind.NUMBER)
    constructor(value: Int) : this(value.toLong(), Kind.NUMBER)
    constructor(value: Boolean) : this(value, Kind.BOOLEAN)

    val isString: Boolean get() = kind == Kind.STRING
    val isNumber: Boolean get() = kind == Kind.NUMBER
    val isBoolean: Boolean get() = kind == Kind.BOOLEAN

    override fun deepCopy(): JsonPrimitive = this

    override fun equals(other: Any?): Boolean = other is JsonPrimitive && other.value == value

    override fun hashCode(): Int = value.hashCode()

    override fun write(out: StringBuilder) {
        if (value is String) writeString(out, value) else out.append(value.toString())
    }
}

object JsonNull : JsonElement() {
    val INSTANCE: JsonNull get() = this

    override fun deepCopy(): JsonNull = this

    override fun write(out: StringBuilder) {
        out.append("null")
    }
}

object JsonParser {
    fun parseString(text: String): JsonElement = Reading(text).document()
}

private fun writeString(out: StringBuilder, s: String) {
    out.append('"')
    for (c in s) {
        when {
            c == '"' -> out.append("\\\"")
            c == '\\' -> out.append("\\\\")
            c < ' ' -> out.append("\\u").append(c.code.toString(16).padStart(4, '0'))
            else -> out.append(c)
        }
    }
    out.append('"')
}

private class Reading(private val s: String) {
    private var i = 0

    fun document(): JsonElement {
        val v = value()
        ws()
        if (i != s.length) fail("text after the value")
        return v
    }

    private fun value(): JsonElement {
        ws()
        if (i >= s.length) fail("end of input")
        return when (s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> JsonPrimitive(string())
            't' -> literal("true", JsonPrimitive(true))
            'f' -> literal("false", JsonPrimitive(false))
            'n' -> literal("null", JsonNull)
            else -> number()
        }
    }

    private fun obj(): JsonObject {
        i++
        val o = JsonObject()
        ws()
        if (peek() == '}') {
            i++
            return o
        }
        while (true) {
            ws()
            if (peek() != '"') fail("a key")
            val key = string()
            if (o.has(key)) fail("\"$key\" twice")
            ws()
            expect(':')
            o.add(key, value())
            ws()
            when (next()) {
                ',' -> continue
                '}' -> return o
                else -> fail("',' or '}'")
            }
        }
    }

    private fun arr(): JsonArray {
        i++
        val a = JsonArray()
        ws()
        if (peek() == ']') {
            i++
            return a
        }
        while (true) {
            a.add(value())
            ws()
            when (next()) {
                ',' -> continue
                ']' -> return a
                else -> fail("',' or ']'")
            }
        }
    }

    private fun string(): String {
        expect('"')
        val out = StringBuilder()
        while (true) {
            val c = next()
            when {
                c == '"' -> return out.toString()
                c == '\\' -> when (val e = next()) {
                    '"', '\\', '/' -> out.append(e)
                    'b' -> out.append('\b')
                    'f' -> out.append('\u000c')
                    'n' -> out.append('\n')
                    'r' -> out.append('\r')
                    't' -> out.append('\t')
                    'u' -> {
                        val hex = if (i + 4 <= s.length) s.substring(i, i + 4) else fail("a \\u escape")
                        if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) fail("a \\u escape")
                        out.append(Char(hex.toInt(16)))
                        i += 4
                    }
                    else -> fail("an escape")
                }
                c < ' ' -> fail("a control character in a string")
                else -> out.append(c)
            }
        }
    }

    private fun number(): JsonPrimitive {
        val start = i
        if (peek() == '-') i++
        while (i < s.length && s[i] in '0'..'9') i++
        val text = s.substring(start, i)
        if (i < s.length && s[i] in ".eE") fail("a whole number")
        return JsonPrimitive(text.toLongOrNull() ?: fail("a number that fits a Long: $text"))
    }

    private fun literal(word: String, v: JsonElement): JsonElement {
        if (!s.startsWith(word, i)) fail(word)
        i += word.length
        return v
    }

    private fun ws() {
        while (i < s.length && s[i] in " \t\n\r") i++
    }

    private fun peek(): Char = if (i < s.length) s[i] else fail("end of input")

    private fun next(): Char = peek().also { i++ }

    private fun expect(c: Char) {
        if (next() != c) fail("'$c'")
    }

    private fun fail(what: String): Nothing = error("JSON: expected $what at $i")
}
