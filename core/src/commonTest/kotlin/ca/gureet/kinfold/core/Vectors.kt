// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.Crypto
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.hexBytes
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

/** The platform's own [Crypto], which every test runs on. */
expect fun platformCrypto(): Crypto

/** The text of spec/vectors/kinfold-v0.json. */
expect fun vectorsText(): String

/** The text of spec/PROTOCOL.md. */
expect fun protocolText(): String

/** spec/vectors/kinfold-v0.json, parsed once. */
object Vectors {
    val root: JsonObject by lazy { JsonParser.parseString(vectorsText()).asJsonObject }

    /** spec/PROTOCOL.md. */
    val spec: String by lazy { protocolText() }

    fun group(name: String): JsonObject = root.getAsJsonObject(name)
}

fun JsonObject.hex(key: String): ByteArray = hexBytes(get(key).asString)

fun JsonObject.str(key: String): String = get(key).asString

fun JsonObject.bool(key: String): Boolean = get(key).asBoolean

fun JsonObject.int(key: String): Int = get(key).asInt

fun JsonObject.list(key: String): List<JsonObject> = getAsJsonArray(key).map { it.asJsonObject }

/** A vector's JSON as a [Json] value; every number in the vectors' payloads is a whole number. */
fun jsonOf(v: JsonElement): Json = when (v) {
    is JsonObject -> Json.Obj(v.entrySet().associate { it.key to jsonOf(it.value) })
    is JsonArray -> Json.Arr(v.map { jsonOf(it) })
    is JsonNull -> Json.Null
    is JsonPrimitive -> when {
        v.isBoolean -> Json.Bool(v.asBoolean)
        v.isNumber -> Json.Num(v.asLong)
        else -> Json.Str(v.asString)
    }
}

/** A vector's JSON object as a [Json.Obj]. */
fun objOf(v: JsonObject): Json.Obj = jsonOf(v) as Json.Obj

/**
 * Runs suspending code that never actually suspends, as every platform's [Crypto] in the tests
 * completes at once. Tests use it; nothing else should.
 */
fun sync(block: suspend () -> Unit) {
    var outcome: Result<Unit>? = null
    block.startCoroutine(Continuation(EmptyCoroutineContext) { outcome = it })
    checkNotNull(outcome) { "the block suspended" }.getOrThrow()
}
