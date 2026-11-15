// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.hexBytes
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

/** spec/vectors/kinfold-v0.json, which the build names in the system property `kinfold.vectors`. */
object Vectors {
    val file: File by lazy { File(checkNotNull(System.getProperty("kinfold.vectors")) { "kinfold.vectors is not set" }) }

    val root: JsonObject by lazy { JsonParser.parseString(file.readText()).asJsonObject }

    /** spec/PROTOCOL.md, next to the vectors. */
    val spec: String by lazy { file.parentFile.parentFile.resolve("PROTOCOL.md").readText() }

    fun group(name: String): JsonObject = root.getAsJsonObject(name)
}

fun JsonObject.hex(key: String): ByteArray = hexBytes(get(key).asString)

fun JsonObject.str(key: String): String = get(key).asString

fun JsonObject.bool(key: String): Boolean = get(key).asBoolean

fun JsonObject.int(key: String): Int = get(key).asInt

fun JsonObject.list(key: String): List<JsonObject> = getAsJsonArray(key).map { it.asJsonObject }

/** A vector's JSON as a [Json] value; every number in the vectors' payloads is a whole number. */
fun jsonOf(v: JsonElement): Json = when {
    v.isJsonObject -> Json.Obj(v.asJsonObject.entrySet().associate { it.key to jsonOf(it.value) })
    v.isJsonArray -> Json.Arr(v.asJsonArray.map { jsonOf(it) })
    v.isJsonNull -> Json.Null
    v.asJsonPrimitive.isBoolean -> Json.Bool(v.asBoolean)
    v.asJsonPrimitive.isNumber -> Json.Num(v.asLong)
    else -> Json.Str(v.asString)
}

/** A vector's JSON object as a [Json.Obj]. */
fun objOf(v: JsonObject): Json.Obj = jsonOf(v) as Json.Obj

/**
 * Runs suspending code that never actually suspends, as everything on the JVM's [Crypto]
 * completes at once. Tests use it; nothing else should.
 */
fun sync(block: suspend () -> Unit) {
    var outcome: Result<Unit>? = null
    block.startCoroutine(Continuation(EmptyCoroutineContext) { outcome = it })
    checkNotNull(outcome) { "the block suspended" }.getOrThrow()
}
