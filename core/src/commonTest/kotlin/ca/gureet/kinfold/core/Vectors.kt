// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

import ca.gureet.kinfold.core.crypto.Crypto
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.hexBytes
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

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

/**
 * Whether the platform's Ed25519 signs as RFC 8032 describes, the same signature every time.
 * CryptoKit adds randomness to each signature (PROTOCOL.md §3.3), so there something signed
 * again can't repeat the vector's bytes.
 */
val signsDeterministically: Boolean by lazy {
    var same = false
    sync {
        val key = platformCrypto().ed25519(ByteArray(32) { 7 })
        val message = "kinfold".encodeToByteArray()
        same = key.sign(message).contentEquals(key.sign(message))
    }
    same
}

/**
 * Checks [again], which this platform signed afresh, against the vector's [expected] bytes. They
 * are the same bytes where signing is deterministic; elsewhere they are the same up to the last
 * [signatureBytes], which hold the signatures. Either way [verifies] must hold for [again].
 */
suspend fun assertSignedAgain(
    expected: ByteArray,
    again: ByteArray,
    message: String? = null,
    signatureBytes: Int = 64,
    verifies: suspend (ByteArray) -> Boolean,
) {
    if (signsDeterministically) {
        assertContentEquals(expected, again, message)
    } else {
        assertEquals(expected.size, again.size, message)
        assertContentEquals(expected.copyOf(expected.size - signatureBytes), again.copyOf(again.size - signatureBytes), message)
    }
    assertTrue(verifies(again), "${message ?: "signed again"}: the signature verifies")
}
