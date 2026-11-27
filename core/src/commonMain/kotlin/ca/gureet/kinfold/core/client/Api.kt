// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import ca.gureet.kinfold.core.ProtocolException
import ca.gureet.kinfold.core.Reason
import ca.gureet.kinfold.core.identity.DeviceCert
import ca.gureet.kinfold.core.identity.IdentityChain
import ca.gureet.kinfold.core.identity.KeyBundle
import ca.gureet.kinfold.core.payload.Json
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.Reader
import ca.gureet.kinfold.core.wire.encode
import kotlin.concurrent.Volatile

/** A `Kinfold-Wake` value (API.md §7, PROTOCOL.md §14.3): how the server wakes recipients that have no stream open. */
enum class Wake(val header: String, internal val code: Int) {
    /** A visible notification: every alert alike. */
    NOTIFY("notify", 1),

    /** The location extension: live-view requests, on direct envelopes only. */
    LOCATE("locate", 2),
}

/** An error the server answered with (API.md §2), and the fields its JSON carries. */
class ApiException(
    val status: Int,
    /** The `error` code: one of API.md §2, or a reason code of PROTOCOL.md §16.5. */
    val error: String,
    detail: String,
    /** The circle's current log position, on errors about log entries and envelopes. */
    val seq: Long? = null,
    val head: Bytes? = null,
    /** How long to wait before trying again, in seconds, on 429. */
    val retryAfterS: Long? = null,
    /** The oldest API revision the server still takes, on 426. */
    val apiMin: Long? = null,
) : Exception("$status $error" + if (detail.isEmpty()) "" else ": $detail") {
    /** [error] as a reason code, when it is one. */
    val reason: Reason? get() = Reason.ofCode(error)
}

/** Something the client can't accept: an answer that doesn't parse, a log that doesn't verify. */
class ClientException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The discovery document (API.md §4). Nothing in it counts until [serverInfo] has been checked. */
class Discovery(
    /** The signed `ServerInfo` (PROTOCOL.md §13.1). */
    val serverInfo: ByteArray,
    val apiMin: Long,
    val apiMax: Long,
    val features: Set<String>,
    val relay: String?,
    val vapidKey: ByteArray?,
    /** The bundle ID the server's own Apple keys reach, with the `apns` feature. */
    val apnsBundleId: String?,
    val apnsEnvironments: Set<String>,
    val repair: Boolean,
    /** A signed `ServerMove` while a move is announced (PROTOCOL.md §13.3). */
    val move: ByteArray?,
)

class Challenge(val challenge: ByteArray, val expiresAt: ULong, val sig: ByteArray)

class SessionToken(val token: ByteArray, val expiresAt: ULong)

/** A page of a circle's log, and the head the server reports for the circle (API.md §6). */
class LogPage(val entries: List<ByteArray>, val seq: Long, val head: Bytes)

/** A page of the inbox: delivery records, the cursor to pass next, and whether more wait (API.md §7). */
class InboxPage(val records: List<ByteArray>, val cursor: String?, val more: Boolean)

class CircleHead(val circleId: Bytes, val seq: Long, val head: Bytes)

/** A silence watch as the server lists it (API.md §8). */
class WatchInfo(val watchedDevice: Bytes, val watcherAccount: Bytes, val afterMin: Long, val issuedAt: ULong, val notAfter: ULong)

/**
 * The HTTP API of a Kinfold server (API.md), one method per call: the headers every call carries,
 * the session, the server's clock, and its errors. It believes nothing a server signs; [Client]
 * checks that.
 */
class ServerApi(private val transport: Transport, val url: String, private val clock: TrustedClock) {
    /** The session's token (API.md §5), sent with every call while set. */
    @Volatile
    var token: ByteArray? = null

    /** The header that carries the session, for a request made outside this class: none without one. */
    fun sessionHeaders(): Map<String, String> = token?.let { mapOf("Authorization" to "Bearer " + Base64Url.encode(it)) } ?: emptyMap()

    suspend fun discovery(): Discovery {
        val o = obj(call("GET", "/.well-known/kinfold"))
        val api = o["api"] as? Json.Obj ?: malformedAnswer("discovery")
        val apns = o["apns"] as? Json.Obj
        return Discovery(
            serverInfo = bytesOf(o, "server_info") ?: malformedAnswer("discovery"),
            apiMin = api.long("min") ?: malformedAnswer("discovery"),
            apiMax = api.long("max") ?: malformedAnswer("discovery"),
            features = strings(o["features"]),
            relay = o.string("relay"),
            vapidKey = bytesOf(o, "vapid_key"),
            apnsBundleId = apns?.string("bundle_id"),
            apnsEnvironments = strings(apns?.get("environments")),
            repair = (o["repair"] as? Json.Bool)?.value == true,
            move = bytesOf(o, "move"),
        )
    }

    /** Registers an account and its first device (API.md §5): the account ID and the device ID. */
    suspend fun register(cert: DeviceCert, chain: IdentityChain, bundle: KeyBundle, regToken: Bytes): Pair<Bytes, Bytes> {
        val body = frames(cert.encode(), chain.encode(), bundle.encode(), regToken.toByteArray())
        val o = obj(call("POST", "/v1/accounts", body, OCTETS))
        return (id(o, "account_id") ?: malformedAnswer("registration")) to (id(o, "device_id") ?: malformedAnswer("registration"))
    }

    suspend fun challenge(deviceId: Bytes): Challenge {
        val o = obj(call("POST", "/v1/auth/challenge", jsonOf("device_id" to b64(deviceId)), JSON, auth = false))
        return Challenge(
            bytesOf(o, "challenge") ?: malformedAnswer("challenge"),
            time(o, "expires_at") ?: malformedAnswer("challenge"),
            bytesOf(o, "challenge_sig") ?: malformedAnswer("challenge"),
        )
    }

    suspend fun session(deviceId: Bytes, challenge: ByteArray, deviceSig: ByteArray): SessionToken {
        val body = jsonOf("device_id" to b64(deviceId), "challenge" to Base64Url.encode(challenge), "device_sig" to Base64Url.encode(deviceSig))
        val o = obj(call("POST", "/v1/auth/session", body, JSON, auth = false))
        return SessionToken(bytesOf(o, "token") ?: malformedAnswer("session"), time(o, "expires_at") ?: malformedAnswer("session"))
    }

    suspend fun endSession() {
        call("DELETE", "/v1/auth/session")
    }

    /** Every circle the account is in, with the server's head for each. */
    suspend fun circles(): List<CircleHead> = array(call("GET", "/v1/circles")).map {
        val o = it as? Json.Obj ?: malformedAnswer("circles")
        CircleHead(id(o, "circle_id") ?: malformedAnswer("circles"), o.long("seq") ?: malformedAnswer("circles"), hash(o, "head") ?: malformedAnswer("circles"))
    }

    /** Creates a circle with its `GENESIS` entry; the circle ID. */
    suspend fun createCircle(genesis: ByteArray): Bytes =
        id(obj(call("POST", "/v1/circles", genesis, OCTETS)), "circle_id") ?: malformedAnswer("circle")

    /** Entries after [after] (from `GENESIS` when null), at most [limit], and the circle's head. */
    suspend fun log(circleId: Bytes, after: Long?, limit: Int? = null): LogPage {
        val query = listOfNotNull(after?.let { "after=$it" }, limit?.let { "limit=$it" }).joinToString("&")
        val r = call("GET", "/v1/circles/${b64(circleId)}/log" + if (query.isEmpty()) "" else "?$query", max = PAGE_MAX)
        val seq = r.header("Kinfold-Seq")?.toLongOrNull() ?: malformedAnswer("log")
        val head = r.header("Kinfold-Head")?.let { Base64Url.decode(it) }?.takeIf { it.size == 32 } ?: malformedAnswer("log")
        return LogPage(unframe(r.body), seq, Bytes.of(head))
    }

    /** Appends one entry; the circle's new `seq` and head. */
    suspend fun append(circleId: Bytes, entry: ByteArray): Pair<Long, Bytes> {
        val o = obj(call("POST", "/v1/circles/${b64(circleId)}/log", entry, OCTETS))
        return (o.long("seq") ?: malformedAnswer("append")) to (hash(o, "head") ?: malformedAnswer("append"))
    }

    /** Uploads an envelope; the server's clock when it first stored it. */
    suspend fun post(circleId: Bytes, envelope: ByteArray, wake: Wake?): ULong {
        val headers = if (wake == null) emptyMap() else mapOf("Kinfold-Wake" to wake.header)
        return time(obj(call("POST", "/v1/circles/${b64(circleId)}/envelopes", envelope, OCTETS, headers)), "received_at")
            ?: malformedAnswer("upload")
    }

    /** Delivery records after [since] (everything still stored when null). */
    suspend fun inbox(since: String?, limit: Int? = null): InboxPage {
        val query = listOfNotNull(since?.let { "since=" + percentEncode(it) }, limit?.let { "limit=$it" }).joinToString("&")
        val r = call("GET", "/v1/inbox" + if (query.isEmpty()) "" else "?$query", max = PAGE_MAX)
        return InboxPage(unframe(r.body), r.header("Kinfold-Cursor"), r.header("Kinfold-More") == "1")
    }

    suspend fun putWatch(circleId: Bytes, watchedDevice: Bytes, grant: ByteArray) {
        call("PUT", "/v1/circles/${b64(circleId)}/watches/${b64(watchedDevice)}", grant, OCTETS)
    }

    /** The watches this account holds in a circle, and those on its devices. */
    suspend fun watches(circleId: Bytes): List<WatchInfo> = array(call("GET", "/v1/circles/${b64(circleId)}/watches")).map {
        val o = it as? Json.Obj ?: malformedAnswer("watches")
        WatchInfo(
            id(o, "watched_device_id") ?: malformedAnswer("watches"),
            id(o, "watcher_account_id") ?: malformedAnswer("watches"),
            o.long("after_min") ?: malformedAnswer("watches"),
            time(o, "issued_at") ?: malformedAnswer("watches"),
            time(o, "not_after") ?: malformedAnswer("watches"),
        )
    }

    /** Ends a watch: this account's own when [watcher] is null, otherwise one on this account's device. */
    suspend fun deleteWatch(circleId: Bytes, watchedDevice: Bytes, watcher: Bytes? = null) {
        val query = watcher?.let { "?watcher=" + b64(it) } ?: ""
        call("DELETE", "/v1/circles/${b64(circleId)}/watches/${b64(watchedDevice)}$query")
    }

    /** Registers an invite (API.md §9); the registration token minted with it, if the server mints them. */
    suspend fun createInvite(circleId: Bytes, inviteId: Bytes, expiresAt: ULong, regToken: Boolean): Bytes? {
        val body = Json.Obj(
            mapOf(
                "circle_id" to Json.Str(b64(circleId)),
                "invite_id" to Json.Str(b64(inviteId)),
                "expires_at" to Json.Num(expiresAt.toLong()),
                "reg_token" to Json.Bool(regToken),
            ),
        ).encode()
        return bytesOf(obj(call("POST", "/v1/invites", body, JSON)), "reg_token")?.let { Bytes.of(it) }
    }

    suspend fun postJoinRequest(inviteId: Bytes, request: ByteArray) {
        call("POST", "/v1/invites/${b64(inviteId)}/requests", request, OCTETS)
    }

    suspend fun joinRequests(inviteId: Bytes): List<ByteArray> = unframe(call("GET", "/v1/invites/${b64(inviteId)}/requests", max = PAGE_MAX).body)

    suspend fun putJoinResult(inviteId: Bytes, result: ByteArray) {
        call("PUT", "/v1/invites/${b64(inviteId)}/result", result, OCTETS)
    }

    /** The join result, waiting up to [waitS] seconds for it; null when there is none yet. */
    suspend fun joinResult(inviteId: Bytes, waitS: Int): ByteArray? {
        val r = call("GET", "/v1/invites/${b64(inviteId)}/result?wait=$waitS", waitS = waitS)
        return if (r.status == 204) null else r.body
    }

    suspend fun deleteInvite(inviteId: Bytes) {
        call("DELETE", "/v1/invites/${b64(inviteId)}")
    }

    /** The regions the server offers (API.md §13), as the JSON it answered: [Regions.parse] reads it. */
    suspend fun tiles(): ByteArray = call("GET", "/v1/tiles").body

    /** Replaces the device's push registration (API.md §12). */
    suspend fun putPush(registration: Json.Obj) {
        call("PUT", "/v1/push", registration.encode(), JSON)
    }

    suspend fun deletePush() {
        call("DELETE", "/v1/push")
    }

    /**
     * One call: the API revision under `/v1/`, the session unless [auth] is false (logging in
     * sends none), the server's clock taken from `Kinfold-Time`, and any status outside 2xx thrown
     * as an [ApiException].
     */
    private suspend fun call(
        method: String,
        path: String,
        body: ByteArray? = null,
        contentType: String? = null,
        headers: Map<String, String> = emptyMap(),
        max: Int = JSON_MAX,
        waitS: Int = 0,
        auth: Boolean = true,
    ): HttpResponse {
        val h = LinkedHashMap<String, String>()
        if (path.startsWith("/v1/")) h["Kinfold-Api"] = API_REVISION
        if (auth) h.putAll(sessionHeaders())
        if (contentType != null) h["Content-Type"] = contentType
        h.putAll(headers)
        val r = transport.exchange(HttpRequest(method, url + path, h, body, max, TIMEOUT_MS + waitS * 1000L))
        r.header("Kinfold-Time")?.toULongOrNull()?.let { clock.observe(it) }
        if (r.status !in 200..299) throw errorOf(r.status, r.body, r.header("Retry-After")?.toLongOrNull())
        return r
    }

    companion object {
        /** The API revision this client speaks (API.md §1). */
        const val API_REVISION = "1"

        private const val JSON = "application/json"
        private const val OCTETS = "application/octet-stream"

        /** Answers in JSON are small; this is generous. */
        private const val JSON_MAX = 64 * 1024

        /** A page of the log or the inbox: 4 MB of entries or records, and their frames. */
        private const val PAGE_MAX = 4 * 1024 * 1024 + 64 * 1024

        /** How long a call may take, beyond any wait it asks the server for. */
        private const val TIMEOUT_MS = 30_000L

        /** The limits for the API's JSON: a payload's, with arrays of any length. */
        internal val LIMITS = Json.Limits.MESSAGE

        /** An error's JSON (API.md §2) as an [ApiException]; also what a stream `result` carries. */
        internal fun errorOf(status: Int, body: ByteArray, retryAfterS: Long?): ApiException {
            val o = Json.parseObject(body, LIMITS)
            return ApiException(
                status = status,
                error = o?.string("error") ?: "http_$status",
                detail = o?.string("message") ?: "",
                seq = o?.long("seq"),
                head = o?.let { hash(it, "head") },
                retryAfterS = retryAfterS ?: o?.long("retry_after"),
                apiMin = o?.long("api_min"),
            )
        }

        internal fun obj(r: HttpResponse): Json.Obj = Json.parseObject(r.body, LIMITS) ?: malformedAnswer("JSON")

        internal fun obj(body: ByteArray): Json.Obj = Json.parseObject(body, LIMITS) ?: malformedAnswer("JSON")

        private fun array(r: HttpResponse): List<Json> = (Json.parseArray(r.body, LIMITS) ?: malformedAnswer("JSON")).items

        private fun b64(b: Bytes): String = Base64Url.encode(b.toByteArray())

        private fun jsonOf(vararg fields: Pair<String, String>): ByteArray = Json.Obj(fields.associate { it.first to Json.Str(it.second) }).encode()

        private fun bytesOf(o: Json.Obj, key: String): ByteArray? = o.string(key)?.let { Base64Url.decode(it) }

        private fun id(o: Json.Obj, key: String): Bytes? = bytesOf(o, key)?.takeIf { it.size == 16 }?.let { Bytes.of(it) }

        private fun hash(o: Json.Obj, key: String): Bytes? = bytesOf(o, key)?.takeIf { it.size == 32 }?.let { Bytes.of(it) }

        internal fun time(o: Json.Obj, key: String): ULong? = o.long(key)?.takeIf { it >= 0 }?.toULong()

        private fun strings(v: Json?): Set<String> = ((v as? Json.Arr)?.items ?: emptyList()).mapNotNull { (it as? Json.Str)?.value }.toSet()

        private fun malformedAnswer(what: String): Nothing = throw ClientException("the server's answer ($what) is malformed")
    }
}

/** Objects in frames (API.md §1): each a `u32` length, then that many bytes. */
fun frames(vararg parts: ByteArray): ByteArray = encode { for (p in parts) vec32(p) }

/** The objects in a body of frames; [ClientException] if the frames don't fit the body exactly. */
fun unframe(body: ByteArray): List<ByteArray> = try {
    val r = Reader(body)
    val out = ArrayList<ByteArray>()
    while (r.remaining > 0) out.add(r.vec32())
    out
} catch (_: ProtocolException) {
    throw ClientException("the server's frames are malformed")
}

/** [text] for a URL's query: every byte but RFC 3986's unreserved characters percent-encoded. */
internal fun percentEncode(text: String): String = buildString {
    for (b in text.encodeToByteArray()) {
        val c = b.toInt() and 0xff
        if (c in 'A'.code..'Z'.code || c in 'a'.code..'z'.code || c in '0'.code..'9'.code || c == '-'.code || c == '.'.code || c == '_'.code || c == '~'.code) {
            append(c.toChar())
        } else {
            append('%').append("0123456789ABCDEF"[c shr 4]).append("0123456789ABCDEF"[c and 15])
        }
    }
}
