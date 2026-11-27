// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import ca.gureet.kinfold.core.push.PushMessage
import ca.gureet.kinfold.core.push.PushReceipt
import ca.gureet.kinfold.core.push.Pushes
import ca.gureet.kinfold.core.wire.Base64Url
import ca.gureet.kinfold.core.wire.Bytes
import ca.gureet.kinfold.core.wire.encode
import ca.gureet.kinfold.core.wire.readAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random

/** The stream's message types (API.md §7). */
internal object StreamMessage {
    const val RECORD = 0x01
    const val CURSOR = 0x02
    const val LOG = 0x03
    const val PUSH = 0x04
    const val EVENT = 0x05
    const val TIME = 0x06
    const val POST = 0x10
    const val RESULT = 0x11
}

/**
 * Waits between attempts to reconnect (API.md §7): from 1 second, doubling to 5 minutes, each wait
 * drawn between half and all of that so that devices don't come back in step.
 */
internal class Backoff(private val random: Random = Random.Default) {
    private var step = 0

    fun reset() {
        step = 0
    }

    /** The next wait, in milliseconds, at least [minMs]. */
    fun next(minMs: Long = 0): Long {
        val base = minOf(MIN_MS shl minOf(step, 9), MAX_MS)
        if (step < 9) step++
        return maxOf(base / 2 + random.nextLong(base / 2 + 1), minMs)
    }

    companion object {
        const val MIN_MS = 1_000L
        const val MAX_MS = 300_000L
    }
}

/** An open stream: uploads on it, and the answers that come back for them (`stream_post`). */
internal class StreamConnection(private val socket: WebSocket) {
    private val lock = Mutex()
    private var nextId = 1L
    private val waiting = HashMap<Long, CompletableDeferred<Pair<Int, ByteArray>>>()

    /** Uploads an envelope as a `post` and waits for its `result`: the server's `received_at`, or what the upload call would have thrown. */
    suspend fun post(envelope: ByteArray, wake: Wake?): ULong {
        val answer = CompletableDeferred<Pair<Int, ByteArray>>()
        val id = lock.withLock {
            val id = nextId
            nextId = if (nextId == 0xffffffffL) 1L else nextId + 1
            waiting[id] = answer
            id
        }
        try {
            socket.send(
                encode {
                    u8(StreamMessage.POST)
                    u32(id)
                    u8(wake?.code ?: 0)
                    bytes(envelope)
                },
            )
            val (status, json) = withTimeout(POST_TIMEOUT_MS) { answer.await() }
            if (status != 201) throw ServerApi.errorOf(status, json, null)
            return ServerApi.time(ServerApi.obj(json), "received_at") ?: throw ClientException("the server's answer (upload) is malformed")
        } catch (_: TimeoutCancellationException) {
            throw TransportException("no answer on the stream to an upload")
        } finally {
            lock.withLock { waiting.remove(id) }
        }
    }

    suspend fun answered(id: Long, status: Int, json: ByteArray) {
        lock.withLock { waiting.remove(id) }?.complete(status to json)
    }

    /** The connection ended: every upload still waiting fails, so that it is made again by HTTP. */
    suspend fun ended(code: Int) {
        val all = lock.withLock { waiting.values.toList().also { waiting.clear() } }
        for (a in all) a.completeExceptionally(WebSocketClosed(code))
    }

    private companion object {
        const val POST_TIMEOUT_MS = 30_000L
    }
}

/** [Client.runStream]: one connection after another, until cancelled or stopped for good. */
internal class StreamRunner(private val c: Client, private val pingIntervalMs: Long) {
    private val backoff = Backoff()

    suspend fun run(): Int {
        while (true) {
            val code = once()
            if (code == REPLACED || code == TOO_OLD) {
                c.listener.stream(StreamChange.Stopped(code))
                return code
            }
            val wait = backoff.next(if (code == RATE_LIMITED) RATE_LIMITED_WAIT_MS else 0)
            c.listener.stream(StreamChange.Disconnected(code, wait))
            delay(wait)
        }
    }

    /** One connection: the code it closed with, or one that says why it didn't open. */
    private suspend fun once(): Int {
        val socket = try {
            c.openStream(pingIntervalMs)
        } catch (e: WebSocketRefused) {
            return when (e.status) {
                401 -> {
                    attempt { c.renewAfter(c.streamSession) }
                    SESSION_ENDED
                }
                400 -> {
                    // The server doesn't know the cursor, as after a restore: start from what it still holds.
                    c.dropCursor()
                    WebSocketClosed.ABNORMAL
                }
                426 -> TOO_OLD
                429 -> RATE_LIMITED
                else -> WebSocketClosed.ABNORMAL
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            c.listener.failed("opening the stream", e)
            return WebSocketClosed.ABNORMAL
        }
        val conn = StreamConnection(socket)
        c.connection = conn
        val opened = monotonicMillis()
        var code = WebSocketClosed.ABNORMAL
        try {
            c.listener.stream(StreamChange.Connected)
            while (true) {
                handle(conn, socket.receive())
                if (monotonicMillis() - opened >= HEALTHY_MS) backoff.reset()
            }
        } catch (e: WebSocketClosed) {
            code = e.code
            if (code == SESSION_ENDED) attempt { c.renewAfter(c.streamSession) }
            return code
        } finally {
            c.connection = null
            withContext(NonCancellable) { conn.ended(code) }
            socket.close(NORMAL)
        }
    }

    /** One message from the server; what goes wrong with it is reported, and the stream goes on. */
    private suspend fun handle(conn: StreamConnection, msg: ByteArray) {
        if (msg.isEmpty()) return
        val body = msg.copyOfRange(1, msg.size)
        attempt {
            when (msg[0].toInt() and 0xff) {
                StreamMessage.RECORD -> c.receiveSafely(body)
                StreamMessage.CURSOR -> c.saveCursor(body.decodeToString())
                StreamMessage.LOG -> {
                    val (circleId, seq) = readAll(body) { (Bytes.of(bytes(16)) to u64().toLong()).also { bytes(32) } }
                    val held = c.heldSeq(circleId)
                    if (held != null && held < seq) c.sync(circleId)
                }
                StreamMessage.PUSH -> push(body)
                StreamMessage.EVENT -> event(body)
                StreamMessage.TIME -> {
                    c.clock.observe(readAll(body) { u64() })
                    c.saveClock()
                }
                StreamMessage.RESULT -> {
                    if (body.size < 6) throw ClientException("a stream result is malformed")
                    val (id, status) = readAll(body.copyOf(6)) { u32() to u16() }
                    conn.answered(id, status, body.copyOfRange(6, body.size))
                }
                else -> {} // a type this client doesn't know
            }
        }.exceptionOrNull()?.let { c.listener.failed("handling a stream message", it) }
    }

    /** A push on the stream: signed by the server, not sealed (API.md §7). */
    private suspend fun push(body: ByteArray) {
        when (val r = Pushes.openSigned(c.p, body, c.keys.deviceId, c.serverKey, c.clock.now())) {
            is PushReceipt.Dropped -> c.listener.pushDropped(r.reason)
            is PushReceipt.Opened -> when (val m = r.message) {
                is PushMessage.Silence -> c.listener.silence(SilenceAlert(m.circleId, m.watchedDevice, m.lastSeenAt, m.sentAt))
                is PushMessage.Records -> for (rec in m.records) c.receiveSafely(encode {
                    u64(rec.receivedAt)
                    bytes(rec.envelope)
                })
                is PushMessage.Wake -> c.fetchInbox()
            }
        }
    }

    private suspend fun event(body: ByteArray) {
        val o = ServerApi.obj(body)
        fun id(key: String): Bytes = o.string(key)?.let { Base64Url.decode(it) }?.takeIf { it.size == 16 }?.let { Bytes.of(it) }
            ?: throw ClientException("a stream event is malformed")
        val event = when (o.string("type")) {
            "removed" -> ServerEvent.Removed(id("circle_id"), o.long("seq") ?: -1).also {
                if (c.heldSeq(it.circleId) != null) c.sync(it.circleId)
            }
            "join_request" -> ServerEvent.JoinRequest(id("invite_id"))
            "share_view" -> ServerEvent.ShareView(id("link_id"), o.long("views") ?: 0)
            "watch_ended" -> ServerEvent.WatchEnded(id("circle_id"), id("watched_device_id"), o.string("reason") ?: "").also {
                c.lock.withLock { c.forgetGrant(it.circleId, it.watchedDevice) }
            }
            "push_dropped" -> ServerEvent.PushDropped
            "notice" -> ServerEvent.Notice(o.string("code") ?: "")
            else -> null // an event this client doesn't know
        }
        if (event != null) c.listener.event(event)
    }

    private companion object {
        const val NORMAL = 1000
        const val SESSION_ENDED = 4401
        const val REPLACED = 4409
        const val TOO_OLD = 4426
        const val RATE_LIMITED = 4429

        /** After 4429 the device waits at least a minute. */
        const val RATE_LIMITED_WAIT_MS = 60_000L

        /** A connection that lasted this long starts the backoff again from 1 second. */
        const val HEALTHY_MS = 60_000L
    }
}
