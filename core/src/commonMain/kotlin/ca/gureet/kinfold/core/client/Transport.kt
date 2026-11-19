// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

/**
 * The platform's networking, which the client layer reaches only through this interface, as the
 * core reaches cryptography only through `Crypto`: HTTPS exchanges and WebSockets, over TLS 1.3
 * with the system's trusted certificates (API.md §1). An implementation adds nothing of its own:
 * no cookies, no cache, no redirects and no retries.
 */
interface Transport {
    /**
     * One request and its response, whatever the response's status. [TransportException] when no
     * response arrived, or its body was longer than the request allows.
     */
    suspend fun exchange(request: HttpRequest): HttpResponse

    /**
     * Opens a WebSocket to [url] (`wss://`) with [headers] on the upgrade request. The socket sends
     * a ping every [pingIntervalMs] and closes itself, as if the server had gone, when a pong hasn't
     * come back by the next ping. [WebSocketRefused] when the server answered the upgrade with an
     * HTTP status of its own; [TransportException] when it didn't answer.
     */
    suspend fun connect(url: String, headers: Map<String, String>, pingIntervalMs: Long): WebSocket
}

class HttpRequest(
    val method: String,
    val url: String,
    val headers: Map<String, String>,
    val body: ByteArray?,
    /** The longest response body the caller takes; a longer one fails the exchange. */
    val maxResponseBytes: Int,
    /** How long the whole exchange may take. */
    val timeoutMs: Long,
)

class HttpResponse(val status: Int, headers: Map<String, String>, val body: ByteArray) {
    private val byName = headers.mapKeys { it.key.lowercase() }

    /** A header's value; names are compared without regard to case. */
    fun header(name: String): String? = byName[name.lowercase()]
}

/** An open WebSocket: binary messages both ways (API.md §7). */
interface WebSocket {
    /** The next message from the server; [WebSocketClosed] once the connection has ended. */
    suspend fun receive(): ByteArray

    /** Sends one binary message; [WebSocketClosed] if the connection has ended. */
    suspend fun send(message: ByteArray)

    /** Closes the connection with [code], if it is still open. */
    fun close(code: Int)
}

/** No response: the network failed, the exchange timed out, or the response was too long. */
class TransportException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The WebSocket has ended: [code] is the close code the server sent, or [ABNORMAL] when none came. */
class WebSocketClosed(val code: Int) : Exception("the stream closed with $code") {
    companion object {
        /** RFC 6455's code for a connection that ended without a close message. */
        const val ABNORMAL = 1006

        /** RFC 6455's code for a message too long to take. */
        const val TOO_BIG = 1009
    }
}

/** The server answered the WebSocket upgrade with [status] and [body] instead of switching protocols. */
class WebSocketRefused(val status: Int, val body: ByteArray) : Exception("the stream was refused with $status")
