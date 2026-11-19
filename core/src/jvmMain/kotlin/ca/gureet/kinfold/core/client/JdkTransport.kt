// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.future.await
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocketHandshakeException
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException
import java.util.concurrent.CompletionStage
import java.util.concurrent.Flow
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.TrustManagerFactory
import java.net.http.HttpRequest as JdkRequest
import java.net.http.HttpResponse as JdkResponse
import java.net.http.WebSocket as JdkWebSocket

/**
 * The [Transport] of the JVM: the JDK's own HTTP client and WebSocket (`java.net.http`), over TLS 1.3
 * and with the JDK's trusted certificates unless [sslContext] says otherwise. It follows no
 * redirects. Proxies come from the JDK's usual system properties.
 */
class JdkTransport(sslContext: SSLContext = SSLContext.getDefault()) : Transport {
    private val client: HttpClient = HttpClient.newBuilder()
        .sslContext(sslContext)
        .sslParameters(SSLParameters().apply { protocols = arrayOf("TLSv1.3") })
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_S))
        .build()

    override suspend fun exchange(request: HttpRequest): HttpResponse {
        val b = JdkRequest.newBuilder(URI(request.url)).timeout(Duration.ofMillis(request.timeoutMs))
        for ((name, value) in request.headers) b.header(name, value)
        b.method(request.method, request.body?.let { JdkRequest.BodyPublishers.ofByteArray(it) } ?: JdkRequest.BodyPublishers.noBody())
        val response = try {
            client.sendAsync(b.build()) { Limited(request.maxResponseBytes) }.await()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw TransportException("${request.method} failed: ${describe(e)}", e)
        }
        val headers = response.headers().map().mapValues { it.value.firstOrNull() ?: "" }
        return HttpResponse(response.statusCode(), headers, response.body())
    }

    override suspend fun connect(url: String, headers: Map<String, String>, pingIntervalMs: Long): WebSocket {
        val socket = Socket(pingIntervalMs)
        val builder = client.newWebSocketBuilder().connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_S))
        for ((name, value) in headers) builder.header(name, value)
        val ws = try {
            builder.buildAsync(URI(url), socket.listener).await()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val cause = (e as? CompletionException)?.cause ?: e
            if (cause is WebSocketHandshakeException) {
                val r = cause.response
                throw WebSocketRefused(r.statusCode(), r.body() as? ByteArray ?: ByteArray(0))
            }
            throw TransportException("the stream didn't open: ${describe(cause)}", cause)
        }
        socket.opened(ws)
        return socket
    }

    /** Collects a response body, failing once it is longer than [max]. */
    private class Limited(private val max: Int) : JdkResponse.BodySubscriber<ByteArray> {
        private val result = CompletableFuture<ByteArray>()
        private val out = ByteArrayOutputStream()
        private var subscription: Flow.Subscription? = null

        override fun getBody(): CompletionStage<ByteArray> = result

        override fun onSubscribe(s: Flow.Subscription) {
            subscription = s
            s.request(Long.MAX_VALUE)
        }

        override fun onNext(items: List<ByteBuffer>) {
            for (b in items) {
                if (out.size().toLong() + b.remaining() > max) {
                    subscription?.cancel()
                    result.completeExceptionally(IOException("a response longer than $max bytes"))
                    return
                }
                val a = ByteArray(b.remaining())
                b.get(a)
                out.write(a)
            }
        }

        override fun onError(throwable: Throwable) {
            result.completeExceptionally(throwable)
        }

        override fun onComplete() {
            result.complete(out.toByteArray())
        }
    }

    /** A JDK WebSocket as a [WebSocket]: whole binary messages in order, pings on a timer, and the close code at the end. */
    private class Socket(private val pingIntervalMs: Long) : WebSocket {
        private val incoming = Channel<ByteArray>(Channel.UNLIMITED)
        private val sendLock = Mutex()
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        private val parts = ByteArrayOutputStream()

        @Volatile
        private var ws: JdkWebSocket? = null

        @Volatile
        private var closedWith: Int? = null

        @Volatile
        private var pongAt = 0L

        val listener = object : JdkWebSocket.Listener {
            override fun onOpen(webSocket: JdkWebSocket) {
                webSocket.request(1)
            }

            override fun onBinary(webSocket: JdkWebSocket, data: ByteBuffer, last: Boolean): CompletionStage<*>? {
                if (parts.size().toLong() + data.remaining() > MAX_MESSAGE) {
                    end(WebSocketClosed.TOO_BIG)
                    webSocket.sendClose(WebSocketClosed.TOO_BIG, "")
                    return null
                }
                val a = ByteArray(data.remaining())
                data.get(a)
                parts.write(a)
                if (last) {
                    incoming.trySend(parts.toByteArray())
                    parts.reset()
                }
                webSocket.request(1)
                return null
            }

            override fun onText(webSocket: JdkWebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
                // The server sends binary messages only (API.md §7).
                end(UNSUPPORTED)
                webSocket.sendClose(UNSUPPORTED, "")
                return null
            }

            override fun onPing(webSocket: JdkWebSocket, message: ByteBuffer): CompletionStage<*>? {
                webSocket.request(1) // the JDK answers with a pong itself
                return null
            }

            override fun onPong(webSocket: JdkWebSocket, message: ByteBuffer): CompletionStage<*>? {
                pongAt = System.nanoTime()
                webSocket.request(1)
                return null
            }

            override fun onClose(webSocket: JdkWebSocket, statusCode: Int, reason: String): CompletionStage<*>? {
                end(statusCode)
                return null
            }

            override fun onError(webSocket: JdkWebSocket, error: Throwable) {
                end(WebSocketClosed.ABNORMAL)
            }
        }

        fun opened(w: JdkWebSocket) {
            ws = w
            scope.launch {
                var pingAt = 0L
                while (isActive) {
                    delay(pingIntervalMs)
                    if (pingAt != 0L && pongAt < pingAt) {
                        // No pong since the last ping: the connection is gone, whatever the socket says.
                        end(WebSocketClosed.ABNORMAL)
                        w.abort()
                        return@launch
                    }
                    pingAt = System.nanoTime()
                    try {
                        sendLock.withLock { w.sendPing(ByteBuffer.allocate(0)).await() }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        end(WebSocketClosed.ABNORMAL)
                        w.abort()
                        return@launch
                    }
                }
            }
        }

        override suspend fun receive(): ByteArray = incoming.receive()

        override suspend fun send(message: ByteArray) {
            closedWith?.let { throw WebSocketClosed(it) }
            val w = ws ?: throw WebSocketClosed(WebSocketClosed.ABNORMAL)
            sendLock.withLock {
                try {
                    w.sendBinary(ByteBuffer.wrap(message), true).await()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    end(WebSocketClosed.ABNORMAL)
                    throw WebSocketClosed(closedWith ?: WebSocketClosed.ABNORMAL)
                }
            }
        }

        override fun close(code: Int) {
            val w = ws
            end(code)
            if (w != null && !w.isOutputClosed) {
                w.sendClose(code, "")
                // Don't wait long for the server to answer the close.
                CompletableFuture.runAsync({ w.abort() }, CompletableFuture.delayedExecutor(CLOSE_WAIT_S, TimeUnit.SECONDS))
            }
        }

        /** The connection is over: [receive] gives what arrived before, then [WebSocketClosed] with [code]. */
        private fun end(code: Int) {
            synchronized(this) {
                if (closedWith != null) return
                closedWith = code
            }
            incoming.close(WebSocketClosed(code))
            scope.cancel()
        }
    }

    companion object {
        private const val CONNECT_TIMEOUT_S = 15L
        private const val CLOSE_WAIT_S = 5L

        /** The longest message the server sends: a record with the largest envelope (API.md §3), with room to spare. */
        private const val MAX_MESSAGE = 256 * 1024

        /** RFC 6455's code for a message of a type the endpoint doesn't take. */
        private const val UNSUPPORTED = 1003

        /**
         * A transport that trusts only [certificatePem], for a server with a certificate of its own,
         * such as one started for a test. Nothing else is relaxed: the name in the certificate must
         * still match the server's.
         */
        fun trusting(certificatePem: ByteArray): JdkTransport {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(certificatePem.inputStream())
            val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("server", cert)
            }
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            return JdkTransport(SSLContext.getInstance("TLSv1.3").apply { init(null, tmf.trustManagers, null) })
        }

        private fun describe(e: Throwable): String = e::class.java.simpleName + (e.message?.let { ": $it" } ?: "")
    }
}
