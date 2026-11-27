// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.Callback
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.TlsVersion
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import okhttp3.WebSocket as OkWebSocket

/**
 * The [Transport] of Android: OkHttp's HTTPS and WebSocket, over TLS 1.3 only, with the system's
 * trusted certificates unless [trustManager] says otherwise. It follows no redirects and keeps no
 * cookies and no cache; it asks for no compression. Proxies come from the system's settings.
 *
 * Android has TLS 1.3 from version 10, the oldest the core supports. Without it the constructor
 * fails.
 */
class OkHttpTransport(trustManager: X509TrustManager = systemTrust()) : Transport {
    private val client: OkHttpClient

    init {
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf(trustManager), null)
        check("TLSv1.3" in context.supportedSSLParameters.protocols) { "no TLS 1.3 here" }
        client = OkHttpClient.Builder()
            .sslSocketFactory(context.socketFactory, trustManager)
            .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS).tlsVersions(TlsVersion.TLS_1_3).build()))
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(CONNECT_TIMEOUT_S, TimeUnit.SECONDS)
            // Each exchange has its own deadline, which covers any wait it asks the server for.
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(0, TimeUnit.SECONDS)
            .webSocketCloseTimeout(CLOSE_WAIT_S, TimeUnit.SECONDS)
            .build()
    }

    override suspend fun exchange(request: HttpRequest): HttpResponse {
        val b = Request.Builder().url(request.url)
        for ((name, value) in request.headers) b.header(name, value)
        // OkHttp would otherwise ask for gzip and unpack it itself.
        if (request.headers.keys.none { it.equals("Accept-Encoding", ignoreCase = true) }) b.header("Accept-Encoding", "identity")
        val body = request.body ?: if (request.method in NEEDS_BODY) ByteArray(0) else null
        b.method(request.method, body?.toRequestBody(null))
        val call = client.newCall(b.build())
        call.timeout().timeout(request.timeoutMs, TimeUnit.MILLISECONDS)
        return suspendCancellableCoroutine { cont ->
            cont.invokeOnCancellation { call.cancel() }
            call.enqueue(
                object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        cont.resumeWithException(TransportException("${request.method} failed: ${describe(e)}", e))
                    }

                    override fun onResponse(call: Call, response: Response) {
                        val result = try {
                            response.use {
                                val headers = it.headers.toMultimap().mapValues { (_, v) -> v.firstOrNull() ?: "" }
                                HttpResponse(it.code, headers, limited(it.body, request.maxResponseBytes))
                            }
                        } catch (e: IOException) {
                            cont.resumeWithException(TransportException("${request.method} failed: ${describe(e)}", e))
                            return
                        }
                        cont.resume(result)
                    }
                },
            )
        }
    }

    override suspend fun connect(url: String, headers: Map<String, String>, pingIntervalMs: Long): WebSocket {
        val b = Request.Builder().url(url)
        for ((name, value) in headers) b.header(name, value)
        val socket = Socket()
        val ws = client.newBuilder()
            .pingInterval(pingIntervalMs, TimeUnit.MILLISECONDS)
            // For the upgrade only: OkHttp lifts the deadline once the socket is open.
            .callTimeout(CONNECT_TIMEOUT_S + UPGRADE_TIMEOUT_S, TimeUnit.SECONDS)
            .build()
            .newWebSocket(b.build(), socket)
        try {
            socket.opened.await()
        } catch (e: CancellationException) {
            ws.cancel()
            throw e
        }
        return socket
    }

    /**
     * Downloads [url] whole into [file] (API.md §13): a map region, fetched once and drawn from the
     * phone, with [headers], the session's, from `Client.downloadRegion`. A file already there, from
     * a download that stopped, is resumed with `Range: bytes=N-` and `If-Range` set to [etag], the
     * region's `sha256` in quotes, so a region replaced meanwhile comes back whole from the start.
     * When the download ends, the file's SHA-256 must be [sha256]; otherwise the file is deleted and
     * [TransportException] thrown. A session the server no longer knows is an [ApiException] with
     * status 401, for the client to log in again. [progress] gets the bytes on the phone and the
     * file's size as they grow. Cancelling stops it, and leaves the file to resume.
     */
    suspend fun download(
        url: String,
        headers: Map<String, String>,
        file: File,
        sha256: ByteArray,
        etag: String,
        progress: (Long, Long) -> Unit = { _, _ -> },
    ) {
        withContext(Dispatchers.IO) {
            val have = if (file.isFile) file.length() else 0L
            val b = Request.Builder().url(url).header("Accept-Encoding", "identity")
            for ((k, v) in headers) b.header(k, v)
            if (have > 0) b.header("Range", "bytes=$have-").header("If-Range", etag)
            val call = downloads.newCall(b.build())
            val job = coroutineContext[Job]
            val cancel = job?.invokeOnCompletion { if (it != null) call.cancel() }
            try {
                call.execute().use { r ->
                    val append = when {
                        r.code == 206 && have > 0 && r.header("Content-Range")?.startsWith("bytes $have-") == true -> true
                        r.code == 200 -> false
                        r.code == 401 -> throw ApiException(401, "unauthorized", "the session has ended")
                        r.code == 416 -> {
                            // Already whole, or longer than the region now is: start again.
                            file.delete()
                            throw TransportException("the download can't resume; it starts again next time")
                        }
                        else -> throw TransportException("the region's download was answered with ${r.code}")
                    }
                    val length = r.body.contentLength()
                    val total = if (length < 0) -1 else if (append) have + length else length
                    var done = if (append) have else 0L
                    FileOutputStream(file, append).use { out ->
                        val buffer = ByteArray(64 * 1024)
                        r.body.byteStream().use { input ->
                            var reported = 0L
                            while (true) {
                                job?.ensureActive()
                                val n = input.read(buffer)
                                if (n < 0) break
                                out.write(buffer, 0, n)
                                done += n
                                if (done - reported >= PROGRESS_EVERY || done == total) {
                                    progress(done, total)
                                    reported = done
                                }
                            }
                        }
                        out.fd.sync()
                    }
                    if (total >= 0 && done != total) throw TransportException("the region's download ended early")
                }
            } catch (e: IOException) {
                throw TransportException("the region's download failed: ${describe(e)}", e)
            } finally {
                cancel?.dispose()
            }
            val md = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    md.update(buffer, 0, n)
                }
            }
            if (!MessageDigest.isEqual(md.digest(), sha256)) {
                file.delete()
                throw TransportException("the region's file isn't the one the server listed: its SHA-256 differs")
            }
        }
    }

    /** For downloads: like [client], but a read that stalls for a minute fails, so the download can resume. */
    private val downloads: OkHttpClient by lazy { client.newBuilder().readTimeout(60, TimeUnit.SECONDS).build() }

    /** An OkHttp WebSocket as a [WebSocket]: whole binary messages in order, and the close code at the end. */
    private class Socket : WebSocketListener(), WebSocket {
        private val incoming = Channel<ByteArray>(Channel.UNLIMITED)
        val opened = CompletableDeferred<Unit>()

        @Volatile
        private var ws: OkWebSocket? = null

        @Volatile
        private var closedWith: Int? = null

        override fun onOpen(webSocket: OkWebSocket, response: Response) {
            ws = webSocket
            opened.complete(Unit)
        }

        override fun onMessage(webSocket: OkWebSocket, bytes: ByteString) {
            if (bytes.size > MAX_MESSAGE) {
                end(WebSocketClosed.TOO_BIG)
                webSocket.close(WebSocketClosed.TOO_BIG, null)
                return
            }
            incoming.trySend(bytes.toByteArray())
        }

        override fun onMessage(webSocket: OkWebSocket, text: String) {
            // The server sends binary messages only (API.md §7).
            end(UNSUPPORTED)
            webSocket.close(UNSUPPORTED, null)
        }

        override fun onClosing(webSocket: OkWebSocket, code: Int, reason: String) {
            end(code)
            // Answer the server's close; codes that may not be sent end the connection instead.
            if (!sendable(code) || !webSocket.close(code, null)) webSocket.cancel()
        }

        override fun onClosed(webSocket: OkWebSocket, code: Int, reason: String) {
            end(code)
        }

        override fun onFailure(webSocket: OkWebSocket, t: Throwable, response: Response?) {
            if (!opened.isCompleted) {
                // The upgrade failed: the server answered with a status of its own, or not at all.
                val failure = if (response != null && response.code != 101) {
                    val body = try {
                        limited(response.body, REFUSAL_MAX)
                    } catch (_: IOException) {
                        ByteArray(0)
                    }
                    WebSocketRefused(response.code, body)
                } else {
                    TransportException("the stream didn't open: ${describe(t)}", t)
                }
                opened.completeExceptionally(failure)
            }
            end(WebSocketClosed.ABNORMAL)
        }

        override suspend fun receive(): ByteArray = incoming.receive()

        override suspend fun send(message: ByteArray) {
            closedWith?.let { throw WebSocketClosed(it) }
            val w = ws ?: throw WebSocketClosed(WebSocketClosed.ABNORMAL)
            // OkHttp queues the message; false means the socket is closing or its queue is full.
            if (!w.send(message.toByteString())) {
                end(WebSocketClosed.ABNORMAL)
                w.cancel()
                throw WebSocketClosed(closedWith ?: WebSocketClosed.ABNORMAL)
            }
        }

        override fun close(code: Int) {
            val w = ws
            end(code)
            if (w != null && (!sendable(code) || !w.close(code, null))) w.cancel()
        }

        /** The connection is over: [receive] gives what arrived before, then [WebSocketClosed] with [code]. */
        private fun end(code: Int) {
            synchronized(this) {
                if (closedWith != null) return
                closedWith = code
            }
            incoming.close(WebSocketClosed(code))
        }
    }

    companion object {
        private const val CONNECT_TIMEOUT_S = 15L

        /** A download tells of its progress about every megabyte. */
        private const val PROGRESS_EVERY = 1L shl 20
        private const val UPGRADE_TIMEOUT_S = 15L
        private const val CLOSE_WAIT_S = 5L

        /** The longest message the server sends: a record with the largest envelope (API.md §3), with room to spare. */
        private const val MAX_MESSAGE = 256 * 1024

        /** The most of a refused upgrade's body worth reading: an error's JSON (API.md §2). */
        private const val REFUSAL_MAX = 16 * 1024

        /** RFC 6455's code for a message of a type the endpoint doesn't take. */
        private const val UNSUPPORTED = 1003

        private val NEEDS_BODY = setOf("POST", "PUT", "PATCH")

        /** The system's trusted certificates, and the app's network security configuration. */
        fun systemTrust(): X509TrustManager = trustManagerOf(null)

        /**
         * A transport that trusts only [certificatePem], for a server with a certificate of its own,
         * such as one started for a test. Nothing else is relaxed: the name in the certificate must
         * still match the server's.
         */
        fun trusting(certificatePem: ByteArray): OkHttpTransport {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(certificatePem.inputStream())
            val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("server", cert)
            }
            return OkHttpTransport(trustManagerOf(store))
        }

        private fun trustManagerOf(store: KeyStore?): X509TrustManager {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            return tmf.trustManagers.filterIsInstance<X509TrustManager>().single()
        }

        /** Reads a body, failing once it is longer than [max]. */
        private fun limited(body: ResponseBody, max: Int): ByteArray {
            val length = body.contentLength()
            if (length > max) throw IOException("a response longer than $max bytes")
            val out = ByteArrayOutputStream(if (length >= 0) length.toInt() else 8192)
            val buffer = ByteArray(8192)
            body.byteStream().use { input ->
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    if (out.size() + n > max) throw IOException("a response longer than $max bytes")
                    out.write(buffer, 0, n)
                }
            }
            return out.toByteArray()
        }

        /** Whether RFC 6455 lets an endpoint send [code] in a close message. */
        private fun sendable(code: Int): Boolean = code in 1000..4999 && code !in 1004..1006 && code !in 1015..2999

        private fun describe(e: Throwable): String = e::class.java.simpleName + (e.message?.let { ": $it" } ?: "")
    }
}
