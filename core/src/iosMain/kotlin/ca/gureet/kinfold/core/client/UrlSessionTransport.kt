// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.client

import ca.gureet.kinfold.core.crypto.toByteArray
import ca.gureet.kinfold.core.crypto.toNSData
import kotlinx.cinterop.COpaquePointerVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import platform.CoreFoundation.CFArrayCreate
import platform.CoreFoundation.CFArrayRef
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.kCFTypeArrayCallBacks
import platform.Foundation.*
import platform.Security.SecCertificateCreateWithData
import platform.Security.SecTrustEvaluateWithError
import platform.Security.SecTrustSetAnchorCertificates
import platform.Security.errSecSuccess
import platform.Security.tls_protocol_version_TLSv13
import platform.darwin.NSObject
import platform.posix.EMSGSIZE
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The [Transport] of iOS: URLSession's HTTPS and WebSocket, over TLS 1.3 only, with the system's
 * trusted certificates unless made with [trusting]. It follows no redirects, keeps no cookies and
 * no cache, and asks for no compression. Proxies come from the system's settings.
 *
 * Every exchange and socket is a task of one session, whose delegate hands each event to the task
 * it belongs to.
 */
class UrlSessionTransport private constructor(anchors: CFArrayRef?) : Transport {
    /** A transport that trusts the system's certificates. */
    constructor() : this(null)

    private val events = Events(anchors)
    private val session: NSURLSession = NSURLSession.sessionWithConfiguration(configuration(), events, null)

    override suspend fun exchange(request: HttpRequest): HttpResponse {
        val r = urlRequest(request.url, request.headers, request.timeoutMs / 1000.0)
        // URLSession would otherwise ask for compression and unpack it itself.
        if (request.headers.keys.none { it.equals("Accept-Encoding", ignoreCase = true) }) {
            r.setValue("identity", forHTTPHeaderField = "Accept-Encoding")
        }
        r.HTTPMethod = request.method
        val body = request.body ?: if (request.method in NEEDS_BODY) ByteArray(0) else null
        if (body != null) r.HTTPBody = body.toNSData()
        val task = session.dataTaskWithRequest(r)
        val response = withTimeoutOrNull(request.timeoutMs) {
            suspendCancellableCoroutine<HttpResponse> { cont ->
                events.add(task, Exchange(request.method, request.maxResponseBytes, cont))
                cont.invokeOnCancellation { task.cancel() }
                task.resume()
            }
        }
        return response ?: throw TransportException("${request.method} took longer than ${request.timeoutMs} ms")
    }

    override suspend fun connect(url: String, headers: Map<String, String>, pingIntervalMs: Long): WebSocket {
        // A stream may be quiet for minutes between pings: only the upgrade has a deadline, below.
        val task = session.webSocketTaskWithRequest(urlRequest(url, headers, STREAM_IDLE_S))
        task.maximumMessageSize = MAX_MESSAGE.toLong()
        val socket = Socket(task, pingIntervalMs)
        events.add(task, socket)
        task.resume()
        try {
            withTimeout(UPGRADE_TIMEOUT_MS) { socket.opened.await() }
        } catch (e: TimeoutCancellationException) {
            task.cancel()
            throw TransportException("the stream didn't open in ${UPGRADE_TIMEOUT_MS / 1000} s", e)
        } catch (e: CancellationException) {
            task.cancel()
            throw e
        }
        return socket
    }

    private fun urlRequest(url: String, headers: Map<String, String>, idleS: Double): NSMutableURLRequest {
        val u = NSURL.URLWithString(url) ?: throw TransportException("not a URL")
        val r = NSMutableURLRequest.requestWithURL(u)
        r.setTimeoutInterval(idleS)
        r.HTTPShouldHandleCookies = false
        for ((name, value) in headers) r.setValue(value, forHTTPHeaderField = name)
        return r
    }

    companion object {
        private const val UPGRADE_TIMEOUT_MS = 30_000L

        /** How long a stream may go without a byte before URLSession gives up on it: a week. */
        private const val STREAM_IDLE_S = 7.0 * 24 * 3600

        private val NEEDS_BODY = setOf("POST", "PUT", "PATCH")

        /**
         * A transport that trusts only [certificatePem], for a server with a certificate of its own,
         * such as one started for a test. Nothing else is relaxed: the name in the certificate must
         * still match the server's.
         */
        fun trusting(certificatePem: ByteArray): UrlSessionTransport = UrlSessionTransport(anchorsOf(certificatePem))

        private fun configuration(): NSURLSessionConfiguration {
            val c = NSURLSessionConfiguration.ephemeralSessionConfiguration
            c.HTTPCookieStorage = null
            c.HTTPShouldSetCookies = false
            c.URLCache = null
            // TLS 1.3 at least (API.md §1)
            c.TLSMinimumSupportedProtocolVersion = tls_protocol_version_TLSv13
            return c
        }

        /** A CFArray holding the one certificate of [pem], for SecTrustSetAnchorCertificates. */
        private fun anchorsOf(pem: ByteArray): CFArrayRef {
            val base64 = pem.decodeToString()
                .substringAfter("-----BEGIN CERTIFICATE-----", "")
                .substringBefore("-----END CERTIFICATE-----", "")
                .filterNot { it.isWhitespace() }
            val der = NSData.create(base64EncodedString = base64, options = 0u)?.toByteArray()
            require(der != null && der.isNotEmpty()) { "not a PEM certificate" }
            val data = der.usePinned { CFDataCreate(null, it.addressOf(0).reinterpret(), der.size.convert()) }
            val certificate = SecCertificateCreateWithData(null, data)
            CFRelease(data)
            requireNotNull(certificate) { "not an X.509 certificate" }
            val anchors = memScoped {
                val values = allocArray<COpaquePointerVar>(1)
                values[0] = certificate
                CFArrayCreate(null, values, 1L, kCFTypeArrayCallBacks.ptr)
            }
            CFRelease(certificate)
            return requireNotNull(anchors)
        }
    }
}

/** The session's delegate: hands each task's events to its [Exchange] or [Socket]. */
private class Events(private val anchors: CFArrayRef?) :
    NSObject(),
    NSURLSessionDataDelegateProtocol,
    NSURLSessionWebSocketDelegateProtocol {
    private val lock = NSLock()
    private val tasks = HashMap<ULong, Any>()

    fun add(task: NSURLSessionTask, owner: Any) = locked(lock) { tasks[task.taskIdentifier] = owner }

    private fun owner(task: NSURLSessionTask): Any? = locked(lock) { tasks[task.taskIdentifier] }

    override fun URLSession(session: NSURLSession, dataTask: NSURLSessionDataTask, didReceiveData: NSData) {
        (owner(dataTask) as? Exchange)?.received(dataTask, didReceiveData)
    }

    override fun URLSession(session: NSURLSession, task: NSURLSessionTask, didCompleteWithError: NSError?) {
        when (val owner = locked(lock) { tasks.remove(task.taskIdentifier) }) {
            is Exchange -> owner.finished(task, didCompleteWithError)
            is Socket -> owner.finished(didCompleteWithError)
        }
    }

    override fun URLSession(
        session: NSURLSession,
        task: NSURLSessionTask,
        willPerformHTTPRedirection: NSHTTPURLResponse,
        newRequest: NSURLRequest,
        completionHandler: (NSURLRequest?) -> Unit,
    ) {
        // No redirects: the redirect itself is the answer.
        completionHandler(null)
    }

    override fun URLSession(
        session: NSURLSession,
        didReceiveChallenge: NSURLAuthenticationChallenge,
        completionHandler: (NSURLSessionAuthChallengeDisposition, NSURLCredential?) -> Unit,
    ) {
        val space = didReceiveChallenge.protectionSpace
        val trust = space.serverTrust
        if (anchors == null || trust == null || space.authenticationMethod != NSURLAuthenticationMethodServerTrust) {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, null)
            return
        }
        // The server's chain must end at the one certificate trusted, under the usual rules for TLS
        // servers, the server's name among them.
        if (SecTrustSetAnchorCertificates(trust, anchors) == errSecSuccess && SecTrustEvaluateWithError(trust, null)) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, NSURLCredential.create(trust = trust))
        } else {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, null)
        }
    }

    override fun URLSession(session: NSURLSession, webSocketTask: NSURLSessionWebSocketTask, didOpenWithProtocol: String?) {
        (owner(webSocketTask) as? Socket)?.didOpen()
    }

    override fun URLSession(
        session: NSURLSession,
        webSocketTask: NSURLSessionWebSocketTask,
        didCloseWithCode: NSURLSessionWebSocketCloseCode,
        reason: NSData?,
    ) {
        (owner(webSocketTask) as? Socket)?.closedByServer(didCloseWithCode.toInt())
    }
}

/** One exchange: its body as it arrives, and its continuation. The delegate calls it on one queue. */
private class Exchange(
    private val method: String,
    private val max: Int,
    private val cont: CancellableContinuation<HttpResponse>,
) {
    private val body = NSMutableData()
    private var tooLong = false

    fun received(task: NSURLSessionDataTask, data: NSData) {
        if (tooLong) return
        val announced = task.response?.expectedContentLength ?: -1L
        if (announced > max || body.length + data.length > max.toULong()) {
            tooLong = true
            task.cancel()
            return
        }
        body.appendData(data)
    }

    fun finished(task: NSURLSessionTask, error: NSError?) {
        val response = task.response as? NSHTTPURLResponse
        when {
            tooLong -> cont.resumeWithException(TransportException("a response longer than $max bytes"))
            error != null || response == null -> cont.resumeWithException(TransportException("$method failed: ${describe(error)}"))
            else -> {
                val headers = response.allHeaderFields.entries.associate { (name, value) -> name.toString() to value.toString() }
                cont.resume(HttpResponse(response.statusCode.toInt(), headers, body.toByteArray()))
            }
        }
    }
}

/** A URLSession WebSocket as a [WebSocket]: whole binary messages in order, and the close code at the end. */
private class Socket(private val task: NSURLSessionWebSocketTask, private val pingIntervalMs: Long) : WebSocket {
    val opened = CompletableDeferred<Unit>()
    private val incoming = Channel<ByteArray>(Channel.UNLIMITED)
    private val lock = NSLock()
    private var closedWith: Int? = null
    private var pongDue = false
    private val pings = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    fun didOpen() {
        opened.complete(Unit)
        receiveNext()
        pings.launch {
            while (true) {
                delay(pingIntervalMs)
                // No pong since the last ping: the server, or the way to it, has gone.
                if (locked(lock) { pongDue.also { pongDue = true } }) {
                    abandon(WebSocketClosed.ABNORMAL)
                    return@launch
                }
                task.sendPingWithPongReceiveHandler { error -> if (error == null) locked(lock) { pongDue = false } }
            }
        }
    }

    private fun receiveNext() {
        task.receiveMessageWithCompletionHandler { message, error ->
            val data = message?.data
            when {
                // The server sends binary messages only (API.md §7).
                message != null && data == null -> abandon(UNSUPPORTED)
                data != null && data.length > MAX_MESSAGE.toULong() -> abandon(WebSocketClosed.TOO_BIG)
                data != null -> {
                    incoming.trySend(data.toByteArray())
                    receiveNext()
                }
                // Longer than the task's maximumMessageSize
                error != null && error.domain == NSPOSIXErrorDomain && error.code == EMSGSIZE.toLong() -> abandon(WebSocketClosed.TOO_BIG)
                // Otherwise the connection has ended, and closedByServer or finished says how.
            }
        }
    }

    /** The server sent a close frame with [code]. */
    fun closedByServer(code: Int) {
        end(code)
        // Answer it; codes that may not be sent end the connection instead.
        if (sendable(code)) task.cancelWithCloseCode(code.toLong(), null) else task.cancel()
    }

    /** The task is over: the upgrade failed, or the connection ended after it. */
    fun finished(error: NSError?) {
        if (!opened.isCompleted) {
            // The server answered the upgrade with a status of its own, or not at all.
            val status = (task.response as? NSHTTPURLResponse)?.statusCode?.toInt() ?: 0
            opened.completeExceptionally(
                if (status != 0 && status != 101) {
                    WebSocketRefused(status, ByteArray(0))
                } else {
                    TransportException("the stream didn't open: ${describe(error)}")
                },
            )
        }
        val code = task.closeCode.toInt()
        end(if (code > 0) code else WebSocketClosed.ABNORMAL)
    }

    override suspend fun receive(): ByteArray = incoming.receive()

    override suspend fun send(message: ByteArray) {
        closedCode()?.let { throw WebSocketClosed(it) }
        suspendCancellableCoroutine<Unit> { cont ->
            task.sendMessage(NSURLSessionWebSocketMessage(data = message.toNSData())) { error ->
                if (error == null) {
                    cont.resume(Unit)
                } else {
                    val code = task.closeCode.toInt()
                    if (code > 0) end(code) else abandon(WebSocketClosed.ABNORMAL)
                    cont.resumeWithException(WebSocketClosed(closedCode() ?: WebSocketClosed.ABNORMAL))
                }
            }
        }
    }

    override fun close(code: Int) = abandon(code)

    /** Ends the connection from this side with [code]. */
    private fun abandon(code: Int) {
        end(code)
        if (sendable(code)) task.cancelWithCloseCode(code.toLong(), null) else task.cancel()
    }

    private fun closedCode(): Int? = locked(lock) { closedWith }

    /** The connection is over: [receive] gives what arrived before, then [WebSocketClosed] with [code]. */
    private fun end(code: Int) {
        val first = locked(lock) {
            if (closedWith != null) {
                false
            } else {
                closedWith = code
                true
            }
        }
        if (!first) return
        incoming.close(WebSocketClosed(code))
        pings.cancel()
    }

}

/** The longest message the server sends: a record with the largest envelope (API.md §3), with room to spare. */
private const val MAX_MESSAGE = 256 * 1024

/** RFC 6455's code for a message of a type the endpoint doesn't take. */
private const val UNSUPPORTED = 1003

private inline fun <T> locked(lock: NSLock, block: () -> T): T {
    lock.lock()
    try {
        return block()
    } finally {
        lock.unlock()
    }
}

private fun sendable(code: Int): Boolean = code in 1000..4999 && code !in 1004..1006 && code !in 1015..2999

private fun describe(error: NSError?): String = error?.let { "${it.domain} ${it.code}: ${it.localizedDescription}" } ?: "no answer"
