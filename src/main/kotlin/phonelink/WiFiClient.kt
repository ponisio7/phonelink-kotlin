package phonelink

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/**
 * El teléfono se conecta al `WiFiServer` de Python. Handshake v2: hello → challenge(nonce) → auth(HMAC) → auth_ok.
 *
 * Reglas de seguridad iguales a las de Python: sin TLS solo se permite loopback salvo `allowInsecureLan = true`.
 * Nota Android emulador: el host de la PC es 10.0.2.2 (no es loopback → necesita TLS o allowInsecureLan).
 */
class WiFiClient(
    private val host: String,
    token: String,
    private val port: Int = DEFAULT_PORT,
    private val reconnect: Boolean = true,
    private val maxBackoffMs: Long = 30_000,
    private val connectTimeoutMs: Long = 10_000,
    internal val sslContext: SSLContext? = null,
    private val allowInsecureLan: Boolean = false,
    /** Dejar en true. false = vulnerable a MITM (equivale a allow_insecure_tls de Python). */
    private val verifyHostname: Boolean = true,
    /** Opt-in explícito para acompañar a verifyHostname=false fuera de loopback. */
    private val allowInsecureTls: Boolean = false,
    private val minStableMs: Long = 3_000,
    private val maxPayload: Int = MAX_PAYLOAD,
    private val handshakeTimeoutMs: Long = 5_000,
    private val sendTimeoutMs: Long = 15_000,
    private val idleTimeoutMs: Long = DEFAULT_IDLE_TIMEOUT_MS,
    private val stopTimeoutMs: Long = 2_000,
    @Volatile var onAuthError: (suspend (String) -> Unit)? = null,
    /** El servidor cerró la sesión con `replaced` o `revoked`; no se reconecta. */
    @Volatile var onSessionTerminated: (suspend (String) -> Unit)? = null,
) : Transport {

    @Volatile var token: String = token

    init {
        require(token.isNotEmpty()) { "Se requiere un token no vacío" }
        require(maxPayload > 0) { "maxPayload debe ser > 0" }
        require(sslContext != null || isLoopback(host) || allowInsecureLan) {
            "Sin TLS solo se permite conectar a loopback. Configura sslContext o allowInsecureLan=true conscientemente."
        }
        if (sslContext != null && !isLoopback(host) && !verifyHostname && !allowInsecureTls) {
            throw IllegalArgumentException(
                "verifyHostname=false fuera de loopback expone el token a un MITM. " +
                "Si lo aceptas conscientemente, pasa allowInsecureTls=true."
            )
        }
        if (allowInsecureLan || !verifyHostname) plog("Modo inseguro activo en cliente (LAN o TLS sin verificación)")
        checkTlsContext(sslContext, isServer = false, host = host, allowInsecureTls = allowInsecureTls)
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var listener: TransportListener? = null
    @Volatile private var stream: MessageStream? = null
    @Volatile private var running = false
    @Volatile private var lastError: Throwable? = null
    private var job: Job? = null

    override fun setListener(listener: TransportListener?) { this.listener = listener }
    override val isConnected: Boolean get() = stream != null
    override val lastRxNanos: Long? get() = stream?.lastRxNanos

    override suspend fun start(timeoutMs: Long?) {
        check(!running) { "WiFiClient ya iniciado" }
        running = true
        lastError = null
        val signal = CompletableDeferred<Unit>()
        job = scope.launch { connectWithRetry(signal) }
        try {
            if (timeoutMs != null) withTimeout(timeoutMs) { signal.await() } else signal.await()
        } catch (e: TimeoutCancellationException) {
            val cause = lastError
            cleanupFailedStart()
            if (cause is AuthRejectedException) throw cause
            throw LinkConnectionException("No se pudo conectar (timeout)", cause)
        } catch (e: Throwable) {
            cleanupFailedStart()
            throw e
        }
    }

    private fun cleanupFailedStart() {
        running = false
        stream?.close()
        job?.cancel()
        job = null
    }

    private fun openSocket(): Socket {
        val raw = Socket()
        try {
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(host, port), connectTimeoutMs.toInt())
            val ctx = sslContext ?: return raw
            raw.soTimeout = connectTimeoutMs.toInt()
            val ssl = ctx.socketFactory.createSocket(raw, host, port, true) as SSLSocket
            // Filtrado estricto: solo TLS 1.2/1.3.
            ssl.enabledProtocols = ssl.supportedProtocols
                .filter { it == "TLSv1.3" || it == "TLSv1.2" }
                .toTypedArray()
            if (verifyHostname) {
                ssl.sslParameters = ssl.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            }
            ssl.startHandshake()
            return ssl
        } catch (t: Throwable) {
            try { raw.close() } catch (_: IOException) {}
            throw t
        }
    }

    private suspend fun authError(reason: String): LinkConnectionException {
        val r = validateReason(reason)
        try { onAuthError?.invoke(r) } catch (_: Throwable) {}
        val err = if (r in Reasons.TRANSIENT) TransientAuthException(r) else AuthRejectedException(r)
        lastError = err
        return err
    }

    private suspend fun handshake(s: MessageStream) {
        s.send(
            JsonObject(mapOf("type" to JsonPrimitive("hello"), "protocol_version" to JsonPrimitive(PROTOCOL_VERSION))),
            handshakeTimeoutMs,
        )
        val challenge = s.recv(HANDSHAKE_MAX, handshakeTimeoutMs) as? JsonObject
        val nonceHex = challenge?.str("nonce")
        if (challenge == null || challenge.str("type") != "challenge" || nonceHex == null) {
            throw authError(challenge?.str("reason") ?: "malformed_challenge")
        }
        val nonce = if (nonceHex.length == NONCE_SIZE * 2) nonceHex.hexToBytesOrNull() else null
        if (nonce == null || nonce.size != NONCE_SIZE) {
            throw AuthRejectedException("malformed_nonce").also { lastError = it }
        }
        s.send(
            JsonObject(mapOf("type" to JsonPrimitive("auth"), "mac" to JsonPrimitive(Auth.macHex(token, nonce)))),
            handshakeTimeoutMs,
        )
        val reply = s.recv(HANDSHAKE_MAX, handshakeTimeoutMs) as? JsonObject
        if (reply == null || reply.str("type") != "auth_ok") {
            throw authError(reply?.str("reason") ?: "malformed_reply")
        }
    }

    private suspend fun connectWithRetry(signal: CompletableDeferred<Unit>) {
        var backoff = 500L
        try {
            while (running) {
                var s: MessageStream? = null
                try {
                    val sock = withContext(Dispatchers.IO) { openSocket() }
                    s = MessageStream(sock, sendTimeoutMs)
                    handshake(s)
                    stream = s
                    signal.complete(Unit)
                    val connectedAt = System.nanoTime()
                    listener?.onConnect()
                    readLoop(s)
                    if ((System.nanoTime() - connectedAt) / 1_000_000 >= minStableMs) backoff = 500L
                } catch (e: CancellationException) {
                    throw e
                } catch (e: AuthRejectedException) {
                    plog("Auth rechazada de forma terminal: ${e.reason}")
                    lastError = e
                    running = false
                    signal.completeExceptionally(e)
                    return
                } catch (e: TransientAuthException) {
                    // rate_limited/server_error son transitorios: avisar y reintentar.
                    plog("Auth transitoria fallida (${e.reason}); reintentando")
                    if (lastError !is AuthRejectedException) lastError = e
                } catch (e: Exception) {
                    plog("Conexión fallida (${e.message})")
                    if (lastError !is AuthRejectedException) lastError = e
                } finally {
                    s?.close()
                    if (stream === s) stream = null
                }
                if (!reconnect || !running) return
                delay(backoff)
                backoff = minOf(backoff * 2, maxBackoffMs)
            }
        } finally {
            if (!signal.isCompleted) {
                val cause = lastError
                signal.completeExceptionally(
                    cause as? LinkConnectionException ?: LinkConnectionException("No se pudo conectar", cause)
                )
            }
        }
    }

    private suspend fun readLoop(s: MessageStream) {
        try {
            while (true) {
                val msg = s.recv(maxPayload, idleTimeoutMs) as? JsonObject ?: continue
                val t = msg.str("type")
                if (t == "replaced" || t == "revoked") {
                    plog("Sesión terminada por el servidor: $t")
                    running = false
                    try { onSessionTerminated?.invoke(validateReason(t)) } catch (_: Throwable) {}
                    break
                }
                listener?.onMessage(msg)
            }
        } catch (_: ProtocolException) {
        } catch (_: IOException) {
        } finally {
            if (stream === s) stream = null
            s.close()
            withContext(NonCancellable) {
                try { listener?.onDisconnect() } catch (_: Throwable) {}
            }
        }
    }

    override suspend fun send(obj: JsonObject) {
        val s = stream ?: throw LinkConnectionException("No conectado")
        try {
            s.send(obj)
        } catch (e: LinkConnectionException) {
            if (stream === s) stream = null
            s.close()
            throw e
        }
    }

    override suspend fun disconnect() {
        val s = stream
        stream = null
        s?.close()
    }

    override suspend fun stop() {
        running = false
        disconnect()
        val j = job
        job = null
        j?.cancel()
        withTimeoutOrNull(stopTimeoutMs) { j?.join() }
    }
}