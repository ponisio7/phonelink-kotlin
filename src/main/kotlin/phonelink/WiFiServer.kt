package phonelink

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * Rate limiter por IP, puerto fiel de `_RateLimiter` (Python v0.4):
 * purga de expirados, evicción LRU que NO desbloquea atacantes y warnings
 * cuando todas las entradas corresponden a IPs bloqueadas activas.
 */


internal class FailureLimiter(
    private val maxFailures: Int,
    private val windowMs: Long,
    private val blockMs: Long,
    private val maxTracked: Int = 10_000,
) {
    private val failures = LinkedHashMap<String, ArrayDeque<Long>>()
    private val blockedUntil = LinkedHashMap<String, Long>()

    @Synchronized
    private fun purgeExpired(now: Long) {
        blockedUntil.entries.removeIf { it.value <= now }
        val iter = failures.entries.iterator()
        while (iter.hasNext()) {
            val entry = iter.next()
            val fresh = ArrayDeque<Long>()
            for (t in entry.value) if (now - t < windowMs) fresh.addLast(t)
            if (fresh.isEmpty()) iter.remove() else entry.setValue(fresh)
        }
    }

    @Synchronized
    private fun purgeIfNeeded(now: Long) {
        purgeExpired(now)
        while (failures.size > maxTracked) {
            val candidate = failures.keys.firstOrNull { it !in blockedUntil }
            if (candidate == null) {
                plog("RateLimiter: ${failures.size} fallos con todas las IPs bloqueadas; no se evicta para no desbloquear atacantes")
                break
            }
            failures.remove(candidate)
        }
        if (blockedUntil.size > maxTracked) {
            plog("RateLimiter: ${blockedUntil.size} IPs bloqueadas activas (>$maxTracked); no se evicta para no desbloquear atacantes")
        }
    }

    @Synchronized
    fun isBlocked(ip: String): Boolean {
        val now = System.currentTimeMillis()
        val until = blockedUntil[ip] ?: return false
        if (until <= now) {
            blockedUntil.remove(ip)
            failures.remove(ip)
            return false
        }
        return true
    }

    @Synchronized
    fun recordFailure(ip: String) {
        val now = System.currentTimeMillis()
        purgeIfNeeded(now)
        val q = failures.getOrPut(ip) { ArrayDeque() }
        while (q.isNotEmpty() && now - q.first() >= windowMs) q.removeFirst()
        q.addLast(now)
        if (q.size >= maxFailures) {
            blockedUntil[ip] = now + blockMs
            failures.remove(ip)
            plog("IP $ip bloqueada por $maxFailures fallos (${blockMs / 1000}s)")
        }
    }

    @Synchronized
    fun recordSuccess(ip: String) {
        failures.remove(ip)
        blockedUntil.remove(ip)
    }
}

/**
 * El teléfono escucha y un `WiFiClient` de Python (u otro Kotlin) se conecta a él.
 * Un solo cliente activo: uno nuevo reemplaza al anterior (le envía `replaced`).
 * Para escuchar en la LAN sin TLS hay que pasar `allowInsecureLan = true` conscientemente.
 *
 * Paridad con wifi.py v0.4: token rotativo (`setToken` + revoke), tokenProvider,
 * semáforos de handshake/preauth con timeout, authFailDelay FUERA de los slots,
 * rate limiter con evicción segura y zeroconf opt-in vía [ZeroconfPublisher].
 */
class WiFiServer(
    token: String,
    private val host: String = "127.0.0.1",
    private val port: Int = DEFAULT_PORT,
    internal val sslContext: SSLContext? = null,
    private val allowInsecureLan: Boolean = false,
    tokenProvider: (() -> String)? = null,
    private val requireStrongToken: Boolean = true,
    private val rateLimit: Boolean = true,
    private val zeroconf: ZeroconfPublisher? = null,
    private val enableZeroconf: Boolean = false,
    private val serviceName: String = "phonelink-pc",
    private val maxPayload: Int = MAX_PAYLOAD,
    private val handshakeTimeoutMs: Long = 5_000,
    private val sendTimeoutMs: Long = 15_000,
    private val idleTimeoutMs: Long = DEFAULT_IDLE_TIMEOUT_MS,
    private val maxPreauthConnections: Int = 32,
    private val maxHandshakes: Int = 8,
    private val handshakeSemTimeoutMs: Long = 2_000,
    private val preauthSemTimeoutMs: Long = 1_000,
    private val revokeTimeoutMs: Long = 3_000,
    private val stopTimeoutMs: Long = 2_000,
    rateMaxFailures: Int = 5,
    rateWindowMs: Long = 60_000,
    rateBlockMs: Long = 300_000,
    private val rateMaxTrackedIps: Int = 10_000,
    private val authFailDelayMs: Long = 500,
) : Transport {

    @Volatile var token: String = token
    private val provider = AtomicReference<(() -> String)?>(tokenProvider)

    init {
        require(token.isNotEmpty()) { "Se requiere un token no vacío" }
        if (requireStrongToken) {
            require(token.length >= MIN_TOKEN_LEN) { "El token debe tener al menos $MIN_TOKEN_LEN caracteres" }
        }
        require(maxPayload > 0) { "maxPayload debe ser > 0" }
        require(maxPreauthConnections > 0) { "maxPreauthConnections debe ser > 0" }
        require(maxHandshakes > 0) { "maxHandshakes debe ser > 0" }
        validateServiceName(serviceName)
        require(sslContext != null || isLoopback(host) || allowInsecureLan) {
            "Sin TLS solo se permite escuchar en loopback. Configura sslContext o allowInsecureLan=true conscientemente."
        }
        checkTlsContext(sslContext, isServer = true)
    }

    private val limiter = if (rateLimit) {
        FailureLimiter(rateMaxFailures, rateWindowMs, rateBlockMs, rateMaxTrackedIps)
    } else null
    private val preauthSem = Semaphore(maxPreauthConnections)
    private val handshakeSem = Semaphore(maxHandshakes)
    private val revokeJobs = CopyOnWriteArrayList<Job>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val current = AtomicReference<MessageStream?>(null)
    @Volatile private var listener: TransportListener? = null
    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var running = false
    @Volatile private var zeroconfPublished = false
    private var acceptJob: Job? = null

    /** Puerto real (útil con port = 0). */
    val boundPort: Int get() = serverSocket?.localPort ?: port
    /** [PARIDAD] Alias snake_case de boundPort, para scripts que vienen de Python. */
    val bound_port: Int get() = boundPort

    override fun setListener(listener: TransportListener?) { this.listener = listener }
    override val isConnected: Boolean get() = current.get() != null
    override val lastRxNanos: Long? get() = current.get()?.lastRxNanos

    // ----------------------------------------------------------- Token
    private fun currentToken(): String {
        val p = provider.get() ?: return token
        val t = p.invoke()
        require(t.isNotEmpty()) { "tokenProvider devolvió un token vacío" }
        if (requireStrongToken) {
            require(t.length >= MIN_TOKEN_LEN) { "tokenProvider devolvió un token demasiado corto (mínimo $MIN_TOKEN_LEN)" }
        }
        return t
    }

    /**
     * Actualiza el token del servidor (paridad con `set_token` de Python).
     *
     * - Con `tokenProvider` activo, exige `updateProvider = true` (rotar el provider)
     *   o `disconnectCurrent = true` (solo revocar la sesión actual).
     * - `disconnectCurrent = true` envía `{"type":"revoked"}` al cliente activo y
     *   cierra su sesión; la tarea se espera en [stop] con [revokeTimeoutMs].
     */
    fun setToken(newToken: String, disconnectCurrent: Boolean = false, updateProvider: Boolean = false) {
        require(newToken.isNotEmpty()) { "Token vacío" }
        if (requireStrongToken) {
            require(newToken.length >= MIN_TOKEN_LEN) { "Token demasiado corto (mínimo $MIN_TOKEN_LEN caracteres)" }
        }
        if (provider.get() != null && !disconnectCurrent && !updateProvider) {
            throw IllegalStateException(
                "setToken() con tokenProvider activo no tiene efecto en futuras autenticaciones. " +
                        "Usa updateProvider=true para rotar el provider, o disconnectCurrent=true solo para revocar la sesión actual."
            )
        }
        token = newToken
        if (updateProvider) provider.set { newToken }
        if (disconnectCurrent) {
            val job = scope.launch { revokeCurrentSession() }
            revokeJobs.add(job)
            job.invokeOnCompletion { revokeJobs.remove(job) }
        }
    }

    private suspend fun revokeCurrentSession() {
        val s = current.getAndSet(null) ?: return
        try { s.send(JsonObject(mapOf("type" to JsonPrimitive("revoked"))), revokeTimeoutMs) } catch (_: Exception) {}
        s.close()
        withContext(NonCancellable) {
            try { listener?.onDisconnect() } catch (_: Throwable) {}
        }
    }

    // ------------------------------------------------------ Ciclo de vida
    override suspend fun start(timeoutMs: Long?) {
        check(!running) { "WiFiServer ya iniciado" }
        val startBlock: suspend () -> Unit = {
            val ss: ServerSocket = withContext(Dispatchers.IO) {
                val s = sslContext?.serverSocketFactory?.createServerSocket() ?: ServerSocket()
                try {
                    s.reuseAddress = true
                    if (s is SSLServerSocket) {
                        s.enabledProtocols = s.supportedProtocols
                            .filter { it == "TLSv1.3" || it == "TLSv1.2" }
                            .toTypedArray()
                    }
                    s.bind(InetSocketAddress(host, port), 16)
                } catch (t: Throwable) {
                    try { s.close() } catch (_: IOException) {}
                    throw t
                }
                s
            }
            serverSocket = ss
            running = true
            acceptJob = scope.launch { acceptLoop(ss) }
            if (enableZeroconf) publishZeroconf()
        }
        if (timeoutMs != null) withTimeout(timeoutMs) { startBlock() } else startBlock()
    }

    private fun publishZeroconf() {
        val zc = zeroconf
        if (zc == null) {
            plog("enableZeroconf=true pero no se pasó ZeroconfPublisher; descubrimiento deshabilitado")
            return
        }
        if (isLoopback(host)) { plog("Servidor en loopback; zeroconf no aplica"); return }
        try {
            zc.publish(serviceName, ZC_SERVICE_TYPE, boundPort, mapOf("token_required" to "1"))
            zeroconfPublished = true
        } catch (e: Exception) {
            plog("No se pudo registrar el servicio zeroconf: ${e.message}")
        }
    }

    private suspend fun acceptLoop(ss: ServerSocket) {
        while (running) {
            val sock = try {
                withContext(Dispatchers.IO) { ss.accept() }
            } catch (e: IOException) {
                if (!running) return
                continue
            }
            scope.launch { handleConnection(sock) }
        }
    }

    private suspend fun handleConnection(sock: Socket) {
        val ip = (sock.remoteSocketAddress as? InetSocketAddress)?.address?.hostAddress ?: "?"
        var preauthAcquired = false
        var handshakeAcquired = false
        var sessionStarted = false   // serveSession es dueña del socket
        var stream: MessageStream? = null
        try {
            sock.tcpNoDelay = true
            if (sock is SSLSocket) {
                withContext(Dispatchers.IO) {
                    sock.soTimeout = handshakeTimeoutMs.toInt()
                    sock.startHandshake()
                }
            }
            val s = MessageStream(sock, sendTimeoutMs)
            stream = s

            // Rate-limit: se responde antes de gastar slots (igual que Python).
            if (limiter?.isBlocked(ip) == true) {
                plog("Rate limit activo para $ip")
                try { s.send(errorMsg(Reasons.RATE_LIMITED), handshakeTimeoutMs) } catch (_: Exception) {}
                return
            }

            // Slot pre-auth con timeout (preauth_sem_timeout de Python).
            // Nota: Semaphore.tryAcquire() de kotlinx.coroutines no acepta
            // timeout; se usa withTimeoutOrNull + acquire().
            val gotPreauth = withTimeoutOrNull(preauthSemTimeoutMs) {
                preauthSem.acquire()
                true
            } ?: false
            if (!gotPreauth) {
                plog("Demasiadas conexiones pre-auth; rechazando $ip")
                return
            }
            preauthAcquired = true

            // Slot de handshake con timeout (handshake_sem de Python).
            val gotHandshake = withTimeoutOrNull(handshakeSemTimeoutMs) {
                handshakeSem.acquire()
                true
            } ?: false
            if (!gotHandshake) {
                plog("Handshake saturado; rechazando $ip")
                return
            }
            handshakeAcquired = true

            val rejectReason = doHandshake(s, ip)
            handshakeSem.release()
            handshakeAcquired = false

            // El retardo anti-fuerza-bruta y el envío del error ocurren FUERA
            // de los semáforos: un fallo de auth no retiene slots.
            preauthSem.release()
            preauthAcquired = false

            if (rejectReason != null) {
                if (rejectReason.isNotEmpty()) {
                    delay(authFailDelayMs)
                    try { s.send(errorMsg(rejectReason), handshakeTimeoutMs) } catch (_: Exception) {}
                }
                return
            }
            sessionStarted = true
            serveSession(s)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            plog("Conexión de $ip falló: ${e.message}")
        } finally {
            if (handshakeAcquired) handshakeSem.release()
            if (preauthAcquired) preauthSem.release()
            if (!sessionStarted) {
                if (stream != null) stream.close() else try { sock.close() } catch (_: IOException) {}
            }
        }
    }

    private fun errorMsg(reason: String) =
        JsonObject(mapOf("type" to JsonPrimitive("error"), "reason" to JsonPrimitive(reason)))

    /** null = OK; "" = cerrar en silencio; otro = motivo a enviar al cliente. */
    private suspend fun doHandshake(s: MessageStream, ip: String): String? {
        val hello = try {
            s.recv(HANDSHAKE_MAX, handshakeTimeoutMs) as? JsonObject
        } catch (e: ProtocolException) { limiter?.recordFailure(ip); return "" }
        catch (e: IOException) { return "" }
        if (hello == null || hello.str("type") != "hello") { limiter?.recordFailure(ip); return Reasons.AUTH_FAILED }
        val version = (hello["protocol_version"] as? JsonPrimitive)?.takeIf { !it.isString }?.content
        // [A7 de Python] El mismatch de versión NO cuenta como fallo de rate-limit.
        if (version != PROTOCOL_VERSION.toString()) return Reasons.PROTOCOL_VERSION_MISMATCH

        val nonce = ByteArray(NONCE_SIZE).also { SecureRandom().nextBytes(it) }
        try {
            s.send(
                JsonObject(mapOf(
                    "type" to JsonPrimitive("challenge"),
                    "nonce" to JsonPrimitive(nonce.toHex()),
                    "protocol_version" to JsonPrimitive(PROTOCOL_VERSION),
                )),
                handshakeTimeoutMs,
            )
        } catch (e: LinkConnectionException) { return "" }

        val auth = try {
            s.recv(HANDSHAKE_MAX, handshakeTimeoutMs) as? JsonObject
        } catch (e: ProtocolException) { limiter?.recordFailure(ip); return "" }
        catch (e: IOException) { return "" }
        val macHex = auth?.str("mac")
        if (auth == null || auth.str("type") != "auth" || macHex == null || macHex.length != 64) {
            limiter?.recordFailure(ip); return Reasons.AUTH_FAILED
        }
        val provided = macHex.hexToBytesOrNull()
        if (provided == null || provided.size != 32) { limiter?.recordFailure(ip); return Reasons.AUTH_FAILED }

        // tokenProvider roto → server_error transitorio, sin castigar la IP.
        val expectedToken = try {
            currentToken()
        } catch (e: Exception) {
            plog("tokenProvider falló (${e.message}); rechazando con server_error")
            return Reasons.SERVER_ERROR
        }
        val expected = Auth.computeMac(expectedToken, nonce)
        if (!Auth.constantTimeEquals(provided, expected)) { limiter?.recordFailure(ip); return Reasons.AUTH_FAILED }

        limiter?.recordSuccess(ip)
        val old = current.getAndSet(s)
        if (old != null && old !== s) {
            try { old.send(JsonObject(mapOf("type" to JsonPrimitive("replaced"))), handshakeTimeoutMs) } catch (_: Exception) {}
            old.close()
        }
        s.send(
            JsonObject(mapOf("type" to JsonPrimitive("auth_ok"), "protocol_version" to JsonPrimitive(PROTOCOL_VERSION))),
            handshakeTimeoutMs,
        )
        return null
    }

    private suspend fun serveSession(s: MessageStream) {
        try {
            listener?.onConnect()
            while (true) {
                val msg = s.recv(maxPayload, idleTimeoutMs) as? JsonObject ?: continue
                listener?.onMessage(msg)
            }
        } catch (_: ProtocolException) {
        } catch (_: IOException) {
        } finally {
            // Si revokeCurrentSession() ya nos quitó del slot, no emitimos
            // un segundo onDisconnect (era la sesión revocada).
            val wasCurrent = current.compareAndSet(s, null)
            s.close()
            if (wasCurrent) withContext(NonCancellable) {
                try { listener?.onDisconnect() } catch (_: Throwable) {}
            }
        }
    }

    // ---------------------------------------------------- Envío / stop
    override suspend fun send(obj: JsonObject) {
        val s = current.get() ?: throw LinkConnectionException("No hay cliente conectado")
        try {
            s.send(obj)
        } catch (e: LinkConnectionException) {
            current.compareAndSet(s, null)
            s.close()
            throw e
        }
    }

    override suspend fun disconnect() {
        current.getAndSet(null)?.close()
    }

    override suspend fun stop() {
        if (!running && acceptJob == null) return   // idempotente
        running = false

        // Baja del servicio mDNS (paridad con unregister de Python).
        if (zeroconfPublished) {
            zeroconfPublished = false
            try { zeroconf?.unpublish() } catch (_: Exception) {}
        }

        // Espera las revocaciones pendientes (paridad con _revoke_tasks):
        // espera revokeTimeoutMs, cancela las que queden y rejoin con stopTimeoutMs.
        val pending = revokeJobs.toList()
        if (pending.isNotEmpty()) {
            withTimeoutOrNull(revokeTimeoutMs) { pending.joinAll() }
            pending.filter { it.isActive }.forEach { it.cancel() }
            if (pending.any { it.isActive }) {
                withTimeoutOrNull(stopTimeoutMs) { pending.joinAll() }
            }
        }

        try { serverSocket?.close() } catch (_: IOException) {}
        serverSocket = null
        disconnect()
        val j = acceptJob
        acceptJob = null
        j?.cancel()
        withTimeoutOrNull(stopTimeoutMs) { j?.join() }
    }
}