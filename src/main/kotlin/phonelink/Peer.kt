package phonelink

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

const val MAX_EVENT_NAME = 256
val RESERVED_EVENTS = setOf("ping", "pong", "replaced", "revoked")
private val EVENT_RE = Regex("^[A-Za-z0-9._-]+$")

fun validateEventName(event: String) {
    require(event.isNotEmpty()) { "event debe ser no vacio" }
    require(event.length <= MAX_EVENT_NAME) { "event demasiado largo (max $MAX_EVENT_NAME)" }
    require(EVENT_RE.matches(event)) { "event solo puede contener letras, digitos, '.', '_' y '-'" }
    require(event !in RESERVED_EVENTS) { "event '$event' esta reservado" }
}

class Peer(
    private val transport: Transport,
    private val heartbeatMs: Long = 15_000,
    private val heartbeatTimeoutFactor: Double = 3.0,
    private val maxPendingHandlers: Int = 64,
    private val maxPendingHandlersGlobal: Int = 64,   // [PARIDAD] default = 64 como Python
    private val onHandlerError: (suspend (String, Throwable) -> Unit)? = null,
    private val onHandlerErrorSync: ((String, Throwable) -> Unit)? = null,
    private val stopTimeoutMs: Long = 5_000,
) : TransportListener {
    init {
        require(heartbeatMs >= 0) { "heartbeat debe ser >= 0" }
        require(heartbeatTimeoutFactor > 0) { "heartbeat_timeout_factor debe ser > 0" }
        require(maxPendingHandlers > 0) { "max_pending_handlers debe ser > 0" }
        require(maxPendingHandlersGlobal > 0) { "max_pending_handlers_global debe ser > 0" }
        transport.setListener(this)
    }
    constructor(
        transport: Transport,
        heartbeatMs: Long = 15_000,
        heartbeatTimeoutFactor: Double = 3.0,
        maxPendingHandlers: Int = 64,
        onHandlerError: (suspend (String, Throwable) -> Unit)? = null,
        stopTimeoutMs: Long = 5_000,
    ) : this(transport, heartbeatMs, heartbeatTimeoutFactor, maxPendingHandlers, 64, onHandlerError, null, stopTimeoutMs)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val handlers = ConcurrentHashMap<String, suspend (Message) -> Unit>()
    @Volatile private var defaultHandler: (suspend (Message) -> Unit)? = null
    private val pendingPerEvent = ConcurrentHashMap<String, AtomicInteger>()
    private val pendingGlobal = AtomicInteger(0)
    @Volatile private var lastSeen: Long? = null
    @Volatile private var lastPong: Long? = null
    @Volatile private var started = false
    private var heartbeatJob: Job? = null
    private val _connected = MutableStateFlow(false)
    val connected: StateFlow<Boolean> = _connected.asStateFlow()
    val isConnected: Boolean get() = transport.isConnected
    fun is_connected(): Boolean = isConnected
    fun last_rx_time(): Long? = transport.lastRxNanos
    fun on(event: String, handler: suspend (Message) -> Unit): Peer {
        validateEventName(event)
        handlers[event] = handler
        return this
    }
    fun onAny(handler: suspend (Message) -> Unit): Peer {
        defaultHandler = handler
        return this
    }
    suspend fun send(event: String, payload: JsonObject) {
        validateEventName(event)
        transport.send(JsonObject(mapOf("type" to JsonPrimitive(event), "payload" to payload)))
    }
    suspend fun send(event: String, vararg pairs: Pair<String, Any?>) = send(event, payloadOf(*pairs))
    suspend fun start(timeoutMs: Long? = null) {
        check(!started) { "Peer ya iniciado" }
        transport.start(timeoutMs)
        started = true
        if (heartbeatMs > 0) heartbeatJob = scope.launch { heartbeatLoop() }
    }
    suspend fun stop() {
        if (!started && heartbeatJob == null) {
            try { transport.stop() } catch (_: Exception) {}
            _connected.value = false
            return
        }
        heartbeatJob?.cancel()
        heartbeatJob = null
        val children = scope.coroutineContext[Job]!!.children.toList()
        children.forEach { it.cancel() }
        withTimeoutOrNull(stopTimeoutMs) { children.joinAll() }
        try { transport.stop() } catch (_: Exception) {}
        started = false
        lastSeen = null
        lastPong = null
        _connected.value = false
    }
    suspend fun waitConnected(timeoutMs: Long? = null) {
        if (timeoutMs != null) withTimeout(timeoutMs) { connected.first { it } } else connected.first { it }
    }
    suspend fun waitDisconnected(timeoutMs: Long? = null) {
        if (timeoutMs != null) withTimeout(timeoutMs) { connected.first { !it } } else connected.first { !it }
    }
    suspend fun wait_connected(timeoutMs: Long? = null) = waitConnected(timeoutMs)
    suspend fun wait_disconnected(timeoutMs: Long? = null) = waitDisconnected(timeoutMs)
    override suspend fun onConnect() {
        _connected.value = true
        plog("Transporte conectado")
    }
    override suspend fun onDisconnect() {
        _connected.value = false
        lastSeen = null
        lastPong = null
        pendingPerEvent.clear()
        pendingGlobal.set(0)
        plog("Transporte desconectado")
    }
    override suspend fun onMessage(msg: JsonObject) {
        val event = msg.str("type")?.takeIf { it.isNotEmpty() && it.length <= MAX_EVENT_NAME } ?: return
        lastSeen = System.nanoTime()
        when (event) {
            "ping" -> {
                try { transport.send(JsonObject(mapOf("type" to JsonPrimitive("pong")))) } catch (_: LinkConnectionException) {}
                return
            }
            "pong" -> { lastPong = System.nanoTime(); return }
        }
        if (event in RESERVED_EVENTS) return
        val handler = handlers[event] ?: defaultHandler ?: return
        if (pendingGlobal.get() >= maxPendingHandlersGlobal) {
            plog("Demasiados handlers globales; descartando '$event'")
            safeError(event, IllegalStateException("max_pending_handlers_global exceeded"))
            return
        }
        val count = pendingPerEvent.getOrPut(event) { AtomicInteger(0) }
        if (count.get() >= maxPendingHandlers) {
            plog("Demasiados handlers pendientes; descartando '$event'")
            safeError(event, IllegalStateException("max_pending_handlers exceeded"))
            return
        }
        val payload = (msg["payload"] as? JsonObject) ?: JsonObject(emptyMap())
        val message = Message(event, payload, msg)
        count.incrementAndGet()
        pendingGlobal.incrementAndGet()
        scope.launch {
            try { handler(message) } catch (e: CancellationException) { throw e } catch (e: Throwable) { safeError(event, e) }
            finally { count.decrementAndGet(); pendingGlobal.decrementAndGet() }
        }
    }

    /**
     * [PARIDAD] Invoca uno u otro callback (prioridad suspend), como Python.
     * Si el usuario pasa ambos, se llama al suspend y no al sync.
     */
    private suspend fun safeError(event: String, t: Throwable) {
        val suspendHandler = onHandlerError
        if (suspendHandler != null) {
            try { suspendHandler(event, t) } catch (_: Throwable) {}
            return
        }
        val syncHandler = onHandlerErrorSync
        if (syncHandler != null) {
            try { syncHandler(event, t) } catch (_: Throwable) {}
        }
    }

    private suspend fun heartbeatLoop() {
        val timeoutNs = (heartbeatMs * heartbeatTimeoutFactor * 1_000_000.0).toLong()
        val periodNs = heartbeatMs * 1_000_000L
        while (true) {
            delay(heartbeatMs)
            if (!transport.isConnected) continue
            val now = System.nanoTime()
            val candidates = listOfNotNull(lastPong, lastSeen, transport.lastRxNanos)
            val lastActivity = candidates.maxOrNull() ?: (now - periodNs)
            if (now - lastActivity > timeoutNs) {
                plog("Heartbeat perdido; cerrando conexion")
                try { transport.disconnect() } catch (_: Exception) {}
                continue
            }
            try { transport.send(JsonObject(mapOf("type" to JsonPrimitive("ping")))) }
            catch (_: LinkConnectionException) {} catch (e: CancellationException) { throw e } catch (_: Exception) {}
        }
    }
}