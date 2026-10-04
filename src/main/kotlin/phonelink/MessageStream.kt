package phonelink

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import java.io.EOFException
import java.io.IOException
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Una conexión TCP/TLS con mensajes enmarcados.
 * Envío serializado con mutex; lectura por chunks con timeout de inactividad.
 */
internal class MessageStream(private val socket: Socket, private val sendTimeoutMs: Long) {
    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()
    private val writeMutex = Mutex()

    @Volatile private var rxStamp: Long = Long.MIN_VALUE

    /** System.nanoTime() del último byte recibido, o null si aún no llegó nada. */
    val lastRxNanos: Long? get() = rxStamp.takeIf { it != Long.MIN_VALUE }

    private fun touch() { rxStamp = System.nanoTime() }

    private fun readExactly(n: Int, idleTimeoutMs: Long?): ByteArray {
        val buf = ByteArray(n)
        var got = 0
        while (got < n) {
            val size = minOf(n - got, READ_CHUNK)
            val r = try {
                input.read(buf, got, size)
            } catch (e: SocketTimeoutException) {
                throw ProtocolException("Timeout de inactividad (${idleTimeoutMs} ms) leyendo $got/$n bytes", e)
            }
            if (r < 0) throw EOFException("Conexión cerrada ($got/$n bytes)")
            got += r
            touch()
        }
        return buf
    }

    suspend fun recv(maxSize: Int = MAX_PAYLOAD, idleTimeoutMs: Long? = null): JsonElement =
        withContext(Dispatchers.IO) {
            socket.soTimeout = (idleTimeoutMs ?: 0L).coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
            val header = readExactly(HEADER_SIZE, idleTimeoutMs)
            val n = ByteBuffer.wrap(header).int // sin signo en Python: negativo = enorme
            if (n < 0 || n > maxSize) {
                throw ProtocolException("Payload anunciado demasiado grande: ${n.toLong() and 0xFFFFFFFFL} > $maxSize")
            }
            Protocol.decode(readExactly(n, idleTimeoutMs))
        }

    suspend fun send(obj: JsonElement, timeoutMs: Long = sendTimeoutMs) {
        val bytes = Protocol.encode(obj)
        writeMutex.withLock {
            coroutineScope {
                val timedOut = AtomicBoolean(false)
                // Las escrituras de socket bloqueantes no son cancelables: un watchdog cierra el socket.
                val watchdog = launch(Dispatchers.Default) {
                    delay(timeoutMs)
                    timedOut.set(true)
                    close()
                }
                try {
                    withContext(Dispatchers.IO) {
                        output.write(bytes)
                        output.flush()
                    }
                } catch (e: IOException) {
                    close()
                    throw LinkConnectionException(
                        if (timedOut.get()) "Timeout al enviar" else "Error al enviar: ${e.message}", e
                    )
                } finally {
                    watchdog.cancel()
                }
            }
        }
    }

    fun close() {
        try { socket.close() } catch (_: IOException) {}
    }
}
