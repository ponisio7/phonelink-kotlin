package phonelink

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.Socket
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReviewRegressionsTest {

    private val TOKEN = "test-token-12345678901234567890"
    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    @Test
    fun startLanzaAuthRejectedConTokenIncorrecto() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peerSrv = Peer(srv, heartbeatMs = 0)
        peerSrv.start()
        try {
            val cli = WiFiClient("127.0.0.1", "otro-token-12345678901234567890",
                port = port, reconnect = false)
            val peerCli = Peer(cli, heartbeatMs = 0)
            var excepcion: Throwable? = null
            try {
                peerCli.start(timeoutMs = 3_000)
            } catch (e: Throwable) {
                excepcion = e
            }
            assertTrue(excepcion is AuthRejectedException)
            assertEquals(Reasons.AUTH_FAILED, (excepcion as AuthRejectedException).reason)
        } finally {
            peerSrv.stop()
        }
    }

    @Test
    fun limitePreauthRechazaConexionExtra() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(
            TOKEN, host = "127.0.0.1", port = port,
            maxPreauthConnections = 2, preauthSemTimeoutMs = 300,
        )
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        val holders = mutableListOf<Socket>()
        try {
            repeat(2) {
                holders.add(Socket("127.0.0.1", port))
            }
            delay(200)
            // La tercera debe ser rechazada con EOF
            Socket("127.0.0.1", port).use { extra ->
                val input = extra.getInputStream()
                extra.soTimeout = 2_000
                val b = input.read()
                assertEquals(-1, b)  // EOF
            }
        } finally {
            holders.forEach { try { it.close() } catch (_: Exception) {} }
            peer.stop()
        }
    }

    @Test
    fun authFailDelayNoBloqueaSlotDeHandshake() = runBlocking {
        val port = freePort()
        val delayMs = 500L
        val srv = WiFiServer(
            TOKEN, host = "127.0.0.1", port = port,
            maxHandshakes = 1, rateLimit = false,
            authFailDelayMs = delayMs,
        )
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            // Cliente malo: handshake con token incorrecto
            val malo = Socket("127.0.0.1", port)
            val replyMalo = handshakeRaw(malo, "mal-token-12345678901234567890")
            assertEquals(Reasons.AUTH_FAILED, replyMalo.str("reason"))
            // El malo ya está fuera del semáforo (delay se aplica después).
            delay(50)

            val t0 = System.nanoTime()
            val bueno = Socket("127.0.0.1", port)
            val replyBueno = handshakeRaw(bueno, TOKEN)
            val elapsedMs = (System.nanoTime() - t0) / 1_000_000

            assertEquals("auth_ok", replyBueno.str("type"))
            assertTrue(elapsedMs < delayMs * 0.6,
                "El slot de handshake se bloqueó por authFailDelay (${elapsedMs}ms)")

            malo.close(); bueno.close()
        } finally {
            peer.stop()
        }
    }

    // -------------------------------------------------- helper

    private fun handshakeRaw(sock: Socket, token: String): JsonObject {
        val out = sock.getOutputStream()
        val input = sock.getInputStream()
        fun write(obj: JsonObject) { out.write(Protocol.encode(obj)); out.flush() }
        fun read(): JsonObject {
            val header = ByteArray(HEADER_SIZE)
            var got = 0
            while (got < HEADER_SIZE) {
                val r = input.read(header, got, HEADER_SIZE - got)
                if (r < 0) error("EOF")
                got += r
            }
            val n = ByteBuffer.wrap(header).int
            val payload = ByteArray(n)
            got = 0
            while (got < n) {
                val r = input.read(payload, got, n - got)
                if (r < 0) error("EOF")
                got += r
            }
            return Protocol.decode(payload) as JsonObject
        }
        write(JsonObject(mapOf(
            "type" to JsonPrimitive("hello"),
            "protocol_version" to JsonPrimitive(PROTOCOL_VERSION),
        )))
        val ch = read()
        val nonce = ch.str("nonce")!!.hexToBytesOrNull()!!
        write(JsonObject(mapOf(
            "type" to JsonPrimitive("auth"),
            "mac" to JsonPrimitive(Auth.macHex(token, nonce)),
        )))
        return read()
    }
}
