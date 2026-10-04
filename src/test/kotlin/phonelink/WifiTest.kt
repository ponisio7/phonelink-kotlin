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

class WifiTest {

    private val TOKEN = "test-token-12345678901234567890"
    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    @Test
    fun segundoClienteReemplazaAlPrimero() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            val c1 = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = false)
            val p1 = Peer(c1, heartbeatMs = 0)
            p1.start(timeoutMs = 3_000)

            val c2 = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = false)
            val p2 = Peer(c2, heartbeatMs = 0)
            p2.start(timeoutMs = 3_000)

            withTimeout(2_000) { while (c1.isConnected) delay(50) }
            assertTrue(c2.isConnected)

            p1.stop(); p2.stop()
        } finally {
            peer.stop()
        }
    }

    @Test
    fun rateLimitBloqueaTrasFallos() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            repeat(5) {
                Socket("127.0.0.1", port).use { sock ->
                    val reply = handshakeConTokenMalo(sock)
                    assertEquals(Reasons.AUTH_FAILED, reply.str("reason"))
                }
            }
            Socket("127.0.0.1", port).use { sock ->
                val reply = handshakeConTokenMalo(sock)
                assertEquals(Reasons.RATE_LIMITED, reply.str("reason"))
            }
        } finally {
            peer.stop()
        }
    }

    @Test
    fun heartbeatMantieneVivaConexionActiva() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peerSrv = Peer(srv, heartbeatMs = 200, heartbeatTimeoutFactor = 3.0)
        peerSrv.start()
        try {
            val cli = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = false)
            val peerCli = Peer(cli, heartbeatMs = 0)  // responde ping vía Peer
            peerCli.start(timeoutMs = 3_000)
            delay(1_000)
            assertTrue(cli.isConnected)
            peerCli.stop()
        } finally {
            peerSrv.stop()
        }
    }

    // -------------------------------------------------- helper

    private fun handshakeConTokenMalo(sock: Socket): JsonObject {
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
        if (ch.str("type") == "error") return ch
        write(JsonObject(mapOf(
            "type" to JsonPrimitive("auth"),
            "mac" to JsonPrimitive("00".repeat(32)),
        )))
        return read()
    }
}
