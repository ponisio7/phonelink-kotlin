package phonelink

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.Socket
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertTrue

class IdleTimeoutTest {

    private val TOKEN = "test-token-12345678901234567890"
    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    @Test
    fun mensajeGrandeQueFluyeNoSeAborta() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            Socket("127.0.0.1", port).use { sock ->
                val ok = rawHandshake(sock, TOKEN)
                assertTrue(ok)
                val big = "x".repeat(160_000)
                val obj = JsonObject(mapOf(
                    "type" to JsonPrimitive("evt"),
                    "payload" to JsonObject(mapOf("d" to JsonPrimitive(big))),
                ))
                val bytes = Protocol.encode(obj)
                val out = sock.getOutputStream()
                var off = 0
                while (off < bytes.size) {
                    val chunk = minOf(8192, bytes.size - off)
                    out.write(bytes, off, chunk)
                    out.flush()
                    off += chunk
                    delay(50)
                }
                // El servidor no debe haber cortado la sesión.
                assertTrue(srv.isConnected)
            }
        } finally {
            peer.stop()
        }
    }

    @Test
    fun silencioEntreMensajesSeAborta() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(
            TOKEN, host = "127.0.0.1", port = port,
            idleTimeoutMs = 300,
        )
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            Socket("127.0.0.1", port).use { sock ->
                rawHandshake(sock, TOKEN)
                withTimeout(3_000) { while (srv.isConnected) delay(50) }
                assertTrue(!srv.isConnected)
            }
        } finally {
            peer.stop()
        }
    }

    // -------------------------------------------------- helper

    private fun rawHandshake(sock: Socket, token: String): Boolean {
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
        return read().str("type") == "auth_ok"
    }
}
