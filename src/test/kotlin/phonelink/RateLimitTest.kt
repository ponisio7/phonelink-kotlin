package phonelink

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals

class RateLimitTest {

    private val TOKEN = "test-token-12345678901234567890"

    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    private fun readMessage(sock: Socket): JsonObject { /* ...igual que en otros tests... */ 
        val input = sock.getInputStream()
        val header = ByteArray(HEADER_SIZE)
        var got = 0
        while (got < HEADER_SIZE) {
            val r = input.read(header, got, HEADER_SIZE - got)
            if (r < 0) error("EOF header")
            got += r
        }
        val n = ByteBuffer.wrap(header).int
        val payload = ByteArray(n)
        got = 0
        while (got < n) {
            val r = input.read(payload, got, n - got)
            if (r < 0) error("EOF payload")
            got += r
        }
        return Protocol.decode(payload) as JsonObject
    }

    private fun writeMessage(sock: Socket, obj: JsonObject) {
        sock.getOutputStream().write(Protocol.encode(obj))
        sock.getOutputStream().flush()
    }

    @Test
    fun bloqueoTrasCincoFallos() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            repeat(5) {
                Socket().use { sock ->
                    sock.connect(InetSocketAddress("127.0.0.1", port), 2_000)
                    writeMessage(sock, JsonObject(mapOf(
                        "type" to JsonPrimitive("hello"),
                        "protocol_version" to JsonPrimitive(PROTOCOL_VERSION),
                    )))
                    val ch = readMessage(sock)
                    val nonce = ch.str("nonce")!!.hexToBytesOrNull()!!
                    writeMessage(sock, JsonObject(mapOf(
                        "type" to JsonPrimitive("auth"),
                        "mac" to JsonPrimitive("00".repeat(32)),
                    )))
                    val reply = readMessage(sock)
                    assertEquals(Reasons.AUTH_FAILED, reply.str("reason"))
                }
            }
            // Sexto intento: rate_limited
            Socket().use { sock ->
                sock.connect(InetSocketAddress("127.0.0.1", port), 2_000)
                writeMessage(sock, JsonObject(mapOf(
                    "type" to JsonPrimitive("hello"),
                    "protocol_version" to JsonPrimitive(PROTOCOL_VERSION),
                )))
                val reply = readMessage(sock)
                assertEquals(Reasons.RATE_LIMITED, reply.str("reason"))
            }
        } finally {
            peer.stop()
        }
    }
}
