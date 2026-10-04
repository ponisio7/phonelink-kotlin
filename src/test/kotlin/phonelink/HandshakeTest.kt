package phonelink

import kotlinx.coroutines.async
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
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class HandshakeTest {

    private val TOKEN = "test-token-12345678901234567890"

    private fun freePort(): Int =
        java.net.ServerSocket(0).use { it.localPort }

    /** Lee un mensaje crudo (header + payload JSON) de un socket. */
    private fun readMessage(sock: Socket): JsonObject {
        val input = sock.getInputStream()
        val header = ByteArray(HEADER_SIZE)
        var got = 0
        while (got < HEADER_SIZE) {
            val r = input.read(header, got, HEADER_SIZE - got)
            if (r < 0) error("EOF leyendo header")
            got += r
        }
        val n = ByteBuffer.wrap(header).int
        val payload = ByteArray(n)
        got = 0
        while (got < n) {
            val r = input.read(payload, got, n - got)
            if (r < 0) error("EOF leyendo payload")
            got += r
        }
        return Protocol.decode(payload) as JsonObject
    }

    private fun writeMessage(sock: Socket, obj: JsonObject) {
        val raw = Protocol.encode(obj)
        sock.getOutputStream().write(raw)
        sock.getOutputStream().flush()
    }

    private fun handshakeCrudo(sock: Socket, token: String): JsonObject {
        writeMessage(sock, JsonObject(mapOf(
            "type" to JsonPrimitive("hello"),
            "protocol_version" to JsonPrimitive(PROTOCOL_VERSION),
        )))
        val challenge = readMessage(sock)
        assertEquals("challenge", challenge.str("type"))
        val nonce = challenge.str("nonce")!!.hexToBytesOrNull()!!
        val mac = Auth.macHex(token, nonce)
        writeMessage(sock, JsonObject(mapOf(
            "type" to JsonPrimitive("auth"),
            "mac" to JsonPrimitive(mac),
        )))
        return readMessage(sock)
    }

    @Test
    fun handshakeCorrecto() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            Socket().use { sock ->
                sock.connect(InetSocketAddress("127.0.0.1", port), 2_000)
                val reply = handshakeCrudo(sock, TOKEN)
                assertEquals("auth_ok", reply.str("type"))
            }
        } finally {
            peer.stop()
        }
    }

    @Test
    fun handshakeTokenIncorrecto() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            Socket().use { sock ->
                sock.connect(InetSocketAddress("127.0.0.1", port), 2_000)
                val reply = handshakeCrudo(sock, "otro-token-12345678901234567890")
                assertEquals("error", reply.str("type"))
                assertEquals(Reasons.AUTH_FAILED, reply.str("reason"))
            }
        } finally {
            peer.stop()
        }
    }

    @Test
    fun protocolVersionMismatch() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            Socket().use { sock ->
                sock.connect(InetSocketAddress("127.0.0.1", port), 2_000)
                writeMessage(sock, JsonObject(mapOf(
                    "type" to JsonPrimitive("hello"),
                    "protocol_version" to JsonPrimitive(99),
                )))
                val reply = readMessage(sock)
                assertEquals(Reasons.PROTOCOL_VERSION_MISMATCH, reply.str("reason"))
            }
        } finally {
            peer.stop()
        }
    }

    @Test
    fun clienteYservidorKotlinHablan() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peerSrv = Peer(srv, heartbeatMs = 0)
        val recibidos = java.util.concurrent.CopyOnWriteArrayList<Message>()
        peerSrv.on("chat") { m -> recibidos.add(m) }
        peerSrv.start()

        try {
            val cli = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = false)
            val peerCli = Peer(cli, heartbeatMs = 0)
            peerCli.start(timeoutMs = 3_000)
            try {
                peerCli.send("chat", payloadOf("text" to "hola"))
                withTimeout(2_000) {
                    while (recibidos.isEmpty()) delay(50)
                }
                assertEquals("hola", recibidos.first().text("text"))
            } finally {
                peerCli.stop()
            }
        } finally {
            peerSrv.stop()
        }
    }
}
