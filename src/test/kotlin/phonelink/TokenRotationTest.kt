package phonelink

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class TokenRotationTest {

    private val TOKEN = "test-token-12345678901234567890"
    private val NUEVO = "nuevo-token-1234567890123456789012"

    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    private fun readMessage(sock: Socket): JsonObject {
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

    private fun handshake(sock: Socket, token: String) {
        writeMessage(sock, JsonObject(mapOf(
            "type" to JsonPrimitive("hello"),
            "protocol_version" to JsonPrimitive(PROTOCOL_VERSION),
        )))
        val ch = readMessage(sock)
        val nonce = ch.str("nonce")!!.hexToBytesOrNull()!!
        writeMessage(sock, JsonObject(mapOf(
            "type" to JsonPrimitive("auth"),
            "mac" to JsonPrimitive(Auth.macHex(token, nonce)),
        )))
        val ok = readMessage(sock)
        assertEquals("auth_ok", ok.str("type"))
    }

    @Test
    fun setTokenDisconnectCurrentEnviaRevoked() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            Socket().use { sock ->
                sock.connect(InetSocketAddress("127.0.0.1", port), 2_000)
                handshake(sock, TOKEN)

                srv.setToken(NUEVO, disconnectCurrent = true)

                val msg = withTimeout(3_000) { readMessage(sock) }
                assertEquals("revoked", msg.str("type"))
            }
        } finally {
            peer.stop()
        }
    }

    @Test
    fun tokenProviderRotoRespondeServerError() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(
            TOKEN, host = "127.0.0.1", port = port,
            tokenProvider = { throw RuntimeException("keystore caído") },
        )
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
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
                    "mac" to JsonPrimitive(Auth.macHex(TOKEN, nonce)),
                )))
                val reply = readMessage(sock)
                assertEquals(Reasons.SERVER_ERROR, reply.str("reason"))
            }
        } finally {
            peer.stop()
        }
    }

    @Test
    fun setTokenConProviderActivoYUpdateProvider() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(
            TOKEN, host = "127.0.0.1", port = port,
            tokenProvider = { TOKEN },
        )
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            srv.setToken(NUEVO, updateProvider = true)
            Socket().use { sock ->
                sock.connect(InetSocketAddress("127.0.0.1", port), 2_000)
                handshake(sock, NUEVO)
            }
        } finally {
            peer.stop()
        }
    }

    @Test
    fun setTokenSinOpcionesConProviderFalla() = runBlocking {
        val srv = WiFiServer(
            TOKEN, host = "127.0.0.1", port = freePort(),
            tokenProvider = { TOKEN },
        )
        assertFailsWith<IllegalStateException> {
            srv.setToken(NUEVO)
        }
    }

    @Test
    fun clienteNoReconectaTrasRevoked() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            val cli = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = true)
            val peerCli = Peer(cli, heartbeatMs = 0)
            peerCli.start(timeoutMs = 3_000)

            srv.setToken(NUEVO, disconnectCurrent = true)

            withTimeout(3_000) {
                while (cli.isConnected) delay(50)
            }
            delay(1_000)
            assertTrue(!cli.isConnected)

            peerCli.stop()
        } finally {
            peer.stop()
        }
    }
}
