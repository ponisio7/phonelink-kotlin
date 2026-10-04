package phonelink

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HeartbeatTest {

    private val TOKEN = "test-token-12345678901234567890"

    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    @Test
    fun heartbeatCierraConexionMuerta() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        // heartbeat cada 200 ms, timeout x3 = 600 ms
        val peer = Peer(srv, heartbeatMs = 200, heartbeatTimeoutFactor = 3.0)
        peer.start()
        try {
            // Cliente "mudo": se conecta pero no responde pings
            java.net.Socket().use { sock ->
                sock.connect(java.net.InetSocketAddress("127.0.0.1", port), 2_000)
                // Necesitamos hacer el handshake manualmente para que el
                // servidor considere la sesión activa.
                val handshakeTest = HandshakeTestHelper(sock, TOKEN)
                handshakeTest.run()
                withTimeout(5_000) {
                    while (srv.isConnected) delay(100)
                }
                assertFalse(srv.isConnected)
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
            val peerCli = Peer(cli, heartbeatMs = 0)  // responde pings vía Peer
            peerCli.start(timeoutMs = 3_000)

            delay(1_000)
            assertTrue(cli.isConnected)

            peerCli.stop()
        } finally {
            peerSrv.stop()
        }
    }
}

/** Helper para hacer el handshake crudo desde un Socket. */
private class HandshakeTestHelper(private val sock: java.net.Socket, private val token: String) {
    fun run() {
        write(JsonObjectOf("type" to "hello", "protocol_version" to PROTOCOL_VERSION))
        val ch = read()
        val nonce = (ch["nonce"] as? kotlinx.serialization.json.JsonPrimitive)?.content!!.hexToBytesOrNull()!!
        write(JsonObjectOf("type" to "auth", "mac" to Auth.macHex(token, nonce)))
        read() // auth_ok
    }
    private fun write(obj: Map<String, Any>) {
        val jo = kotlinx.serialization.json.JsonObject(
            obj.mapValues { (_, v) ->
                when (v) {
                    is String -> kotlinx.serialization.json.JsonPrimitive(v)
                    is Int -> kotlinx.serialization.json.JsonPrimitive(v)
                    else -> kotlinx.serialization.json.JsonPrimitive(v.toString())
                }
            }
        )
        sock.getOutputStream().write(Protocol.encode(jo))
        sock.getOutputStream().flush()
    }
    private fun read(): kotlinx.serialization.json.JsonObject {
        val input = sock.getInputStream()
        val header = ByteArray(HEADER_SIZE)
        var got = 0
        while (got < HEADER_SIZE) {
            val r = input.read(header, got, HEADER_SIZE - got)
            if (r < 0) error("EOF header")
            got += r
        }
        val n = java.nio.ByteBuffer.wrap(header).int
        val payload = ByteArray(n)
        got = 0
        while (got < n) {
            val r = input.read(payload, got, n - got)
            if (r < 0) error("EOF payload")
            got += r
        }
        return Protocol.decode(payload) as kotlinx.serialization.json.JsonObject
    }
    private fun JsonObjectOf(vararg pairs: Pair<String, Any>): Map<String, Any> = pairs.toMap()
}
