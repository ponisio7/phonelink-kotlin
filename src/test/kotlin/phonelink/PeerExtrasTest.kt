package phonelink

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PeerExtrasTest {

    private val TOKEN = "test-token-12345678901234567890"
    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    @Test
    fun pingRespondePongAutomaticamente() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            val sock = java.net.Socket("127.0.0.1", port)
            val out = sock.getOutputStream()
            val input = sock.getInputStream()
            fun write(obj: kotlinx.serialization.json.JsonObject) {
                out.write(Protocol.encode(obj)); out.flush()
            }
            fun read(): kotlinx.serialization.json.JsonObject {
                val header = ByteArray(HEADER_SIZE)
                var got = 0
                while (got < HEADER_SIZE) {
                    val r = input.read(header, got, HEADER_SIZE - got)
                    if (r < 0) error("EOF")
                    got += r
                }
                val n = java.nio.ByteBuffer.wrap(header).int
                val payload = ByteArray(n)
                got = 0
                while (got < n) {
                    val r = input.read(payload, got, n - got)
                    if (r < 0) error("EOF")
                    got += r
                }
                return Protocol.decode(payload) as kotlinx.serialization.json.JsonObject
            }
            // handshake
            write(kotlinx.serialization.json.JsonObject(mapOf(
                "type" to kotlinx.serialization.json.JsonPrimitive("hello"),
                "protocol_version" to kotlinx.serialization.json.JsonPrimitive(PROTOCOL_VERSION),
            )))
            val ch = read()
            val nonce = ch.str("nonce")!!.hexToBytesOrNull()!!
            write(kotlinx.serialization.json.JsonObject(mapOf(
                "type" to kotlinx.serialization.json.JsonPrimitive("auth"),
                "mac" to kotlinx.serialization.json.JsonPrimitive(Auth.macHex(TOKEN, nonce)),
            )))
            read()

            // ping → pong automático
            write(kotlinx.serialization.json.JsonObject(mapOf(
                "type" to kotlinx.serialization.json.JsonPrimitive("ping"),
            )))
            val reply = withTimeout(2_000) {
                while (true) {
                    val m = read()
                    if (m.str("type") == "pong") return@withTimeout m
                }
                @Suppress("UNREACHABLE_CODE") error("no pong")
            }
            assertEquals("pong", reply.str("type"))
            sock.close()
        } finally {
            peer.stop()
        }
    }

    @Test
    fun limiteHandlersConcurrentes() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peerSrv = Peer(srv, heartbeatMs = 0, maxPendingHandlers = 4)
        // handler que duerme mucho
        peerSrv.on("slow") { delay(5_000) }
        var normales = 0
        peerSrv.on("normal") { normales++ }
        peerSrv.start()
        try {
            val cli = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = false)
            val peerCli = Peer(cli, heartbeatMs = 0)
            peerCli.start(timeoutMs = 3_000)
            // saturar con 20 mensajes "slow"
            repeat(20) { peerCli.send("slow", payloadOf()) }
            delay(300)
            // Un mensaje normal debe seguir pasando (no lo bloquea el límite)
            peerCli.send("normal", payloadOf())
            withTimeout(2_000) { while (normales == 0) delay(50) }
            assertTrue(normales >= 1)
            peerCli.stop()
        } finally {
            peerSrv.stop()
        }
    }
}
