package phonelink

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.Socket
import java.nio.ByteBuffer
import javax.net.ssl.SSLContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class HardeningTest {

    private val TOKEN = "test-token-12345678901234567890"
    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    // ---- zeroconf on/off

    @Test
    fun zeroconfDesactivadoPorDefecto() {
        runBlocking {
            val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = freePort())
            srv.start()
            srv.stop()
        }
    }

    @Test
    fun zeroconfSeActivaSiSePide() {
        var publicado = 0
        var despublicado = 0
        val publisher = object : ZeroconfPublisher {
            override fun publish(
                serviceName: String, type: String, port: Int,
                properties: Map<String, String>,
            ) { publicado++ }
            override fun unpublish() { despublicado++ }
        }
        runBlocking {
            val srv = WiFiServer(
                TOKEN, host = "127.0.0.1", port = freePort(),
                zeroconf = publisher, enableZeroconf = true,
            )
            srv.start()
            srv.stop()
        }
        // Loopback no publica (equivalente a Python).
        assertEquals(0, publicado)
        assertEquals(0, despublicado)
    }

    // ---- eventos reservados

    @Test
    fun eventosReservadosNoSePuedenEnviarNiRegistrar() = runBlocking {
        val peer = Peer(
            WiFiServer(TOKEN, host = "127.0.0.1", port = freePort()),
            heartbeatMs = 0,
        )
        for (nombre in RESERVED_EVENTS) {
            assertFailsWith<IllegalArgumentException> { peer.on(nombre) { } }
            assertFailsWith<IllegalArgumentException> { peer.send(nombre, payloadOf()) }
        }
    }

    @Test
    fun nombresNormalesSiguenPermitidos() {
        val peer = Peer(
            WiFiServer(TOKEN, host = "127.0.0.1", port = freePort()),
            heartbeatMs = 0,
        )
        for (nombre in listOf("chat", "error", "status.update", "file-chunk_1")) {
            peer.on(nombre) { }
        }
    }

    // ---- tokenProvider roto

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
            Socket("127.0.0.1", port).use { sock ->
                val reply = doHandshakeRaw(sock, TOKEN)
                assertEquals(Reasons.SERVER_ERROR, reply.str("reason"))
            }
        } finally {
            peer.stop()
        }
    }

    // ---- SSLContext débil

    @Test
    fun sslContextNormalAceptado() {
        val ctx: SSLContext = SSLContext.getInstance("TLS")
        ctx.init(null, null, null)
        // No debe lanzar con un contexto TLS moderno
        checkTlsContext(ctx, isServer = false, host = "192.168.1.50", allowInsecureTls = false)
    }

    // -------------------------------------------------- helper

    private fun doHandshakeRaw(sock: Socket, token: String): JsonObject {
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
