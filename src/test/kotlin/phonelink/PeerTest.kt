package phonelink

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PeerTest {

    private val TOKEN = "test-token-12345678901234567890"

    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    @Test
    fun handlerQueLanzaNoRompeConexion() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peerSrv = Peer(srv, heartbeatMs = 0)
        val recibidos = java.util.concurrent.CopyOnWriteArrayList<Message>()
        peerSrv.on("malo") { error("boom") }
        peerSrv.on("bueno") { m -> recibidos.add(m) }
        peerSrv.start()
        try {
            val cli = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = false)
            val peerCli = Peer(cli, heartbeatMs = 0)
            peerCli.start(timeoutMs = 3_000)
            peerCli.send("malo", payloadOf())
            delay(200)
            peerCli.send("bueno", payloadOf("ok" to true))
            withTimeout(2_000) { while (recibidos.isEmpty()) delay(50) }
            assertTrue(recibidos.first().payload["ok"].toString().contains("true"))
            peerCli.stop()
        } finally {
            peerSrv.stop()
        }
    }

    @Test
    fun handlerErrorCallbackRecibeEvento() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        var eventRecibido: String? = null
        val peerSrv = Peer(srv, heartbeatMs = 0, onHandlerError = { event, _ -> eventRecibido = event })
        peerSrv.on("malo") { error("boom") }
        peerSrv.start()
        try {
            val cli = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = false)
            val peerCli = Peer(cli, heartbeatMs = 0)
            peerCli.start(timeoutMs = 3_000)
            peerCli.send("malo", payloadOf())
            withTimeout(2_000) { while (eventRecibido == null) delay(50) }
            assertEquals("malo", eventRecibido)
            peerCli.stop()
        } finally {
            peerSrv.stop()
        }
    }

    @Test
    fun stopEsIdempotente() = runBlocking {
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = freePort())
        val peer = Peer(srv, heartbeatMs = 0)
        peer.stop()   // antes de start
        peer.stop()   // segunda vez
    }
}
