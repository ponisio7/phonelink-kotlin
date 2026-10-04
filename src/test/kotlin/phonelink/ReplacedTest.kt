package phonelink

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertTrue

class ReplacedTest {

    private val TOKEN = "test-token-12345678901234567890"

    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    @Test
    fun segundoClienteReemplazaAlPrimero() = runBlocking {
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.start()
        try {
            val cli1 = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = true)
            val peer1 = Peer(cli1, heartbeatMs = 0)
            var terminado1: String? = null
            cli1.onSessionTerminated = { r -> terminado1 = r }
            peer1.start(timeoutMs = 3_000)

            val cli2 = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = true)
            val peer2 = Peer(cli2, heartbeatMs = 0)
            peer2.start(timeoutMs = 3_000)

            withTimeout(3_000) {
                while (terminado1 != "replaced") kotlinx.coroutines.delay(50)
            }
            // El cliente 1 no debe reconectar
            kotlinx.coroutines.delay(1_000)
            assertTrue(!cli1.isConnected)

            peer1.stop()
            peer2.stop()
        } finally {
            peer.stop()
        }
    }
}
