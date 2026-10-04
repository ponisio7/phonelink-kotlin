package phonelink

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Kotlin cliente ↔ Kotlin servidor por loopback (sin TLS). */
class LinkTest {
    @Test
    fun echoRoundTrip() = runBlocking {
        withTimeout(20_000) {
            val token = generateToken()
            val serverTransport = WiFiServer(token, "127.0.0.1", 0)
            val server = Peer(serverTransport, heartbeatMs = 0)
            server.on("chat") { m -> server.send("chat", "text" to "eco: ${m.text("text")}") }
            server.start()

            val got = CompletableDeferred<String>()
            val client = Peer(WiFiClient("127.0.0.1", token, serverTransport.boundPort, reconnect = false), heartbeatMs = 0)
            client.on("chat") { m -> got.complete(m.text("text") ?: "") }
            client.start(5_000)
            client.send("chat", "text" to "hola ñ")

            assertEquals("eco: hola ñ", got.await())
            client.stop()
            server.stop()
        }
    }

    @Test
    fun wrongTokenIsRejected() = runBlocking {
        withTimeout(20_000) {
            val serverTransport = WiFiServer(generateToken(), "127.0.0.1", 0)
            val server = Peer(serverTransport, heartbeatMs = 0)
            server.start()

            val client = WiFiClient("127.0.0.1", generateToken(), serverTransport.boundPort, reconnect = false)
            val e = assertFailsWith<AuthRejectedException> { client.start(5_000) }
            assertEquals(Reasons.AUTH_FAILED, e.reason)
            server.stop()
        }
    }

    @Test
    fun plainTextOutsideLoopbackRequiresOptIn() {
        assertFailsWith<IllegalArgumentException> { WiFiClient("192.168.1.20", generateToken()) }
        WiFiClient("192.168.1.20", generateToken(), allowInsecureLan = true)
    }
}
