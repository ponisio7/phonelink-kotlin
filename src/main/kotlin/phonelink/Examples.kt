package phonelink

import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

private const val TOKEN = "tu-token-de-32-chars-minimo"

fun mainServer(): Unit = runBlocking {
    val peer = Peer(WiFiServer(TOKEN, host = "127.0.0.1", port = 8888))
    peer.on("chat") { m ->
        println("Teléfono dice: ${m.text("text")}")
        peer.send("chat", payloadOf("text" to "PC recibió: ${m.text("text")}"))
    }
    peer.start()
    println("Esperando al teléfono... (Ctrl+C para salir)")
    awaitCancellation()
}

fun mainClient(): Unit = runBlocking {
    val peer = Peer(WiFiClient("127.0.0.1", TOKEN, port = 8888, reconnect = false))
    peer.on("chat") { m -> println("PC dice: ${m.text("text")}") }
    peer.start(timeoutMs = 5_000)
    peer.send("chat", payloadOf("text" to "Hola desde Kotlin"))
    delay(2_000)
    peer.stop()
}

fun main() = mainServer()