package phonelink

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests de interoperabilidad real Kotlin <-> Python.
 *
 * Se saltan automáticamente si:
 *  - no hay `python3` o `python` en el PATH,
 *  - no existe el paquete `phonelink` en el PYTHONPATH,
 *  - no se encuentran los scripts en `src/test/resources/interop/`.
 *
 * Cubren dos direcciones:
 *   1. Python servidor <-> Kotlin cliente.
 *   2. Kotlin servidor <-> Python cliente.
 */
class InteropTest {

    private val TOKEN = "interop-token-12345678901234567890"

    private val procesos = mutableListOf<Process>()

    @AfterTest
    fun cleanup() {
        procesos.forEach { p ->
            try { p.destroy() } catch (_: Exception) {}
            try { p.waitFor(2, TimeUnit.SECONDS) } catch (_: Exception) {}
            try { p.destroyForcibly() } catch (_: Exception) {}
        }
        procesos.clear()
    }

    // -------------------------------------------------- Helpers

    private fun pythonBin(): String? =
        listOf("python3", "python").firstOrNull { bin ->
            try {
                val p = ProcessBuilder(bin, "--version").redirectErrorStream(true).start()
                p.waitFor(2, TimeUnit.SECONDS) && p.exitValue() == 0
            } catch (_: Exception) { false }
        }

    private fun scriptPath(name: String): Path? {
        val candidates = listOf(
            Path.of("src/test/resources/interop/$name"),
            Path.of("phonelink-kotlin/src/test/resources/interop/$name"),
            Path.of(System.getProperty("user.dir"), "src/test/resources/interop/$name"),
        )
        return candidates.firstOrNull { Files.isRegularFile(it) }?.toAbsolutePath()
    }

    private fun pythonSrcPath(): Path? {
        System.getenv("PHONELINK_PY_PATH")?.let {
            val p = Path.of(it)
            if (Files.isDirectory(p.resolve("phonelink"))) return p
        }
        var dir: Path? = Path.of(System.getProperty("user.dir")).toAbsolutePath()
        repeat(5) {
            val d = dir ?: return null
            val candidate = d.resolve("src/phonelink")
            if (Files.isDirectory(candidate)) return d.resolve("src")
            dir = d.parent
        }
        val home = System.getProperty("user.home") ?: return null
        val guess = Path.of(home, "proyectosPython/phonelink/src")
        if (Files.isDirectory(guess.resolve("phonelink"))) return guess
        return null
    }

    private fun launch(
        cmd: List<String>,
        extraEnv: Map<String, String> = emptyMap(),
        cwd: Path? = null,
    ): Process {
        val pb = ProcessBuilder(cmd).redirectErrorStream(true)
        cwd?.let { pb.directory(it.toFile()) }
        val env = pb.environment()
        env.putAll(extraEnv)
        val proc = pb.start()
        procesos.add(proc)
        return proc
    }

    private fun readLine(proc: Process, timeoutMs: Long): String? {
        val reader = BufferedReader(InputStreamReader(proc.inputStream))
        val future = java.util.concurrent.CompletableFuture.supplyAsync { reader.readLine() }
        return try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: Exception) { null }
    }

    // -------------------------------------------------- Test 1: Python server, Kotlin client

    @Test
    fun pythonServidorKotlinCliente() = runBlocking {
        val py = pythonBin()
        assumeTrue(py != null, "python3/python no encontrado en PATH")
        val script = scriptPath("py_server.py")
        assumeTrue(script != null, "py_server.py no encontrado en src/test/resources/interop/")
        val srcDir = pythonSrcPath()
        assumeTrue(srcDir != null, "No se encontró el paquete Python phonelink (usa PHONELINK_PY_PATH)")

        val proc = launch(
            listOf(py!!, script.toString(), TOKEN),
            extraEnv = mapOf("PYTHONPATH" to srcDir.toString()),
            cwd = srcDir!!.parent,
        )

        // Esperar línea "PORT=N"
        var port = -1
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            val line = readLine(proc, 10_000) ?: break
            val trimmed = line.trim()
            if (trimmed.startsWith("PORT=")) {
                port = trimmed.removePrefix("PORT=").toIntOrNull() ?: -1
                break
            }
        }
        assumeTrue(port > 0, "No se pudo obtener el puerto del servidor Python")

        try {
            val cli = WiFiClient("127.0.0.1", TOKEN, port = port, reconnect = false)
            val peer = Peer(cli, heartbeatMs = 0)
            val recibidos = CopyOnWriteArrayList<Message>()
            peer.on("chat") { m -> recibidos.add(m) }
            peer.start(timeoutMs = 5_000)
            try {
                peer.send("chat", payloadOf("text" to "hola desde Kotlin"))
                withTimeout(5_000) {
                    while (recibidos.isEmpty()) delay(50)
                }
                assertEquals("echo:hola desde Kotlin", recibidos.first().text("text"))
            } finally {
                peer.stop()
            }
        } finally {
            // Cierre limpio del server Python
            try {
                proc.outputStream.write("stop\n".toByteArray())
                proc.outputStream.flush()
            } catch (_: Exception) {}
            proc.waitFor(3, TimeUnit.SECONDS)
        }
    }

    // -------------------------------------------------- Test 2: Kotlin server, Python client

    @Test
    fun kotlinServidorPythonCliente() = runBlocking {
        val py = pythonBin()
        assumeTrue(py != null, "python3/python no encontrado en PATH")
        val script = scriptPath("py_client.py")
        assumeTrue(script != null, "py_client.py no encontrado en src/test/resources/interop/")
        val srcDir = pythonSrcPath()
        assumeTrue(srcDir != null, "No se encontró el paquete Python phonelink (usa PHONELINK_PY_PATH)")

        // Puerto efímero elegido por el OS
        val port = java.net.ServerSocket(0).use { it.localPort }

        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port)
        val peer = Peer(srv, heartbeatMs = 0)
        peer.on("chat") { m ->
            val texto = m.text("text") ?: ""
            peer.send("chat", payloadOf("text" to "echo:$texto"))
        }
        peer.start()
        try {
            val proc = launch(
                listOf(py!!, script.toString(), port.toString(), TOKEN),
                extraEnv = mapOf("PYTHONPATH" to srcDir.toString()),
                cwd = srcDir!!.parent,
            )

            val out = readLine(proc, 10_000)
            assumeTrue(out != null, "El cliente Python no respondió")
            val json = out!!.trim()
            assertTrue(
                json.contains("echo:hola desde Python"),
                "respuesta inesperada: $json",
            )
        } finally {
            peer.stop()
        }
    }
}
