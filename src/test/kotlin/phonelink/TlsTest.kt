package phonelink

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Tests TLS que generan certificados autofirmados con openssl en tiempo real.
 * Se saltan si openssl no está disponible.
 */
class TlsTest {

    private val TOKEN = "test-token-12345678901234567890"
    private val tmpDir: Path = Files.createTempDirectory("phonelink-tls-")

    @AfterTest
    fun cleanup() {
        tmpDir.toFile().deleteRecursively()
    }

    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    private fun opensslDisponible(): Boolean =
        try {
            val p = ProcessBuilder("openssl", "version")
                .redirectErrorStream(true).start()
            p.waitFor(2, TimeUnit.SECONDS) && p.exitValue() == 0
        } catch (_: Exception) { false }

    private fun generarCert(cn: String = "test"): Pair<Path, Path> {
        val cert = tmpDir.resolve("$cn.crt")
        val key = tmpDir.resolve("$cn.key")
        ProcessBuilder(
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key.toString(), "-out", cert.toString(),
            "-days", "1", "-subj", "/CN=$cn",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ).redirectErrorStream(true).start().let { p ->
            val ok = p.waitFor(10, TimeUnit.SECONDS) && p.exitValue() == 0
            check(ok) { "openssl falló al generar el certificado" }
        }
        return cert to key
    }

    private fun serverCtx(cert: Path, key: Path): SSLContext {
        val ctx = SSLContext.getInstance("TLS")
        val ks = java.security.KeyStore.getInstance("PKCS12")
        // Generamos un .p12 temporal a partir de cert+key con openssl
        val p12 = tmpDir.resolve("server.p12")
        ProcessBuilder(
            "openssl", "pkcs12", "-export",
            "-in", cert.toString(), "-inkey", key.toString(),
            "-out", p12.toString(), "-passout", "pass:clave",
        ).redirectErrorStream(true).start().let { p ->
            val ok = p.waitFor(10, TimeUnit.SECONDS) && p.exitValue() == 0
            check(ok) { "openssl pkcs12 falló" }
        }
        ks.load(Files.newInputStream(p12), "clave".toCharArray())
        val kmf = javax.net.ssl.KeyManagerFactory
            .getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm())
            .apply { init(ks, "clave".toCharArray()) }
        ctx.init(kmf.keyManagers, null, null)
        return ctx
    }

    private fun clientCtx(cert: Path): SSLContext {
        val ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType())
        ks.load(null, null)
        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        val c = Files.newInputStream(cert).use { cf.generateCertificate(it) }
        ks.setCertificateEntry("server", c)
        val tmf = javax.net.ssl.TrustManagerFactory
            .getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(ks) }
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, tmf.trustManagers, null)
        return ctx
    }

    @Test
    fun tlsHandshakeExitoso() = runBlocking {
        if (!opensslDisponible()) return@runBlocking
        val (cert, key) = generarCert()
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port,
            sslContext = serverCtx(cert, key))
        val peerSrv = Peer(srv, heartbeatMs = 0)
        val recibidos = java.util.concurrent.CopyOnWriteArrayList<Message>()
        peerSrv.on("chat") { m -> recibidos.add(m) }
        peerSrv.start()
        try {
            val cli = WiFiClient("127.0.0.1", TOKEN, port = port,
                reconnect = false, sslContext = clientCtx(cert),
                verifyHostname = false)  // cert no tiene SAN para 127.0.0.1 verificable aquí
            val peerCli = Peer(cli, heartbeatMs = 0)
            peerCli.start(timeoutMs = 3_000)
            try {
                peerCli.send("chat", payloadOf("text" to "hola TLS"))
                withTimeout(2_000) { while (recibidos.isEmpty()) delay(50) }
                assertEquals("hola TLS", recibidos.first().text("text"))
            } finally {
                peerCli.stop()
            }
        } finally {
            peerSrv.stop()
        }
    }

    @Test
    fun tlsRechazaClienteSinCA() = runBlocking {
        if (!opensslDisponible()) return@runBlocking
        val (cert, key) = generarCert()
        val port = freePort()
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = port,
            sslContext = serverCtx(cert, key))
        val peerSrv = Peer(srv, heartbeatMs = 0)
        peerSrv.start()
        try {
            // Contexto por defecto: NO confía en el cert autofirmado.
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, null, null)
            val cli = WiFiClient("127.0.0.1", TOKEN, port = port,
                reconnect = false, sslContext = ctx)
            val peerCli = Peer(cli, heartbeatMs = 0)
            var excepcion: Throwable? = null
            try {
                peerCli.start(timeoutMs = 2_000)
            } catch (e: Throwable) {
                excepcion = e
            }
            assertTrue(excepcion != null)
            assertTrue(!cli.isConnected)
        } finally {
            peerSrv.stop()
        }
    }

    @Test
    fun serverRechazaLanSinTls() {
        assertFailsWith<IllegalArgumentException> {
            WiFiServer(TOKEN, host = "0.0.0.0", port = 8888)
        }
    }

    @Test
    fun clientRechazaLanSinTls() {
        assertFailsWith<IllegalArgumentException> {
            WiFiClient("192.168.1.1", TOKEN, port = 8888)
        }
    }

    @Test
    fun serverLoopbackSinTlsPermitido() {
        val srv = WiFiServer(TOKEN, host = "127.0.0.1", port = 8888)
        assertEquals(null, srv.sslContext)
    }

    @Test
    fun serverLanSinTlsConOverride() {
        val srv = WiFiServer(TOKEN, host = "0.0.0.0", port = 8888,
            allowInsecureLan = true)
        assertEquals(null, srv.sslContext)
    }
}
