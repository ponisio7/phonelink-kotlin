package phonelink

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.nio.file.Path
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

object Auth {
    fun computeMac(token: String, nonce: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(token.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(nonce)
    }
    fun macHex(token: String, nonce: ByteArray): String = computeMac(token, nonce).toHex()
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)
    fun generateToken(nbytes: Int = 32): String {
        require(nbytes >= MIN_TOKEN_LEN) { "nbytes debe ser >= $MIN_TOKEN_LEN" }
        val b = ByteArray(nbytes)
        SecureRandom().nextBytes(b)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    }
}
fun generateToken(nbytes: Int = 32): String = Auth.generateToken(nbytes)
private val HEX = "0123456789abcdef".toCharArray()
internal fun ByteArray.toHex(): String {
    val out = CharArray(size * 2)
    for (i in indices) {
        val v = this[i].toInt() and 0xFF
        out[i * 2] = HEX[v ushr 4]
        out[i * 2 + 1] = HEX[v and 0x0F]
    }
    return String(out)
}
internal fun String.hexToBytesOrNull(): ByteArray? {
    if (length % 2 != 0) return null
    val out = ByteArray(length / 2)
    for (i in out.indices) {
        val hi = Character.digit(this[i * 2], 16)
        val lo = Character.digit(this[i * 2 + 1], 16)
        if (hi < 0 || lo < 0) return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}
object Tls {
    fun trustCertificate(pem: InputStream): SSLContext {
        val certs = CertificateFactory.getInstance("X.509").generateCertificates(pem)
        require(certs.isNotEmpty()) { "El PEM no contiene certificados" }
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            certs.forEachIndexed { i, c -> setCertificateEntry("phonelink-$i", c) }
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
        return SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, SecureRandom()) }
    }
    fun trustCertificate(pem: File): SSLContext = pem.inputStream().use { trustCertificate(it) }
    fun trustCertificate(pem: Path): SSLContext = trustCertificate(pem.toFile())
    fun trustCertificate(pemBytes: ByteArray): SSLContext = trustCertificate(ByteArrayInputStream(pemBytes))
    fun serverContext(pkcs12: InputStream, password: CharArray): SSLContext {
        val ks = KeyStore.getInstance("PKCS12").apply { load(pkcs12, password) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, password) }
        return SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, SecureRandom()) }
    }
    fun serverContext(pkcs12: File, password: CharArray): SSLContext = pkcs12.inputStream().use { serverContext(it, password) }
    fun serverContext(pkcs12: Path, password: CharArray): SSLContext = serverContext(pkcs12.toFile(), password)
    fun serverContextFromP12(pkcs12: InputStream, password: CharArray): SSLContext = serverContext(pkcs12, password)
    fun serverContextFromP12(pkcs12: File, password: CharArray): SSLContext = serverContext(pkcs12, password)
    fun serverContextFromP12(pkcs12: Path, password: CharArray): SSLContext = serverContext(pkcs12, password)
    fun serverContext(certPem: InputStream, keyPem: InputStream): SSLContext {
        val certs = CertificateFactory.getInstance("X.509").generateCertificates(certPem)
        require(certs.isNotEmpty()) { "El PEM de cert no contiene certificados" }
        val privateKey = loadPrivateKey(keyPem)
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry("phonelink-server", privateKey, CharArray(0), certs.toTypedArray())
        }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, CharArray(0)) }
        return SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, SecureRandom()) }
    }
    fun serverContext(certFile: File, keyFile: File): SSLContext =
        certFile.inputStream().use { cIn -> keyFile.inputStream().use { kIn -> serverContext(cIn, kIn) } }
    fun serverContext(certPath: Path, keyPath: Path): SSLContext = serverContext(certPath.toFile(), keyPath.toFile())
    private fun loadPrivateKey(pemStream: InputStream): PrivateKey {
        val pemText = pemStream.bufferedReader().readText()
        val base64 = pemText
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replace("-----BEGIN EC PRIVATE KEY-----", "")
            .replace("-----END EC PRIVATE KEY-----", "")
            .replace(Regex("\\s"), "")   // FIX: una sola vez, doble backslash
        val der = Base64.getDecoder().decode(base64)
        val factories = listOf("RSA", "EC", "DSA")
        for (alg in factories) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(PKCS8EncodedKeySpec(der))
            } catch (_: Exception) {}
        }
        if ("RSA PRIVATE KEY" in pemText) {
            throw IllegalArgumentException(
                "Clave RSA PKCS#1 no soportada directamente. Convierte a PKCS#8: openssl pkcs8 -topk8 -nocrypt -in server.key -out server-pkcs8.key"
            )
        }
        throw IllegalArgumentException("No se pudo parsear la clave privada PEM (soportado PKCS#8)")
    }
}
data class Message(val type: String, val payload: JsonObject, val raw: JsonObject) {
    fun text(key: String): String? = payload.str(key)

    /** Paridad con Python Message.get(key, default=None):
     *  - payload[key] si existe
     *  - "type" -> type
     *  - "payload" -> payload
     *  - raw[key] si existe
     *  - default
     */
    fun get(key: String, default: JsonElement? = null): JsonElement? = when {
        key in payload -> payload[key]
        key == "type" -> JsonPrimitive(type)
        key == "payload" -> payload
        key in raw -> raw[key]
        else -> default
    }

    operator fun get(key: String): JsonElement? = get(key, null)
    operator fun contains(key: String): Boolean = key in payload || key in raw
    fun getString(key: String, default: String? = null): String? =
        (payload[key] as? JsonPrimitive)?.content
            ?: (raw[key] as? JsonPrimitive)?.content
            ?: default
    fun payloadContains(key: String): Boolean = key in payload
}
fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
fun toJson(v: Any?): JsonElement = when (v) {
    null -> JsonNull
    is JsonElement -> v
    is String -> JsonPrimitive(v)
    is Boolean -> JsonPrimitive(v)
    is Number -> JsonPrimitive(v)
    is Map<*, *> -> JsonObject(v.entries.associate { (k, x) -> k.toString() to toJson(x) })
    is Iterable<*> -> JsonArray(v.map { toJson(it) })
    is Array<*> -> JsonArray(v.map { toJson(it) })
    else -> JsonPrimitive(v.toString())
}
fun payloadOf(vararg pairs: Pair<String, Any?>): JsonObject =
    JsonObject(pairs.associate { it.first to toJson(it.second) })
interface TransportListener {
    suspend fun onMessage(msg: JsonObject)
    suspend fun onConnect()
    suspend fun onDisconnect()
}
interface Transport {
    fun setListener(listener: TransportListener?)
    suspend fun start(timeoutMs: Long? = null)
    suspend fun send(obj: JsonObject)
    suspend fun disconnect()
    suspend fun stop()
    val isConnected: Boolean
    val lastRxNanos: Long?
}
object PhoneLinkLog {
    @Volatile var sink: ((String) -> Unit)? = null
    fun setLogSink(fn: ((String) -> Unit)?) { sink = fn }
    fun getLogSink(): ((String) -> Unit)? = sink
}
fun setLogSink(fn: ((String) -> Unit)?) = PhoneLinkLog.setLogSink(fn)
fun getLogSink(): ((String) -> Unit)? = PhoneLinkLog.getLogSink()
internal fun plog(msg: String) {
    try { PhoneLinkLog.sink?.invoke(msg) } catch (_: Throwable) {}
}
private val LOOPBACK_V4 = Regex("^127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
internal fun isLoopback(host: String): Boolean {
    if (host.isBlank()) return false
    val h = host.lowercase()
    return h == "localhost" || h == "::1" || h == "[::1]" || LOOPBACK_V4.matches(h)
}
internal fun validateReason(reason: Any?): String =
    if (reason is String && reason.isNotEmpty() && reason.length < 256 && Regex("^[a-zA-Z0-9_.-]+$").matches(reason)) reason else "unknown"

/**
 * [PARIDAD v0.6] Helpers top-level equivalentes a protocol.py de Python.
 */
internal suspend fun writeMessage(stream: MessageStream, obj: JsonElement) {
    stream.send(obj)
}
internal fun closeQuietly(stream: MessageStream) {
    stream.close()
}