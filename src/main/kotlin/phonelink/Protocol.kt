package phonelink

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

// Constantes idénticas a phonelink/protocol.py (protocolo v2).
const val PROTOCOL_VERSION = 2
const val HEADER_SIZE = 4
const val MAX_PAYLOAD = 1 * 1024 * 1024
const val CONTROL_MAX = 64 * 1024
const val HANDSHAKE_MAX = 4 * 1024
const val NONCE_SIZE = 32
const val DEFAULT_IDLE_TIMEOUT_MS = 60_000L
const val READ_CHUNK = 16 * 1024
const val MAX_JSON_DEPTH = 64
const val MAX_INT_DIGITS = 100
const val MAX_JSON_KEYS = 10_000
const val DEFAULT_PORT = 8888
const val MIN_TOKEN_LEN = 16

// ---------------------------------------------------------------- Excepciones
open class PhoneLinkException(message: String, cause: Throwable? = null) : Exception(message, cause)
class ProtocolException(message: String, cause: Throwable? = null) : PhoneLinkException(message, cause)
open class LinkConnectionException(message: String, cause: Throwable? = null) : PhoneLinkException(message, cause)
class AuthRejectedException(val reason: String) : LinkConnectionException("Auth rechazada: $reason")
class TransientAuthException(val reason: String) : LinkConnectionException("Auth temporalmente rechazada: $reason")

object Reasons {
    const val AUTH_FAILED = "auth_failed"
    const val PROTOCOL_VERSION_MISMATCH = "protocol_version_mismatch"
    const val RATE_LIMITED = "rate_limited"
    const val REVOKED = "revoked"
    const val SERVER_ERROR = "server_error"
    val TRANSIENT = setOf(RATE_LIMITED, SERVER_ERROR)
}

// ------------------------------------------------------- Framing y validación
/** Formato en el cable: [4 bytes big-endian = N][N bytes JSON UTF-8]. */
object Protocol {
    private val NUMBER_RE = Regex("""^-?\d+(\.\d+)?([eE][+-]?\d+)?$""")

    fun encode(obj: JsonElement, maxPayload: Int = MAX_PAYLOAD): ByteArray {
        checkPrimitives(obj, 0)
        val data = obj.toString().toByteArray(Charsets.UTF_8) // compacto, sin espacios
        if (data.size > maxPayload) throw ProtocolException("Payload demasiado grande: ${data.size} bytes")
        return ByteBuffer.allocate(HEADER_SIZE + data.size).putInt(data.size).put(data).array()
    }

    fun decode(payload: ByteArray): JsonElement {
        val text = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(payload)).toString()
        } catch (e: CharacterCodingException) {
            throw ProtocolException("UTF-8 inválido", e)
        }
        prevalidate(text)
        val el = try {
            Json.parseToJsonElement(text)
        } catch (e: SerializationException) {
            throw ProtocolException("JSON inválido: ${e.message}", e)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException("JSON inválido: ${e.message}", e)
        }
        checkPrimitives(el, 0)
        return el
    }

    /** Profundidad, enteros gigantes y número de claves, antes de parsear (C4/C11/M10 de Python). */
    internal fun prevalidate(text: String) {
        var inString = false
        var escape = false
        var digitRun = 0
        var depth = 0
        var colons = 0
        for (ch in text) {
            if (inString) {
                if (escape) escape = false
                else if (ch == '\\') escape = true
                else if (ch == '"') inString = false
                continue
            }
            when {
                ch == '"' -> { inString = true; digitRun = 0 }
                ch == '{' || ch == '[' -> {
                    depth++
                    if (depth > MAX_JSON_DEPTH) throw ProtocolException("JSON demasiado profundo")
                    digitRun = 0
                }
                ch == '}' || ch == ']' -> {
                    depth--
                    if (depth < 0) throw ProtocolException("JSON mal formado: cierre inesperado")
                    digitRun = 0
                }
                ch == ':' -> {
                    colons++
                    if (colons > MAX_JSON_KEYS) throw ProtocolException("Demasiadas claves")
                    digitRun = 0
                }
                ch in '0'..'9' || (ch == '-' && digitRun == 0) -> {
                    digitRun++
                    if (digitRun > MAX_INT_DIGITS) throw ProtocolException("Entero demasiado largo")
                }
                else -> digitRun = 0
            }
        }
        if (depth != 0) throw ProtocolException("JSON mal formado: brackets desbalanceados")
    }

    /** Rechaza NaN/Infinity y literales no JSON (Python usa allow_nan=False). */
    private fun checkPrimitives(e: JsonElement, depth: Int) {
        if (depth > MAX_JSON_DEPTH) throw ProtocolException("JSON demasiado profundo")
        when (e) {
            is JsonPrimitive -> if (!e.isString) {
                val c = e.content
                if (c != "true" && c != "false" && c != "null" && !NUMBER_RE.matches(c)) {
                    throw ProtocolException("Literal JSON no permitido: $c")
                }
            }
            is JsonObject -> e.values.forEach { checkPrimitives(it, depth + 1) }
            is JsonArray -> e.forEach { checkPrimitives(it, depth + 1) }
        }
    }
}