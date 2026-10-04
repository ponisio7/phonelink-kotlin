package phonelink

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ProtocolTest {

    @Test
    fun encodePrefijoLongitud() {
        val raw = Protocol.encode(JsonObject(mapOf("a" to JsonPrimitive(1))))
        assertTrue(raw.size > HEADER_SIZE)
        val n = ByteBuffer.wrap(raw, 0, HEADER_SIZE).int
        assertEquals(raw.size - HEADER_SIZE, n)
    }

    @Test
    fun encodePayloadDemasiadoGrande() {
        val grande = buildJsonObject {
            put("x", "a".repeat(MAX_PAYLOAD + 1))
        }
        assertFailsWith<ProtocolException> { Protocol.encode(grande) }
    }

    @Test
    fun decodeRoundtrip() {
        val original = JsonObject(mapOf("hola" to JsonPrimitive("mundo")))
        val raw = Protocol.encode(original)
        val payload = raw.copyOfRange(HEADER_SIZE, raw.size)
        assertEquals(original, Protocol.decode(payload))
    }

    @Test
    fun decodeJsonInvalido() {
        assertFailsWith<ProtocolException> { Protocol.decode("{no es json}".toByteArray()) }
    }

    @Test
    fun prevalidateProfundidadExcesiva() {
        val profundo = buildString {
            append("{")
            repeat(MAX_JSON_DEPTH + 1) { append("\"a\":{") }
            repeat(MAX_JSON_DEPTH + 1) { append("}") }
            append("}")
        }
        assertFailsWith<ProtocolException> { Protocol.prevalidate(profundo) }
    }

    @Test
    fun prevalidateEnteroGigante() {
        val grande = "{\"n\": ${"9".repeat(MAX_INT_DIGITS + 1)}}"
        assertFailsWith<ProtocolException> { Protocol.prevalidate(grande) }
    }

    @Test
    fun prevalidateDemasiadasClaves() {
        val muchas = buildString {
            append("{")
            repeat(MAX_JSON_KEYS + 1) { i -> append("\"k$i\":0,") }
            append("\"x\":0}")
        }
        assertFailsWith<ProtocolException> { Protocol.prevalidate(muchas) }
    }

    @Test
    fun decodeRechazaNaN() {
        val payload = "{\"x\": NaN}".toByteArray()
        assertFailsWith<ProtocolException> { Protocol.decode(payload) }
    }
}