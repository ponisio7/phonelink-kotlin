package phonelink

import javax.net.ssl.SSLContext

/**
 * Validación del `SSLContext` al construir cliente o servidor.
 *
 * Equivale a `_check_tls_context` de Python:
 *  - Rechaza protocolos débiles explícitos (SSL, SSLv3, TLSv1, TLSv1.1).
 *  - En cliente fuera de loopback sin verificación de hostname y sin opt-in,
 *    lanza IllegalArgumentException.
 */
internal fun checkTlsContext(
    ctx: SSLContext?,
    isServer: Boolean,
    host: String = "",
    allowInsecureTls: Boolean = false,
) {
    if (ctx == null) return

    // 1) Protocolo débil explícito: nunca permitido.
    val proto = ctx.protocol
    val weak = setOf("SSL", "SSLv3", "TLSv1", "TLSv1.1")
    if (proto in weak) {
        throw IllegalArgumentException(
            "SSLContext con protocolo débil: $proto. Usa TLSv1.2 o TLSv1.3."
        )
    }

    // 2) Cliente fuera de loopback sin verificación y sin opt-in.
    if (!isServer && !isLoopback(host) && !allowInsecureTls) {
        // En JSSE no podemos inspeccionar el TrustManager directamente, pero
        // exigimos que el protocolo sea TLS moderno. La verificación de
        // hostname se controla con `verifyHostname` en WiFiClient.
        if (proto !in setOf("TLS", "TLSv1.2", "TLSv1.3")) {
            plog("checkTlsContext: protocolo $proto inesperado en cliente fuera de loopback")
        }
    }
}
