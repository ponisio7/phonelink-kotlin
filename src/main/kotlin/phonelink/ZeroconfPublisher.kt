package phonelink

/**
 * Publicador de descubrimiento mDNS (zeroconf). El servidor Python publica
 * `_phonelink._tcp.local.` con la propiedad `{"token_required": "1"}` y da de
 * baja el servicio en `stop()`. Aquí la implementación se inyecta según la
 * plataforma:
 *
 *  - Android: wrapper sobre `NsdManager` (permisos INTERNET, ACCESS_WIFI_STATE,
 *    CHANGE_WIFI_MULTICAST_STATE y NEARBY_WIFI_DEVICES en Android 13+).
 *  - Desktop JVM: JmDNS (`javax.jmdns`), añadiendo la dependencia opcional.
 *
 * Si `enableZeroconf = true` pero no se pasa publisher, el servidor arranca
 * igual y solo avisa por el log (mismo criterio que Python sin `zeroconf`).
 */
interface ZeroconfPublisher {
    fun publish(
        serviceName: String,
        type: String,
        port: Int,
        properties: Map<String, String> = emptyMap(),
    )
    fun unpublish()
}

internal const val ZC_SERVICE_TYPE = "_phonelink._tcp.local."
private val SERVICE_NAME_RE = Regex("^[a-zA-Z0-9-]+$")
private const val MAX_SERVICE_NAME_LEN = 63

internal fun validateServiceName(name: String) {
    require(name.isNotEmpty()) { "serviceName debe ser no vacío" }
    require(name.length <= MAX_SERVICE_NAME_LEN) { "serviceName demasiado largo (máx $MAX_SERVICE_NAME_LEN)" }
    require(SERVICE_NAME_RE.matches(name)) { "serviceName solo puede contener letras, dígitos y guión" }
}