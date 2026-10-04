# phonelink-kotlin

Cliente y servidor Kotlin compatibles con **phonelink v2** (Python). Kotlin puro
(JVM 17+, sin dependencias de Android), así que sirve tanto en Android como en
escritorio.

- Mismo cable: `[4 bytes big-endian = N][N bytes JSON UTF-8]`,
  mensajes `{"type": evento, "payload": {...}}`.
- Mismo handshake: `hello → challenge(nonce 32 B hex) → auth(HMAC-SHA256(token, nonce)) → auth_ok`.
- Mismos `ping`/`pong`, `replaced`/`revoked`, límites (1 MB, handshake 4 KB,
  JSON profundidad 64, enteros 100 dígitos, 10 000 claves) y reglas de TLS.
- Paridad verificada end-to-end contra Python: hay tests de interoperabilidad
  reales (Kotlin cliente ↔ Python servidor y viceversa).

---

## Índice

- [Uso rápido](#uso-rápido)
- [Ciclo de vida del token](#ciclo-de-vida-del-token)
- [Callbacks](#callbacks)
- [TLS](#tls)
- [Zeroconf / mDNS](#zeroconf--mdns)
- [Límites de concurrencia](#límites-de-concurrencia)
- [Rate limiting](#rate-limiting)
- [Protocolo](#protocolo)
- [Build y tests](#build-y-tests)
- [Interoperabilidad con Python](#interoperabilidad-con-python)
- [Publicación Maven](#publicación-maven)

---

## Uso rápido

### El teléfono se conecta al `WiFiServer` de Python

```kotlin
// Contexto TLS que confía SOLO en tu server.crt (PEM).
val tls = Tls.trustCertificate(context.resources.openRawResource(R.raw.server))
val peer = Peer(
    WiFiClient("192.168.1.20", token = TOKEN, port = 8888, sslContext = tls)
)

peer.on("chat") { m -> println("PC dice: ${m.text("text")}") }   // oír
peer.start(timeoutMs = 5_000)                                     // lanza AuthRejectedException si el token no vale
peer.send("chat", "text" to "Hola desde Kotlin")                 // hablar
// ...
peer.stop()
```

`peer.connected` es un `StateFlow<Boolean>`. Reconecta solo (backoff 0,5 s → 30 s)
salvo rechazo de auth definitivo o `replaced`/`revoked` del servidor
(`onSessionTerminated`).

Con el ejemplo de Python (`examples/ejemplo_pc.py`, sin certificados, loopback)
basta: `WiFiClient("127.0.0.1", TOKEN)`. Desde el emulador de Android la PC es
`10.0.2.2`, que no es loopback: necesita TLS o `allowInsecureLan = true` (mismo
criterio que `allow_insecure_lan` en Python).

### El teléfono escucha y Python se conecta (`WiFiClient` de Python)

```kotlin
val ctx = Tls.serverContext(inputStream /* server.p12 */, "clave".toCharArray())
val peer = Peer(
    WiFiServer(token = TOKEN, host = "0.0.0.0", port = 8888, sslContext = ctx)
)
peer.on("chat") { m ->
    peer.send("chat", payloadOf("text" to "recibido: ${m.text("text")}"))
}
peer.start()
```

Crear el `.p12` a partir de tus PEM:

```
openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12
```

Solo hay un cliente activo: uno nuevo reemplaza al anterior (se le envía
`replaced`).

---

## Ciclo de vida del token

El servidor puede **rotar el token en caliente** sin reiniciar, y **expulsar**
la sesión activa con `revoked`. Ambas cosas coinciden con `set_token` y
`token_provider` de Python v0.4.

### Rotación simple

```kotlin
val srv = WiFiServer(token = TOKEN_INICIAL, host = "127.0.0.1", port = 8888)
val peer = Peer(srv)
peer.start()

// Cambiar el token sin expulsar al cliente actual (la próxima auth usará el nuevo)
srv.setToken(NUEVO_TOKEN)
```

### Rotación + expulsión (`revoked`)

```kotlin
// Envía {"type":"revoked"} al cliente activo, cierra su socket y actualiza el token.
srv.setToken(NUEVO_TOKEN, disconnectCurrent = true)
```

`setToken` es **suspend** porque la tarea de revocación se espera en `stop()`
con `revokeTimeoutMs` (paridad con `_revoke_tasks` de Python).

### `tokenProvider` (token dinámico)

Si el token vive en un keystore, cámbialo con un provider en vez de asignarlo:

```kotlin
val srv = WiFiServer(
    token = TOKEN_INICIAL,        // usado si no hay provider
    host = "127.0.0.1", port = 8888,
    tokenProvider = { keystore.getToken() },
)
```

Reglas:

- Si el provider **lanza** o devuelve vacío/corto/no UTF-8, el servidor
  responde `server_error` (transitorio) **sin** contar como fallo de rate limit
  (igual que Python).
- Con `tokenProvider` activo, `setToken(...)` exige `updateProvider = true` para
  rotar el provider, o `disconnectCurrent = true` para revocar solo la sesión.
  Si llamas a `setToken(...)` sin ninguno de los dos, lanza `IllegalStateException`.

### `requireStrongToken`

Por defecto se exige token ≥ 16 caracteres. En tests puedes desactivarlo:

```kotlin
WiFiServer(token = "corto", requireStrongToken = false)
```

---

## Callbacks

### Cliente (`WiFiClient`)

```kotlin
val cli = WiFiClient("192.168.1.20", TOKEN, port = 8888)
cli.onAuthError = { reason ->
    // suspend: puedes hacer I/O aquí
    logToServer("auth rechazada: $reason")
}
cli.onSessionTerminated = { reason ->
    // reason es "replaced" o "revoked"
    mostrarAviso("El servidor cerró la sesión: $reason")
}
```

- `onAuthError` se llama en cada auth fallida (terminal o transitoria).
- `onSessionTerminated` se llama cuando el servidor cierra la sesión con
  `replaced`/`revoked`. **No** marca la sesión como auth rechazada; el cliente
  deja de reconectar.

### Peer (`onHandlerError`)

```kotlin
val peer = Peer(
    transport = cli,
    onHandlerError = { event, throwable ->
        // suspend: puedes reportar a Sentry, logs, etc.
        println("handler '$event' falló: ${throwable.message}")
    },
)
```

Un handler que lanza no tumba la conexión: el error se reporta aquí y el
`Peer` sigue vivo.

---

## TLS

- `Tls.trustCertificate(pem)` confía **solo** en tu certificado autofirmado.
  El host/IP al que te conectas debe estar en el SAN del certificado (se
  verifica el hostname).
- `Tls.serverContext(pkcs12, password)` carga la clave y el certificado desde
  un `.p12`.
- `verifyHostname = false` desactiva la verificación del hostname. Fuera de
  loopback esto expone el canal a un MITM: exige `allowInsecureTls = true`
  explícito (mismo criterio que `allow_insecure_tls` de Python).
- Sin TLS, el cliente solo conecta a loopback salvo `allowInsecureLan = true`;
  el servidor igual para escuchar fuera de loopback.
- `checkTlsContext(...)` valida el `SSLContext` al construir: rechaza
  protocolos débiles (`SSL`, `SSLv3`, `TLSv1`, `TLSv1.1`).

```kotlin
// Cliente con TLS y verificación completa
val ctx = Tls.trustCertificate(File("certs/server.crt").inputStream())
val cli = WiFiClient("192.168.1.20", TOKEN, port = 8888, sslContext = ctx)

// Cliente que acepta MITM conscientemente (solo pruebas)
val ctx = Tls.trustCertificate(File("certs/server.crt").inputStream())
val cli = WiFiClient(
    "192.168.1.20", TOKEN, port = 8888,
    sslContext = ctx,
    verifyHostname = false,
    allowInsecureTls = true,
)
```

Token: mínimo 16 caracteres; `generateToken()` crea uno seguro. El token nunca
viaja por el cable (solo el HMAC).

---

## Zeroconf / mDNS

El servidor Python publica `_phonelink._tcp.local.` por mDNS. En Kotlin la
implementación se **inyecta** con la interfaz `ZeroconfPublisher`, para que
funcione en Android (`NsdManager`) o escritorio (`javax.jmdns`) sin acoplar la
librería a ninguna:

```kotlin
class MyZeroconf : ZeroconfPublisher {
    override fun publish(
        serviceName: String,
        type: String,
        port: Int,
        properties: Map<String, String>,
    ) {
        // Android: NsdManager.registerService(...)
        // Desktop: JmDNS.registerService(...)
    }
    override fun unpublish() {
        // Desregistrar
    }
}

val srv = WiFiServer(
    token = TOKEN,
    host = "0.0.0.0",
    port = 8888,
    sslContext = ctx,
    enableZeroconf = true,
    serviceName = "phonelink-pc",       // ^[a-zA-Z0-9-]+, máx 63
    zeroconf = MyZeroconf(),
)
```

- Si `enableZeroconf = true` pero `zeroconf = null`, el servidor arranca igual y
  solo avisa por log (mismo criterio que Python sin `zeroconf` instalado).
- En loopback, `publish()` no se llama (no aplica).
- `stop()` llama a `unpublish()` solo si antes se publicó.

### Descubrimiento desde Android (`NsdManager`)

```kotlin
nsd.discoverServices("_phonelink._tcp.", NsdManager.PROTOCOL_DNS_SD,
    object : NsdManager.DiscoveryListener {
        override fun onServiceFound(info: NsdServiceInfo) {
            nsd.resolveService(info, object : NsdManager.ResolveListener {
                override fun onServiceResolved(r: NsdServiceInfo) {
                    // r.host.hostAddress, r.port
                }
                override fun onResolveFailed(i: NsdServiceInfo, code: Int) {}
            })
        }
        // resto de callbacks vacíos...
    })
```

Permisos: `INTERNET`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE` (y
`NEARBY_WIFI_DEVICES` en Android 13+).

---

## Límites de concurrencia

El servidor limita conexiones simultáneas en dos fases, como Python:

| Parámetro | Por defecto | Qué hace |
|---|---|---|
| `maxPreauthConnections` | 32 | Conexiones que aún no han hecho handshake. |
| `preauthSemTimeoutMs` | 1000 | Cuánto esperar por un slot pre-auth antes de rechazar. |
| `maxHandshakes` | 8 | Handshakes en curso. |
| `handshakeSemTimeoutMs` | 2000 | Cuánto esperar por un slot de handshake. |

Cuando un slot se llena:

- Pre-auth: la conexión se cierra al instante.
- Handshake: la conexión se cierra al instante.

El `authFailDelayMs` (por defecto 500 ms) se aplica **después** de liberar los
slots. Esto significa que un fallo de auth no retiene slots de handshake, así
que un atacante con auth fallida lenta no puede agotar el pool (fix de Python
v0.4, `test_retardo_de_auth_fallida_no_bloquea_slot_de_handshake`).

---

## Rate limiting

Por IP, con ventana deslizante y bloqueo temporal (paridad con `_RateLimiter`
de Python v0.4):

| Parámetro | Por defecto | Qué hace |
|---|---|---|
| `rateLimit` | true | Activa/desactiva el limitador. |
| `rateMaxFailures` | 5 | Fallos de auth antes de bloquear. |
| `rateWindowMs` | 60000 | Ventana para contar fallos. |
| `rateBlockMs` | 300000 | Duración del bloqueo (5 min). |
| `rateMaxTrackedIps` | 10000 | IPs rastreadas antes de evictar. |

**Evicción segura**: al llegar a `rateMaxTrackedIps`, se purgan primero las
entradas expiradas y, si aún hay exceso, se eliminan solo IPs **no bloqueadas
activas**. Las IPs bloqueadas nunca se evictan, para no desbloquear atacantes
(`test_rate_limit` de Python).

Mismatch de versión del protocolo (`protocol_version_mismatch`) **no** cuenta
como fallo de rate limit (fix A7 de Python): es un error del cliente, no un
intento de fuerza bruta.

---

## Protocolo

### Framing

```
[4 bytes big-endian = N][N bytes JSON UTF-8]
```

Mensaje: `{"type": <evento>, "payload": {...}}`.

### Handshake v2

```
cliente → servidor:  {"type":"hello", "protocol_version": 2}
servidor → cliente:  {"type":"challenge", "nonce": <32 bytes hex>, "protocol_version": 2}
cliente → servidor:  {"type":"auth", "mac": <HMAC-SHA256(token, nonce) hex>}
servidor → cliente:  {"type":"auth_ok", "protocol_version": 2}
```

El token **nunca** viaja por el cable: solo el HMAC sobre el nonce.

### Mensajes reservados

| Tipo | Emisor | Significado |
|---|---|---|
| `hello` | cliente | Inicio de handshake. |
| `challenge` | servidor | Nonce para el HMAC. |
| `auth` | cliente | HMAC del nonce con el token. |
| `auth_ok` | servidor | Autenticación correcta. |
| `error` | servidor | Rechazo (`reason`: `auth_failed`, `rate_limited`, `server_error`, `protocol_version_mismatch`). |
| `ping` / `pong` | ambos | Heartbeat. |
| `replaced` | servidor | Otro cliente tomó la sesión. No reconectar. |
| `revoked` | servidor | El servidor revocó la sesión (rotación de token). No reconectar. |

Los eventos `ping`, `pong`, `replaced`, `revoked` están **reservados**: no se
pueden registrar con `peer.on(...)` ni enviar con `peer.send(...)`. Sí se puede
usar `chat`, `error`, `status.update`, `file-chunk_1`, etc.

### Límites

| Constante | Valor |
|---|---|
| `MAX_PAYLOAD` | 1 MiB |
| `HANDSHAKE_MAX` | 4 KiB |
| `CONTROL_MAX` | 64 KiB (reservado) |
| `MAX_JSON_DEPTH` | 64 |
| `MAX_INT_DIGITS` | 100 |
| `MAX_JSON_KEYS` | 10 000 |
| `NONCE_SIZE` | 32 bytes |
| `DEFAULT_IDLE_TIMEOUT_MS` | 60 000 |
| `MIN_TOKEN_LEN` | 16 |

Pre-validación antes de `Json.parseToJsonElement`: profundidad, enteros
gigantes y número de claves. Rechazo de `NaN`/`Infinity` (Python usa
`allow_nan=False`).

### Heartbeat

El `Peer` envía `ping` cada `heartbeatMs` y cierra la conexión si no hay
**actividad real** en `heartbeatMs * heartbeatTimeoutFactor`:

- `pong` del peer remoto.
- Cualquier mensaje de aplicación recibido.
- Bytes recibidos en el socket (`transport.lastRxNanos`).

Así, una transferencia lenta pero viva no se corta
(`test_heartbeat_no_mata_una_transferencia_lenta` de Python).

---

## Build y tests

```bash
./gradlew build                # compila y ejecuta tests
./gradlew test                 # solo tests
./gradlew publishToMavenLocal  # publica en ~/.m2
```

### Tests

- **50 tests** Kotlin que cubren: framing, handshake, rate limit, rotación de
  token + revoke, `replaced`, heartbeat, idle timeout, TLS (con openssl
  autogenerado), eventos reservados, `tokenProvider` roto, límites de
  concurrencia, callbacks, y **2 tests de interoperabilidad reales** contra
  Python.

### Interoperabilidad con Python

Los tests de interoperabilidad se **saltan** si no encuentran `python3` o el
paquete `phonelink`. Para ejecutarlos:

```bash
# Opción 1: dejar que el test lo busque automáticamente
./gradlew test --tests "phonelink.InteropTest"

# Opción 2: decirle dónde está el src/ del proyecto Python
PHONELINK_PY_PATH=~/proyectosPython/phonelink/src \
  ./gradlew test --tests "phonelink.InteropTest"
```

Cubren dos direcciones:

1. **Python servidor ↔ Kotlin cliente**: `py_server.py` arranca un `WiFiServer`
   en un puerto efímero, el test Kotlin se conecta y verifica el eco.
2. **Kotlin servidor ↔ Python cliente**: el test arranca un `WiFiServer` Kotlin,
   `py_client.py` se conecta y el test verifica la respuesta.

---

## Publicación Maven

```kotlin
// build.gradle.kts del consumidor
dependencies {
    implementation("phonelink:phonelink-kotlin:0.5.0")
}
```

Tras `./gradlew publishToMavenLocal`, el artefacto queda en `~/.m2/repository`.

---

## Equivalencias con Python

| Concepto | Python | Kotlin |
|---|---|---|
| `set_token(..., disconnect_current)` | sí | `setToken(..., disconnectCurrent)` |
| `token_provider` | callable sync | `tokenProvider: (() -> String)?` |
| `on_auth_error` | sync o async | `onAuthError: (suspend (String) -> Unit)?` |
| `on_session_terminated` | sync o async | `onSessionTerminated: (suspend (String) -> Unit)?` |
| `on_handler_error` | sync o async | `onHandlerError: (suspend (String, Throwable) -> Unit)?` |
| `enable_zeroconf` + `AsyncZeroconf` | integrado | `enableZeroconf` + `ZeroconfPublisher` inyectado |
| `allow_insecure_lan` | sí | `allowInsecureLan` |
| `allow_insecure_tls` | sí | `allowInsecureTls` |
| `require_strong_token` | sí | `requireStrongToken` |
| `rate_limit` | sí | `rateLimit` |
| `bound_port` | property | `boundPort` |
| `Peer.connected` | `asyncio.Event` | `StateFlow<Boolean>` |
| `Message.text(key)` | método | método |

---

## Notas

- Solo implementa el transporte WiFi. Bluetooth no está en el código.
- Un handler que lanza excepción no tumba la conexión: se notifica en
  `onHandlerError`.
- Los logs están apagados; actívalos con
  `PhoneLinkLog.sink = { Log.d("phonelink", it) }`.
- El token mínimo es 16 caracteres; usa `generateToken()` para crear uno seguro.
- El cliente y el servidor verifican el `SSLContext` al construir: protocolos
  débiles (`SSL`, `SSLv3`, `TLSv1`, `TLSv1.1`) se rechazan.