
# PROTOCOL_SPEC.md - Fuente de verdad phonelink v2 (Python + Kotlin)

> Regla: Paridad = union de capacidades. Si una tiene algo, se le anade a la otra.

## 1. Framing
- Formato cable: [4 bytes BE uint32 N][N bytes JSON UTF-8]
- `HEADER_SIZE=4`, `MAX_PAYLOAD=1 MiB` (configurable), `HANDSHAKE_MAX=4 KiB`, `CONTROL_MAX=64 KiB`
- `READ_CHUNK=16 KiB`, `DEFAULT_IDLE_TIMEOUT=60s`, `NONCE_SIZE=32 bytes`, `PROTOCOL_VERSION=2`

## 2. JSON hardening (C4/C11/M10)
- Pre-validacion antes de `json.loads`/`Json.parse`:
  - `MAX_JSON_DEPTH=64`
  - `MAX_INT_DIGITS=100`
  - `MAX_JSON_KEYS=10_000`
  - Rechazo de `NaN/Infinity` (`allow_nan=False` en Python, `checkPrimitives` en Kotlin)
  - UTF-8 estricto
- Implementado en `protocol.py::_prevalidate_json_payload` y `Protocol.prevalidate`

## 3. Handshake v2 challenge-response (token nunca en claro)
```
C -> S: {"type":"hello","protocol_version":2}
S -> C: {"type":"challenge","nonce": hex(32 bytes), "protocol_version":2}
C -> S: {"type":"auth","mac": HMAC-SHA256(token utf8, nonce) hex}
S -> C: {"type":"auth_ok","protocol_version":2} | {"type":"error","reason": "..."}
```
- Validaciones: nonce hex 64 chars -> 32 bytes, mac hex 64 chars -> 32 bytes, `constantTimeEquals`
- `token_provider` puede fallar -> `server_error` transitorio, no cuenta para rate limit
- `protocol_version_mismatch` NO cuenta para rate limit (A7)
- Razones: `auth_failed`, `protocol_version_mismatch`, `rate_limited`, `revoked`, `replaced`, `server_error`
- Terminal: `auth_failed`, `protocol_version_mismatch`, `revoked` -> `AuthRejected`
- Transitorio: `rate_limited`, `server_error` -> `TransientAuthError`

## 4. TLS
- TLS 1.2+ obligatorio fuera de loopback
- Cliente: `verify_mode=CERT_REQUIRED` + `check_hostname=True` fuera de loopback salvo `allow_insecure_tls=true` (Python) / `allowInsecureTls=true` + `verifyHostname=false` (Kotlin)
- `allow_insecure_lan=true` permite loopback sin TLS (warning)
- Helpers:
  - Python: `trust_certificate(pem_path)`, `server_context(cert,key)`, `server_context_from_p12(p12, pwd)`
  - Kotlin: `Tls.trustCertificate(InputStream|File|Path|ByteArray)`, `Tls.serverContext(cert,key)`, `Tls.serverContext(p12, pwd)`, `serverContextFromP12` alias
- `_check_tls_context` / `checkTlsContext`: rechaza SSLv3/TLS1.0/TLS1.1 explicitos, exige ciphers en server

## 5. Rate limiting
- Ventana `rate_window=60s`, `max_failures=5`, `block_seconds=300s`, `max_tracked_ips=10_000`
- Eviccion LRU que NO desbloquea atacantes: si todas las IPs estan bloqueadas, no se evicta, se loggea warning
- `FailureLimiter` (Kotlin) y `_RateLimiter` (Python) identicos

## 6. Transportes
- `Transport` contrato: `start(timeout?)`, `send(obj)`, `disconnect()`, `stop()`, `is_connected`/`isConnected`, `last_rx_time`/`lastRxNanos`
- `WiFiServer`:
  - Params: `token`, `host=127.0.0.1`, `port=8888`, `service_name`, `ssl_context`, `allow_insecure_lan`, `token_provider`, `require_strong_token`, `rate_limit`, `enable_zeroconf`, `zeroconf` (Kotlin inyectable), `max_payload`, `handshake_timeout`, `send_timeout`, `revoke_timeout`, `stop_timeout` (nuevo en Python), `idle_timeout`, `max_preauth_connections`, `max_handshakes`, `handshake_sem_timeout`, `preauth_sem_timeout`, `auth_fail_delay`, `rate_*`
  - Un solo cliente activo: nuevo reemplaza anterior con `replaced`
  - `set_token(token, disconnect_current=False, update_provider=False)`: si hay provider, exige flag
  - `bound_port`/`boundPort`: puerto real tras `start()` con `port=0`
  - Zeroconf: `_phonelink._tcp.local.` con `token_required=1`
- `WiFiClient`:
  - Params: `host`, `token`, `port`, `reconnect`, `max_backoff`, `connect_timeout`, `ssl_context`, `allow_insecure_lan`, `verify_hostname` (nuevo en Python), `allow_insecure_tls`, `min_stable_seconds`, `max_payload`, `handshake_timeout`, `send_timeout`, `idle_timeout`, `stop_timeout`, `on_auth_error`, `on_session_terminated`
  - Reconexion con backoff exponencial, reset tras `min_stable`
  - `replaced`/`revoked` del server -> termina sin reintentar, dispara `on_session_terminated`

## 7. Peer (alto nivel)
- `on(event, handler)`, `on_any(handler)`, `send(event, payload|kwargs|pairs)`, `start(timeout?)`, `stop()`
- Validacion `event`: regex `^[A-Za-z0-9._-]+$`, `MAX_EVENT_NAME=256`, reservados `ping/pong/replaced/revoked`
- `Message`: `type`, `payload: JsonObject/dict`, `raw`, `text(key)`, `get`, `contains`, `get(key, default)` (nuevo Kotlin)
- `connected`: Python `bool` + `wait_connected/disconnected`, Kotlin `StateFlow<Boolean>` + `waitConnected/waitDisconnected` + `is_connected()` alias
- Heartbeat: envia `ping` cada `heartbeat`, espera `pong` o `last_rx` o `last_seen`. Si `now - last_activity > heartbeat*timeout_factor`, cierra
- `last_seen`/`last_pong` = None hasta actividad real (M5)
- `max_pending_handlers` por evento (Kotlin) + global (Python + nuevo Kotlin `maxPendingHandlersGlobal`)
- `on_handler_error`/`onHandlerError`: soporta sync y async (Python ya, Kotlin nuevo sync)

## 8. Logging
- `set_log_sink(fn)` / `get_log_sink()` / `PhoneLinkLog.sink`, `plog(msg)` blindado con try/catch

## 9. Excepciones
```
PhoneLinkError (Python) / PhoneLinkException (Kotlin) : ConnectionError
  ProtocolError / ProtocolException
  LinkConnectionError / LinkConnectionException
    AuthRejected (reason) / AuthRejectedException
    TransientAuthError (reason) / TransientAuthException
```

## 10. Seguridad checklist (tests hardening)
- token nunca viaja en claro (captura trafico)
- tokenProvider roto -> server_error, no banea IP
- cipher info / TLS minimo 1.2
- onConnect que explota no rompe server
- setToken x2 + stop espera revoke_tasks
- rate limit eviccion segura
- max_payload, idle_timeout, handshake timeout configurables
- TCP_NODELAY y SO_REUSEADDR

## 11. Interop
- Python server <-> Kotlin client y viceversa en CI
- `InteropTest.kt` y `test_parity_kotlin.py` deben pasar
- Matriz de paridad automatica en CI
