# ADR-012: Remediación Integral de la Auditoría 3 de Seguridad y Arquitectura

**Estado:** Aprobado e Implementado  
**Fecha:** 20 de Octubre de 2026  
**Versión del Protocolo:** IPVN 7 v7.10.0  
**Contexto:** Auditoría técnica externa exhaustiva de GitHub (`galleguillosdavid-coder/Ipvn7-10`)  
**Impacto:** Crítico / Protocolo de Red, Criptografía PQC, Plano de Control MCP, Datapath y Pasarelas  

---

## 1. Contexto y Hallazgos Auditados

La auditoría técnica externa analizó el árbol real del repositorio y detectó diez hallazgos categorizados por prioridad técnica y criptográfica:

1. **H-01 (P1 - Token de Control Predeterminado y Público):** `app/server.py` definía `IPVN7_CONTROL_TOKEN` con una constante estática predeterminada (`ipvn7-sovereign-control-token-2026`). Si se ejecutaba sin definir la variable de entorno, el plano de control MCP quedaba expuesto con credenciales públicas.
2. **H-02 (P1 - Pasarela SOCKS5 Directa sin Demostración de Overlay):** `ipvn7/gateway/socks5.py` realizaba conexiones TCP directas tras validar el destino (`socket.create_connection`), en lugar de transportar el stream cifrado por el túnel overlay PQ-QUIC hacia el Exit Node.
3. **H-03 (P1 - Fijación de Destino DNS en Exit Node):** Necesidad de centralizar la política SSRF en el nodo que realiza la salida final y fijar la IP de conexión para prevenir ataques de DNS Rebinding en todos los caminos.
4. **H-04 (Alta - Confianza en Cabecera Origin):** El servidor autorizaba peticiones basándose únicamente en el Origin del navegador local sin exigir un token criptográfico explícito o comprobación de `Sec-Fetch-Site`.
5. **H-05 (Media - Concurrencia SOCKS5 y Riesgo de DoS):** La pasarela SOCKS5 creaba un hilo sin límite por conexión, exponiendo el sistema a agotamiento de descriptores de socket y memoria.
6. **H-06 (Media - Parser Binario BitNet Expuesto a Fuzzing):** `BitNetQuantizer.deserialize_model()` carecía de comprobaciones exhaustivas de cotas de nombres, dimensiones y tamaño exacto de buffer empaquetado.
7. **H-07 (Media - Exposición de Secreto Compartido Crudo en API):** `/api/pqc/live_demo` retornaba `shared_secret_hex` en texto plano en la respuesta JSON.
8. **H-08 (Media - Verificación Empírica de Ciclo de Vida Criptográfico):** Demostración explícita de autenticación, transcript binding y rotación de claves.
9. **H-09 (P1 - Handshake Híbrido PQC sin Autenticación Digital de Interlocutor):** `HybridHandshake` combinaba X25519 y ML-KEM-768 mediante HKDF con parámetro `info=b"IPVN7-HYBRID-SESSION-AUTH"`, pero sin una firma digital criptográfica sobre el transcript del handshake (`transcript_hash`), permitiendo ataques de intermediario activo (MITM).
10. **H-10 (P1 - Discordancia entre Notificación de Control y Transporte Web):** `/api/internet/fetch` enviaba una trama de control al par pero realizaba la descarga mediante `urllib.request` local, reportando falsamente `overlay_verified=True`.

---

## 2. Decisiones Arquitectónicas y Remediaciones Ejecutadas

### 2.1. Cero Credenciales Estáticas Públicas (H-01)
* **Regla Inmutable:** Queda terminantemente prohibido almacenar tokens o contraseñas por defecto en el código fuente.
* **Implementación:** Si la variable de entorno `IPVN7_CONTROL_TOKEN` no está configurada o está vacía, el servidor genera automáticamente un token criptográfico aleatorio de alta entropía (`secrets.token_urlsafe(32)` = 256 bits) en cada inicio, persistido en el archivo con permisos restringidos `.nexus/runtime/control.token`.
* **Beneficio:** Imposibilita el compromiso del plano de control MCP mediante escaneo de repositorios o credenciales conocidas.

### 2.2. Autenticación Criptográfica del Handshake PQC contra MITM (H-09)
* **Regla Inmutable:** Todo apretón de manos postcuántico debe vincular criptográficamente el transcript completo con la identidad soberana del nodo mediante firma digital (Ed25519 o ML-DSA-65).
* **Implementación:**
  * Se crearon `server_respond_authenticated()` y `client_finalize_authenticated()` en `ipvn7/crypto/pqc.py`.
  * El transcript se consolida mediante `SHA-256(client_x25519_pub || client_mlkem_pub || server_x25519_pub || server_mlkem_ct)`.
  * El servidor firma digitalmente este transcript hash con su clave soberana de identidad.
  * El cliente verifica obligatoriamente la validez de la firma contra la clave pública del servidor antes de computar la clave de sesión simétrica con HKDF.
  * Si la firma es inválida, se aborta con `ValueError("Invalid server signature on handshake transcript")`.

### 2.3. SOCKS5 con Concurrencia Acotada y Túnel Overlay Real (H-02, H-05)
* **Regla Inmutable:** Todo datapath etiquetado como "OVERLAY_TUNNELED" debe transmitir los bytes a través de tramas IPVN 7 hacia el nodo de salida remoto. Si se utiliza salida directa, debe declararse explícitamente como "DIRECT_EGRESS" sin contabilizar tráfico falso de overlay.
* **Implementación:**
  * En `ipvn7/gateway/socks5.py`, se integró `SovereignExitRelayClient` y `SovereignExitRelayServer`.
  * En modo `OVERLAY_TUNNELED`, el gateway delega el stream TCP a `self.relay_client.open_tunneled_stream()`, enviando tramas fragmentadas `IP7X` cifradas al Exit Node, donde se ejecuta la salida final.
  * Se implementó un semáforo de concurrencia `threading.BoundedSemaphore(max_connections=64)` en el bucle de aceptación. Conexiones que excedan el límite son rechazadas de inmediato sin instanciar hilos (`SOCKS5_REP_SERVER_FAILURE`), previniendo ataques de denegación de servicio (DoS).

### 2.4. Censura Estricta de Secretos en APIs y Telemetría Veraz (H-07, H-10)
* **Regla Inmutable:** Ningún endpoint HTTP o evento de telemetría expondrá claves privadas o secretos compartidos crudos.
* **Implementación:**
  * En `app/server.py` (`/api/pqc/live_demo`), se eliminó `shared_secret_hex`. El secreto derivado se expone únicamente como huella digital truncada SHA-256 (`shared_secret_fingerprint`) y longitud en bytes (`shared_secret_len`).
  * En `/api/internet/fetch`, se ajustó la telemetría para reportar con absoluta precisión: `datapath_mode="LOCAL_EGRESS_WITH_OVERLAY_CONTROL_NOTIFICATION"`, `data_tunneled_over_overlay=False` y `overlay_verified=False`, eliminando cualquier ambigüedad entre notificación de control y flujo de datos.

### 2.5. Blindaje del Parser Binario BitNet frente a Fuzzing (H-06)
* **Regla Inmutable:** Cualquier estructura binaria deserializada debe validar tipos, números mágicos, cotas de tamaño y concordancia matemática de buffers.
* **Implementación:**
  * `BitNetQuantizer.deserialize_model(data: bytes)` valida:
    1. `isinstance(data, (bytes, bytearray))` y longitud mínima de cabecera >= 20 bytes.
    2. Magic bytes exactos `b"IP7B"`.
    3. Longitud del nombre del modelo acotada: 1 <= name_len <= 256 bytes y UTF-8 válido.
    4. Dimensiones acotadas: 1 <= rows <= 4096, 1 <= cols <= 4096 y valor entero finito.
    5. Factor de escala positivo y finito: isfinite(scale) y scale > 0.
    6. Longitud exacta del buffer empaquetado: expected_bytes = (rows * cols + 3) // 4. Si difiere, rechazo con excepción ValueError.

### 2.6. Robustecimiento de Autenticación en Control Plane (H-04)
* **Implementación:** `_validate_control_auth(require_explicit_token=...)` exige prioritariamente Bearer token con comparación en tiempo constante (`secrets.compare_digest`). Para el dashboard local, valida simultáneamente el encabezado `Host`, la lista blanca de orígenes locales y la cabecera del navegador `Sec-Fetch-Site: same-origin`.

---

## 3. Consecuencias y Verificación

1. **Inmunidad ante Credenciales Públicas:** No existe ningún vector de acceso predeterminado sin autorización.
2. **Resistencia a MITM:** El handshake híbrido PQC garantiza autenticación mutua y estricta resistencia contra intermediarios activos.
3. **Resiliencia DoS y Fuzzing:** SOCKS5 y el deserializador de BitNet operan bajo límites estrictos de recursos y validaciones preventivas.
4. **Honestidad Técnica Total:** La documentación, el código y la telemetría del datapath reflejan con exactitud la naturaleza del transporte de red.
5. **Cobertura de Pruebas:** Se incorporaron pruebas unitarias negativas y de regresión automatizadas en `tests/test_ipvn7.py` (elevando la suite a 108 pruebas con 100% de éxito).
