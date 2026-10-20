# LECCIONES APRENDIDAS (LESSONS LEARNED) — LAIA

**Versión:** 1.0  
**Ámbito:** IPVN 7  

---

### LL-001 — Prohibición Absoluta de Credenciales Estáticas en Código Fuente
- **Contexto:** `app/server.py` inicializaba `CONTROL_AUTH_TOKEN` con `"ipvn7-sovereign-control-token-2026"` si no existía la variable de entorno `IPVN7_CONTROL_TOKEN`.
- **Qué se esperaba:** Facilitar el desarrollo local sin necesidad de configurar variables de entorno.
- **Qué ocurrió realmente:** Cualquier instalación o escaneo público del repositorio conocía el token de control para ejecutar herramientas privilegiadas MCP.
- **Causa Raíz:** R5 (Autorización fragmentada) y R7 (Cierre prematuro con atajos de conveniencia).
- **Acción Correctiva:** Generación dinámica con `secrets.token_urlsafe(32)` en memoria y persistencia en `.nexus/runtime/control.token`.
- **Regla Creada:** `ER-SEC-001`.
- **Prueba de Regresión:** `test_mcp_control_plane_requires_auth_and_bearer_token` y validación estática de ausencia de strings conocidos.

---

### LL-002 — Falso Túnel Overlay en Pasarela SOCKS5
- **Contexto:** `ipvn7/gateway/socks5.py` aceptaba conexiones SOCKS5 y ejecutaba `socket.create_connection((target_ip, dest_port))` directo a la IP de Internet, pero la documentación y el dashboard lo contaban como tráfico cuántico tunelizado.
- **Qué se esperaba:** Enrutar el tráfico de aplicaciones a través del overlay cuántico.
- **Qué ocurrió realmente:** El tráfico salía directamente desde la máquina local sin cifrado overlay ni protección de Exit Node.
- **Causa Raíz:** R3 (Separación incompleta entre control y datos) y R10 (Documentación divergente de la realidad).
- **Acción Correctiva:** Integración con `SovereignExitRelayClient` para transportar el flujo por tramas `IP7X` al Exit Node en modo `OVERLAY_TUNNELED`, y telemetría honesta en modo directo.
- **Regla Creada:** `ER-SEC-006` y `ER-SEC-010`.
- **Prueba de Regresión:** `test_audit_3_h02_h05_socks5_concurrency_and_mode_accounting` y `test_sovereign_exit_relay_true_overlay_datapath`.

---

### LL-003 — SSRF y DNS Rebinding por Re-resolución de Dominio
- **Contexto:** El proxy validaba si el dominio era seguro, pero la función de conexión volvía a resolver el nombre mediante el DNS del sistema operativo.
- **Qué se esperaba:** Bloquear accesos a IPs locales y privadas.
- **Qué ocurrió realmente:** Un dominio con TTL de 0 segundos y servidores DNS dinámicos podía cambiar su resolución entre la validación y la conexión efectiva.
- **Causa Raíz:** R4 (Validación de entrada sin garantía de uso seguro / TOCTOU).
- **Acción Correctiva:** Retornar la lista de IPs resueltas desde `EgressSecurityPolicy` y conectar exclusivamente a `valid_ips[0]`.
- **Regla Creada:** `ER-SEC-002`.
- **Prueba de Regresión:** `test_audit_h01_proxy_blocks_private_and_honest_logging`.

---

### LL-004 — Confianza Excesiva en Origen HTTP sin Token de Control
- **Contexto:** El servidor web autorizaba peticiones que incluyeran la cabecera `Origin: http://127.0.0.1:7070` sin exigir Bearer token.
- **Qué se esperaba:** Permitir que el dashboard interactivo del navegador consumiera la API localmente sin fricción.
- **Qué ocurrió realmente:** Herramientas locales o ataques de falsificación podían inyectar la cabecera `Origin` o abusar de sesiones locales para invocar operaciones críticas.
- **Causa Raíz:** R5 (Autorización fragmentada) y confusión de control de origen con autenticación.
- **Acción Correctiva:** Exigir prioritariamente Bearer token con comparación en tiempo constante y validar `Sec-Fetch-Site: same-origin`.
- **Regla Creada:** `ER-SEC-004`.
- **Prueba de Regresión:** `test_mcp_control_plane_requires_auth_and_bearer_token`.

---

### LL-005 — DoS por Agotamiento de Hilos en SOCKS5
- **Contexto:** Cada conexión entrante en el socket SOCKS5 creaba un hilo nuevo con `threading.Thread(target=self._handle_client).start()` sin límite superior.
- **Qué se esperaba:** Soportar múltiples conexiones concurrentes de aplicaciones.
- **Qué ocurrió realmente:** Un script cliente que abriera cientos de sockets en bucle agotaba la memoria y los descriptores del sistema operativo.
- **Causa Raíz:** R6 (Pruebas que no verifican estados límite o concurrencia).
- **Acción Correctiva:** Implementación de `threading.BoundedSemaphore(64)` en el bucle de aceptación.
- **Regla Creada:** `ER-SEC-010`.
- **Prueba de Regresión:** `test_audit_3_h02_h05_socks5_concurrency_and_mode_accounting`.

---

### LL-006 — Fuzzing y Desbordamiento en Deserializador BitNet
- **Contexto:** `BitNetQuantizer.deserialize_model(data)` desempaquetaba la cabecera binaria sin verificar si la longitud del nombre o las dimensiones excedían límites razonables o si el buffer de pesos coincidía con el tamaño declarado.
- **Qué se esperaba:** Cargar pesos compactados de redes neuronales ternarias.
- **Qué ocurrió realmente:** Buffers truncados o malformados causaban errores no controlados o intentaban alocar dimensiones absurdas.
- **Causa Raíz:** R6 (Pruebas que no contemplan entradas maliciosas) y falta de validación defensiva.
- **Acción Correctiva:** Validación estricta de números mágicos `IP7B`, longitud de nombre ($\le 256$), cotas ($\le 4096$), escala positiva y concordancia exacta de bytes.
- **Regla Creada:** `ER-SEC-011`.
- **Prueba de Regresión:** `test_audit_3_h06_bitnet_deserialize_bounds_and_fuzz_resilience`.

---

### LL-007 — Exposición de Secretos Compartidos en Respuestas JSON
- **Contexto:** `/api/pqc/live_demo` incluía el campo `"shared_secret_hex": ss1.hex()` para que el usuario del dashboard pudiera ver el resultado del intercambio ML-KEM.
- **Qué se esperaba:** Proporcionar una demostración visual didáctica.
- **Qué ocurrió realmente:** Se normalizó la mala práctica de exponer secretos criptográficos en endpoints HTTP.
- **Causa Raíz:** R2 (Confusión entre componentes didácticos y garantías de seguridad).
- **Acción Correctiva:** Eliminación total de `shared_secret_hex`; exposición exclusiva de `shared_secret_fingerprint` (SHA-256 truncado) y `shared_secret_len`.
- **Regla Creada:** `ER-SEC-008`.
- **Prueba de Regresión:** `test_audit_3_h07_api_pqc_live_demo_censors_raw_shared_secret`.

---

### LL-008 — Ausencia de Firma Digital en Handshake PQC Híbrido
- **Contexto:** El handshake X25519 + ML-KEM-768 ejecutaba el intercambio y derivaba la clave mediante HKDF, pero el servidor no firmaba el transcript con su clave de identidad (`ML-DSA-65` / `Ed25519`).
- **Qué se esperaba:** Proteger la sesión contra adversarios cuánticos ("Harvest Now, Decrypt Later").
- **Qué ocurrió realmente:** Un intermediario activo clásico podía interceptar las claves efímeras y realizar un ataque MITM sin ser detectado.
- **Causa Raíz:** R1 (Diseño sin invariantes verificables) y R2 (Confundir primitivas con protocolo seguro).
- **Acción Correctiva:** `server_respond_authenticated()` firma el transcript hash SHA-256 y `client_finalize_authenticated()` verifica obligatoriamente la firma antes de derivar la clave.
- **Regla Creada:** `ER-SEC-009`.
- **Prueba de Regresión:** `test_audit_3_h09_pqc_authenticated_handshake_and_mitm_rejection`.

---

### LL-009 — Discrepancia entre Notificación de Control y Descarga Web
- **Contexto:** `/api/internet/fetch` enviaba una trama de control al nodo par pero descargaba la página localmente con `urllib.request`, reportando `overlay_verified: true`.
- **Qué se esperaba:** Probar la descarga de URLs a través de la red.
- **Qué ocurrió realmente:** La notificación de control y el tráfico de datos eran operaciones completamente separadas.
- **Causa Raíz:** R3 (Separación incompleta entre control y datos).
- **Acción Correctiva:** Telemetría veraz: `datapath_mode="LOCAL_EGRESS_WITH_OVERLAY_CONTROL_NOTIFICATION"`, `data_tunneled_over_overlay=False`, `overlay_verified=False`.
- **Regla Creada:** `ER-SEC-006`.
- **Prueba de Regresión:** Inspección de payload de `/api/internet/fetch`.

---

### LL-010 — Omisión de Variables de Scope en Refactorizaciones de IA
- **Contexto:** Durante una refactorización de `ipvn7/crypto/pqc.py`, la IA modificó `client_finalize` para usar `transcript_hash` pero olvidó calcular la variable en el scope local de la función, provocando un `NameError` que rompió 12 pruebas del QUIC handshake.
- **Qué se esperaba:** Añadir transcript binding de forma rápida.
- **Qué ocurrió realmente:** El código no fue verificado antes de considerarlo completado; la ejecución de `pytest` atrapó de inmediato el error.
- **Causa Raíz:** Antipatrón de IA (Alucinación de scope y cierre prematuro).
- **Acción Correctiva:** Ejecución obligatoria de `pytest -q` tras cada modificación antes de declarar el éxito de la tarea.
- **Regla Creada:** Mandato Constitucional 1 y `ER-SEC-012`.
- **Prueba de Regresión:** Suite completa de 108 tests pasando al 100%.
