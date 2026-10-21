# REGLAS OPERATIVAS DE INGENIERÍA (ENGINEERING RULES) — LAIA

**Versión:** 1.0  
**Fecha:** 20 de Octubre de 2026  
**Ámbito:** IPVN 7 y proyectos derivados en Antigravity  

---

### ER-SEC-001 — Cero Secretos y Tokens Predeterminados Conocidos
- **ID:** `ER-SEC-001`
- **Riesgo:** Compromiso total del plano de control MCP o servicios administrativos por escaneo de repositorios o credenciales públicas conocidas.
- **Activación:** Cualquier servicio, API, servidor HTTP o componente con autenticación de control.
- **Acción Obligatoria:** Exigir variable de entorno para credenciales; si no está definida, generar dinámicamente un token con `secrets.token_urlsafe(32)` (256 bits de entropía) en memoria y guardarlo en almacenamiento local restringido. Prohibir valores literales constantes por defecto.
- **Ejemplo Incorrecto:**
  ```python
  CONTROL_TOKEN = os.environ.get("IPVN7_TOKEN", "ipvn7-sovereign-control-token-2026")
  ```
- **Ejemplo Correcto:**
  ```python
  token = os.environ.get("IPVN7_TOKEN")
  if not token:
      token = secrets.token_urlsafe(32)
      persist_runtime_token(token)
  ```
- **Método de Verificación:** Búsqueda estática (`grep`) de cadenas conocidas y prueba unitaria de arranque sin variables de entorno verificando que el token sea dinámico y no coincida con ningún valor público.
- **Incidentes Anteriores:** Auditoría 3 H-01.

---

### ER-SEC-002 — Validación Estricta de Egress y Fijación de IP Anti-SSRF/TOCTOU
- **ID:** `ER-SEC-002`
- **Riesgo:** Server-Side Request Forgery (SSRF), DNS Rebinding y acceso no autorizado a rangos privados (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.169.254`, IPv6 `::1`, ULA `fc00::/7`).
- **Activación:** Proxies HTTP, pasarelas SOCKS5, resolvers DNS o clientes de descarga web (`fetch`).
- **Acción Obligatoria:** Resolver el hostname a dirección IP antes de conectar, validar la IP contra la lista negra completa de rangos RFC, y conectar **exclusivamente a la IP resuelta y validada** en lugar de re-resolver el hostname.
- **Ejemplo Incorrecto:**
  ```python
  if is_safe_domain(host):
      socket.create_connection((host, port))  # Vulnerable a DNS Rebinding TOCTOU
  ```
- **Ejemplo Correcto:**
  ```python
  is_allowed, reason, valid_ips = EgressSecurityPolicy.resolve_and_validate_host(host, port)
  if not is_allowed:
      raise SecurityError(reason)
  socket.create_connection((valid_ips[0], port))  # Fijación de IP validada
  ```
- **Método de Verificación:** Pruebas unitarias negativas contra dominios que resuelven a `127.0.0.1`, `169.254.169.254` y subdominios dinámicos de rebinding.
- **Incidentes Anteriores:** Auditoría 2 H-01, H-02; Auditoría 3 H-03.

---

### ER-SEC-003 — Validación de Host Header contra DNS Rebinding
- **ID:** `ER-SEC-003`
- **Riesgo:** Ejecución de código malicioso o llamadas a APIs locales desde un navegador mediante nombres de dominio controlados por atacantes que apuntan a `127.0.0.1`.
- **Activación:** Servidores HTTP expuestos en loopback (`127.0.0.1`, `localhost`).
- **Acción Obligatoria:** Comprobar que la cabecera `Host` corresponda estrictamente a una lista blanca de nombres locales (`127.0.0.1`, `localhost`, `[::1]`). Rechazar cualquier otro valor con `HTTP 400 Bad Request`.
- **Método de Verificación:** Prueba unitaria enviando peticiones con `Host: evil-attacker.com` y comprobando rechazo inmediato.
- **Incidentes Anteriores:** Auditoría 2 H-03.

---

### ER-SEC-004 — Autenticación Criptográfica Robusta en Plano de Control (MCP)
- **ID:** `ER-SEC-004`
- **Riesgo:** Ejecución no autorizada de herramientas del sistema mediante manipulación de origen o peticiones entre sitios (CSRF).
- **Activación:** Endpoints `/api/mcp`, `/mcp` y operaciones privilegiadas de nodo.
- **Acción Obligatoria:** Exigir cabecera `Authorization: Bearer <token>` o `X-IPVN7-Auth` con comparación en tiempo constante (`secrets.compare_digest`). No autorizar mutaciones basándose exclusivamente en cabecera `Origin` sin verificar `Sec-Fetch-Site: same-origin`.
- **Incidentes Anteriores:** Auditoría 2 H-04; Auditoría 3 H-04.

---

### ER-SEC-005 — Inspección Obligatoria de Saltos de Redirección HTTP
- **ID:** `ER-SEC-005`
- **Riesgo:** Evasión de controles SSRF mediante redirecciones `301/302` hacia URLs locales internas tras una validación inicial exitosa.
- **Activación:** Clientes HTTP o handlers de descarga (`urllib`, `requests`, `httpx`).
- **Acción Obligatoria:** Interceptar cada salto de redirección (`SafeRedirectHandler`) y re-validar la URL de destino antes de establecer la conexión subsecuente.
- **Incidentes Anteriores:** Auditoría 2 H-05.

---

### ER-SEC-006 — Veracidad Estricta en Telemetría y Datapath
- **ID:** `ER-SEC-006`
- **Riesgo:** Falsa sensación de seguridad; afirmar que el tráfico está protegido por un túnel cuántico cuando viaja en texto plano por un socket directo.
- **Activación:** Pasarelas de red (SOCKS5, proxies HTTP, endpoints de fetch web).
- **Acción Obligatoria:** Etiquetar como `OVERLAY_TUNNELED` únicamente el tráfico cuyos bytes son cursados y medidos a través del túnel overlay cifrado hacia el Exit Node. Si la conexión es local/directa, declararla explícitamente como `DIRECT_TCP_EGRESS` con `overlay_verified: False`.
- **Incidentes Anteriores:** Auditoría 2 H-06; Auditoría 3 H-02, H-10.

---

### ER-SEC-007 — Métodos Seguros HTTP y Prohibición de Mutaciones en GET
- **ID:** `ER-SEC-007`
- **Riesgo:** Ejecución involuntaria de acciones privilegiadas por prefetching de navegadores, bots de rastreo o ataques de falsificación de enlaces.
- **Activación:** Todos los endpoints de la API web.
- **Acción Obligatoria:** Toda operación con efectos secundarios (rotación de claves, creación de identidades, despacho de paquetes) debe residir exclusivamente en `POST`. Peticiones `GET` a estos endpoints deben responder con `HTTP 405 Method Not Allowed`.
- **Incidentes Anteriores:** Auditoría 2 H-07.

---

### ER-SEC-008 — Censura Estricta de Secretos en APIs y Telemetría
- **ID:** `ER-SEC-008`
- **Riesgo:** Fuga de material criptográfico crítico a través de respuestas JSON, logs de consola o trazas de diagnóstico.
- **Activación:** Respuestas JSON en endpoints de demostración, estado o telemetría.
- **Acción Obligatoria:** Prohibir la inclusión de `shared_secret_hex`, claves privadas o valores crudos. Exponer únicamente huellas digitales truncadas SHA-256 (`shared_secret_fingerprint`) y longitudes en bytes.
- **Incidentes Anteriores:** Auditoría 3 H-07.

---

### ER-SEC-009 — Autenticación Digital de Identidad en Handshake PQC
- **ID:** `ER-SEC-009`
- **Riesgo:** Ataques de Intermediario Activo (MITM) que sustituyen claves efímeras X25519 o ML-KEM sin que los extremos detecten la intercepción.
- **Activación:** Handshake híbrido postcuántico (`ipvn7/crypto/pqc.py`).
- **Acción Obligatoria:** Calcular el hash SHA-256 del transcript completo (`client_pub || srv_pub || ct`) y firmarlo digitalmente con la clave privada de identidad del servidor (`ML-DSA-65` / `Ed25519`). El cliente debe verificar obligatoriamente la firma antes de derivar la clave de sesión.
- **Incidentes Anteriores:** Auditoría 3 H-09.

---

### ER-SEC-010 — Bounded Concurrency y Protección contra Agotamiento de Recursos (DoS)
- **ID:** `ER-SEC-010`
- **Riesgo:** Denegación de servicio por agotamiento de hilos del sistema operativo o descriptores de sockets.
- **Activación:** Listeners de pasarelas de red (SOCKS5, servidores web).
- **Acción Obligatoria:** Limitar la concurrencia con `threading.BoundedSemaphore(N)`. Si se alcanza el límite, rechazar la conexión de inmediato (`SOCKS5_REP_SERVER_FAILURE` o cierre de socket) sin instanciar nuevos hilos.
- **Incidentes Anteriores:** Auditoría 3 H-05.

---

### ER-SEC-011 — Deserialización Defensiva y Validación Exhaustiva de Cotas
- **ID:** `ER-SEC-011`
- **Riesgo:** Fuzzing, corrupción de memoria, desbordamientos de buffer o excepciones no controladas por contenedores binarios maliciosos.
- **Activación:** Motores de parsing binario (BitNet b1.58, serializadores de tramas `IP7H`/`IP7X`).
- **Acción Obligatoria:** Validar tipo de datos, número mágico de cabecera, longitud acotada de nombres ($\le 256$), cotas de dimensiones ($\le 4096$), factores de escala finitos y longitud matemática exacta del buffer de pesos empaquetados.
- **Incidentes Anteriores:** Auditoría 3 H-06.

---

### ER-SEC-012 — Sincronización Matemática de Métricas entre Código y Documentación
- **ID:** `ER-SEC-012`
- **Riesgo:** Documentación divergente o desactualizada que declare capacidades no soportadas o métricas irreales.
- **Activación:** Cierre de tareas, releases y actualizaciones de versión.
- **Acción Obligatoria:** Sincronizar el número exacto de pruebas aprobadas (ej. 115), herramientas MCP protegidas (66) y versiones de Python en `README.md`, `AUTONOMOUS_OPERATIONAL_MANIFESTO.md`, `.nexus/memory/level1_core.json` y CI workflows.
- **Incidentes Anteriores:** Auditoría 2 H-08; Auditoría 3 Sección 4.

---

### ER-OPS-013 — Preferencia por Scripts de Python sobre PowerShell Inline
- **ID:** `ER-OPS-013`
- **Riesgo:** Fallos de sintaxis por interpolación de comillas, errores de escape de caracteres especiales o truncamiento de tuberías complejas en la consola PowerShell de Windows.
- **Activación:** Toda tarea técnica o de auditoría que requiera lógica multi-línea, regex o procesamiento de datos en Windows.
- **Acción Obligatoria:** Escribir y ejecutar scripts de Python independientes (por ejemplo en `scripts/` o ficheros de verificación dedicados) en lugar de encadenar comandos complejos de PowerShell inline (`python -c "..."` multilinea).
- **Ejemplo Incorrecto:**
  ```powershell
  python.exe -c "import re; f=open('file'); ids=re.findall(r'id=\"([^\"]+)\"', f.read()); ..."
  ```
- **Ejemplo Correcto:**
  Escribir `scripts/audit_ids.py` con el código limpio y ejecutar `.\.venv\Scripts\python.exe scripts/audit_ids.py`.

