# POLÍTICA DE GOBERNANZA DE SEGURIDAD Y VERIFICACIÓN CONTINUA (ANTI-FAIL POLICY)
## Directiva Inmutable para Agentes Autónomos e Ingenieros del Protocolo IPVN 7

- **Fecha de Aprobación:** 20 de Octubre de 2026
- **Vigencia:** Permanente e Innegociable
- **Alcance:** Todo el código fuente, pasarelas de red, APIs de control, interfaces MCP y documentación de IPVN 7.

---

### PREÁMBULO: LA LECCIÓN DE LA AUDITORÍA DE SEGURIDAD #2

La auditoría técnica independiente identificó discrepancias entre promesas arquitecturales y rutas de ejecución reales (H-01 a H-08). Esta política establece salvaguardas técnicas y documentales obligatorias para **garantizar que jamás vuelva a existir una discrepancia entre lo que declara la documentación y lo que ejecuta el código.**

---

### DIRECTIVAS TÉCNICAS OBLIGATORIAS (LAS 8 REGLAS INMUTABLES)

#### Regla 1 (Anti-H01 & Anti-H06): Honestidad Estricta en el Datapath y Egress
- **Prohibición Absoluta de Etiquetas Simuladas:** Queda terminantemente prohibido catalogar una conexión como `TUNNELED_PQ_QUIC` o `OVERLAY_VERIFIED` si los bytes de la carga útil (payload de datos) no atravesaron efectivamente el túnel cifrado hacia el nodo de salida.
- **Estados Canónicos Requeridos:**
  - `OVERLAY_DATA_TUNNELED`: Solo cuando los bytes de datos son encapsulados y transportados por la sesión overlay hacia el exit node.
  - `CONTROL_SENT_DATA_PATH_DIRECT`: Cuando se envía telemetría de control por la malla pero la conexión TCP de datos es abierta localmente.
  - `DIRECT_LOCAL_EGRESS`: Conexión de salida directa del host local.
- **Prohibición de "simulated":** Si no existe una sesión criptográfica activa (ML-KEM-768/X25519) con clave derivada compartida, el campo de huella debe ser `null` o `"NO_ACTIVE_SESSION"` y `overlay_verified` debe ser estrictamente `false`.

#### Regla 2 (Anti-H02 & Anti-H04): Blindaje Universal Anti-SSRF y Validación de Destinos
- Toda pasarela que conecte hacia el exterior (Proxy HTTP/HTTPS, SOCKS5 RFC 1928, `/api/internet/fetch`):
  1. Debe resolver el nombre de host mediante `socket.getaddrinfo`.
  2. Debe analizar **todas** las direcciones IP resultantes mediante la librería estándar `ipaddress`.
  3. Debe rechazar incondicionalmente cualquier dirección perteneciente a:
     - Loopback (`127.0.0.0/8`, `::1`).
     - Rangos privados RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`).
     - Metadatos en la nube y Link-Local (`169.254.0.0/16`, `fe80::/10`).
     - Multicast, Reservados, Broadcast o Unspecified (`0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`, `::`).
  4. La conexión TCP debe realizarse **directamente a la dirección IP previamente validada**, fijando la cabecera `Host` al nombre de dominio original, para inmunizar el sistema contra ataques de **DNS Rebinding (TOCTOU)**.
  5. En solicitudes HTTP con redirecciones (301/302/307), cada salto de redirección debe pasar por el mismo filtro estricto antes de seguir el enlace.

#### Regla 3 (Anti-H03): Autenticación y Autorización Obligatoria en Plano de Control (MCP y API)
- El plano de control (`/mcp`, `/api/mcp`, y endpoints administrativos de mutación):
  1. Exige autenticación obligatoria mediante token criptográfico soberano (`Authorization: Bearer <token>`).
  2. Implementa validación estricta de cabeceras `Host` y `Origin`: solo se admiten peticiones dirigidas a `127.0.0.1:7070` o `localhost:7070`. Todo `Origin` ajeno a la lista blanca local es rechazado inmediatamente con HTTP 403 Forbidden para prevenir Cross-Site Scripting y peticiones inducidas desde páginas web maliciosas.
  3. El servidor MCP (`ipvn7/node/mcp.py`) debe validar los permisos de ejecución por herramienta según roles jerárquicos (`ordinary`, `operator`, `admin`).

#### Regla 4 (Anti-H05): Control de Concurrencia, Cuotas y Validación Estricta de Rangos
- Ningún parámetro numérico proveniente de la red o querystring puede ser casteado sin validación de cotas (`bounds checking`).
  - Ejemplo: en simulaciones o benchmarks, los parámetros `nodes` deben acotarse estrictamente (ej: `5 <= nodes <= 150`) y `churn` (`0.0 <= churn <= 0.85`).
- El servidor HTTP debe implementar un límite de concurrencia activo (semáforo de solicitudes en vuelo, máximo 32 concurrentes) y timeouts de lectura/escritura de 10 segundos por conexión para prevenir agotamiento de hilos (Thread Starvation DoS).

#### Regla 5 (Anti-H07): Idempotencia HTTP y Separación Estricta de Métodos
- Las operaciones con efectos secundarios (mutación de estado, rotación de claves, cambios en cortafuegos o despacho de paquetes) están **terminantemente prohibidas en peticiones GET**.
- Todo endpoint de mutación debe residir exclusivamente en `POST`, exigiendo autenticación y cabecera `Content-Type: application/json`. Las peticiones `GET` a endpoints de mutación deben responder con `HTTP 405 Method Not Allowed`.

#### Regla 6 (Anti-H08): Sincronía Continua entre Documentación, Código y CI
- Las métricas del repositorio (número exacto de pruebas unitarias, número exacto de herramientas MCP y versión soportada de Python) deben estar matemáticamente sincronizadas en:
  - `README.md`
  - `AUTONOMOUS_OPERATIONAL_MANIFESTO.md`
  - `.github/workflows/ci.yml` (la matriz de versiones de Python debe incluir la versión principal declarada, ej: Python 3.14).
  - Pruebas unitarias de catálogo (`tests/test_ipvn7.py`).
- Si se añade un test o una herramienta MCP, todos estos archivos deben actualizarse en el mismo commit atómico.

#### Regla 7: Pruebas Unitarias Negativas Obligatorias para Cada Vector de Riesgo
- Todo parche de seguridad debe acompañarse de pruebas unitarias específicas que intenten activamente explotar el fallo (pruebas negativas de SSRF, DNS rebinding, llamadas sin token a MCP, payloads malformados y mutaciones por GET) demostrando que son bloqueadas de forma segura.

#### Regla 8: Protocolo de Handover Verificado y Auditoría Cruzada Periódica
- Antes de cerrar cualquier ciclo de desarrollo autónomo:
  1. `pytest -q` debe arrojar 100% de pruebas aprobadas sin ninguna excepción.
  2. El servidor debe levantarse y verificarse en vivo mediante consultas reales.
  3. Los cambios deben comitearse con mensaje descriptivo y sincronizarse en `main`.
