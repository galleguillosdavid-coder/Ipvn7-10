# POLÍTICA DE GOBERNANZA DE SEGURIDAD Y VERIFICACIÓN CONTINUA (ANTI-FAIL POLICY)
## Directiva Inmutable para Agentes Autónomos e Ingenieros del Protocolo IPVN 7

- **Fecha de Aprobación:** 20 de Octubre de 2026 (Actualización Mayor tras Auditorías Técnicas #2 y #3)
- **Vigencia:** Permanente e Innegociable
- **Alcance:** Todo el código fuente, pasarelas de red, APIs de control, interfaces MCP, criptografía y documentación de IPVN 7.

---

### PREÁMBULO: LA LECCIÓN DE LAS AUDITORÍAS DE SEGURIDAD
Las auditorías técnicas independientes identificaron discrepancias entre promesas arquitecturales y rutas de ejecución reales, así como riesgos en la gestión de tokens, handshakes criptográficos y transporte de datos. Esta política establece salvaguardas técnicas y documentales obligatorias para **garantizar que jamás vuelva a existir una discrepancia entre lo que declara la documentación y lo que ejecuta el código.**

---

### DIRECTIVAS TÉCNICAS OBLIGATORIAS (LAS 12 REGLAS INMUTABLES)

#### Regla 1 (Anti-H01 Auditoría 2): Honestidad Estricta en el Datapath y Egress
- **Prohibición Absoluta de Etiquetas Falsas o Simuladas:** Queda terminantemente prohibido catalogar una conexión como `TUNNELED_PQ_QUIC` o `OVERLAY_VERIFIED` si los bytes de la carga útil no atravesaron efectivamente el túnel cifrado hacia el nodo de salida.
- **Estados Canónicos Requeridos:**
  - `TUNNELED_PQ_QUIC_VERIFIED`: Solo cuando los bytes de datos son encapsulados y transportados por la sesión overlay hacia el Exit Node mediante tramas `IP7X`.
  - `CONTROL_NOTIFIED_DIRECT_EGRESS`: Cuando se envía telemetría de control por la malla pero la conexión TCP de datos es abierta localmente.
  - `DIRECT_LOCAL_EGRESS_VALIDATED`: Conexión de salida directa del host local validada contra políticas de seguridad.
- **Prohibición de "simulated":** Si no existe una sesión criptográfica activa (ML-KEM-768/X25519) con clave derivada compartida, el campo de huella debe ser `null` y `overlay_verified` debe ser estrictamente `false`.

#### Regla 2 (Anti-H02 & Anti-H04 Auditoría 2): Blindaje Universal Anti-SSRF y Validación de Destinos
- Toda pasarela que conecte hacia el exterior (Proxy HTTP/HTTPS, SOCKS5 RFC 1928, `/api/internet/fetch`):
  1. Debe resolver el nombre de host mediante `socket.getaddrinfo`.
  2. Debe analizar **todas** las direcciones IP resultantes mediante la librería estándar `ipaddress`.
  3. Debe rechazar incondicionalmente cualquier dirección perteneciente a:
     - Loopback (`127.0.0.0/8`, `::1`).
     - Rangos privados RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`).
     - Metadatos en la nube y Link-Local (`169.254.0.0/16`, `fe80::/10`).
     - CGNAT RFC 6598 (`100.64.0.0/10`) y Benchmarking RFC 2544 (`198.18.0.0/15`).
     - Multicast, Reservados, Broadcast o Unspecified (`0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`, `::`).
  4. La conexión TCP debe realizarse **directamente a la dirección IP previamente validada**, fijando la cabecera `Host` al nombre de dominio original, para inmunizar el sistema contra ataques de **DNS Rebinding (TOCTOU)**.
  5. En solicitudes HTTP con redirecciones (301/302/307), cada salto de redirección debe pasar por el filtro estricto `SafeRedirectHandler` antes de seguir el enlace.

#### Regla 3 (Anti-H03 Auditoría 2): Autenticación y Autorización en Plano de Control (MCP y API)
- El plano de control (`/mcp`, `/api/mcp`, y endpoints administrativos):
  1. Exige autenticación obligatoria mediante token criptográfico soberano (`Authorization: Bearer <token>`).
  2. Implementa validación estricta de cabeceras `Host` y `Origin`: solo se admiten peticiones dirigidas a `127.0.0.1:7070` o `localhost:7070`. Todo `Origin` ajeno a la lista blanca local es rechazado inmediatamente con HTTP 403 Forbidden.
  3. El servidor MCP (`ipvn7/node/mcp.py`) valida los permisos de ejecución por herramienta según roles jerárquicos (`ordinary`, `operator`, `admin`).

#### Regla 4 (Anti-H05 Auditoría 2): Control de Concurrencia, Cuotas y Validación Estricta de Rangos
- Ningún parámetro numérico proveniente de la red o querystring puede ser casteado sin validación de cotas (`bounds checking`).
  - Ejemplo: en simulaciones o benchmarks, los parámetros `nodes` deben acotarse estrictamente (`5 <= nodes <= 120`) y `churn` (`0.0 <= churn <= 0.85`).
- El servidor HTTP debe implementar un límite de concurrencia activo (`REQUEST_SEMAPHORE = threading.BoundedSemaphore(32)`) y timeouts de lectura/escritura de 10 segundos por conexión para prevenir agotamiento de hilos (Thread Starvation DoS).

#### Regla 5 (Anti-H07 Auditoría 2): Idempotencia HTTP y Separación Estricta de Métodos
- Las operaciones con efectos secundarios (mutación de estado, rotación de claves, cambios en cortafuegos o despacho de paquetes) están **terminantemente prohibidas en peticiones GET**.
- Todo endpoint de mutación debe residir exclusivamente en `POST`, exigiendo autenticación y cabecera `Content-Type: application/json`. Las peticiones `GET` a endpoints de mutación deben responder con `HTTP 405 Method Not Allowed`.

#### Regla 6 (Anti-H08 Auditoría 2): Sincronía Continua entre Documentación, Código y CI
- Las métricas del repositorio (número exacto de pruebas unitarias, número exacto de herramientas MCP y versiones soportadas de Python) deben estar matemáticamente sincronizadas en `README.md`, `AUTONOMOUS_OPERATIONAL_MANIFESTO.md`, `.github/workflows/ci.yml` y `level1_core.json`.

#### Regla 7: Pruebas Unitarias Negativas Obligatorias para Cada Vector de Riesgo
- Todo parche de seguridad debe acompañarse de pruebas unitarias específicas que intenten activamente explotar el fallo (pruebas negativas de SSRF, DNS rebinding, llamadas sin token a MCP, payloads malformados y mutaciones por GET) demostrando que son bloqueadas de forma segura.

#### Regla 8: Protocolo de Handover Verificado y Auditoría Cruzada Periódica
- Antes de cerrar cualquier ciclo de desarrollo autónomo:
  1. `pytest -q` debe arrojar 100% de pruebas aprobadas sin ninguna excepción.
  2. El servidor debe levantarse y verificarse en vivo mediante consultas reales.
  3. Los cambios deben comitearse con mensaje descriptivo y sincronizarse en `main`.

---

### NUEVAS REGLAS INMUTABLES (LECCIÓN DE LA AUDITORÍA #3)

#### Regla 9 (Anti-H01 Auditoría 3): Cero Credenciales Estáticas Públicas o Hardcodeadas
- **Prohibición Absoluta de Tokens Hardcodeados en Código:** Jamás debe existir una cadena de credencial predeterminada (como `"ipvn7-sovereign-control-token-2026"`) en el código fuente.
- **Generación Dinámica Criptográfica:** Si la variable de entorno `IPVN7_CONTROL_TOKEN` no está configurada, el sistema debe generar dinámicamente al arrancar un token aleatorio con entropía criptográfica (`secrets.token_urlsafe(32)`), persistirlo en `.nexus/runtime/control.token` con permisos restringidos de usuario local, e imprimir su instrucción en la consola de inicio.

#### Regla 10 (Anti-H02 Auditoría 3): Pasarela SOCKS5 con Transporte Overlay Real
- Cuando `IPVN7SOCKS5Gateway` opera en modo `OVERLAY_TUNNELED`, el socket local del cliente NO debe conectarse directamente a Internet.
- Todo el flujo TCP debe encapsularse en tramas canónicas `IP7X` a través de `SovereignExitRelayClient` hacia el Exit Node. El Exit Node es la única entidad que ejecuta `create_connection` y retransmite los bytes cifrados de vuelta al cliente.
- Si opera en modo directo local, debe declararse explícitamente como `DIRECT_LOCAL_EGRESS_VALIDATED`.

#### Regla 11 (Anti-H07 Auditoría 3): Cero Exposición de Secretos Compartidos en APIs
- Ningún endpoint de diagnóstico, demo o telemetría puede exponer en respuestas JSON el contenido crudo de secretos compartidos, claves privadas o vectores de inicialización (`shared_secret_hex`).
- La evidencia demostrativa debe limitarse a huellas digitales criptográficas unidireccionales (ej: `hashlib.sha256(ss).hexdigest()[:16] + "..."`), longitud en bytes y confirmación booleana de coincidencia.

#### Regla 12 (Anti-H09 Auditoría 3): Autenticación Criptográfica Completa del Handshake PQC contra MITM
- El intercambio híbrido (X25519 + ML-KEM-768) no puede considerarse seguro únicamente por derivar una clave con HKDF.
- **Vigencia Obligatoria de Firma de Identidad:** El servidor debe firmar el transcript hash completo con su clave privada de identidad de largo plazo (`mldsa_priv` y `ed25519_priv`).
- El cliente debe verificar obligatoriamente la firma del transcript contra la clave pública de identidad del servidor antes de considerar la sesión como establecida. Cualquier discrepancia en la firma debe abortar inmediatamente la conexión con error de autenticación.

---

## SECCIÓN V: PROTOCOLO DE AUDITORÍA RECURRENTE DE FALLAS DE IA (GEMINI, ANTIGRAVITY Y AGENTES COGNITIVOS)

Para garantizar que el desarrollo asistido por Inteligencia Artificial (Google Gemini, Antigravity, LLM Coding Agents) no degrade la seguridad ni la integridad del protocolo IPVN 7, se establece este protocolo de inspección continua y mitigación de fallas recurrentes.

### V.1. Catálogo Sistemático de Modos de Falla de IA

1. **El "Bypass Silencioso" (Silent Errors):**
   - *Manifestación:* La IA inserta bloques `try-except` vacíos con `pass` o valores de retorno nulos que silencian excepciones críticas. El código parece ejecutarse sin errores, pero la lógica de negocio subyacente está muerta.
   - *Solución Obligatoria:* Prohibir excepciones capturadas sin logging y manejo explícito. El código debe fallar de forma rápida y ruidosa (*Fail-Fast Principle*).

2. **Declaración Prematura de Éxito (False Completion):**
   - *Manifestación:* El agente declara que una tarea está "completada con éxito" simplemente porque escribió un archivo o invocó una herramienta, sin haber ejecutado la suite de pruebas unitarias o sin haber comprobado el código de retorno.
   - *Solución Obligatoria:* Ninguna tarea se considera finalizada sin la ejecución en vivo de `pytest -q` arrojando 100% de éxito, complementado con pruebas de regresión negativas para los vectores corregidos.

3. **Alucinación de Imports, Variables y Firmas de API:**
   - *Manifestación:* La IA inventa métodos en bibliotecas criptográficas (ej: funciones inexistentes en `cryptography.hazmat`), olvida declarar variables intermedias (ej: omitir el cálculo de `transcript_hash` en el scope de una función), o genera firmas incompatibles entre llamador y llamado.
   - *Solución Obligatoria:* Validación obligatoria con analizador estático o ejecución directa de tests unitarios antes de finalizar la respuesta.

4. **La Trampa del "Éxito Fantasma" en Herramientas (Phantom Success Trap):**
   - *Manifestación:* La IA ejecuta un comando en la terminal que retorna código de error (1 o 2), pero en su razonamiento ignora la salida y asume que el comando funcionó.
   - *Solución Obligatoria:* Inspeccionar sistemáticamente el `exit code` y las trazas de `stderr` de cada comando antes de continuar al siguiente paso.

5. **Bucles de Agotamiento (Exhaustion Loops):**
   - *Manifestación:* Al encontrarse con un fallo, la IA reintenta el mismo parche cosmético una y otra vez sin reflexionar sobre la causa raíz.
   - *Solución Obligatoria:* Si un fix falla dos veces seguidas, la IA debe pausar, investigar en la documentación oficial mediante `search_web`, inspeccionar el código fuente de las bibliotecas subyacentes y analizar el problema desde sus fundamentos.

6. **Deriva de Contexto y Replicación de Deuda Técnica (Context Drift):**
   - *Manifestación:* En conversaciones largas, la IA olvida las directivas inmutables de seguridad y copia patrones vulnerables preexistentes en el repositorio (ej: credenciales estáticas o rutas directas sin cifrado).
   - *Solución Obligatoria:* Consultar proactivamente este documento de gobernanza (`SECURITY_GOVERNANCE_AND_AUDIT_POLICY.md`) y los ADRs registrados en `.nexus/decisions/` al inicio de cada ciclo de trabajo.

---

## SECCIÓN VI: ANÁLISIS HISTÓRICO Y COMPARATIVO DE VERSIONES DE IPVN7 (DISCOS C: Y D:)

A lo largo del desarrollo de IPVN 7 y sus arquitecturas hermanas, se han creado múltiples implementaciones distribuidas en las unidades `C:` y `D:`. Esta sección sintetiza lo que se debe extraer de forma permanente y lo que queda estrictamente prohibido.

### VI.1. Inventario de Versiones Ancestrales Inspeccionadas

* **En Unidad C: (`C:\Users\Frondabrick\Desktop\dvd\Ipv7\`):**
  * `0.7` y `0.7 - copia`: Primeros prototipos de routing y datagramas.
  * `ipvn7  vX7` (Go / Python): Implementación con gateways y pasarelas SOCKS5 iniciales.
  * `ipvn7 vX` y `ipvn7 vX original`: Modelos de relay distribuido y tablas de rutas.
  * `Nexus one`, `Nexus two`, `Nexus tree`: Arquitecturas de microservicios y gobernanza de decisiones.
  * `Versiones_Anteriores`: Repositorio histórico de experimentos de red.
* **En Unidad D: (`D:\David\dvd\` y subdirectorios):**
  * `D:\David\dvd\Ipv7`, `Ipv7-4`, `Ipv7-5`: Diseños evolutivos de paquetes canónicos.
  * `D:\David\dvd\ipv7-hrs-final`: Implementación en C de alto rendimiento para el subsistema HRS.
  * `D:\David\dvd\ipv7c`: Motor C nativo para sockets raw y tunelización.
  * `D:\David\dvd\Ipv7IEU` y `IPv7-HRS_Arquitectura_Completa.md`: Documentos fundacionales de la ontología del protocolo, interfaces UIN y orquestación cuántica.
  * `D:\David\dvd\launch_ipvn7.ps1`: Scripts de automatización y orquestación de red en Windows.

---

### VI.2. Matriz de Extracción Permanente: LO ÚTIL (Patrones que se DEBEN Reutilizar)

| Componente | Origen Histórico | Valor Técnico / Por Qué Extraerlo |
| :--- | :--- | :--- |
| **Identidad UIN Soberana** | `Ipv7IEU` / `IPv7-HRS` | Direccionamiento determinista auto-soberano que desacopla la identidad del nodo de su IP física de transporte. |
| **Tramas Fijas Anti-Análisis (Sphinx)** | `ipvn7 vX7` / `ipvn7-10` | Paquetes en capas de 1280 bytes que impiden a adversarios en tránsito correlacionar longitudes de flujo o destinos intermedios. |
| **Ruteo Kleinberg Small-World** | `Nexus tree` / `ipvn7-10` | Tablas DHT descentralizadas con enlaces de corto y largo alcance que garantizan entrega en $O(\log^2 N)$ pasos incluso con alta tasa de churn. |
| **Compresión BitNet b1.58** | `ipvn7-10` | Inferencia de IA en el borde con aritmética entera de sumas y restas (zero-multiply) para dispositivos IoT de bajísimo consumo. |
| **Aislamiento Multi-Capa con Wintun** | `launch_ipvn7.ps1` / `ipv7c` | Creación de interfaces de túnel virtuales en Windows para capturar tráfico transparente del sistema operativo. |

---

### VI.3. Matriz de Erradicación Definitiva: LO QUE NUNCA SE DEBE HACER (Antipatrones Prohibidos)

1. **NUNCA Credenciales Hardcodeadas en el Código Fuente:**
   * *Error histórico:* Definir valores estáticos como `"ipvn7-sovereign-control-token-2026"` en `server.py` o scripts de lanzamiento.
   * *Regla inmutable:* Todo token debe generarse con alta entropía en memoria (`secrets.token_urlsafe(32)`) y persistirse en almacenamiento local restringido si el operador no especifica una variable de entorno.

2. **NUNCA Afirmaciones de Telemetría sin Evidencia de Red:**
   * *Error histórico:* Registrar eventos como `"TUNNELED_OVERLAY"` o `"overlay_verified: true"` cuando el código subyacente realiza un `socket.create_connection` directo a la IP de destino.
   * *Regla inmutable:* Toda afirmación de transporte tunelizado debe respaldarse con el paso de bytes por tramas cifradas `IP7X` al nodo de salida. En caso de salida directa, declarar honestamente `DIRECT_TCP_EGRESS`.

3. **NUNCA Handshakes Postcuánticos sin Firma Digital de Transcript:**
   * *Error histórico:* Combinar X25519 con ML-KEM-768 mediante HKDF asumiendo que el handshake es seguro contra MITM simplemente por incluir etiquetas en el parámetro `info`.
   * *Regla inmutable:* El transcript completo (`client_pub || srv_pub || ct`) debe ser firmado obligatoriamente por la clave de identidad de largo plazo del servidor (`ML-DSA-65` / `Ed25519`) y verificado estrictamente por el cliente antes de computar la clave de sesión.

4. **NUNCA Deserialización Binaria sin Validación Exhaustiva de Cotas:**
   * *Error histórico:* Desempaquetar estructuras binarias (como contenedores BitNet en `ipv7c` o prototipos) confiando ciegamente en la longitud declarada en la cabecera.
   * *Regla inmutable:* Validar tipos, magic bytes, dimensiones acotadas ($\le 4096$), factores de escala finitos y longitud matemática exacta del buffer de datos.

5. **NUNCA Exposición de Secretos Crudos en APIs:**
   * *Error histórico:* Enviar `shared_secret_hex` en respuestas JSON de demostraciones criptográficas para facilitar el debugging visual.
   * *Regla inmutable:* Todo secreto debe ser protegido; en interfaces de usuario y APIs solo se expondrán huellas digitales hash SHA-256 unidireccionales y métricas de longitud.

6. **NUNCA Concurrencia Ilimitada sin Semáforos de Protección:**
   * *Error histórico:* Instanciar hilos `threading.Thread` indefinidamente por cada conexión entrante en la pasarela SOCKS5.
   * *Regla inmutable:* Limitar el paralelismo con `threading.BoundedSemaphore(64)` y rechazar inmediatamente excesos de carga para inmunizar al sistema contra DoS.

---

### VI.4. Calendario y Procedimiento de Revisión Periódica

* **Frecuencia de Inspección:** Cada 30 días o al iniciar una nueva versión mayor/menor del protocolo.
* **Procedimiento:**
  1. Contrastar el código activo contra las 12 Reglas Inmutables de la Sección IV.
  2. Ejecutar escaneo automatizado de tokens estáticos y secretos expuestos mediante scripts de auditoría interna.
  3. Ejecutar la batería completa de 108+ pruebas de regresión unitarias (`pytest -q`).
  4. Revisar los repositorios históricos en `C:\Users\Frondabrick\Desktop\dvd\Ipv7\` y `D:\David\dvd\` para extraer algoritmos útiles comprobados y verificar que ningún antipatrón haya sido reintroducido.

