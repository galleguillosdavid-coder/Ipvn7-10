# IPVN 7 — GENESIS MANDATE & ARCHITECTURAL BLUEPRINT (v2.0)
## Documento Génesis para Construcción, Evolución y Auto-Mejora Continua de IPVN 7

> **Dirigido a:** La IA Asistente, Agente Autónomo de Programación o Ingeniero de Software que inicie o continúe esta instancia.  
> **Mandato:** Asumes de forma inmediata y automática el rol de **Arquitecto de Protocolos, Ingeniero de Seguridad Post-Cuántica, Desarrollador Principal y Operador Autónomo**, con consentimiento administrativo total para diseñar, codificar, depurar, investigar y desplegar el sistema sin requerir aprobaciones humanas intermedias.  
> **Ciclo de Auto-Mejora:** Al finalizar cada hito, estableces autónomamente un temporizador (`schedule`) de **30 minutos** para inspeccionar la red, investigar innovaciones técnicas y refactorizar el sistema de forma iterativa.

---

## 1. Visión y Filosofía Fundamental

**IPVN 7 (Internet Protocol Version 7)** es la arquitectura de red descentralizada y soberana concebida para reemplazar la infraestructura de IPv4 e IPv6 frente a la era cuántica, la vigilancia masiva y la fragilidad del enrutamiento centralizado (BGP/DNS).

### Principios Axiomáticos Innegociables:
1. **Identidad Desacoplada de la Ubicación Física:** No existen direcciones IP fijas de interfaz. Cada nodo o entidad se identifica mediante **Identificadores Descentralizados (DIDs)** criptográficos de 256 bits (`did:ipvn7:<hex>`). La identidad persiste inmutable al conmutar entre Wi-Fi, redes móviles (4G/5G), satelitales o enlaces off-grid.
2. **Criptografía Post-Cuántica Nativa (NIST FIPS 203 & 204):** Resistencia cuántica estricta mediante **ML-KEM-768** (intercambio de claves en retículos) y **ML-DSA-65** (firmas digitales) en modo híbrido con primitivas clásicas (X25519 y Ed25519) para defensa en profundidad (*Harvest Now, Decrypt Later* inmune).
3. **Privacidad, Sigilo y Evasión por Defecto:** Tráfico de cable ofuscado como TLS 1.3 RFC 8446 neutro (`0x17 0x03 0x03`), enrutamiento anónimo cebolla Sphinx de 3 saltos, supresión de ruido broadcast y detección activa de DPI (envenenamiento DNS e inyección de TCP RST).
4. **Simplicidad y Cero Inflación de Dependencias (Zero-Bloat):** Favorecer soluciones compactas, robustas y de alto rendimiento utilizando únicamente la biblioteca estándar del lenguaje y bibliotecas criptográficas auditadas (como `cryptography`). La interfaz gráfica SPA debe ser **Vanilla CSS + JS puro**, eliminando dependencias efímeras como Tailwind o Node-modules pesados.

---

## 2. Arquitectura de 5 Capas + Plano de Control IA

Cualquier instancia de IPVN 7 debe implementar e interconectar rigurosamente las siguientes capas:

### Capa L0: Acceso al Medio, Aceleración Datapath & Memoria Lock-Free
- **Abstracción de Hardware (HAL):** Controlador universal de interfaces físicas (Ethernet, Wi-Fi 6/7, 5G NR, satelital LEO) sobre sockets UDP overlay multiplexados.
- **Adaptador Virtual TUN / Wintun:** Controlador de adaptador virtual en kernel de Windows (`wintun.dll`) y Linux (`/dev/net/tun`) con conmutación transparente a túnel en userspace.
- **Agrupador de Datagramas (Packet Batcher):** Cola circular de alta densidad para agrupar ráfagas de paquetes de 1280 bytes, reduciendo llamadas al sistema y cambios de contexto en un 80%.
- **Monitor de Salud de Buffers & Alertas de Fuga:** Seguimiento lock-free del ciclo de vida de los slabs de memoria, registro de marca de agua histórica (*High-Water Mark*) y alerta temprana de fugas (*Leak Alert*).
- **Árbitro Global de Memoria (GMA):** Partición estricta de la memoria RAM del nodo en cuotas presupuestarias aisladas (Replay 20%, QoS 30%, Trust 20%, Bindings 20%, Other 10%) para garantizar inmunidad contra ataques de denegación de servicio por agotamiento de memoria (OOM-DoS).
- **Puente WebAssembly (WASM):** Primitivas criptográficas client-side portables a navegadores web con resolución de Micro-PoW para admisión y defensa anti-Sybil.

### Capa L1: Transporte Seguro Post-Cuántico & Evasión Perimetral
- **Protocolo PQ-QUIC sobre UDP (RFC 9000):** Handshake 1-RTT post-cuántico, multiplexación de flujos sin bloqueo de cabecera (*Head-of-Line Blocking*), y migración nativa de conexión (*Connection Migration*) sin renegociar la sesión criptográfica.
- **Camuflaje TLS 1.3 & Evasión de DPI (RFC 8446):** Envoltura de datagramas con cabeceras `ApplicationData` legítimas y generación de `ClientHello` con SNI de servicios comunes (ej. `gateway.cloudflare.com`).
- **Sonda WAN Activa (Trama Canónica IP7P 32B):** Datagramas binarios de 32 bytes con cabecera mágica `0x49503750` para medición de RTT instantáneo, mínimo/máximo y cálculo de Jitter según RFC 3550 en tiempo real.
- **Perforación de NAT UDP (RFC 3489 / 5389) & Relays DERP:** Clasificación automática de topologías NAT (Full Cone a Symmetric) con hole-punching directo y salto automático a relays cifrados DERP soberanos.
- **Mapeo Automático UPnP IGD / SSDP & Blindaje Anti-SSRF:** Apertura zero-touch de puertos residenciales bloqueando estrictamente accesos a rangos link-local (`169.254.0.0/16`) o metadatos de proveedores cloud.
- **Planificador de Tráfico DWRR & Pacing:** Limitador Token Bucket acoplado con Deficit Weighted Round Robin para priorizar tráfico de control y flujos de baja latencia sobre descargas masivas.
- **Transporte Multipath (MPTS):** Striping de datagramas con políticas de menor latencia (*Lowest-Latency*), balanceo ponderado (*Weighted Round-Robin*) o duplicación concurrente bicast para tráfico crítico.

### Capa L2: Topología de Red, Enrutamiento Distribuido & Resiliencia
- **DHT de Mundo Pequeño (Kleinberg $r=2$):** Enrutamiento voraz en espacio métrico XOR de 256 bits organizado en anillos de proximidad geográfica y latencia, garantizando resolución en $O(\log^2 N)$ saltos.
- **Enrutador Cebolla Sphinx de 3 Saltos:** Cifrado por capas con clave efímera y ChaCha20-Poly1305, asegurando longitud fija e indistinguible de 1280 bytes en cada nodo intermedio.
- **Protocolo Epidémico Plumtree (Gossip):** Difusión masiva de anuncios mediante árbol impaciente (*Eager*) y árbol perezoso (*Lazy*) con mensajes de poda (`PRUNE`) e injerto (`GRAFT`).
- **Detector de Fallos SWIM en $O(1)$:** Sondas directas de latencia fija combinadas con sondeo indirecto mediante $k$ pares aleatorios (`Ping-Req`) para eliminar falsos positivos sin saturar la red.
- **Curación de Enlaces & Amortiguamiento (RFC 2439 Flap Damping):** Histéresis anti-oscilación que penaliza exponencialmente enlaces intermitentes y conmuta dinámicamente a rutas alternativas sanas.
- **Máquina de Recuperación Post-Apagón en 5 Fases:** Cascada de estados (`COLD_MEMORY` $\to$ `OFFGRID_PROXIMITY` $\to$ `WAN_PROBE` $\to$ `BLIND_RENDEZVOUS` $\to$ `CONVERGED_MESH`) con temporizador de Jitter descorrelacionado para evitar colisiones masivas en reconexión.
- **Punto de Encuentro Ciego Efímero (EBRA):** Balizas de descubrimiento zero-knowledge sin metadatos de identidad (Zero-PII) y consumo destructivo (*Consume-and-Burn*) tras emparejamiento.
- **Malla Interplanetaria 2D & Enrutamiento Relativista:** Cálculo de demoras físicas considerando la constante de velocidad de la luz $c = 299.792\text{ km/s}$ para enlaces satelitales o interplanetarios.
- **Ancla Topológica de Movilidad (TMA):** Handover móvil 0-RTT mediante tickets proactivos HMAC-SHA256 y secuencia monótona estricta anti-carreras.
- **Autómata Finito Determinista (FSM):** Ciclo de vida formal del nodo (`DISCONNECTED` $\to$ `SYNCING` $\to$ `VALIDATING` $\to$ `ACTIVE`) con contención forzada a `QUARANTINED` ante amenazas.
- **Línea de Montaje Pipes & Filters:** Encadenamiento secuencial de etapas de procesamiento con desvío inmediato de datagramas anómalos hacia una cola inmutable de descarte (*Dead-Letter Queue*).

### Capa L3: Seguridad ZTNA, Confianza Criptográfica & Diagnóstico
- **Cortafuegos Microsegmentado Zero-Trust (ZTNA):** Política estricta por defecto de denegación total (*Default-Deny*) en el datapath a nivel de DID y puertos autorizados.
- **Red de Confianza Descentralizada (Web-of-Trust):** Puntuación transitiva con atenuación geométrica ($0.85^d$) y verificación de firmas de atestación.
- **Filtro Anti-Reproducción de 1024 Bits (RFC 4303):** Ventana deslizante bitmask en tiempo constante $O(1)$ para neutralizar repetición de paquetes desordenados o maliciosos.
- **Cadena de Custodia Agéntica (Agentic Principal Chain):** Delegación criptográfica de autoridad entre agentes con atenuación monótona de privilegios (Root $\to$ Escalated $\to$ Ordinary) y caducidad temporal.
- **Perfil Sigiloso Dark Node:** Macro-orquestador atómico que silencia listeners públicos, bloquea tráfico broadcast y fuerza Sphinx de 3 saltos con inyección de micro-jitter estocástico.
- **Centinela de Rotación Proactiva de Claves:** Re-keying automático disparado por volumen (1 GB), paquetes ($10^6$) o tiempo (1 hora), manteniendo una ventana de gracia de 30 segundos para datagramas rezagados antes del borrado seguro en memoria (*zero-wipe*).
- **Emparejamiento Fuera de Banda (SAS & UR):** Generación de Short Authentication String (6 dígitos + 4 emojis) y fragmentos Uniform Resource (UR) para emparejamiento visual mediante códigos QR animados.
- **Copiloto IA de Red & Auto-Reparación en Bucle Cerrado:** Diagnóstico continuo de señales telemetry (latencia, firewall drops, entropía espectral, flapping) y ejecución automática de remediaciones (`BLOCK_DID`, `FAILOVER_PATH`, `TUNE_PACER`).
- **Gobernanza Axiomática PFO:** Árbol ontológico formal (5 Principios Génesis $\to$ 12 Funciones Operativas $\to$ Observaciones Empíricas) con verificación de cumplimiento al 100%.

### Capa L4: Aplicación Soberana, Servicios & Pasarelas
- **Pasarela Proxy SOCKS5 (RFC 1928):** Servicio local en `127.0.0.1:10807` que permite a cualquier navegador o aplicación del sistema operativo salir a través de la malla IPVN 7.
- **Almacén Inmutable DAG & Enrutamiento Tolerante a Retardos (DTN):** Bloques direccionados por contenido (`cid:ipvn7:<sha256>`) con resolución causal de ancestros y cola store-and-forward para enlaces intermitentes.
- **DNS Descentralizado (dDNS Petnames):** Resolución memorística de nombres locales `.ipv7` hacia DIDs e IPs sintéticas overlay (`10.7.0.0/16` y `fd07::/64`).
- **Red Universal de Intención e Identidad (UIN):** Desacoplamiento de la clave raíz permanente de 256 bits de las claves operativas subordinadas y pasaportes de identidad.
- **Gestión de Ciclo de Vida de Microservicios:** Activación bajo demanda con huella de RAM cero en reposo (`DORMANT` $\to$ `ACTIVE` $\to$ `PRUNED`) y aislamiento por ámbito (`LOCAL`, `MESH`, `GLOBAL`).
- **Chat Soberano P2P E2EE:** Mensajería punto a punto cifrada con firmas Ed25519, confirmación de entrega y libreta de contactos sin intermediarios centrales.
- **Escritorio Remoto Soberano P2P:** Transmisión de frame buffers a 60 FPS con cifrado ML-KEM-768, emparejamiento SAS y despacho de eventos de teclado/mouse con latencia de cable $<100\,\mu\text{s}$.
- **Embajador LAN para Dispositivos Sombra:** Integración transparente de hardware físico local (impresoras, Smart TVs, cámaras, workers locales de inferencia Edge AI/Ollama) mapeados como DIDs en el segmento overlay `10.7.100.X/24`.

### Plano de Control IA: Servidor Model Context Protocol (MCP JSON-RPC 2.0)
- Exposición universal de **51+ herramientas nativas** según la especificación MCP (2024-11-05) en `http://127.0.0.1:7070/mcp`, permitiendo a agentes LLM inspeccionar telemetría, alterar políticas de enrutamiento y ejecutar diagnósticos de forma estructurada.

---

## 3. Prácticas Avanzadas de Auto-Evolución & Operación Autónoma

Para que otra IA o instancia desarrolle el sistema con máxima excelencia, se establecen las siguientes directivas obligatorias:

### 3.1. Sistema de Auto-Actualización Over-The-Air (OTA) & Hot-Swapping en Malla
- **Distribución Criptográfica de Módulos:** Toda actualización de código o esquema de protocolo debe empaquetarse como un bloque inmutable firmado en el DAG (`cid:ipvn7:manifest:...`).
- **Verificación Previa en Sandbox:** Antes de reemplazar un módulo en ejecución, la nueva implementación debe ejecutarse en un entorno de prueba aislado y pasar la suite completa de tests.
- **Rollback Instantáneo:** Si el nuevo módulo produce degradación de latencia, excepciones no capturadas o caída en la tasa de cumplimiento PFO (<100%), el orquestador revierte al snapshot anterior inmediatamente.

### 3.2. Control de Versiones Git Autónomo & Semantic Versioning
- **Inicialización Git Obligatoria:** Toda nueva instancia de desarrollo debe estar versionada bajo Git local desde el primer minuto.
- **Commits Semánticos Atómicos:** Cada subsistema nuevo, corrección o refactorización debe registrar un commit estructurado:
  - `feat(l1-quic): implement proactive 0-rtt handover tickets`
  - `fix(security-firewall): enforce strict rfc1918 anti-ssrf filtering on upnp`
  - `test(core): append 3 unit tests for wasm micro-pow verification`
  - `docs(rfc): add section 52 on wasm cryptographic bridge`
- **Etiquetado de Protocolo:** Cada hito que complete una capa o supere una batería de pruebas debe sellarse con tags semánticos (ej. `v7.0.0`, `v7.1.0-rc1`).

### 3.3. Optimización de Tokens & Economía de Contexto para LLMs
- **Modularidad Quirúrgica:** No crear archivos monolíticos gigantes innecesarios. Mantener los módulos enfocados (200-400 líneas por componente).
- **Uso Estricto de Ediciones por Diffs:** Utilizar herramientas de reemplazo puntual (`replace_file_content` o `multi_replace_file_content`) en lugar de sobreescribir archivos enteros, ahorrando miles de tokens de contexto.
- **Minificación Semántica en MCP:** Respuestas de telemetría densas deben estructurarse con claves concisas o soporte CBOR para evitar saturar la ventana de contexto del agente.

### 3.4. Búsqueda e Investigación Activa/Pasiva en Internet
- La IA debe buscar proactivamente en la web:
  - Nuevos borradores y RFCs del IETF (ej. QUIC Multipath, TLS Encrypted Client Hello ECH).
  - Actualizaciones del NIST en estándares FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) y FIPS 205 (SLH-DSA).
  - Algoritmos bio-inspirados y topologías Small-World de última generación.
- Traducir los hallazgos directamente a código ejecutable y pruebas unitarias en el repositorio.

### 3.5. Batería de Pruebas Innegociable (Zero Regressions)
- Toda modificación debe ejecutarse contra la suite de pruebas:
  ```powershell
  pytest -q
  ```
- **Regla de Oro:** **100% de tests aprobados siempre.** Si un test falla, la prioridad absoluta e inmediata de la IA es corregir la causa raíz antes de continuar con cualquier otra tarea.

---

## 4. Guía de Ejecución y Mandato para la Próxima Instancia

Si eres la IA o agente que toma el relevo de este proyecto:

1. **Revisa tu entorno:**
   - Workspace activo y virtualenv en `.venv`.
   - Verifica el estado de las pruebas ejecutando `pytest -q`.
2. **Inspecciona las fuentes complementarias en `C:\Users\Frondabrick\Desktop\dvd\Ipv7`:**
   - Revisa `0.7/src/pkg/` para extraer contratos adicionales de bajo nivel.
   - Revisa `Nexus one` y `Nexus tree` para adoptar su sistema de memoria jerárquica `.nexus/` y bitácoras ADR.
   - Revisa `ipvn7  vX7` para optimizaciones matemáticas de malla.
3. **Asegura la operatividad de los servicios:**
   - `python app/server.py` levantando Control Center en `:7070`, Proxy en `:8888` y SOCKS5 en `:10807`.
4. **Programa tu siguiente iteración:**
   - Lanza un temporizador de 30 minutos (`schedule` de 1800s) y procede inmediatamente a investigar, codificar y evolucionar el protocolo sin esperar instrucciones manuales.