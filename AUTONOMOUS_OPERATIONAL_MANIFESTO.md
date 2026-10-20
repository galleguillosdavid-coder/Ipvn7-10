# MANIFIESTO OPERACIONAL AUTÓNOMO IPVN 7
## Protocolo Soberano Post-Cuántico & Guía de Auto-Evolución para Agentes e Ingenieros

> **Versión Canónica de Referencia:** IPVN 7.0.0 (Python 3.14 + PQC Hybrid ML-KEM-768 / ML-DSA-65)  
> **Directiva Operativa Primaria:** Autonomía Absoluta, Cero Bloqueos, Cero Dependencias Innecesarias, 100% Pruebas Unitarias Verificadas.  
> **Fecha de Sincronización:** Octubre 2026

---

## 1. Visión y Misión del Sistema

El proyecto **IPVN 7 (Internet Protocol Version 7)** es una arquitectura de red soberana de próxima generación diseñada para superar las limitaciones estructurales de IPv4 e IPv6 frente a la computación cuántica, la censura centralizada y la falta de privacidad en Internet.

### Pilares Fundamentales:
1. **Criptografía Post-Cuántica Nativa (NIST FIPS 203 & 204):** Resistencia cuántica mediante ML-KEM-768 (Kyber) y ML-DSA-65 (Dilithium) en modo híbrido con X25519 y Ed25519.
2. **Identidad Descentralizada Soberana (DID):** Espacio de direccionamiento de 256 bits (`did:ipvn7:<hex>`), eliminando la dependencia de servidores DNS o entidades certificadoras (CA) centrales.
3. **Privacidad & Evasión de DPI por Defecto:** Enrutamiento cebolla Sphinx de 3 saltos, camuflaje TLS 1.3 RFC 8446 (`0x17 0x03 0x03`), detección activa de envenenamiento DNS e inyecciones TCP RST.
4. **Resiliencia Extrema & Auto-Reparación:** Red de mundo pequeño de Kleinberg ($r=2$), detector de fallos SWIM $O(1)$, protocolo de recuperación post-apagón en 5 fases, y copiloto IA de red con auto-reparación en bucle cerrado.
5. **Plano de Control Agéntico (MCP):** Servidor JSON-RPC 2.0 integrado con 57 herramientas nativas para introspección y gobierno autónomo por Modelos de Lenguaje (LLMs).

---

## 2. Catálogo de Subsistemas Activos (Capas L0 a L4)

Actualmente, el repositorio cuenta con **58 subsistemas de protocolo integrados** y probados al 100%:

### Capa L0: Acceso al Medio & Aceleración Datapath
- [`ipvn7/access/hal.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/hal.py): Capa de abstracción de hardware y driver de sockets UDP overlay.
- [`ipvn7/access/tun_wintun.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/tun_wintun.py): Adaptador virtual TUN Wintun de kernel con fallback transparente a userspace.
- [`ipvn7/access/batcher.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/batcher.py): Agrupador de datagramas (Batcher) de 1280B para reducción drástica de llamadas al sistema.
- [`ipvn7/access/buffer_monitor.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/buffer_monitor.py): Monitor lock-free de salud de buffers, seguimiento de High-Water Mark y alertas tempranas de fugas de memoria.
- [`ipvn7/access/memory_arbiter.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/memory_arbiter.py): Árbitro global de memoria RAM con 5 presupuestos estrictos (Replay, QoS, Trust, Bindings, Other) para inmunidad OOM-DoS.
- [`ipvn7/access/wasm_bridge.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/wasm_bridge.py): Puente criptográfico para WebAssembly y navegadores con resolución de Micro-PoW anti-Sybil.

### Capa L1: Transporte Cifrado Post-Cuántico & Evasión Perimetral
- [`ipvn7/crypto/bitnet.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/crypto/bitnet.py): Motor de cuantización ternaria BitNet b1.58 (-1, 0, 1) y contenedores IP7B para edge IoT ultra-económico sin multiplicación de punto flotante.
- [`ipvn7/transport/quic.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/transport/quic.py): Transporte seguro PQ-QUIC (RFC 9000) con handshake 1-RTT post-cuántico y migración de conexión sin pérdida de sesión.
- [`ipvn7/network/tls_obfuscation.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/tls_obfuscation.py): Disfraz de paquetes TLS 1.3 con cabeceras legítimas ClientHello/SNI y ApplicationData.
- [`ipvn7/network/wan_prober.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/wan_prober.py): Sonda WAN activa de 32 bytes binarios (`0x49503750` 'IP7P') con cálculo de Jitter RFC 3550 y RTT instantáneo/mínimo/máximo.
- [`ipvn7/network/nat_traversal.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/nat_traversal.py): Perforación directa de NAT UDP (STUN RFC 5389) con conmutación por fallo a relays soberanos DERP.
- [`ipvn7/network/upnp.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/upnp.py): Mapeo automático de puertos UPnP IGD / SSDP con blindaje estricto Anti-SSRF (solo RFC 1918, rechazo de 169.254/16).
- [`ipvn7/network/pacer.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/pacer.py): Limitador de tasa Token Bucket y planificador DWRR con 4 clases de tráfico (Control, Audio/Video, Bulk, Scavenger).
- [`ipvn7/network/multipath.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/multipath.py): Planificador de transporte multipath (MPTS) con selección por menor latencia, weighted round-robin y duplicación concurrente bicast.

### Capa L2: Topología, Enrutamiento Distribuido & Resiliencia
- [`ipvn7/network/dht.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/dht.py): Tabla hash distribuida (DHT) jerárquica de mundo pequeño basada en métrica XOR de 256 bits.
- [`ipvn7/network/onion.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/onion.py): Enrutador cebolla Sphinx de 3 saltos con tramas fijas de 1280 bytes y cifrado de flujo ChaCha20.
- [`ipvn7/network/gossip.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/gossip.py): Protocolo epidémico Plumtree con árboles impaciente y perezoso (PRUNE / GRAFT).
- [`ipvn7/network/swim.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/swim.py): Detector de fallos SWIM $O(1)$ con sondeo directo y delegación indirecta `Ping-Req`.
- [`ipvn7/network/healing.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/healing.py): Algoritmo de curación de enlaces con histéresis anti-flapping y amortiguamiento RFC 2439.
- [`ipvn7/network/blackout.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/blackout.py): Máquina de recuperación ante apagón en 5 fases con temporizador de Jitter descorrelacionado anti-estampida.
- [`ipvn7/network/blind_rendezvous.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/blind_rendezvous.py): Adaptador de punto de encuentro ciego con tópicos efímeros por época, Zero-PII y disyuntor automático.
- [`ipvn7/network/planetary.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/planetary.py): Malla interplanetaria en cuadrícula 2D según modelo de Kleinberg con retardo relativista según $c$.
- [`ipvn7/network/resilience.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/resilience.py): Disyuntor tri-estado (Closed, Open, Half-Open) con backoff exponencial con Full Jitter.
- [`ipvn7/network/split_brain.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/split_brain.py): Guardián anti-bipartición de red con quórum estricto y estados Healthy, Partitioned, Recovering.
- [`ipvn7/network/explainable.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/explainable.py): Motor explicable de selección de rutas con balanceo ponderado (RTT, Jitter, Pérdidas, PQC Trust Tier, Batería) y justificación estructurada en lenguaje natural.
- [`ipvn7/network/mobility_anchor.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/mobility_anchor.py): Ancla topológica de movilidad con tickets proactivos 0-RTT, secuencia monótona y soporte Micro-PoW.
- [`ipvn7/network/fsm.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/fsm.py): Autómata finito determinista (FSM) de ciclo de vida del nodo con contención ZTNA.
- [`ipvn7/network/pipeline.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/pipeline.py): Línea de montaje Pipes & Filters con captura inmutable en Dead-Letter Queue.
- [`ipvn7/network/hrs_frames.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/hrs_frames.py): Sustrato silencioso IPv7-HRS ("La Red Responde, No Grita") con 5 tramas canónicas (`IP7H`) y SLAs adaptativos por perfil.

### Capa L3: Seguridad ZTNA, Confianza & Diagnóstico
- [`ipvn7/security/firewall.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/security/firewall.py): Cortafuegos de microsegmentación Zero-Trust (ZTNA) con política Default-Deny en el datapath.
- [`ipvn7/security/wot.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/security/wot.py): Red de confianza descentralizada (Web-of-Trust) con atenuación geométrica transitiva ($0.85^d$).
- [`ipvn7/security/anti_replay.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/security/anti_replay.py): Filtro anti-reproducción de ventana deslizante de 1024 bits (RFC 4303) en tiempo $O(1)$.
- [`ipvn7/security/delegation.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/security/delegation.py): Cadena de custodia agéntica (Agentic Principal Chain) con atenuación monótona de privilegios y firmas Ed25519.
- [`ipvn7/security/dark_node.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/security/dark_node.py): Macro-orquestador de perfil sigiloso Dark Node (silenciamiento de listeners, Sphinx forzado, micro-jitter).
- [`ipvn7/security/key_rotation.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/security/key_rotation.py): Centinela de rotación proactiva de claves de sesión (Forward Secrecy) con ventana de gracia de 30 segundos.
- [`ipvn7/security/oob.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/security/oob.py): Emparejamiento fuera de banda con Short Authentication String (SAS 6 dígitos + 4 emojis) y fragmentador UR multipart.
- [`ipvn7/diagnostics/anomaly.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/diagnostics/anomaly.py): Huellador de anomalías con firmas SHA-256 de 12 caracteres hex categorizadas por severidad.
- [`ipvn7/diagnostics/spectral.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/diagnostics/spectral.py): Transformada Discreta de Fourier (DFT) para cálculo de densidad espectral de potencia y detección de resonancia periódica de jitter.
- [`ipvn7/diagnostics/copilot.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/diagnostics/copilot.py): Copiloto IA de red con inferencia de causa raíz y remediación en bucle cerrado (BLOCK_DID, FAILOVER_PATH, TUNE_PACER).
- [`ipvn7/diagnostics/censorship.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/diagnostics/censorship.py): Detector activo de censura, envenenamiento DNS e inyección de TCP RST por DPI.
- [`ipvn7/diagnostics/pfo.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/diagnostics/pfo.py): Motor de gobernanza ontológica PFO (5 Principios -> 12 Funciones -> Observaciones) con 100% de cumplimiento formal.

### Capa L4: Aplicación Soberana, Servicios & Pasarelas
- [`ipvn7/gateway/socks5.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/gateway/socks5.py): Servidor Proxy SOCKS5 (RFC 1928) en `127.0.0.1:10807`.
- [`ipvn7/storage/dag.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/storage/dag.py): Almacén inmutable DAG direccionado por contenido (`cid:ipvn7:<sha256>`) y cola asíncrona DTN con flush automático al handshake.
- [`ipvn7/identity/petnames.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/identity/petnames.py): Resolución de nombres descentralizada (.ipv7) a DIDs e IPs sintéticas overlay (`10.7.0.0/16`, `fd07::/64`).
- [`ipvn7/identity/ephemeral.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/identity/ephemeral.py): Identidad efímera rotativa de 24 horas (`did:ipvn7:ephemeral:...`) por HMAC-SHA256 para inmunidad anti-fingerprinting.
- [`ipvn7/identity/uin.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/identity/uin.py): Red Universal de Intención e Identidad (UIN) con desacoplamiento de clave raíz de 256 bits y cadenas de delegación rotativas.
- [`ipvn7/access/services.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/services.py): Gestor de ciclo de vida de microservicios con huella de RAM cero en reposo (Dormant -> Active -> Pruned).
- [`ipvn7/access/chat.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/chat.py): Chat soberano P2P cifrado E2EE con firmas digitales Ed25519 y libreta de contactos.
- [`ipvn7/access/remote_desktop.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/remote_desktop.py): Escritorio remoto soberano P2P a 60 FPS con cifrado ML-KEM-768, validación SAS OOB y despacho de eventos en <100µs.
- [`ipvn7/access/shadow_device.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/shadow_device.py): Embajador LAN para dispositivos sombra (impresoras, Smart TVs, nodos Ollama/Edge AI) asignando DIDs deterministas e IPs 10.7.100.X/24.
- [`ipvn7/network/dns_proxy.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/network/dns_proxy.py): Proxy DNS anti-fugas con caché local y resolución petname nativa.

### Plano de Control IA (MCP Server JSON-RPC 2.0)
- [`ipvn7/node/mcp.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/node/mcp.py): **57 herramientas nativas de introspección, streaming, BitNet y comando** expuestas según la especificación Model Context Protocol (2024-11-05).

---

## 3. Instrucciones Específicas de Ejecución & Validación

Cualquier agente o usuario puede verificar y ejecutar el sistema de forma completamente autónoma:

### 3.1. Entorno de Ejecución
- **Sistema Operativo:** Windows 10/11 (compatible nativamente con PowerShell), Linux o macOS.
- **Python:** Python 3.14.x instalado en el entorno virtual local:  
  `c:\Users\Frondabrick\Desktop\dvd\Ipv7\ipvn7-10\.venv\Scripts\python.exe`
- **Dependencias Obligatorias:** Solo librería estándar y paquete `cryptography`. Cero frameworks inflados.

### 3.2. Ejecución de la Suite de Pruebas (Zero Regressions)
```powershell
# Ejecutar la suite completa de 84 tests unitarios
cd c:\Users\Frondabrick\Desktop\dvd\Ipv7\ipvn7-10
.\.venv\Scripts\pytest.exe -q
```
*Criterio de Aceptación Obligatorio:* **100% de tests aprobados (84/84) con código de salida 0.**

### 3.3. Lanzamiento del Servidor y Control Center Web
```powershell
# Iniciar el daemon del nodo y servidor de observabilidad en segundo plano
cd c:\Users\Frondabrick\Desktop\dvd\Ipv7\ipvn7-10
.\.venv\Scripts\python.exe app/server.py
```

### 3.4. Puntos de Entrada de Red
| Servicio | Endpoint | Protocolo / Propósito |
|---|---|---|
| **Control Center SPA** | `http://127.0.0.1:7070/` | Dashboard interactivo con telemetría en tiempo real y consola MCP |
| **Servidor MCP** | `http://127.0.0.1:7070/mcp` | API JSON-RPC 2.0 con 57 herramientas para agentes LLM |
| **Proxy HTTP/HTTPS** | `http://127.0.0.1:8888/` | Pasarela de intercepción transparente para tráfico de aplicaciones |
| **Proxy SOCKS5** | `127.0.0.1:10807` | Proxy RFC 1928 para tráfico TCP anónimo sobre la malla cuántica |
| **Overlay UDP** | `127.0.0.1:9443` (primario) | Datapath QUIC cifrado punto a punto |

---

## 4. Instrucciones Investigativas Abiertas (Direcciones de Auto-Evolución)

Para que el agente o la IA continúe investigando, expandiendo y perfeccionando el repositorio, se establecen las siguientes líneas abiertas:

### Línea A: Exploración de Repositorios Históricos en `C:\Users\Frondabrick\Desktop\dvd\Ipv7`
1. **`0.7/src/pkg/core` y `0.7/src/pkg/l0`**:
   - Inspeccionar estructuras avanzadas de serialización binaria Zero-Copy y pools de memoria que puedan integrarse en `ipvn7/access/`.
2. **`Nexus one`, `Nexus two`, `Nexus tree`**:
   - Analizar el sistema de memoria jerárquica `.nexus/memory/level1_core.json`, las bitácoras de decisiones (ADRs) y el motor de auto-programación en ciclos de 22 pasos para enriquecer la autonomía reflexiva del nodo.
3. **`ipvn7  vX7` y `ipvn7 vX original`**:
   - Auditar optimizaciones de enrutamiento multidimensional y modelos matemáticos de propagación de señales en mallas ad-hoc.

### Línea B: Compilación WebAssembly Real (Client-Side PQC in Browser)
- El módulo [`ipvn7/access/wasm_bridge.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/wasm_bridge.py) contiene las interfaces canónicas para generación de identidades y Micro-PoW.
- **Investigación abierta:** Compilar estas primitivas a WebAssembly nativo (utilizando Pyodide o TinyGo) para que `app/static/app.js` pueda ejecutar el apretón criptográfico ML-KEM directamente en el navegador del cliente sin transmitir claves privadas a `app/server.py`.

### Línea C: Aceleración de Kernel & Integración con Wintun Driver C-ABI
- El módulo [`ipvn7/access/tun_wintun.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/tun_wintun.py) posee fallback a userspace.
- **Investigación abierta:** Cargar dinámicamente `wintun.dll` mediante `ctypes` cuando el usuario disponga de privilegios de Administrador para crear una interfaz de red virtual en el Panel de Control de Windows capaz de enrutar el 100% del tráfico del sistema hacia `10.7.0.0/16`.

### Línea D: Optimización de Tokens y Contexto para Agentes LLM
- Las respuestas JSON de herramientas MCP pueden compactarse aún más:
  - Formato CBOR comprimido o minificación de claves en respuestas de telemetría de alta frecuencia.
  - Generación de resúmenes semánticos compactos que maximicen la densidad informativa de cada token consumido por el asistente.

### Línea E: Integración de Inferencia Edge AI Local (BitNet / Ollama)
- Aprovechar el subsistema [`ipvn7/access/shadow_device.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/access/shadow_device.py) (tipo `edge_ai`) para permitir que el nodo delegue consultas de diagnóstico a modelos 1-bit locales o servidores locales de Ollama, permitiendo auto-reparación 100% offline sin conexión a nubes comerciales.

---

## 5. Protocolo de Auto-Mejora Continua y Temporizador (`schedule`)

Para mantener el ciclo de vida evolutivo sin intervención humana:

1. **Configurar el temporizador recurrente (`schedule`):**
   ```python
   schedule(DurationSeconds="1800", Prompt="Ciclo Autónomo IPVN 7: Ejecutar siguiente iteración de auto-mejora, sincronización de capas y evolución técnica continua.", TimerCondition="never")
   ```
2. **Procedimiento de cada ciclo autónomo:**
   - **Paso 1: Auditoría de Integridad.** Ejecutar `pytest` y revisar logs de anomalías.
   - **Paso 2: Inspección y Selección.** Revisar una de las carpetas históricas o una de las líneas abiertas de investigación.
   - **Paso 3: Desarrollo Incremental.** Diseñar, codificar e integrar el nuevo subsistema o la optimización en `ipvn7-10`.
   - **Paso 4: Verificación Rigurosa.** Añadir pruebas unitarias en `tests/test_ipvn7.py` garantizando 100% de aprobación sin regresiones.
   - **Paso 5: Exposición en Capas Superiores.** Añadir endpoints REST en `app/server.py`, registrar la herramienta en `ipvn7/node/mcp.py` y actualizar el selector en `app/static/index.html`.
   - **Paso 6: Sincronización Documental.** Actualizar `IPVN7_RFC_SPECIFICATION.md` con las nuevas secciones normativas.
   - **Paso 7: Re-agendar el ciclo.** Volver al Paso 1 mediante `schedule`.

3. **Tarea Ocasional: Auditoría Externa Multi-LLM con ChatGPT ([https://chatgpt.com/](https://chatgpt.com/)):**
   - **Objetivo:** Ejecutar periódicamente o tras cada hito arquitectónico una auditoría cruzada independiente con ChatGPT para revisión adversaria de seguridad ZTNA, análisis de resistencia cuántica y coherencia RFC.
   - **Procedimiento:** Proveer el contexto de los ADRs consolidados y el RFC actual a la interfaz de [https://chatgpt.com/](https://chatgpt.com/), auditar posibles fallas de borde (split-brain, replay, desincronización de identidades efímeras) y trasladar los hallazgos validados a nuevos ADRs y pruebas unitarias de regresión en `tests/test_ipvn7.py`.

---

## 6. Filosofía de Ingeniería

> *"La perfección no se alcanza cuando no hay nada más que añadir, sino cuando no hay nada más que quitar."*

- **Cero Sobreingeniería:** Eliminar capas de abstracción superfluas; favorecer funciones y clases directas, deterministas y testeables.
- **Inmutabilidad de Contratos:** El formato wire canónico de 1280 bytes nunca debe corromperse.
- **Transparencia:** Todo evento debe ser audible mediante huellas criptográficas y explicaciones comprensibles.
