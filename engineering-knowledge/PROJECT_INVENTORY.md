# INVENTARIO DE PROYECTOS Y VERSIONES HISTÓRICAS (PROJECT INVENTORY) — LAIA

**Fecha de Relevamiento:** 20 de Octubre de 2026  
**Ámbito:** Unidades locales C: y D:  

---

## 1. Proyectos en Unidad C: (`C:\Users\Frondabrick\Desktop\dvd\Ipv7\`)

| Directorio | Tecnología | Estado | Descripción y Hallazgos |
| :--- | :--- | :--- | :--- |
| **`ipvn7-10`** | Python 3.14 / PQC | **ACTIVO (v7.10.0)** | Implementación de referencia actual. Handshake híbrido NIST FIPS 203/204 con firma digital, Exit Node Relay, SOCKS5 acotado, BitNet b1.58, Small-World DHT y 108 pruebas pasando. |
| **`ipvn7  vX7`** | Go / Python | Histórico | Prototipo híbrido con `pkg/l1/socks5_gateway.go`. Introdujo la pasarela SOCKS5 original pero realizaba conexiones directas sin overlay. |
| **`ipvn7 vX`** | Python | Histórico | Experimentos tempranos de routing por capas y sockets directos. |
| **`0.7` / `0.7 - copia`** | Python | Histórico | Primeros prototipos de tramas canónicas y descubrimiento P2P básico. |
| **`Nexus one`, `two`, `tree`** | Python / JSON | Histórico | Subsistemas de gobernanza, topologías en árbol y Small-World DHT. |
| **`Versiones_Anteriores`** | Mixto | Archivo | Repositorio histórico de experimentos previos. |

---

## 2. Proyectos y Documentos en Unidad D: (`D:\David\dvd\` y subdirectorios)

| Ruta | Formato | Estado | Contenido Relevante |
| :--- | :--- | :--- | :--- |
| **`D:\David\dvd\ipv7-hrs-final`** | C / Sockets | Histórico | Implementación en C de alto rendimiento para el subsistema HRS. Base del procesamiento a nivel de bytes. |
| **`D:\David\dvd\ipv7c`** | C / C++ | Histórico | Motor nativo de sockets raw y captura de paquetes de red. |
| **`D:\David\dvd\Ipv7IEU`** | Especificación | Histórico | Definición de la interfaz ontológica del protocolo y la ontología UIN. |
| **`D:\David\dvd\IPv7-HRS_Arquitectura_Completa.md`** | Markdown | Histórico | Documento maestro de arquitectura del protocolo IPv7-HRS y sus principios cuánticos. |
| **`D:\David\dvd\launch_ipvn7.ps1`** | PowerShell | Operativo | Scripts de orquestación y arranque de servicios en Windows. |
| **`D:\David\dvd\Ipv7-4` / `Ipv7-5`** | Python / C | Histórico | Iteraciones previas de la capa de transporte y datagramas. |

---

## 3. Matriz de Extracción Permanente

### Lo que se DEBE Reutilizar
1. **Identidad UIN Soberana:** Desacoplamiento de la identidad del nodo de su IP física de transporte.
2. **Tramas Fijas Anti-Análisis (Sphinx 1280 bytes):** Inmunidad ante análisis de tráfico e inspección profunda de paquetes (DPI).
3. **Kleinberg Small-World DHT:** Entrega en $O(\log^2 N)$ saltos bajo particiones de red severas.
4. **BitNet b1.58:** Aritmética entera pura de sumas y restas para inferencia ultraligera en nodos de borde.

### Lo que se DEBE Erradicar
1. Credenciales o tokens estáticos en código fuente.
2. Afirmaciones de telemetría de red no respaldadas por bytes reales en el overlay.
3. Handshakes híbridos sin firma digital de transcript contra ataques MITM.
4. Deserialización de modelos binarios sin validación estricta de cotas.
5. Exposición de secretos compartidos en APIs o interfaces de usuario.
6. Creación ilimitada de hilos sin semáforos de concurrencia.
