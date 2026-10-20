# IPVN 7 — Internet Protocol Version 7
> **Next-Generation Post-Quantum Sovereign Internet Protocol**  
> *Implementación Canónica en Python 3.14 con Criptografía Híbrida NIST FIPS 203 & 204*

---

## ⚡ Guías Principales de Documentación
- **[Manifiesto Operacional Autónomo & Guía de Auto-Evolución](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/AUTONOMOUS_OPERATIONAL_MANIFESTO.md)**: Manual exhaustivo para operación autónoma de agentes, orden de subsistemas, comandos deterministas e instrucciones de investigación abierta.
- **[Especificación RFC de IPVN 7](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/IPVN7_RFC_SPECIFICATION.md)**: 52 secciones normativas detallando la arquitectura de capas L0-L4, wire formats de 1280B y contratos criptográficos.
- **[Principios de Génesis](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/genesis.md)**: Declaración de principios axiomáticos y visión fundacional.

---

## 🚀 Inicio Rápido (Quickstart)

### 1. Ejecutar la Batería de Pruebas
```powershell
.\.venv\Scripts\pytest.exe -q
```
*Estado actual:* **74/74 pruebas unitarias aprobadas al 100%** en ~4.89s.

### 2. Iniciar el Servidor de Red y Control Center
```powershell
.\.venv\Scripts\python.exe app/server.py
```

### 3. Puntos de Conexión
- **Control Center SPA (Dashboard Web):** [http://127.0.0.1:7070](http://127.0.0.1:7070)
- **Servidor MCP JSON-RPC 2.0 (51 herramientas nativas):** [http://127.0.0.1:7070/mcp](http://127.0.0.1:7070/mcp)
- **Proxy HTTP/HTTPS Interceptor:** `127.0.0.1:8888`
- **SOCKS5 Proxy RFC 1928:** `127.0.0.1:10807`

---

## 🛡️ Resumen de Capacidades
- **Criptografía Post-Cuántica (PQC):** ML-KEM-768 + X25519 y ML-DSA-65 + Ed25519 en todas las sesiones y firmas.
- **Enrutamiento Inteligente:** Sphinx 3-Hop Onion, DHT Small-World Kleinberg, Epidemic Gossip Plumtree, SWIM Failure Detector, Multipath Striping y Reloj Relativista.
- **Seguridad ZTNA & Anti-Censura:** Default-Deny datapath, camuflaje TLS 1.3 con SNI neutro, auditoría de inyecciones TCP RST y envenenamiento DNS.
- **Aplicaciones Soberanas:** Chat P2P E2EE, Escritorio Remoto a 60 FPS con SAS OOB (<100µs wire dispatch), Almacén Inmutable DAG (`cid:ipvn7:...`), dDNS Petnames (`.ipv7`), Pasaporte de Identidad UIN y puente WebAssembly.
