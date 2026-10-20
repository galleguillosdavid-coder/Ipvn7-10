# ADR-004: Remediación Integral de la Auditoría Técnica y de Seguridad Externa (ChatGPT Audit)

**Estado:** APROBADO & IMPLEMENTADO  
**Fecha:** 20 de octubre de 2026  
**Autor:** Agente Autoevolutivo Autónomo IPVN 7  
**Contexto de Auditoría:** Revisión técnica independiente multi-LLM realizada vía [ChatGPT](https://chatgpt.com/) sobre el repositorio [galleguillosdavid-coder/Ipvn7-10](https://github.com/galleguillosdavid-coder/Ipvn7-10).

---

## 1. Resumen Ejecutivo de la Auditoría

La auditoría técnica externa analizó la arquitectura criptográfica, datapath de red, APIs de control y reproducibilidad del proyecto, emitiendo 5 hallazgos prioritarios clasificados de H-01 a H-05. La presente decisión documenta la resolución arquitectónica, matemática e ingenieril punto a punto ejecutada de forma autónoma.

---

## 2. Hallazgos y Remediaciones Ejecutadas

### 🛡️ H-01: Datapath Real del Proxy a través del Túnel Overlay PQ-QUIC
- **Hallazgo:** El proxy local abría sockets TCP directos mediante `remote_sock.connect` y la interfaz `/api/internet/fetch` no evidenciaba de forma matemática la travesía de datagramas por el túnel cifrado ML-KEM-768/X25519 hacia el nodo de egreso (`exit_node`).
- **Resolución Implementada:**
  - En [`ipvn7/gateway/proxy.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/gateway/proxy.py), se estableció el parámetro formal `mode: str = "OVERLAY_TUNNELED"` (con fallback configurable `"DIRECT_EGRESS"`).
  - En modo `OVERLAY_TUNNELED`, el proxy encapsula metadatos y peticiones en datagramas `IPVN7_TUNNEL_EGRESS` transmitidos mediante `node.send_message_sync(exit_node.did, tunnel_envelope)` sobre la sesión PQ-QUIC real.
  - La telemetría reporta fielmente `"status": "TUNNELED_PQ_QUIC"` si y solo si la verificación overlay fue exitosa, registrando `overlay_verified: True` y el DID del nodo de egreso (`exit_node_did`).
  - En [`app/server.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/app/server.py), el endpoint `/api/internet/fetch` transmite la orden de egreso a través de `PRIMARY_NODE.send_message_sync(PEER_NODE.did, egress_envelope)` e informa la huella digital criptográfica (`fp:{session_key_fp}`) de la clave de sesión compartida activa.

---

### 🔐 H-02: Protocolo Híbrido Criptográfico con Transcript Binding y Pruebas Negativas
- **Hallazgo:** El retorno de `client_init()` declaraba 3 elementos pero devolvía 4. La derivación HKDF utilizaba un salt estático sin vincular formalmente las identidades efímeras negociadas (riesgo de sustitución y manipulación). Se requerían pruebas negativas de rechazo seguro.
- **Resolución Implementada:**
  - En [`ipvn7/crypto/pqc.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/ipvn7/crypto/pqc.py):
    - Corregida la anotación de tipos de `client_init()` para retornar la tupla exacta de 4 elementos: `Tuple[bytes, bytes, x25519.X25519PrivateKey, mlkem.MLKEM768PrivateKey]`.
    - Implementado **Transcript Binding**: el salt del HKDF se calcula mediante el resumen criptográfico SHA-256 de todas las claves efímeras del intercambio:
      $$\text{transcript\_hash} = \text{SHA256}(\text{client\_x25519\_pub} \parallel \text{server\_x25519\_pub} \parallel \text{mlkem\_ciphertext})$$
      Cualquier alteración o sustitución en tránsito de las claves públicas efímeras o del texto cifrado ML-KEM genera una clave derivada discordante.
  - En [`tests/test_ipvn7.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/tests/test_ipvn7.py), se añadieron pruebas negativas rigurosas:
    - `test_pqc_handshake_tampered_ciphertext_fails`: prueba que la inversión de 1 bit en el ciphertext ML-KEM hace fallar con seguridad la desencapsulación o el descifrado AEAD.
    - `test_pqc_handshake_tampered_x25519_key_fails`: prueba que la manipulación de la clave pública X25519 del servidor altera el transcript binding y provoca rechazo seguro inmediato.
    - `test_pqc_signature_tampered_message_fails`: prueba que un mensaje alterado falla la verificación híbrida ML-DSA-65 + Ed25519.

---

### 🌐 H-03: Especificación Formal de PQ-QUIC como Transporte Soberano P2P
- **Hallazgo:** La implementación PQ-QUIC posee un encabezado propietario de 21 bytes y algoritmo BBR adaptado, por lo que no debe confundirse con la implementación de QUIC sobre TLS 1.3 tradicional conforme a RFC 9000/9001 (orientada a clientes Web legados con dependencias de Autoridades de Certificación X.509).
- **Resolución Implementada:**
  - Se documenta formalmente en [`README.md`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/README.md) y [`IPVN7_RFC_SPECIFICATION.md`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/IPVN7_RFC_SPECIFICATION.md) que **PQ-QUIC es un protocolo de transporte soberano experimental con wire framing canónico de 21 bytes**:
    - Optimizado para mallas descentralizadas P2P y constelaciones satelitales con MTU estricto de 1280 bytes.
    - Elimina la dependencia de la infraestructura centralizada de PKI/X.509 y TLS 1.3 tradicional, anclando la confianza en Identidades Descentralizadas (DIDs criptográficos W3C) y el intercambio híbrido ML-KEM-768/X25519.

---

### 🔒 H-04: Seguridad de la API Local, Restricción CORS y Prevención SSRF
- **Hallazgo:** El panel exponía `Access-Control-Allow-Origin: *` en respuestas JSON, carecía de límite en el tamaño de cuerpos POST y permitía solicitudes hacia cualquier URL en `/api/internet/fetch` sin filtro de SSRF.
- **Resolución Implementada:**
  - En [`app/server.py`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/app/server.py):
    - **CORS Restringido:** Se eliminó el comodín `*`. Se implementó lista blanca estricta que únicamente autoriza peticiones con origen local (`http://127.0.0.1:7070` y `http://localhost:7070`). Peticiones foráneas no reciben encabezados CORS permisivos.
    - **Manejador `do_OPTIONS`:** Se incorporó respuesta formal pre-flight con encabezados de seguridad `X-Content-Type-Options: nosniff` y `X-Frame-Options: DENY`.
    - **Protección DoS por Carga Útil:** En `do_POST`, se valida el encabezado `Content-Length`. Peticiones que superen 1 MB (1,048,576 bytes) son rechazadas inmediatamente con código `413 Payload Too Large`.
    - **Mitigación Estricta de SSRF:** En `/api/internet/fetch`, se rechazan esquemas distintos a `http` y `https`. Se bloquean todas las peticiones dirigidas a interfaces de loopback (`127.0.0.1`, `localhost`), enlaces locales de metadatos en la nube (`169.254.169.254`) y bloques de direccionamiento privado RFC 1918 (`10.0.0.0/8`, `192.168.0.0/16`).

---

### 📦 H-05: Reproducibilidad Absoluta del Entorno y Pipeline CI
- **Hallazgo:** `requirements.txt` presentaba inconsistencias de codificación y faltaba pipeline de integración continua que respaldara las afirmaciones documentales de las pruebas unitarias.
- **Resolución Implementada:**
  - Reescrito [`requirements.txt`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/requirements.txt) en UTF-8 estándar fijando dependencias mínimas requeridas (`cryptography>=44.0.0`, `pytest>=8.0.0`).
  - Creado el flujo de trabajo de Integración Continua en [`.github/workflows/ci.yml`](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/.github/workflows/ci.yml) para ejecutar automáticamente las pruebas bajo Python 3.12, 3.13 y 3.14 en entornos limpios de Ubuntu y Windows.
  - La suite de pruebas se expandió a **88 pruebas unitarias aprobadas al 100% (0 fallos) en 6.57s**.

---

## 3. Estado de la Suite de Pruebas Unitarias

```
============================== 88 passed in 6.57s ==============================
```
- **84 pruebas base:** Arquitectura canónica, criptografía PQC, transporte PQ-QUIC, DHT, ZTNA, DAG, WoT, SOCKS5, proxies, BitNet b1.58, Edge AI LAN y Churn stress.
- **4 pruebas nuevas post-auditoría:**
  1. `test_pqc_handshake_tampered_ciphertext_fails` (Protección contra manipulación KEM).
  2. `test_pqc_handshake_tampered_x25519_key_fails` (Transcript Binding validation).
  3. `test_pqc_signature_tampered_message_fails` (Verificación estricta de integridad de firma).
  4. `test_proxy_overlay_mode_validation` (Verificación de aislamiento de modo de túnel overlay).
