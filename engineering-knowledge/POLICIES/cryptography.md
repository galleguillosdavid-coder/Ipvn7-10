# POLÍTICA DE GESTIÓN CRIPTOGRÁFICA Y HANDSHAKES — LAIA

**ID:** `POL-SEC-003`  
**Ámbito:** Criptografía Postcuántica e Híbrida en IPVN 7  

---

## 1. Principio Rector
Ningún algoritmo criptográfico se implementará de forma casera si existe una biblioteca estándar, mantenida y auditada que lo implemente (`cryptography` sobre OpenSSL 3.5.0-dev).

## 2. Invariantes del Handshake Híbrido PQC
1. **Doble Capa:** Toda negociación debe combinar obligatoriamente una primitiva clásica de alta velocidad (`X25519` / `Ed25519`) y una primitiva postcuántica aprobada por NIST (`ML-KEM-768` / `ML-DSA-65`).
2. **Transcript Binding Obligatorio:** El material de derivación debe incorporar el hash SHA-256 de todos los mensajes intercambiados en el handshake como salt del HKDF.
3. **Firma Digital de Identidad:** El servidor debe firmar el transcript hash con su clave de identidad de largo plazo. El cliente debe verificar la firma contra la clave pública del servidor antes de computar la clave de sesión simétrica.
4. **Censura de Secretos en APIs:** Queda prohibida la serialización de secretos compartidos (`shared_secret_hex`) en respuestas JSON o logs de telemetría.
5. **Rotación Silenciosa y Forward Secrecy:** Las claves de sesión deben tener tiempos de expiración y límites de paquetes transmitidos antes de desencadenar rekeying automático (`rotate_session_key`).
