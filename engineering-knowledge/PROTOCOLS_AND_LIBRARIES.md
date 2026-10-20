# ESPECIFICACIÓN DE PROTOCOLOS, ESTÁNDARES Y BIBLIOTECAS — LAIA

**Versión:** 1.0  
**Ámbito:** Criptografía y Red en IPVN 7  

Este documento justifica la elección técnica de estándares internacionales y bibliotecas criptográficas implementadas en IPVN 7.

---

## 1. Primitivas Criptográficas Implementadas

| Algoritmo | Estándar Oficial | Función en IPVN 7 | Justificación Técnica |
| :--- | :--- | :--- | :--- |
| **ML-KEM-768** | NIST FIPS 203 (Agosto 2024) | Encapsulación de Claves Postcuántica (KEM) | Nivel 3 de seguridad NIST (equivalente a AES-192). Resistencia contra algoritmos de Shor y ataques retrospectivos. |
| **ML-DSA-65** | NIST FIPS 204 (Agosto 2024) | Firma Digital Postcuántica | Autenticación criptográfica de identidades de nodos y firmado de transcripts en el handshake. |
| **X25519** | RFC 7748 | Intercambio Clásico Diffie-Hellman | Protección híbrida clásica comprobada. Inmunidad ante fallas de implementación en primitivas PQC tempranas. |
| **Ed25519** | RFC 8032 | Firma Digital Clásica de Alta Velocidad | Firma de tramas de control, petnames, beacons ciegos y tokens UIN. Cross-signing con ML-DSA-65. |
| **HKDF-SHA256** | RFC 5869 | Derivación y Expansión de Claves | Derivación determinista del secreto de sesión combinando el secreto clásico y el secreto cuántico con salt de transcript. |
| **AES-256-GCM** | NIST SP 800-38D | Cifrado Autenticado (AEAD) | Cifrado simétrico de datagramas QUIC y tramas overlay `IP7X` con autenticación de integridad de 128 bits. |

---

## 2. Bibliotecas y Dependencias

- **`cryptography` ($\ge$ 44.0.0, actualmente 50.0.2):** Biblioteca criptográfica de referencia basada en Rust y OpenSSL 3.5.0-dev. Proporciona implementaciones formales, auditadas y aceleradas por hardware de NIST FIPS 203 y FIPS 204.
- **Biblioteca Estándar de Python (`secrets`, `hashlib`, `socket`, `threading`, `struct`, `urllib`):** Cero dependencias externas adicionales en tiempo de ejecución. Reduce la superficie de ataque de la cadena de suministro al mínimo absoluto.

---

## 3. Protocolos de Red de Referencia

- **RFC 1928 / RFC 1929:** Protocolo SOCKS5 para interoperabilidad con software comercial estándar (navegadores, curl, SSH).
- **RFC 9000 / RFC 9001:** Principios de transporte multiplexado sobre UDP (inspiración de PQ-QUIC).
- **Sphinx Onion Routing:** Formato de tramas fijas de 1280 bytes para anonimato de ruta y prevención de análisis de tráfico.
- **Kleinberg Small-World DHT:** Modelo de enrutamiento epidémico descentralizado en $O(\log^2 N)$ saltos.
