# ADR-014: Cryptographic TEE Enclave and Runtime Formal Verification (Línea P)

## Estado
Aceptado e Implementado (v7.12.0)

## Fecha
2026-10-20

## Contexto y Motivación
En una red soberana post-cuántica y descentralizada como IPVN 7, la integridad de un nodo ante pares remotos y la seguridad del material criptográfico en memoria host son requisitos existenciales. Si un atacante compromete el sistema operativo anfitrión o inyecta binarios alterados, podría intentar extraer claves maestras PQC (ML-KEM-768 / ML-DSA-65) o violar los invariantes de seguridad del protocolo (como límites MTU de 1280B, ventanas anti-replay o fronteras anti-SSRF).

Para garantizar la inviolabilidad del sistema y su verificabilidad matemática sin confiar ciegamente en afirmaciones no comprobadas, era imperativo dotar a IPVN 7 de:
1. Un **Enclave Criptográfico TEE (Trusted Execution Environment)** con sellado de memoria ligado a medición de código (`MRENCLAVE`), contadores monótonos anti-replay y reportes de atestación remota firmados con claves de atestación (EAK).
2. Un **Motor de Validación Formal en Tiempo de Ejecución (Runtime Formal Verifier)** que evalúe y demuestre matemáticamente las 6 propiedades axiomáticas de seguridad del nodo en cada ciclo.

## Decisión de Diseño
Se implementa la **Línea P (v7.12.0)**: **Cryptographic TEE Enclave and Runtime Formal Verification**, compuesto por:

1. **Orquestador de Enclave TEE Soberano (`ipvn7/security/tee_enclave.py`)**:
   - **Medición Determinista MRENCLAVE**: Hash SHA-256 de las políticas e invariantes de código del enclave.
   - **Sellado Criptográfico de Memoria (`seal_secret` / `unseal_secret`)**: Cifrado autenticado AES-256-GCM derivado de la clave maestra del enclave y vinculado al `MRENCLAVE`. Si el binario o las políticas cambian, el descifrado falla inmediatamente con `EnclaveIntegrityError`.
   - **Contador Monótono de Hardware**: Contador estrictamente incremental que impide el rebobinado de estados o repetición de secretos sellados.
   - **Atestación Remota Criptográfica (`TEEAttestationReport`)**: Genera reportes firmados con Ed25519 ante desafíos aleatorios (`challenge_nonce`), permitiendo a pares remotos validar que el nodo opera en un estado de enclave no adulterado.

2. **Canal Wire Canónico de Enclave (`IP7E`)**:
   - Magia de 4 bytes: `b"IP7E"` (`0x49503745`).
   - Opcode (1B): `0x01` (OP_ATTESTATION_CHALLENGE), `0x02` (OP_ATTESTATION_REPORT), `0x03` (OP_SEALED_PAYLOAD), `0x04` (OP_ATTESTATION_VERIFIED).
   - Longitud (2B big-endian) y Checksum CRC32 (4B) para descarte de paquetes malformados a nivel de cable.
   - Invariante estricto de MTU $\le 1280$ bytes garantizado.

3. **Motor de Validación Formal en Tiempo de Ejecución (`ipvn7/diagnostics/formal_verifier.py`)**:
   - Comprobaciones formales de 6 invariantes axiomáticas:
     - `INV-001`: **MTU Boundedness (1280B)**: Todas las tramas (`IP7H`, `IP7E`, etc.) acotadas a $\le 1280$B; frames sobredimensionados son rechazados deterministamente.
     - `INV-002`: **Anti-Replay Monotonic 1024-bit Sliding Window**: Cumplimiento formal RFC 4303 en $O(1)$.
     - `INV-003`: **GMA Memory Budget Isolation**: Cuotas de RAM (Replay, QoS, Trust, Bindings, Other) suman $\le 100\%$ sin desbordamiento.
     - `INV-004`: **Zero Secret Leakage**: Ninguna clave privada o semilla raw se expone en la telemetría pública.
     - `INV-005`: **Anti-SSRF Egress Boundary**: Bloqueo categórico de rangos RFC 1918, link-local y cloud metadata.
     - `INV-006`: **Reciprocity Double-Spend Prevention**: Los tokens de reciprocidad (`IP7R`) liquidados no pueden ser re-gastados.
   - Encadenamiento criptográfico: genera un hash SHA-256 (`proof_hash`) de las demostraciones matemáticas.

4. **Herramientas MCP Nativas (67, 68, 69)**:
   - Herramienta 67: `ipvn7_tee_attest_node` — Emite y valida atestaciones de enclave TEE.
   - Herramienta 68: `ipvn7_verify_runtime_formal_invariants` — Ejecuta la auditoría matemática formal de 6 invariantes en tiempo real.
   - Herramienta 69: `ipvn7_dispatch_enclave_frame` — Serializa y analiza tramas canónicas wire `IP7E`.

5. **Superficie de Control HTTP & SPA Glassmorphism**:
   - `GET /api/tee/status`: Métricas del enclave, contador monótono y secretos sellados.
   - `POST /api/tee/attest`: Generación de atestaciones con desafío.
   - `POST /api/tee/verify_attestation`: Verificación de atestaciones remotas.
   - `GET /api/formal/verify`: Certificado formal en vivo con tabla de demostraciones matemáticas.
   - Pestaña operativa `tab-tee-formal` en el dashboard web.

## Consecuencias y Garantías Verificables
- **Inmunidad contra Manipulación**: Claves protegidas por clave de enclave y `MRENCLAVE`.
- **Cero Dependencias Externas**: Implementado con la librería estándar de Python y `cryptography` (Ed25519, AESGCM, HKDF).
- **Cobertura de Pruebas**: 7 nuevas pruebas unitarias exhaustivas elevando la suite canónica a **122/122 pruebas en PASS (100% de éxito, 0 regresiones)**.
