# ADR-015: Zero-Knowledge Proofs and Sovereign Ephemeral Ring Signatures (Línea Q)

## Estado
Aceptado e Implementado (v7.13.0)

## Fecha
2026-10-21

## Contexto y Motivación
En una red soberana, anónima y resistente a la censura como IPVN 7, existen dos escenarios críticos de privacidad y gobernanza:
1. **Gobernanza Anónima y Votación Descentralizada**: Un operador o nodo debe poder participar en votaciones de la malla o emitir alertas de seguridad urgentes demostrando pertenencia a un grupo autorizado de validadores (anillo) sin revelar su identidad específica (DID o clave pública real). Además, es fundamental prevenir el doble voto o doble firma en una misma época sin romper la privacidad.
2. **Confidencialidad de Saldos y Cuotas (Tokens IP7R)**: En el modelo de reciprocidad soberana (Línea O), los nodos deben poder demostrar que disponen de un saldo no negativo acotado $v \in [0, 2^n)$ sin exponer la cifra exacta a pares o intermediarios.

Para resolver estos desafíos sin introducir librerías externas pesadas ni violar los límites de MTU de 1280B, se diseñó la **Línea Q (v7.13.0)**: **Sovereign ZKP and Ephemeral Ring Signatures**.

## Decisión de Diseño
Se implementan dos nuevos subsistemas criptográficos nativos en `ipvn7/crypto/zkp.py` y `ipvn7/security/ring_signature.py`:

1. **Pruebas de Conocimiento Cero ZK-Schnorr (`SovereignZKSchnorr`)**:
   - Protocolo Sigma de 3 movimientos sobre grupo aditivo modular $\mathbb{Z}_q$:
     - Prover: $r \leftarrow \mathbb{Z}_q$, compromiso $R = r \cdot G \pmod q$.
     - Desafío Fiat-Shamir no interactivo: $e = H(\text{context} \parallel Y \parallel R) \pmod q$.
     - Respuesta: $s = (r + e \cdot x) \pmod q$.
     - Verificación: $s \cdot G \equiv R + e \cdot Y \pmod q$.
   - Garantía de sonido y completitud estricta con invariante `ZERO_FIAT_SHAMIR_REUSE`.

2. **Prueba de Rango Confidencial Bulletproof (`SovereignBulletproof`)**:
   - Compromiso de Pedersen $C = v \cdot G + r \cdot H \pmod q$.
   - Descomposición homomórfica de bits: $v = \sum_{i=0}^{n-1} 2^i b_i$, con $\sum_{i=0}^{n-1} 2^i C_i \equiv C \pmod q$.
   - OR-proofs Σ 1-de-2 (CDS94) por bit para demostrar $b_i \in \{0, 1\}$.
   - Serialización wire compacta Base64 en trama canónica `IP7Z` con CRC32, garantizando MTU $\le 1280$ bytes.

3. **Motor de Firmas en Anillo Efímeras (`SovereignRingSignature`)**:
   - Protocolo Schnorr Ring (Abe-Ohkubo-Suzuki / AOS02) de $n$ miembros:
     - El firmante real en índice $s$ genera un compromiso real $R_s = r_s \cdot G \pmod q$.
     - Para los miembros $i \neq s$, se simulan respuestas aleatorias $s_i$ y se derivan los compromisos simulados $R_i = (s_i \cdot G - c_i \cdot Y_i) \pmod q$.
     - Propagación determinista de desafíos: $c_{i+1} = H(msg \parallel K \parallel R_i \parallel ring \parallel epoch \parallel ctx)$.
     - Cierre cíclico del anillo: $c_n \equiv c_0$.
     - Nulificador `key_image` $K = x_s \cdot H(PK_s)$: determinista para cada par $(x_s, PK_s)$. Permite detectar instantáneamente doble voto o doble firma en la misma época (`is_double_signed`) preservando el anonimato absoluto del firmante.
   - Formato wire canónico `IP7S` (Magic `b'IP7S'`, Version `0x01`, Type `0x10`, CRC32), $\le 1280$B MTU.

4. **Nuevas Herramientas MCP para Gobernanza Agéntica (Herramientas 70, 71, 72)**:
   - **Tool 70 (`ipvn7_zkp_schnorr_prove`)**: Generación de claves, emisión de pruebas ZK-Schnorr y verificación criptográfica sin revelación de clave privada.
   - **Tool 71 (`ipvn7_zkp_range_proof`)**: Demostración y validación de rangos numéricos confidenciales (Pedersen Bulletproof) con comprobación MTU $\le 1280$B.
   - **Tool 72 (`ipvn7_ring_signature`)**: Generación de miembros, firma en anillo anónima, verificación y auditoría anti-doble-voto (`is_double_signed`).

5. **Expansión del Catálogo y Cobertura de Pruebas**:
   - Catálogo MCP ampliado de 69 a **72 herramientas nativas**.
   - Suite canónica de pruebas unitarias ampliada de 122 a **131 pruebas en PASS (100% de éxito, 0 regresiones)** en Python 3.14.

## Consecuencias y Garantías Verificables
- **Anonimato Criptográfico Incondicional**: Ningún verificador puede distinguir cuál miembro del anillo emitió la firma.
- **Inmunidad al Doble Voto**: La invariante del nulificador $K$ garantiza detección en tiempo $O(1)$ de firmas duplicadas en la misma época.
- **Conformidad Estricta de MTU**: Ambas tramas (`IP7Z` y `IP7S`) cumplen rigurosamente la directiva de MTU $\le 1280$ bytes con validación CRC32 de 4 bytes.
- **Cero Dependencias Pesadas Externas**: Desarrollado 100% con Python stdlib + `cryptography` existente en el entorno virtual.
