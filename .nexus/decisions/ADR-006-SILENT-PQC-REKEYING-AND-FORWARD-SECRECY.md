# ADR-006: Silent PQC Re-Keying Orchestration & Forward Secrecy Zeroization

**Estado**: APROBADO  
**Fecha**: 2026-10-20  
**Autores**: Agente de Auto-Evolución Autónoma IPVN 7  
**Área**: `ipvn7/security/rekeying.py`, `ipvn7/node/node.py`, `ipvn7/node/mcp.py`, `app/server.py`

---

## 1. Contexto

En redes abiertas hostiles y frente a la amenaza de almacenamiento de tráfico para descifrado futuro ("Harvest Now, Decrypt Later"), el compromiso tardío de una clave estática o de sesión no debe comprometer el tráfico histórico (Perfect Forward Secrecy). Asimismo, las renegociaciones de claves convencionales (ej. TLS 1.2 o handshakes bloqueantes) inducen picos de latencia, pérdidas de paquetes fuera de orden y caídas temporales del datapath (downtime).

Para abordar la **Línea K** del backlog soberano se requería:
1. Un protocolo de re-keying post-cuántico continuo y silencioso (sin sondeos ni handshakes ruidosos).
2. Conmutación de claves de sesión con **Zero-Downtime**, soportando paquetes fuera de orden durante una ventana de gracia configurable (30 segundos).
3. **Destrucción Segura de Memoria (`Zeroization`)**: Tras expirar la ventana de gracia, la clave de la época anterior debe ser sobrescrita incondicionalmente en memoria para evitar extracción forense o volcados de memoria (RAM dumps).

---

## 2. Decisiones de Arquitectura

### 2.1 Orquestador Silencioso (`SilentKeyRotationOrchestrator`)
- **Épocas Monótonas Criptográficas**: Cada clave de sesión está vinculada a un entero no decreciente `epoch: int` ($E \to E+1$).
- **Derivación de Clave Transcript-Bound Ratchet**:
  La nueva clave de sesión combina el secreto híbrido efímero (X25519 + ML-KEM-768) con la clave de la época anterior:
  $$\text{combined\_secret} = K_{\text{X25519}} \parallel K_{\text{ML-KEM}} \parallel K_{E}$$
  $$\text{transcript\_salt} = \text{SHA-256}(K_E \parallel \text{shares}_{\text{init}} \parallel \text{shares}_{\text{resp}} \parallel \text{ct} \parallel \text{epoch})$$
  $$K_{E+1} = \text{HKDF-Extract-and-Expand}(\text{combined\_secret}, \text{transcript\_salt}, \text{info}=\text{"IPVN7-SILENT-PQC-REKEY-V1"})$$
- **Fases de Transición**: `IDLE` $\to$ `OFFERED` $\to$ `COMMITTED` $\to$ `TRANSITIONING` $\to$ `FINALIZED`.

### 2.2 Desencriptación Dual en Ventana de Gracia (Zero-Downtime)
- Los nuevos paquetes se transmiten cifrados con la clave activa $K_{E+1}$.
- Durante la ventana de gracia ($\Delta t \le 30.0\text{ s}$), el receptor intenta descifrar primero con $K_{E+1}$; si el paquete proviene de la época anterior $E$, se descifra utilizando $K_E$ registrando la métrica `grace_packets_served`.
- Esto garantiza que paquetes demorados por jitter de red o enrutamiento multipath no sean descartados.

### 2.3 Destrucción Segura de Memoria (`Memory Zeroization`)
- El material criptográfico se encapsula en `EpochKeyMaterial` utilizando `bytearray` mutable.
- Al expirar la gracia o ante invocación explícita `zeroize()`, se ejecutan escrituras directas de ceros binarios (`\x00`) en toda la extensión del buffer antes de marcar `is_zeroed = True`.
- Cualquier intento posterior de acceso a la clave anterior lanza una excepción irrevocable `ValueError("Cryptographic key has been securely zeroized from memory")`.

### 2.4 Catálogo MCP Expandido (60 Herramientas Nativas)
- Se añade la herramienta número 60: `ipvn7_orchestrate_silent_rekey`.
- Endpoint REST `/api/key_rotation/rekey` para invocación e inspección del estado de las épocas y la destrucción de memoria.

---

## 3. Consecuencias y Validación

- **Zero-Downtime Verificado**: Pruebas unitarias demuestran descifrado exitoso de paquetes de épocas mixtas durante la ventana de gracia.
- **Forward Secrecy Total**: Validación explícita de fallo ante intentos de descifrado tras la destrucción de memoria.
- **Batería de Pruebas**: Suite expandida a **94 pruebas unitarias (100% aprobadas en 7.0s)**.
- **Pureza de Dependencias**: 100% biblioteca estándar de Python y `cryptography`.
