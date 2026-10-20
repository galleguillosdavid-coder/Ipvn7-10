# ADR-013: Gobernanza de Cuotas y Liquidación Micro-Económica Soberana con Tokens de Reciprocidad P2P

- **Estado:** Aceptado e Implementado
- **Fecha:** 2026-10-20
- **Versión de IPVN 7:** v7.11.0
- **Autor:** Agente Autónomo Autoevolutivo (Línea O del Backlog Soberano)
- **Suite de Pruebas:** 108+ aprobadas (100% verde, 0 regresiones)
- **Herramientas MCP Activas:** 66 herramientas nativas

---

## 1. Contexto y Desafío de Equidad en la Malla (Tit-for-Tat)

En redes ad-hoc y mallas descentralizadas como IPVN 7, los nodos intermedios actúan como repetidores (*relays*) y enrutadores para pares remotos. El modelo original de contabilidad `TransitAccounting` aplica la heurística clásica de *Tit-for-Tat* clasificando a los pares según el ratio $\text{Ratio} = \frac{\text{Bytes Rx}}{\text{Bytes Tx}}$.

Sin embargo, este modelo presentaba limitaciones en topologías asimétricas:
1. **Problema del Nodo Hoja o Borde:** Nodos en periferias geográficas o dispositivos móviles a menudo consumen más ancho de banda del que pueden enrutar directamente hacia un par específico, cayendo indebidamente en los niveles de servicio `BEST_EFFORT` o `THROTTLED`.
2. **Falta de Compensación Multilateral:** Si el nodo B enruta 100 MB para el nodo A, pero el nodo A no tiene tráfico directo que enrutar de vuelta a B, la contribución altruista de B no podía ser transferida ni acreditada para mejorar su acceso ante un tercer nodo C.
3. **Vulnerabilidad a Replay y Doble Gasto:** Cualquier sistema de crédito descentralizado sin cadena de bloques centralizada debe prevenir ataques de repetición de recibos, falsificación de firmas y auto-emisión fraudulenta.

---

## 2. Decisión de Arquitectura Soberana

Se implementa el subsistema **`SovereignReciprocitySettlement`** (`ipvn7/network/settlement.py`), estructurado sobre los siguientes contratos:

### A. Token Criptográfico de Reciprocidad (`ReciprocityToken`)
Cada comprobante de tránsito (*Proof-of-Transit*) contiene:
- `token_id`: Identificador canónico SHA-256 de 32 caracteres hex.
- `issuer_did`: DID del nodo consumidor que certifica la recepción del servicio.
- `beneficiary_did`: DID del nodo relay que proporcionó el tránsito.
- `bandwidth_credits`: Cantidad de bytes acreditados (entero estrictamente positivo, tope de 100 GiB por token).
- `epoch`: Época diaria (`int(time.time() // 86400)`), con ventana de caducidad máxima de 30 días.
- `nonce`: Secuencia monótona estricta por emisor.
- `issued_at`: Marca de tiempo Unix.
- `signature_hex`: Firma digital Ed25519 sobre el payload canónico `IP7R-TOKEN-V1:...`.

### B. Enmarcado Canónico en el Cable `IP7R` (MTU <= 1280B)
Se estandariza el Magic en cable `b"IP7R"` (4 bytes) con formato binario seguro:
`[4B MAGIC (IP7R)][1B OPCODE][2B LENGTH][PAYLOAD][4B CRC32]`
Opcodes normativos:
- `0x01` - `OP_TOKEN_ISSUE`: Emisión de comprobante de tránsito firmado.
- `0x02` - `OP_SETTLEMENT_CLAIM`: Reclamo de liquidación por el beneficiario.
- `0x03` - `OP_SETTLEMENT_RECEIPT`: Confirmación y emisión de recibo de balance acreditado.
- `0x04` - `OP_AUDIT_BALANCE`: Auditoría y consulta de saldo de créditos no gastados.

### C. Prevención de Doble Gasto y Replay
1. **Registro Inmutable de Tokens Gastados:** El motor mantiene el conjunto `spent_token_ids`; cualquier intento de presentar un token previamente liquidado es rechazado inmediatamente con error de doble gasto.
2. **Monotonía de Nonces por Emisor:** Se audita que `token.nonce > last_nonce[issuer]`.
3. **Prohibición de Auto-Emisión:** `token.issuer_did != token.beneficiary_did`.
4. **Ventana Temporal Acotada:** Rechazo de tokens con épocas futuras o superiores a 30 días de antigüedad.

### D. Gobernanza de Cuotas y Remediación QoS
El método `apply_quota_remediation(did)` permite a un nodo en estado `THROTTLED` o `BEST_EFFORT` canjear sus créditos acumulados de reciprocidad para saldar su déficit en `TransitAccounting`. Los créditos quemados aumentan `bytes_rx`, recalculando y promoviendo automáticamente su `ServiceTier` a `NORMAL` o `PRIORITY`.

---

## 3. Interfaces Operativas y Herramientas MCP Incorporadas

1. **Herramientas MCP del Plano de Control Agéntico (Herramientas 64, 65 y 66):**
   - `ipvn7_issue_reciprocity_token`: Emite y firma un token canónico `IP7R`.
   - `ipvn7_settle_reciprocity_token`: Liquida un token, valida la firma Ed25519 y acredita el balance.
   - `ipvn7_get_settlement_ledger`: Inspecciona el libro mayor de liquidación y balances.

2. **Endpoints REST HTTP en `app/server.py`:**
   - `GET /api/settlement/summary`: Resumen de tokens emitidos, liquidados y balances activos.
   - `POST /api/settlement/issue`: Emisión autenticada de comprobantes de reciprocidad.
   - `POST /api/settlement/settle`: Liquidación y remediación de cuotas QoS.

3. **Invariantes de Ingeniería Preservados (LAIA):**
   - Cero dependencias externas (`ed25519` vía `cryptography`, `struct`, `zlib`).
   - Cero credenciales estáticas.
   - Datapath MTU de 1280 bytes respetado al 100%.

---

## 4. Consecuencias y Beneficios

- **Equidad Descentralizada:** Resuelve el problema del "free-rider" y los desbalances de enrutamiento asimétrico sin depender de servidores de facturación centrales ni blockchains de alta latencia.
- **Micro-Incentivos en Tiempo Real:** Permite a nodos de bajos recursos ganar créditos de tránsito durante la noche enrutando paquetes para otros, y gastarlos durante el día en streaming o consultas de alta prioridad.
