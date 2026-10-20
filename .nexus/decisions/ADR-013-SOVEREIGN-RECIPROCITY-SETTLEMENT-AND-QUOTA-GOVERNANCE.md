# ADR-013: Sovereign Reciprocity Settlement and Micro-Economic Quota Governance (Línea O)

## Estado
Aceptado e Implementado (v7.11.0)

## Fecha
2026-10-20

## Contexto y Motivación
Bajo el modelo de tráfico simétrico de IPVN 7 (implementado en Línea J con contabilidad de tránsito P2P y Service Tiers: Priority, Normal, Throttled, Blocked), un nodo asimétrico (por ejemplo, clientes móviles, nodos detrás de CGNAT severo o consumidores puros de contenido) podía quedar permanentemente degradado en tier `THROTTLED` debido a un ratio de reciprocidad bajo (`ratio < 0.25`), sin un mecanismo nativo para canjear servicios computacionales auxiliares (routing relay, almacenamiento DHT, o crédito de reciprocidad transferible) por cuota de tránsito prioritaria.

Asimismo, era imperativo evitar esquemas de pago centralizados basados en fiat o tokens de blockchain pesados con dependencias externas, preservando la soberanía matemática del nodo y la autosuficiencia en redes de malla locales (offline mesh).

## Decisión de Diseño
Se introduce la **Línea O (v7.11.0)**: **Sovereign Reciprocity Settlement and Micro-Economic Quota Governance** (`ipvn7/network/settlement.py`), compuesto por:

1. **Tokens de Reciprocidad Criptográficos (`ReciprocityToken`)**:
   - Estructura inmutable con `token_id` derivado del hash SHA-256 de sus componentes canónicos.
   - Campos: `issuer_did`, `beneficiary_did`, `amount_credits`, `nonce`, `issued_at`, `expires_at`, `signature`.
   - Firma criptográfica asimétrica Ed25519 sobre el hash canónico del token.
   - Protección estricta contra replay y doble gasto mediante `settled_tokens_ledger` persistente y nonces monótonamente incrementales por emisor.
   - Control estricto de caducidad temporal (`expires_at < time.time()`).

2. **Protocolo Canónico de Enmarcado Wire (`IP7R`)**:
   - Cabecera binaria canónica de 4 bytes: `IP7R`.
   - Opcode (1 byte): `0x01` (TOKEN_ISSUE), `0x02` (TOKEN_SETTLE), `0x03` (TOKEN_ACK), `0x04` (REMEDIATION_NOTICE).
   - Longitud (2 bytes, big-endian) del payload JSON canónico UTF-8.
   - Checksum CRC32 (4 bytes, big-endian) al final del paquete para validación instantánea de integridad física en el cable antes de deserializar.
   - Cumple el invariante estricto de MTU de red $\le 1280$ bytes (IPv6/IPVN7 safe).

3. **Remediación Dinámica de Cuotas de Tránsito (Tit-for-Tat Compensatorio)**:
   - Los créditos de reciprocidad acumulados en el balance del nodo (`earned_credits`) pueden ser quemados voluntariamente (`apply_quota_remediation`) para acreditar bytes recibidos equivalentes en `TransitAccounting`.
   - Cada crédito de reciprocidad canjeado remedia una cuota de $1024$ bytes ($1\text{ crédito} = 1\text{ KB de crédito de tránsito}$).
   - Si el nodo receptor se encontraba en tier `THROTTLED` debido a ratio bajo, la remediación eleva su ratio a $\ge 0.5$, restituyendo inmediatamente su tier de servicio a `NORMAL` o `PRIORITY`.

4. **Herramientas de Agente MCP Nativas (64, 65, 66)**:
   - Herramienta 64: `ipvn7_issue_reciprocity_token` — Emite un token firmado con cuota de créditos.
   - Herramienta 65: `ipvn7_settle_reciprocity_token` — Liquida y valida un token de reciprocidad, actualizando el balance del nodo.
   - Herramienta 66: `ipvn7_get_settlement_ledger` — Inspecciona el balance económico de reciprocidad, tokens liquidados y estado contable.

5. **Superficie de Control HTTP Soberana**:
   - `GET /api/settlement/summary`: Estado en tiempo real de balances y créditos acumulados.
   - `POST /api/settlement/issue`: Emisión segura de tokens de reciprocidad para nodos cooperativos.
   - `POST /api/settlement/settle`: Liquidación atómica y verificación criptográfica.

## Consecuencias y Garantías Verificables
- **Sin Dependencias Centralizadas**: Funciona puramente con firmas Ed25519 nativas de `cryptography` y contabilidad local en memoria.
- **Invariante Anti-Doble Gasto**: Un token con `token_id` ya liquidado es rechazado deterministamente con `ValueError("Token ... has already been settled")`.
- **Invariante Anti-Replay Temporal**: Tokens con marcas de tiempo en el futuro o expirados son descartados.
- **Invariante de Formato Wire**: Paquetes malformados, con longitud inconsistente o checksum CRC32 corrupto son rechazados antes de ejecución.
- **Cobertura de Pruebas**: 6 pruebas unitarias específicas añadidas en `tests/test_ipvn7.py` elevando la suite completa a 114/114 pruebas en PASS.
