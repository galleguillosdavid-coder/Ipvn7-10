# H-07-AUDIT-3 — Fuga de Secretos Criptográficos Crudos en Respuestas de la API

- **Identificador Estable:** `H-07-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P2 / Media`
- **Archivo(s) y Líneas Afectadas:** `app/server.py:L570-L600`
- **Componente Afectado:** Web UI / PQC Live Demo API

---

## 1. Descripción del Comportamiento Observado
El endpoint de demostración criptográfica `/api/pqc/live_demo` ejecutaba un handshake ML-KEM-768 y retornaba en el payload JSON el secreto compartido derivado en formato hexadecimal (`shared_secret_hex`). Aunque se diseñó con propósitos educativos para visualizar la convergencia criptográfica entre Alice y Bob en el dashboard, violaba el principio de mínimo privilegio y ponía en riesgo la confidencialidad de sesiones si dicho patrón se transfería a endpoints de producción.

## 2. Evidencia Original
```json
{
  "alice_did": "did:ipvn7:...",
  "bob_did": "did:ipvn7:...",
  "shared_secret_hex": "4a7f290b3c...",
  "handshake_verified": true
}
```

## 3. Causa Raíz
- **Causa Raíz:** R2 (Confusión entre componentes y garantías) y R7 (Exposición de datos internos con fines de depuración).
- **Mecanismo:** Omisión de un filtro de censura de secretos compartidos en la capa de serialización hacia el cliente.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** Se eliminó por completo el campo `shared_secret_hex`. En su lugar, la API calcula y retorna un digest truncado SHA-256 de confirmación (`shared_secret_hash_prefix`), permitiendo verificar que ambos extremos derivaron el mismo material sin revelar ningún byte del secreto crudo.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-007` (Censura estricta de material de claves y secretos compartidos en APIs).
- **Invariante:** `INV-6` (Cero Exposición de Secretos Criptográficos Crudos).

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Pruebas:** `test_pqc_live_demo_censors_raw_shared_secret`.

## 7. Riesgo Residual
Nulo. Ningún endpoint del sistema expone secretos compartidos crudos.
