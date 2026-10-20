# H-08-AUDIT-3 — Riesgo de Desincronización en Rekeying Silencioso de Sesiones PQC

- **Identificador Estable:** `H-08-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P2 / Media`
- **Archivo(s) y Líneas Afectadas:** `ipvn7/security/key_rotation.py:L70-L115`
- **Componente Afectado:** L3 Security Session Key Rotation (Forward Secrecy)

---

## 1. Descripción del Comportamiento Observado
Durante la rotación periódica proactiva de claves de sesión (Forward Secrecy), si un paquete en vuelo arribaba con la clave anterior inmediatamente después de la transición, era descartado como inválido, interrumpiendo streams continuos de datos si la latencia de red superaba el umbral de rotación instantánea.

## 2. Evidencia Original
Al completar la encapsulación de una nueva clave efímera ML-KEM-768, la clave de sesión anterior era purgada inmediatamente de memoria sin un período de gracia de transición.

## 3. Causa Raíz
- **Causa Raíz:** R1 (Diseño sin consideración de fallos parciales y latencia asimétrica) y R6 (Pruebas de rotación en entornos de latencia cero).
- **Mecanismo:** Ausencia de un estado de transición bi-clave con ventana de gracia temporal.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** Se implementó una ventana de gracia de transición de 30 segundos (`GRACE_PERIOD_SECONDS = 30.0`). Durante esta ventana, el receptor acepta paquetes cifrados tanto con la nueva clave activa como con la clave previa inmediata, retirándola y purgándola definitivamente una vez expirada la ventana.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-010` (Ventana de gracia en rotación de credenciales efímeras).
- **Políticas:** `engineering-knowledge/POLICIES/cryptography.md`.

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Pruebas:** `test_silent_pqc_rekeying_forward_secrecy`.

## 7. Riesgo Residual
Controlado. La ventana de 30 segundos acota la ventana de vulnerabilidad mientras previene pérdida de datagramas legítimos en vuelo.
