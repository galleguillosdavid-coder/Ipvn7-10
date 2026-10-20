# H-09-AUDIT-3 — Handshake Híbrido PQC sin Autenticación Digital de Interlocutor

- **Identificador Estable:** `H-09-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P1 / Alta`
- **Archivo(s) y Líneas Afectadas:** `ipvn7/crypto/pqc.py:L110-L168`
- **Componente Afectado:** Cryptography / PQC Handshake

---

## 1. Descripción del Comportamiento Observado
`server_respond()` y `client_finalize()` combinaban las claves efímeras X25519 y ML-KEM-768 y aplicaban HKDF sobre un hash del transcript. Sin embargo, no se incluía una firma digital que vinculara criptográficamente el transcript con la identidad de largo plazo del servidor. Un atacante en el medio (MITM) activo podía suplantar las claves efímeras y descifrar la sesión sin ser detectado.

## 2. Evidencia Original
```python
# HKDF con info descriptivo pero sin firma digital sobre transcript
derived_key = derive_shared_secret(combined_secret, salt=transcript_hash, info=b"IPVN7-PQ-QUIC-HANDSHAKE-V1-AUTH")
```

## 3. Causa Raíz
- **Causa Raíz:** R1 (Diseño sin invariantes verificables) y R2 (Confundir primitivas con garantías de protocolo).
- **Mecanismo:** Se consideró que el salt y el info en HKDF bastaban para la autenticación de la sesión, confundiendo la derivación de clave con la autenticación de la entidad.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** Implementados `server_respond_authenticated()` y `client_finalize_authenticated()` en `PQCHybridKeyExchange`. El servidor firma el hash SHA-256 del transcript completo con `ML-DSA-65` y `Ed25519`, y el cliente verifica obligatoriamente la firma antes de derivar la clave de sesión. Si la firma es inválida, se aborta la sesión.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-009` e Invariante 3 (`SECURITY_INVARIANTS.md`).

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Prueba:** `test_audit_3_h09_pqc_authenticated_handshake_and_mitm_rejection` (incluye prueba honesta, ataque de manipulación de clave efímera MITM y ataque de suplantación de identidad).

## 7. Riesgo Residual
Cero en sesiones autenticadas.
