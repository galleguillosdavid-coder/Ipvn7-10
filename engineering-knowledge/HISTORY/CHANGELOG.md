# HISTORIAL DE CAMBIOS Y TRAZABILIDAD (CHANGELOG) — LAIA

Todas las versiones, auditorías y cambios de seguridad del protocolo IPVN 7 se registran en este documento de acuerdo con el principio de **TRAZABILIDAD > MEMORIA CONVERSACIONAL**.

---

## [7.10.0] — 2026-10-20 (Auditoría de Seguridad #3 & Despliegue Sistema LAIA)

### Remediación Integral de la Auditoría 3
- **Seguridad (H-01):** Eliminada credencial estática predeterminada `ipvn7-sovereign-control-token-2026` en `app/server.py`. Implementada generación dinámica con `secrets.token_urlsafe(32)` persistida en `.nexus/runtime/control.token`.
- **Datapath y Pasarelas (H-02, H-05):** Integrada pasarela SOCKS5 (`ipvn7/gateway/socks5.py`) con `SovereignExitRelayClient` en modo `OVERLAY_TUNNELED`. Implementado semáforo de concurrencia acotada `threading.BoundedSemaphore(64)` para mitigar DoS por saturación de hilos.
- **SSRF y DNS Rebinding (H-03):** Centralizada la fijación de IP validada en el Exit Node.
- **Autorización (H-04):** Robustecido `_validate_control_auth()` con validación estricta de Bearer token y `Sec-Fetch-Site: same-origin`.
- **Parsing Defensivo (H-06):** Blindado `BitNetQuantizer.deserialize_model()` con comprobación de límites de nombre ($\le 256$), dimensiones ($\le 4096$) y concordancia matemática de buffer de pesos.
- **Criptografía (H-07):** Censurada la exposición de secretos en `/api/pqc/live_demo`, reemplazando `shared_secret_hex` por `shared_secret_fingerprint` SHA-256.
- **Handshake PQC contra MITM (H-09):** Incorporada firma digital obligatoria del transcript hash mediante `server_respond_authenticated()` y verificación en `client_finalize_authenticated()`.
- **Telemetría Veraz (H-10):** Telemetría de `/api/internet/fetch` ajustada a `LOCAL_EGRESS_WITH_OVERLAY_CONTROL_NOTIFICATION` y `overlay_verified: False`.
- **Suite de Pruebas:** Incorporadas pruebas unitarias negativas de regresión. Suite elevada a **108 pruebas pasando al 100%**.
- **Gobernanza:** Creado el sistema persistente de memoria de ingeniería **`engineering-knowledge/`** (Constitución, Reglas Operativas, Invariantes, Causas Raíz, Lecciones Aprendidas y Políticas).

---

## [7.9.0] — 2026-10-20
- Implementado `SovereignExitRelayServer` y `SovereignExitRelayClient` con tramas binarias canónicas `IP7X` para transporte tunelizado real en el overlay.
- Documentado en `ADR-011`. Suite de 104 pruebas.

---

## [7.8.0] — 2026-10-20
- Remediación integral de Auditoría de Seguridad #2 (H-01 a H-08).
- Implementada `EgressSecurityPolicy` con resolución estricta, anti-SSRF y anti-DNS rebinding.
- Documentado en `ADR-010`. Suite de 103 pruebas.
