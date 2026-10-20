# ADR-010: Remediación Integral de Auditoría Técnica de Seguridad (Hallazgos H-01 a H-08) y Política Inmutable de Gobernanza

- **Estado:** Aceptado e Implementado
- **Fecha:** 2026-10-20
- **Versión de IPVN 7:** v7.8.0
- **Autor:** Agente Autónomo Autoevolutivo (Línea O del Backlog Soberano)
- **Suite de Pruebas:** 103/103 aprobadas (100% verde)
- **Herramientas MCP Activas:** 63 herramientas canónicas
- **Gobernanza:** [.nexus/security/SECURITY_GOVERNANCE_AND_AUDIT_POLICY.md](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/.nexus/security/SECURITY_GOVERNANCE_AND_AUDIT_POLICY.md)

---

## 1. Contexto y Auditoría Técnica Externa

Tras la publicación de la versión v7.7.0, se llevó a cabo una auditoría técnica y estática rigurosa sobre el repositorio `galleguillosdavid-coder/Ipvn7-10`, identificando 8 vectores y discrepancias prioritarias:
1. **H-01 (Crítico):** Discrepancia en `ipvn7/gateway/proxy.py` donde se enviaba señal de control por la malla pero se abría conexión TCP directa, registrándose falsamente como `TUNNELED_PQ_QUIC`.
2. **H-02 (Crítico):** Pasarela SOCKS5 (`ipvn7/gateway/socks5.py`) conectaba directamente a destinos solicitados sin validar políticas de salida ni autenticación, permitiendo pivot hacia servicios internos o metadatos de nube.
3. **H-03 (Alto):** Plano de control MCP (`/mcp`, `/api/mcp`) en `app/server.py` sin autenticación obligatoria ni mitigación estricta de Cross-Origin Request / DNS Rebinding.
4. **H-04 (Alto):** Validación SSRF en `/api/internet/fetch` basada en lista estática de cadenas, susceptible a bypass por representaciones alternativas de IP, CGNAT, link-local, y redirecciones HTTP 302 hacia destinos internos.
5. **H-05 (Alto):** Agotamiento de recursos en `/api/simulation/small-world` y concurrencia irrestricta de hilos en `ThreadingHTTPServer`.
6. **H-06 (Medio):** Estado de túnel overlay reportaba huellas de clave `"simulated"` cuando no existía una sesión PQC activa.
7. **H-07 (Medio):** Operación con efectos secundarios (`/api/key_rotation/rekey`) expuesta en método HTTP `GET`.
8. **H-08 (Bajo):** Matriz de integración continua en `.github/workflows/ci.yml` probaba Python 3.12 y 3.13 mientras la documentación declaraba compatibilidad con Python 3.14, sumado a desincronización de métricas en el README.

---

## 2. Decisión de Arquitectura y Remediación Ejecutada

### A. Honestidad Categórica de Datapath (H-01 y H-06)
- **Eliminación de Simulación:** Se prohíbe el uso de cadenas `'simulated'` o estados sintéticos en los reportes de sesión. Si no existe una clave de sesión PQC 1-RTT activa en `quic_connections`, el valor de huella es estrictamente `null` y el estado se reporta como `DIRECT_LOCAL_EGRESS_CONTROL_NOTIFIED`.
- **Registro Fiel:** Los eventos del proxy y de SOCKS5 registran `CONTROL_NOTIFIED_DIRECT_EGRESS` y `DIRECT_LOCAL_EGRESS_VALIDATED` hasta que un túnel de reenvío de datos cifrado completo esté activo y demostrado.

### B. Motor Centralizado de Seguridad de Salida Anti-SSRF (`EgressSecurityPolicy`) (H-02 y H-04)
- Se implementó `ipvn7/security/egress_policy.py`:
  - **Inspección Canónica con `ipaddress`:** Evaluación de cada IP resuelta verificando `is_loopback`, `is_private`, `is_link_local`, `is_multicast`, `is_reserved`, `is_unspecified`, `169.254.169.254` (cloud metadata), `100.64.0.0/10` (RFC 6598 CGNAT) y `198.18.0.0/15` (RFC 2544).
  - **Fijación de Destino DNS:** Resolución previa y conexión directa a la IP pública validada, mitigando ataques de DNS Rebinding.
  - **Intercepción de Redirecciones (`SafeRedirectHandler`):** Inspección estricta de cada salto HTTP 301/302/307 antes de permitir la conexión sucesiva.

### C. Aislamiento y Autenticación del Plano de Control MCP (H-03)
- Validación obligatoria de credenciales en `/mcp` y `/api/mcp` tanto en `GET` como en `POST`.
- Aceptación exclusiva de:
  - Cabecera `Authorization: Bearer <CONTROL_AUTH_TOKEN>` o `X-IPVN7-Auth: <CONTROL_AUTH_TOKEN>`.
  - Peticiones originadas desde el dashboard local (`http://127.0.0.1:7070` o `http://localhost:7070`) con validación de cabecera `Host` para impedir DNS Rebinding.
- Solicitudes no autenticadas reciben `401 Unauthorized` con código JSON-RPC `-32000`.

### D. Concurrencia Acotada y Validación de Rangos (H-05)
- Semáforo acotado `REQUEST_SEMAPHORE = threading.BoundedSemaphore(32)` con timeout de adquisición para proteger el servidor de agotamiento de hilos.
- Clamping estricto en `/api/simulation/small-world`:
  - `nodes`: acotado obligatoriamente a $[5, 120]$.
  - `churn`: acotado obligatoriamente a $[0.0, 0.85]$.

### E. Idempotencia y Métodos Seguros HTTP (H-07)
- `GET /api/key_rotation/rekey` retorna inmediatamente `405 Method Not Allowed`.
- La orquestación de rekeying se ejecuta exclusivamente mediante `POST /api/key_rotation/rekey`.

### F. Sincronización de CI y Métricas Documentales (H-08)
- Actualizada matriz de `.github/workflows/ci.yml` para incluir `["3.12", "3.13", "3.14"]`.
- Documentación unificada a **103 pruebas unitarias aprobadas al 100%** y **63 herramientas MCP canónicas activas**.

---

## 3. Matriz de Cobertura y Verificación (Tests 98 a 103)

| Test ID | Hallazgo | Módulo Validado | Resultado |
|---|---|---|---|
| `test_audit_h04_egress_security_policy_ssrf_filtering` | H-04 | `ipvn7/security/egress_policy.py` | APROBADO (100%) |
| `test_audit_h02_socks5_blocks_internal_and_loopback_destinations` | H-02 | `ipvn7/gateway/socks5.py` | APROBADO (100%) |
| `test_audit_h01_proxy_blocks_private_and_honest_logging` | H-01 | `ipvn7/gateway/proxy.py` | APROBADO (100%) |
| `test_audit_h07_rekey_method_not_allowed_on_get` | H-07 | `app/server.py` | APROBADO (100%) |
| `test_audit_h03_mcp_control_plane_authentication` | H-03 | `app/server.py` / `mcp.py` | APROBADO (100%) |
| `test_audit_h05_simulation_small_world_clamping` | H-05 | `app/server.py` | APROBADO (100%) |
