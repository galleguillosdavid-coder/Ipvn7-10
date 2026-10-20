# H-04-AUDIT-3 — Invocación de Herramientas MCP sin Autenticación Fuerte

- **Identificador Estable:** `H-04-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P1 / Alta`
- **Archivo(s) y Líneas Afectadas:** `app/server.py:L1350-L1365`
- **Componente Afectado:** MCP Server / JSON-RPC 2.0 Engine

---

## 1. Descripción del Comportamiento Observado
El endpoint `/api/mcp` procesaba solicitudes JSON-RPC 2.0 delegando la ejecución directamente a `PRIMARY_NODE.mcp_server.handle_jsonrpc(body)`. Aunque existían verificaciones de encabezado `Origin` y `Sec-Fetch-Site` para prevenir ataques CSRF basados en navegadores, peticiones anónimas enviadas directamente por clientes HTTP locales o scripts curl podían ejecutar cualquiera de las herramientas del plano de control sin proveer credenciales.

## 2. Evidencia Original
```python
elif path in ("/api/mcp", "/mcp"):
    rpc_response = PRIMARY_NODE.mcp_server.handle_jsonrpc(body)
    self._send_json(rpc_response)
```

## 3. Causa Raíz
- **Causa Raíz:** R5 (Autorización fragmentada) y R2 (Confusión entre mitigación de origen y autenticación).
- **Mecanismo:** Se confundió la protección contra Cross-Origin Request Forgery (CORS/Sec-Fetch-Site) con un control de identidad y autorización de peticiones.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** Se exige `self._validate_control_auth()` en `/api/mcp`. Si la cabecera `Authorization: Bearer <token>` está ausente o no coincide con `CONTROL_AUTH_TOKEN`, la solicitud es rechazada inmediatamente con HTTP 401 Unauthorized y código de error JSON-RPC -32000.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-004` (Autenticación universal del plano de control).
- **Invariante:** `INV-2` (Control Plane Autenticado).

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Pruebas:** `test_mcp_control_plane_requires_auth_and_bearer_token` (rechazo sin credenciales, rechazo con credencial inválida, aceptación con Bearer token legítimo).

## 7. Riesgo Residual
Ninguno. Cualquier agente o script debe suministrar el token de autorización.
