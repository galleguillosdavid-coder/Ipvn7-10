# H-01-AUDIT-3 — Credencial de Control Predeterminada y Pública

- **Identificador Estable:** `H-01-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P1 / Alta`
- **Archivo(s) y Líneas Afectadas:** `app/server.py:L45-L55`
- **Componente Afectado:** Control Plane / MCP Engine

---

## 1. Descripción del Comportamiento Observado
El servidor HTTP definía `IPVN7_CONTROL_TOKEN` con una constante estática fija (`ipvn7-sovereign-control-token-2026`). Si el nodo se ejecutaba sin definir la variable de entorno, cualquier actor con acceso a la red local o que leyera el repositorio público podía invocar las herramientas privilegiadas del plano de control MCP.

## 2. Evidencia Original
```python
CONTROL_AUTH_TOKEN = os.environ.get("IPVN7_CONTROL_TOKEN", "ipvn7-sovereign-control-token-2026")
```

## 3. Causa Raíz
- **Causa Raíz:** R5 (Autorización fragmentada) y R7 (Atajo de conveniencia en desarrollo local).
- **Mecanismo:** La necesidad de probar el dashboard local sin configurar archivos `.env` propició un valor estático por defecto que violaba el principio de seguridad por defecto.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** Si `IPVN7_CONTROL_TOKEN` no está configurado, el servidor genera un token criptográfico aleatorio de alta entropía (`secrets.token_urlsafe(32)`) y lo persiste en `.nexus/runtime/control.token` con permisos restringidos de usuario local.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-001`
- **Otros Proyectos Afectados:** Revisadas versiones anteriores en `c:\Users\Frondabrick\Desktop\dvd\Ipv7\` para erradicar tokens por defecto.

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Pruebas:** `test_mcp_control_plane_requires_auth_and_bearer_token` y validación estática de ausencia del string literal.

## 7. Riesgo Residual
Bajo. Operadores en entornos distribuidos deben asegurarse de configurar la variable de entorno para compartir el secreto de forma segura entre nodos si no desean usar el token generado automáticamente.
