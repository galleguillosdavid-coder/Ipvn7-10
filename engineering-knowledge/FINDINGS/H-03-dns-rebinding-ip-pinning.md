# H-03-AUDIT-3 — Riesgo de DNS Rebinding y Discrepancia entre Validación y Conexión

- **Identificador Estable:** `H-03-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P1 / Alta`
- **Archivo(s) y Líneas Afectadas:** `ipvn7/security/egress_policy.py:L110-L140`, `ipvn7/gateway/exit_relay.py:L85-L100`
- **Componente Afectado:** L0/L4 Egress Security & Exit Node Relay

---

## 1. Descripción del Comportamiento Observado
En pasarelas de salida y en el Exit Node, `EgressSecurityPolicy` validaba que el hostname de destino no resolviera a direcciones IP privadas o de loopback (anti-SSRF). Sin embargo, tras la validación, la conexión de socket se realizaba volviendo a pasar el hostname original a `socket.create_connection((target_host, port))`. Un atacante con control sobre el servidor DNS podía retornar una IP pública en la validación y una IP privada (e.g. `127.0.0.1` o `169.254.169.254`) en la conexión efectiva (DNS Rebinding / TOCTOU).

## 2. Evidencia Original
```python
is_allowed, reason = EgressSecurityPolicy.resolve_and_validate_host(target_host, port)
if is_allowed:
    sock = socket.create_connection((target_host, port)) # Segunda resolución DNS vulnerable
```

## 3. Causa Raíz
- **Causa Raíz:** R4 (Validación de entrada sin garantía de uso seguro) y R1 (Diseño sin invariantes verificables).
- **Mecanismo:** Desacoplamiento entre la fase de validación de seguridad y la fase de ejecución de socket.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** `EgressSecurityPolicy.resolve_and_validate_host()` retorna una tupla `(is_allowed, reason, valid_ips)`. El socket de salida se conecta obligatoriamente a la IP validada (`valid_ips[0]`), preservando el hostname original únicamente para la cabecera SNI / HTTP `Host`.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-003` (Fijación estricta de IP resuelta anti-SSRF).
- **Otros Proyectos Afectados:** Aplicable a cualquier proxy, gateway o cliente HTTP desarrollado por LAIA.

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Pruebas:** `test_exit_node_dns_rebinding_ip_pinning_and_ssrf_mitigation`.

## 7. Riesgo Residual
Mínimo. Se mitiga completamente el riesgo de resolución divergente en el punto de salida.
