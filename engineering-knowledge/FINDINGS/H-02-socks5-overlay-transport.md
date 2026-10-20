# H-02-AUDIT-3 — Pasarela SOCKS5 Directa sin Demostración de Overlay

- **Identificador Estable:** `H-02-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P1 / Alta`
- **Archivo(s) y Líneas Afectadas:** `ipvn7/gateway/socks5.py:L220-L260`
- **Componente Afectado:** Data Plane / SOCKS5 Gateway

---

## 1. Descripción del Comportamiento Observado
La pasarela SOCKS5 validaba la dirección de destino y luego ejecutaba `socket.create_connection((target_ip, dest_port))` seguido de un puente TCP directo entre el cliente local y el servidor de destino. Aunque la documentación declaraba que el tráfico pasaba por el overlay postcuántico, los bytes salían directamente por la interfaz local de red.

## 2. Evidencia Original
```python
remote = socket.create_connection((target_ip, dest_port), timeout=6.0)
# Puente select directo client <-> remote
```

## 3. Causa Raíz
- **Causa Raíz:** R3 (Separación incompleta entre control y datos) y R10 (Documentación divergente de la implementación real).
- **Mecanismo:** La pasarela se inspiró en prototipos de prueba de concepto que aún no habían completado la orquestación del relay de salida.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** Se integró `SovereignExitRelayClient` en `ipvn7/gateway/socks5.py`. En modo `OVERLAY_TUNNELED`, el stream TCP se delega a `open_tunneled_stream()`, transmitiendo tramas cifradas `IP7X` al Exit Node donde se ejecuta la conexión final. En modo directo, se declara honestamente `DIRECT_TCP_EGRESS` con `overlay_verified: False`.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-006` y `ER-SEC-010`.

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Pruebas:** `test_audit_3_h02_h05_socks5_concurrency_and_mode_accounting` y `test_sovereign_exit_relay_true_overlay_datapath`.

## 7. Riesgo Residual
Mínimo. En despliegues donde no se configure un nodo par de salida remoto, la pasarela opera explícitamente en modo directo reportando la verdad del datapath.
