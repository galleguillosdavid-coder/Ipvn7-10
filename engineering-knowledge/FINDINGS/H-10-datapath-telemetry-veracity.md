# H-10-AUDIT-3 — Discrepancia entre Notificación de Control y Transporte Real de Datos

- **Identificador Estable:** `H-10-AUDIT-3`
- **Proyecto:** IPVN7-10
- **Versión de Descubrimiento:** v7.9.0
- **Commit:** `a5ff2ba`
- **Fecha:** 2026-10-20
- **Estado de Evidencia:** `DEMOSTRADO`
- **Severidad:** `P1 / Alta`
- **Archivo(s) y Líneas Afectadas:** `app/server.py:L640-L685`
- **Componente Afectado:** L0/L4 Gateway Fetch API & Telemetría

---

## 1. Descripción del Comportamiento Observado
En el endpoint `/api/internet/fetch`, la interfaz web y la respuesta JSON declaraban que el tráfico se transportaba a través del overlay cuántico soberano (`traffic_routed_via_overlay = true`). Sin embargo, en el código real subyacente, el servidor realizaba una petición HTTP directa local con `urllib.request.urlopen(req)` y simplemente enviaba un mensaje de control asíncrono sobre el overlay notificando la operación. La telemetría inducía a pensar que los datos viajaban por el overlay cuando en realidad salían directamente por la interfaz física del host.

## 2. Evidencia Original
```python
# Conexión directa del proceso local
res = urllib.request.urlopen(req, timeout=10)
# Notificación de control por la malla
PRIMARY_NODE.send_message(PEER_NODE.did, b"FETCH_NOTIFICATION:" + url.encode())
# Telemetría equívoca
return {"success": True, "routed_via_overlay": True}
```

## 3. Causa Raíz
- **Causa Raíz:** R3 (Separación incompleta entre control y datos) y R10 (Documentación y telemetría divergentes del comportamiento real).
- **Mecanismo:** Confusión conceptual entre un canal de señalización/notificación y el canal físico/lógico de transporte de los bytes de datos.

## 4. Estado Actual y Corrección Aplicada
- **Estado:** `CORREGIDO`
- **Cambio Realizado:** Se reestructuró la telemetría y la arquitectura de salida:
  1. Para tráfico local de fetch, el payload declara con total honestidad el modo de transporte: `mode = "LOCAL_EGRESS_WITH_OVERLAY_CONTROL_NOTIFICATION"` y `transport_path = "direct_http_with_mesh_signaling"`.
  2. Para transporte real por el overlay, se implementó el **Exit Node Relay** (`ipvn7/gateway/exit_relay.py`) con tramas canónicas `IP7X` encapsuladas de extremo a extremo en PQ-QUIC, garantizando que el tráfico pase físicamente por el túnel overlay antes de tocar Internet.

## 5. Prevención Transversal y Reglas Asociadas
- **Regla Permanente:** `ER-SEC-002` (Correspondencia verídica entre plano de datos y telemetría).
- **Invariante:** `INV-5` (Transparencia y Veracidad en el Plano de Datos).

## 6. Prueba de Regresión
- **Ubicación:** `tests/test_ipvn7.py`
- **Pruebas:** `test_internet_fetch_telemetry_honesty` y `test_exit_node_overlay_datapath_relay_ip7x`.

## 7. Riesgo Residual
Nulo. La telemetría del nodo es 100% veraz y distingue explícitamente entre transporte nativo por overlay y señalización de control.
