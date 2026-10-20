# ADR-009: Telemetría de Túneles Soberanos, Descubrimiento Dinámico de Path MTU (PMTU) y Failover Bicast Multipath

- **Estado:** Aceptado e Implementado
- **Fecha:** 2026-10-20
- **Versión de IPVN 7:** v7.7.0
- **Autor:** Agente Autónomo Autoevolutivo (Línea N del Backlog Soberano)
- **Suite de Pruebas:** 97/97 aprobadas (100% verde)
- **Herramientas MCP Activas:** 63 herramientas

---

## 1. Contexto y Desafío Operativo

En entornos de malla WAN y enlaces híbridos (Wintun userspace/kernel TUN, overlays WireGuard y sockets directos UDP), el tráfico de datos enfrenta dos desafíos estructurales:
1. **Caídas Silenciosas por MTU (Black Hole Drops):** La encapsulación PQC y los túneles superpuestos añaden encabezados que pueden sobrepasar la MTU del enlace físico intermedio (típicamente 1500B en Ethernet o 1420B en WireGuard), provocando descartes por `Fragmentation Needed` bloqueados por cortafuegos o DPI.
2. **Degradación Estocástica de Enlace y Jitter Extremo:** Cuando un túnel WAN sufre una pérdida súbita de paquetes (>10%) o picos de fluctuación de fase (Jitter RFC 3550 >50ms), las conexiones de streaming o RPC sufren congelamientos si dependen de conmutaciones lentas.

---

## 2. Decisión de Arquitectura Soberana

Se implementa el subsistema **`SovereignTunnelTelemetry`** (`ipvn7/network/tunnel_telemetry.py`), estructurado sobre los siguientes principios:

### A. Motor de Descubrimiento Dinámico de Path MTU (`PathMTUEngine`)
- Explora adaptativamente el techo de MTU en tránsito entre un límite mínimo seguro de 576 bytes (RFC 791/2460) y un techo de 1420 bytes (WireGuard envelope).
- **Convergencia Binaria Rápida:** Ante sondas exitosas de mayor tamaño, expande gradualmente la MTU activa. Ante pérdidas o descartes, aplica retroceso inmediato a un tamaño seguro garantizando que los datagramas subsiguientes no sufran fragmentación en el camino.

### B. Enmarcado Canónico en el Cable `IP7T` con Integridad CRC32
Se estandariza el Magic en cable `b"IP7T"` (4 bytes) con 5 tipos de trama:
- `0x01` - `PROBE`: Sonda unicast periódica de telemetría y RTT.
- `0x02` - `PROBE_ACK`: Respuesta con marca de tiempo remota para cálculo de latencia de ida y vuelta.
- `0x03` - `PMTU_DISCOVERY`: Sonda de tamaño variable con relleno determinista para probar el tamaño máximo admisible sin fragmentación.
- `0x04` - `PMTU_FEEDBACK`: Notificación del extremo receptor sobre el tamaño máximo de paquete recibido íntegramente.
- `0x05` - `FAILOVER_SIGNAL`: Señal de alerta temprana para activación inmediata de duplicación bicast en interfaces secundarias.

### C. Algoritmo de Jitter RFC 3550 y RTT EWMA
- Cálculo continuo del Jitter de llegada inter-paquete:
  $$J(i) = J(i-1) + \frac{|D(i-1, i)| - J(i-1)}{16}$$
- Estimador EWMA de RTT según RFC 6298 ($\alpha = 0.125$).
- Clasificación de salud automática:
  - `HEALTHY`: Pérdida $\le 3\%$, Jitter $\le 20\text{ ms}$.
  - `DEGRADED`: Pérdida entre $3\%$ y $10\%$, o Jitter entre $20\text{ ms}$ y $50\text{ ms}$.
  - `CRITICAL_FAILOVER`: Pérdida $> 10\%$ o Jitter $> 50\text{ ms}$ $\to$ Se activa automáticamente la replicación concurrente bicast sobre el planificador multipath sin esperar timeout de sesión.

---

## 3. Interfaces Operativas Incorporadas

1. **Herramienta MCP #63 (`ipvn7_probe_tunnel_telemetry`):**
   - Parámetros: `tunnel_id`, `sample_rtt_ms`, `packet_lost`, `pmtu_probe_size`, `pmtu_probe_success`.
   - Retorno: Métricas de túnel en tiempo real, PMTU activo, Jitter RFC 3550, tasa de pérdida y estado de failover bicast.

2. **Endpoints HTTP/JSON Dashboard REST:**
   - `GET /api/tunnel/telemetry`: Resumen consolidado de todos los túneles activos, MTUs descubiertas y estado de salud.
   - `POST /api/tunnel/telemetry/probe`: Inyección y simulación de sondas de telemetría y adaptación PMTU.

3. **Prueba Unitaria 97:**
   - `test_sovereign_tunnel_telemetry_pmtu_and_bicast_failover`: Cobertura exhaustiva de empaquetado binario `IP7T`, verificación CRC32, adaptación de PMTU, cálculo de Jitter RFC 3550 y disparo de conmutación bicast.

---

## 4. Estado de Verificación

- **Pruebas Automatizadas:** 97/97 aprobadas (100% verde).
- **Tiempo de Ejecución:** ~6.8 segundos en entorno Windows local.
- **Validación en Vivo:**
  ```json
  {
    "total_tunnels": 1,
    "tunnels": {
      "tun0-wintun": {
        "interface": "wintun",
        "remote": "127.0.0.1:9443",
        "pmtu": 1280,
        "rtt_ewma_ms": 10.31,
        "jitter_ms": 0.469,
        "loss_ratio": 0.0,
        "health": "HEALTHY",
        "bicast_active": false
      }
    }
  }
  ```
