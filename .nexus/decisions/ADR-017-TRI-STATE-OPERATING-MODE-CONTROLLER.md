# ADR-017: Sovereign Tri-State Operating Mode Controller & Adaptive Health Governor (Línea T)

## Estado
Aceptado e Implementado (v7.15.0)

## Fecha
2026-10-21

## Contexto y Motivación
En el documento fundacional de arquitectura (`ip7uin_MVP_Spec_v1.1.docx` Sección 4.8) y en prototipos históricos (`0.7/src/pkg/core/operating_modes.go`), un nodo soberano IPVN 7 no puede considerarse un sistema estático con políticas fijas. Frente a fluctuaciones drásticas en las condiciones operativas —congestión severa, hostilidad de la red, ataques de denegación de servicio o necesidad de sigilo absoluto— el nodo debe orquestar sus subsistemas de forma coherente y atómica.

Hasta la versión v7.14.0 existía un orquestador binario (`DarkNodeMacroOrchestrator`) que alternaba entre `STANDARD_MESH` y `DARK_NODE_EGRESS_ONLY`. Sin embargo:
1. No existía un modo específico para degradación y defensa ante recursos agotados o congestión extrema (`MODE_DEGRADED`).
2. Faltaba un **Gobernador Adaptativo de Salud** que monitorease autónomamente métricas de pérdida de paquetes, descarte de eBPF/XDP y saturación de colas para disparar automáticamente contramedidas y recuperarse tras una ventana de enfriamiento (*cool-down*).
3. No se contaba con un anillo de auditoría inmutable de transiciones con snapshots causales de telemetría.

Para resolver estas deficiencias se formaliza la **Línea T (v7.15.0)**: **Sovereign Tri-State Operating Mode Controller & Adaptive Health Governor**.

## Decisión de Diseño

Se implementa el módulo `ipvn7/security/operating_modes.py`, unificando y expandiendo el perfil de seguridad en coordinación con `DarkNodeMacroOrchestrator`, `ZTNAFirewall`, `DWRRScheduler` y `XDPKernelSimulator`:

1. **Modos de Operación Tri-Estado (`NodeOperatingMode`)**:
   - `MODE_OPEN` (Malla Nominal Estándar):
     - Comunicación bidireccional abierta.
     - Anuncios de escucha activos en la DHT (visibilidad normal).
     - Asignación balanceada de cuotas y pesos DWRR en las 4 clases de tráfico.
     - Evaluación estándar ZTNA.
   - `MODE_SAFE` (Nodo Oscuro / Sigilo Activo):
     - Perfil Egress-Only con Cero-PII.
     - Anuncios públicos en DHT silenciados (*Zero Broadcast Leakage*).
     - Enrutamiento cebolla Sphinx mandatorio de 3 saltos con tramas fijas de 1280B.
     - Micro-jitter activo en el pacer contra análisis de correlación temporal de flujos.
     - Cortafuegos ZTNA con *Default-Deny* estricto en tráfico no solicitado.
   - `MODE_DEGRADED` (Defensa Austera & Contención de Congestión):
     - Purga inmediata de la cola Scavenger / Bulk (`QoSClass.BULK`) en el planificador DWRR para liberar RAM al instante.
     - Reasignación de pesos DWRR: Control (peso 6000) y Realtime (peso 3500) concentran el 95% de la capacidad de transmisión; Bulk queda en 0.
     - Anuncios públicos silenciados para reducir el vector de ataque externo.
     - Cortafuegos ZTNA en *Default-Deny* reforzado.

2. **Gobernador Adaptativo de Salud (`evaluate_health`)**:
   - Monitorea tres señales críticas de saturación de red:
     * Pérdida de paquetes > 30% (`loss_pct > 30.0%`).
     * Tasa de descarte temprano eBPF/XDP > 25% (`drop_ratio_pct > 25.0%`).
     * Ocupación de buffer de colas DWRR > 80% (`buffer_util_pct > 80.0%`).
   - Disparo Inmediato: Si cualquiera de las tres invariantes es violada, el nodo conmuta atómicamente a `MODE_DEGRADED`, preservando en `pre_degraded_mode` el estado anterior (`MODE_OPEN` o `MODE_SAFE`).
   - Auto-Recuperación con Ventana de Enfriamiento: Una vez que las métricas retornan al rango nominal, el controlador requiere que transcurra el tiempo de enfriamiento (`cooldown_sec`, defecto 10.0s) y se registren al menos 2 evaluaciones limpias consecutivas antes de restaurar automáticamente el modo previo.

3. **Anillo de Auditoría Causal de Transiciones**:
   - Bounded ring buffer de hasta 32 transiciones (`collections.deque(maxlen=32)`).
   - Cada transición registra: `from_mode`, `to_mode`, `reason`, `timestamp_iso`, `timestamp_epoch` y un snapshot de las métricas de telemetría en el momento del cambio.
   - Idempotencia estricta: llamadas repetidas al mismo modo no introducen ruido ni consumen ranuras en el historial.

4. **Herramienta MCP 74 (`ipvn7_operating_mode`)**:
   - Catálogo ampliado a 74 herramientas nativas.
   - Acciones soportadas: `get_status`, `set_mode`, `evaluate_health`, `get_history`.

5. **Exposición REST y Dashboard Web**:
   - Endpoints: `GET /api/mode/status`, `GET /api/mode/history`, `POST /api/mode/set`, `POST /api/mode/evaluate`.
   - UI: Pestaña `tab-operating-mode` con 3 tarjetas de control (Estado y Protecciones, Simulador del Gobernador de Salud, Anillo de Auditoría) e indicador de modo en el encabezado general de la aplicación.

## Consecuencias
- **Positivas**:
  * Autodefensa determinista ante DoS y congestión sin reinicio de demonio ni interrupción del tráfico de control post-cuántico.
  * Preservación del 100% de retrocompatibilidad con `toggle_dark_node_mode()` y las directivas de Línea L1.
  * Trazabilidad forense inmutable de incidentes de congestión y cambios de modo.
- **Riesgos Mitigados**:
  * La purga de colas Bulk previene la saturación del GMA (Global Memory Arbiter) y la pérdida de datagramas de control o apretones de manos PQC.
