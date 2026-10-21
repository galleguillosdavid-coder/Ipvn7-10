# ADR-016: Sovereign eBPF / XDP Wire-Speed Switch & Early-Drop Engine (Línea S)

## Estado
Aceptado e Implementado (v7.14.0)

## Fecha
2026-10-21

## Contexto y Motivación
Bajo condiciones de ataque de denegación de servicio (DDoS), inundación de tráfico UDP espurio o saturación de enlaces inter-nodo, procesar paquetes ilegítimos en el espacio de usuario (Python / sockets estándar) impone una sobrecarga crítica por:
1. Asignación de estructuras `sk_buff` en el kernel de Linux.
2. Cambio de contexto (context switch) e interrupciones de hardware hacia espacio de usuario.
3. Deserialización y análisis de tramas que no pertenecen a la red soberana IPVN 7.

Inspirado en los prototipos históricos rescatados de `0.7/src/pkg/l0/ebpf_xdp_spec.go` y `xdp_ipvn7.c`, se formaliza la **Línea S (v7.14.0)**: **Sovereign eBPF / XDP Wire-Speed Switch & Early-Drop Engine**.

## Decisión de Diseño
Se implementa un subsistema de conmutación de nivel de kernel en `ipvn7/access/xdp_switch.py`, integrado en el núcleo `ipvn7/node/node.py`, en el servidor MCP (`ipvn7/node/mcp.py`), en la API REST (`app/server.py`) y en la interfaz de usuario (`app/static/`):

1. **Simulador de Kernel eBPF / XDP (`XDPKernelSimulator`)**:
   - Emulación rigurosa del verificador de límites (*packet bounds checking*) del kernel de Linux:
     - Ethernet: 14 bytes mínimos (`h_proto == ETH_P_IP` o `ETH_P_IPV6`).
     - IPv4: IHL $\ge 20$ bytes y `protocol == IPPROTO_UDP` (17).
     - IPv6: Cabecera fija de 40 bytes y `next_header == IPPROTO_UDP`.
     - UDP: Cabecera de 8 bytes y discriminación de puerto de malla (`dest_port == mesh_port`).
   - El tráfico que no va dirigido al puerto de la malla (ej: TCP local, DNS 53) es devuelto con `XDP_PASS` al stack normal del sistema operativo para no interferir con la conectividad del host.

2. **Descarte Temprano en Alambre en $O(1)$ (*Wire-Speed Early Drop*)**:
   - Todo paquete dirigido al puerto de la malla IPVN 7 que viole el MTU acotado ($\text{payload} > 1280$B) es descartado de inmediato con `XDP_DROP`.
   - Datagramas truncados ($< 4$ bytes) son descartados con `XDP_DROP` e incrementan el contador de malformados.
   - Reconocimiento estricto del catálogo completo de las 11 cabeceras mágicas canónicas:
     - `IP7V`: Legacy Genesis Datagram (0x49503756)
     - `IP7H`: HRS Silent Substrate Frame (0x49503748)
     - `IP7M`: Mobility Anchor Ticket Frame (0x4950374D)
     - `IP7B`: BitNet Quantized Container (0x49503742)
     - `IP7X`: Exit Relay Overlay Frame (0x49503758)
     - `IP7R`: Reciprocity Settlement Token Frame (0x49503752)
     - `IP7S`: Ephemeral Ring Signature / DHT Sync Frame (0x49503753)
     - `IP7T`: Tunnel Telemetry PMTU Frame (0x49503754)
     - `IP7E`: TEE Enclave Sealed Frame (0x49503745)
     - `IP7Z`: Zero-Knowledge Proof Frame (0x4950375A)
     - `IP7P`: WAN Active Prober Binary Frame (0x49503750)
   - Cualquier tráfico ilegítimo o foráneo que impacte el puerto seguro es descartado en $O(1)$ sin asignación de memoria.

3. **Generador y Exportador de Código C Nativo de Kernel**:
   - Método `generate_c_program(mesh_port)` genera el código fuente completo en C listo para compilación con:
     `clang -O2 -target bpf -c xdp_ipvn7.c -o xdp_ipvn7.o`
   - Define mapas BPF de tipo `BPF_MAP_TYPE_PERCPU_ARRAY` (`ipvn7_stats_map`) para telemetría atómica lock-free en el driver.

4. **Herramienta MCP 73 (`ipvn7_xdp_switch`)**:
   - Acciones soportadas: `process_frame`, `process_payload`, `get_stats`, `reset_stats`, `export_c`, `synthesize_frame`.
   - Permite que agentes y copilotos de IA inspeccionen en vivo la saturación del filtro y descarguen el programa C nativo para despliegue en entornos Linux de producción.

5. **API REST y Panel de Control Interactivo**:
   - `GET /api/xdp/stats`: Estadísticas atómicas y porcentaje de early drop.
   - `GET /api/xdp/export_c`: Código fuente nativo en C con flags de compilación.
   - `POST /api/xdp/filter`: Evaluación en tiempo real de tramas o cargas útiles.
   - `POST /api/xdp/reset`: Reinicio de contadores atómicos.
   - `POST /api/xdp/synthesize`: Síntesis de tramas Ethernet/IPv4/UDP para pruebas de laboratorio.
   - UI Glassmorphism: Nueva pestaña `tab-xdp` con 3 tarjetas de control y actualización periódica de telemetría.

6. **Cobertura de Pruebas Unitarias**:
   - Añadidos Tests 133 al 137 en `tests/test_ipvn7.py`.
   - Total de suite: **137 pruebas unitarias pasando al 100% de éxito (0 regresiones)**.

## Consecuencias y Garantías Verificables
- **Mitigación DDoS en Capa 0**: Descarte en la tarjeta de red (NIC driver) antes de que el paquete alcance el stack IP del kernel.
- **Invariante MTU Garantizada**: Ningún payload $> 1280$B puede atravesar el conmutador hacia la pila QUIC/ZTNA.
- **Compatibilidad Dual**: Operable como simulador nativo en Python en plataformas Windows/macOS y como programa eBPF nativo de kernel en plataformas Linux de producción.
