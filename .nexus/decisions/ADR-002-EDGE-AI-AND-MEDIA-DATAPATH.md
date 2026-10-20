# ADR-002: Embajador Edge AI LAN, Datapath de Streaming Multimedia IP7M y Estrés de Churn

## Estado
**Aceptado y Activo** (2026-10-20)

## Contexto
Siguiendo las directivas de auto-evolución y las líneas de trabajo abiertas en el Manifiesto de IPVN 7, se requería:
1. Conectar de forma transparente la inferencia de Inteligencia Artificial local (modelos en Ollama, BitNet, Exo en LAN) a través de la malla cuántica.
2. Permitir el streaming bidireccional multimedia de baja latencia (video AV1/H.265 y audio Opus) para el escritorio remoto y comunicaciones P2P sin superar el MTU de 1280 bytes.
3. Evaluar empíricamente la robustez topológica de la red Small-World bajo condiciones adversas severas (churn, pérdida de paquetes y jitter).

## Decisión
1. **Embajador Edge AI en Dispositivos Sombra (`ipvn7/access/shadow_device.py`)**:
   - Asignación de DIDs deterministas (`did:ipvn7:shadow:...`) e IPs virtuales `10.7.100.X/24` a workers físicos de IA.
   - Enrutamiento de prompts vía HTTP a endpoints locales con fallback elástico a síntesis soberana emulada ante desconexión física.
   - Herramienta MCP: `ipvn7_dispatch_edge_ai_prompt`.

2. **Datapath de Streaming Multimedia Canónico IP7M (`ipvn7/access/remote_desktop.py`)**:
   - Cabecera binaria de 25 bytes (`0x4950374D 'IP7M'`) con fragmentación en datagramas $\le 1280$ bytes (máx payload: 1250B).
   - Ensamblado determinista con verificación estricta CRC32 por fragmento.
   - Herramienta MCP: `ipvn7_dispatch_remote_media_frame`.

3. **Banco de Pruebas de Estrés de Churn y Multipath (`ipvn7/simulation/churn.py`)**:
   - Simulación de caídas masivas de nodos (hasta 40%), pérdidas estocásticas de paquetes (5%-20%) y latencias fluctuantes (100ms-2000ms).
   - Cálculo automático de puntuación de resiliencia compuesta.
   - Herramienta MCP: `ipvn7_run_churn_stress_test`.

## Consecuencias
- **Catálogo MCP Ampliado:** De 53 a **56 herramientas nativas**.
- **Cobertura de Pruebas:** De 78 a **82 tests unitarios pasando al 100%**.
- **Subsistemas Integrados:** De 54 a **57 subsistemas activos**.
- **Cero Dependencias Adicionales:** Se mantiene el mandato estricto de cero librerías externas fuera de `cryptography` y la librería estándar de Python 3.14.
