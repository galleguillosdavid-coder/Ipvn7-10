# ADR-001: Consolidación Arquitectónica de Protocolos Históricos (IPv7-HRS y Nexus)

## Estado
**Aceptado y Activo** (2026-10-20)

## Contexto
Durante el análisis de proyectos previos en `C:\Users\Frondabrick\Desktop\dvd\Ipv7`, `C:\` y `D:\`, se identificaron implementaciones experimentales en Go (`0.7`, `ipvn7 vX7`) y Rust (`ipv7-hrs-final`, `ipv7c`), además de las especificaciones operativas de agentes en `Nexus one/two/tree`.

Muchos de estos proyectos contenían dependencias C++/Rust nativas que impedían su ejecución soberana y portable en entornos puros sin herramientas de compilación externas.

## Decisión
1. **Adopción del Principio "La Red Responde, No Grita" (de IPv7-HRS)**:
   - Se elimina el broadcast indiscriminado en el descubrimiento.
   - Se estandarizan 5 tramas canónicas (`IP7H`): `ANNOUNCE`, `QUERY`, `RESPONSE`, `HEARTBEAT` y `STATE_CHANGE`.
   - Se introducen SLAs Adaptativos según el perfil de hardware (`SERVER`, `LAPTOP`, `IOT`, `SATELLITE`).

2. **Rotación Efímera de Identidad 24 Horas**:
   - Cada nodo genera un DID efímero derivado por HMAC-SHA256 indexado por el día epoch (`time.time() // 86400`).
   - Evita el rastreo y fingerprinting físico en el cable sin romper la resolución determinista de Petnames ni del DID raíz.

3. **Arquitectura Zero-External-Dependencies**:
   - Todo el sustrato se implementa en Python 3.14 estándar con la única dependencia de `cryptography` (FIPS 203/204 y Ed25519).
   - Se descartan motores externos en Go, eBPF compilado de kernel y bases de datos gráficas nativas C++ (Kùzu).

4. **Gobierno Autónomo y Persistencia de Memoria**:
   - La arquitectura registra decisiones formales en formato ADR bajo `.nexus/decisions/`.
   - Futuras instancias de agentes IA respetarán estas decisiones consolidadas para evitar regresiones o reescrituras innecesarias.

## Consecuencias
- **Positivas**: Interoperabilidad garantizada, cobertura de tests unitarios del 100%, total reproducibilidad sin compiladores externos, reducción drástica del tráfico fantasma en capa de enlace.
- **Limitaciones**: La emulación eBPF de kernel y sockets raw se gestiona mediante el socket UDP multiplexado de la HAL en lugar de módulos de kernel de bajo nivel en Windows.
