# ADR-018: Sovereign Over-The-Air (OTA) Hot-Swapping & Sandboxing Engine (Línea U)

## Estado
Aceptado e Implementado (v7.16.0)

## Fecha
2026-10-21

## Contexto y Motivación
En una red soberana y distribuida como IPVN 7, los nodos operan en entornos heterogéneos, perimetrales y a menudo no asistidos. La necesidad de desplegar parches de seguridad, optimizaciones de algoritmos o extensiones de servicios en tiempo real se enfrenta al dilema de la disponibilidad y la integridad:
1. **Disponibilidad Continua**: Reiniciar el proceso del nodo interrumpe sesiones criptográficas activas, borra tablas de enrutamiento efímeras y produce caídas momentáneas en los túneles PQC.
2. **Seguridad y Confianza Cero**: Cargar código ejecutable dinámicamente sin verificación formal o aislamiento estático expone al nodo a ejecución remota de código (RCE) malicioso o exfiltración de secretos locales (claves privadas ML-KEM/Falcon).
3. **Resiliencia ante Fallos de Ejecución**: Si un nuevo módulo entra en fallo durante las primeras invocaciones, el sistema debe revertir automáticamente al estado previo sin requerir intervención manual del operador.

Para solucionar estos desafíos de forma soberana y determinista, se diseña la **Línea U (v7.16.0)**: **Sovereign Over-The-Air (OTA) Hot-Swapping & Sandboxing Engine**.

## Decisión de Diseño

Se implementa el subsistema `ipvn7/access/ota_hotswap.py`, coordinado con el nodo soberano `IPVN7Node`:

1. **Manifiesto Criptográfico y Direccionamiento DAG (`ModuleManifest`)**:
   - Cada paquete de software OTA se encapsula en un manifiesto que incluye:
     * Metadatos: `module_name`, `version`, `author_did`, `target_subsystem`, `description`.
     * Integridad del código: hash SHA-256 de los bytes del payload (`code_sha256`).
     * Firma Digital Ed25519: firma generada sobre la serialización canónica JSON de los metadatos y el hash del código.
     * Identificador Descentralizado de Contenido (DAG CID): `cid:ipvn7:manifest:<sha256>`, permitiendo almacenamiento y direccionamiento inmutable en la red IPVN 7.

2. **Caja de Arena de Pre-Vuelo y AST Sanitizer (`IsolatedModuleSandbox`)**:
   - Antes de cualquier compilación o ejecución, el código fuente es analizado sintácticamente mediante el árbol de sintaxis abstracta (`ast.parse`).
   - Lista negra estricta de módulos prohibidos: `os`, `sys`, `subprocess`, `socket`, `shutil`, `pty`, `commands`. Cualquier intento de importación estática o dinámica dispara `SecurityError`.
   - Lista negra de built-ins prohibidos: `eval`, `exec`, `__import__`, `open`, `compile`, `getattr`, `globals`, `locals`.
   - Entorno de ejecución restringido: Se ejecuta en un espacio de nombres con built-ins mínimos y seguros (`len`, `range`, `str`, `int`, etc.), impidiendo accesos al sistema de archivos local o creación de sockets crudos no autorizados.

3. **Reemplazo Atómico en Caliente (*Atomic Hot-Swap*)**:
   - El administrador de OTA (`SovereignOTAManager`) mantiene un registro thread-safe de módulos activos con `threading.RLock`.
   - Antes de instalar un nuevo módulo, se toma un snapshot del estado actual (`ModuleSnapshot`), preservando el bytecode previo, versión y referencias en memoria.
   - Si la validación en la caja de arena es exitosa, el puntero en memoria del módulo activo se intercambia atómicamente, pasando a estado `PROBATION`.

4. **Watchdog de Período de Prueba y Reversión Automática (*Probation Watchdog*)**:
   - Cada módulo recién instalado entra en estado `PROBATION` durante una ventana configurable (por defecto 5.0 segundos).
   - Durante este período, las invocaciones al módulo (`execute_module`) son monitoreadas por el watchdog.
   - Si el módulo arroja cualquier excepción o fallo no controlado, el watchdog activa inmediatamente una reversión automática (`rollback_module`), restaurando el snapshot previo y marcando el módulo como `ROLLED_BACK`.
   - Si el módulo opera sin errores y expira la ventana de prueba, se promueve automáticamente a estado `ACTIVE`.

5. **Herramienta MCP 75 (`ipvn7_ota_hotswap`)**:
   - El catálogo de herramientas MCP de IPVN 7 alcanza exactamente 75 herramientas nativas.
   - Acciones soportadas: `get_status`, `list_modules`, `package_module`, `install_module`, `rollback_module`.

6. **Integración REST y Dashboard Web**:
   - Endpoints:
     * `GET /api/ota/status`: Devuelve el DID de autoridad, modo de sandboxing, ventana de prueba y conteo de módulos.
     * `GET /api/ota/modules`: Lista todos los módulos registrados con sus estados de ciclo de vida.
     * `POST /api/ota/package`: Empaqueta, firma criptográficamente y calcula el DAG CID de un código fuente.
     * `POST /api/ota/install`: Valida en sandbox, ejecuta pre-vuelo y realiza el hot-swap atómico.
     * `POST /api/ota/rollback`: Reversión manual o forzada al snapshot previo.
   - UI: Pestaña `tab-ota` con tarjetas para estado/empaquetado interactivo y panel de inspección de módulos activos con botón de reversión.

## Consecuencias y Garantías

- **Zero-Downtime Patching**: Actualización de algoritmos de enrutamiento o extensiones de servicios sin reiniciar procesos ni reconectar túneles PQC.
- **Inmunidad a RCE y Escalada de Privilegios**: El analizador AST y sandbox impiden que código no autenticado o con llamadas a librerías de sistema operativo sea ejecutado.
- **Autocorrección Garantizada**: Fallos en módulos probatorios no degradan el nodo permanentemente, gracias al rollback automático por watchdog.
