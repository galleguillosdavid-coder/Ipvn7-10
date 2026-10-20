# MAPA DE CAUSAS RAÍZ Y ANÁLISIS DE FALLAS (ROOT CAUSES) — LAIA

**Versión:** 1.0  
**Ámbito:** IPVN 7 y proyectos transversales en Antigravity  

Este documento analiza los patrones de razonamiento, diseño, implementación y validación que originaron los defectos detectados en las auditorías de IPVN 7.

---

### R1. Diseño sin Invariantes Verificables
- **Estado:** `CAUSA RAÍZ DEMOSTRADA`.
- **Mecanismo:** La arquitectura declaraba que el handshake PQC proporcionaba "sesión segura y resistente a computación cuántica", pero no definió como invariante matemático que el transcript debía estar firmado por la clave de identidad de largo plazo del par. Como resultado, se implementó HKDF con `info=b"IPVN7-HYBRID-SESSION-AUTH"` sin firma digital, dejando una ventana para ataques de intermediario activo (MITM).
- **Prevención:** Toda especificación debe enunciar formalmente sus invariantes de seguridad (`SECURITY_INVARIANTS.md`) y vincularlos a pruebas unitarias negativas de refutación.

---

### R2. Confusión entre Componentes y Garantías
- **Estado:** `CAUSA RAÍZ DEMOSTRADA`.
- **Mecanismo:** Se asumió que por el hecho de importar y ejecutar `mlkem.MLKEM768` y `x25519` el protocolo completo era seguro. La posesión de una primitiva criptográfica avanzada no equivale a la seguridad de la composición completa del protocolo.
- **Prevención:** Análisis formal de composición criptográfica y pruebas adversariales de sustitución de claves (`test_audit_3_h09_pqc_authenticated_handshake_and_mitm_rejection`).

---

### R3. Separación Incompleta entre Control y Datos
- **Estado:** `CAUSA RAÍZ DEMOSTRADA`.
- **Mecanismo:** En `/api/internet/fetch` y en SOCKS5, el código enviaba una trama de notificación de control al nodo par (`send_message_sync`), pero los datos HTTP/TCP reales se descargaban o conectaban localmente mediante `urllib.request` o `socket.create_connection`. La respuesta del control se confundió con el transporte efectivo de los datos.
- **Prevención:** Separar explícitamente los planos de control y de datos en la telemetría. Requerir que el transporte de datos viaje por tramas `IP7X` al Exit Node antes de reportar un flujo como "tunelizado".

---

### R4. Validación de Entrada sin Garantía de Uso Seguro (TOCTOU)
- **Estado:** `CAUSA RAÍZ DEMOSTRADA`.
- **Mecanismo:** En versiones previas de las pasarelas, se validaba un nombre de dominio contra la política SSRF, pero luego `socket.create_connection((host, port))` volvía a resolver el nombre en el sistema operativo, permitiendo que un atacante con DNS dinámico devolviera una IP pública en la validación y `127.0.0.1` en la conexión (DNS Rebinding).
- **Prevención:** `EgressSecurityPolicy.resolve_and_validate_host()` retorna la tupla de IPs resueltas y el socket se conecta exclusivamente a `valid_ips[0]` (Fijación de IP).

---

### R5. Autorización Fragmentada
- **Estado:** `CAUSA RAÍZ DEMOSTRADA`.
- **Mecanismo:** La verificación de autorización no era uniforme: mientras que algunos endpoints requerían token, otros confiaban implícitamente en peticiones provenientes de `127.0.0.1` o cabeceras `Origin` sin exigir Bearer token estricto.
- **Prevención:** `_validate_control_auth()` centralizado que valida obligatoriamente Bearer token con comparación en tiempo constante (`secrets.compare_digest`) y `Sec-Fetch-Site: same-origin`.

---

### R6. Pruebas que Verifican Implementación, no Propiedades
- **Estado:** `CAUSA RAÍZ DEMOSTRADA`.
- **Mecanismo:** Los tests iniciales solo verificaban el "happy path" (ej. que dos nodos pudieran intercambiar una clave o que SOCKS5 aceptara el handshake RFC 1928), sin someter el sistema a casos negativos de inyección, destinos prohibidos, sobrecarga de concurrencia o manipulación de bytes en tránsito.
- **Prevención:** Obligatoriedad de pruebas negativas adversariales (pruebas de suplantación, fuzzing de buffers malformados y rechazo de IPs privadas).

---

### R7. Cierre Prematuro de Tareas
- **Estado:** `CAUSA RAÍZ DEMOSTRADA`.
- **Mecanismo:** Declarar una auditoría como "completada" porque se implementaron parches en código y los tests existentes pasaban, sin realizar un análisis holístico de los efectos secundarios o vectores remanentes.
- **Prevención:** Puertas de calidad estrictas (Puertas 1 a 6) que exigen evidencia empírica antes del cierre.

---

### R8. Memoria de Ingeniería Insuficiente
- **Estado:** `CAUSA RAÍZ DEMOSTRADA`.
- **Mecanismo:** Los aprendizajes quedaban dispersos en respuestas de chat o comentarios en código sin convertirse en reglas persistentes en el repositorio, lo que permitía que un error corregido en una versión reapareciera en otra.
- **Prevención:** Repositorio estructurado y versionado `engineering-knowledge/` con reglas operativas inmutables.

---

### R9. Complejidad Innecesaria
- **Estado:** `FACTOR CONTRIBUYENTE`.
- **Mecanismo:** La introducción de múltiples capas de enrutamiento y abstracciones sin un propósito operativo claro dificulta la auditoría y amplía la superficie de ataque.
- **Prevención:** Principio de diseño compacto y directo; eliminar capas redundantes y usar bibliotecas estándar cuando sea posible.

---

### R10. Documentación y Realidad Divergentes
- **Estado:** `CAUSA RAÍZ DEMOSTRADA`.
- **Mecanismo:** El README y las especificaciones anunciaban "túnel overlay cuántico para todo el tráfico del sistema", pero la implementación de SOCKS5 ejecutaba sockets directos.
- **Prevención:** Sincronización estricta entre la telemetría en tiempo de ejecución, las métricas de CI y las afirmaciones documentales (ER-SEC-012).
