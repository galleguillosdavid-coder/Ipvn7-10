# POLÍTICA DE AUTORIZACIÓN DEL PLANO DE CONTROL MCP — LAIA

**ID:** `POL-SEC-004`  
**Ámbito:** Model Context Protocol (MCP) y Operaciones de Servidor en IPVN 7  

---

## 1. Principio Rector
El protocolo MCP proporciona una interfaz de invocación de herramientas, pero **no delega implícitamente la autorización de la aplicación**. Cada invocación de herramienta debe validar identidad, permisos y límites operativos.

## 2. Invariantes de Seguridad MCP
1. **Autenticación Obligatoria:** Todas las llamadas a `/api/mcp` o `/mcp` deben presentar un Bearer token criptográfico válido (`CONTROL_AUTH_TOKEN`) o provenir de un origen local verificado con `Sec-Fetch-Site: same-origin`.
2. **Denegación por Defecto:** Las herramientas que no figuren explícitamente en el catálogo de herramientas autorizadas son rechazadas con error `-32601 Method not found`.
3. **Mínimo Privilegio:** Herramientas que modifiquen el sistema de archivos, ejecuten comandos del sistema operativo o alteren tablas de enrutamiento requieren un nivel de privilegio superior y confirmación explícita.
4. **Validación de Esquemas:** Todo parámetro recibido en `execute_tool` debe coincidir en tipo, longitud y formato con el esquema JSON Schema declarado.
