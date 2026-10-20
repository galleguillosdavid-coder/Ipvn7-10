# POLÍTICA DE VALORES POR DEFECTO SEGUROS (SECURE DEFAULTS) — LAIA

**ID:** `POL-SEC-001`  
**Ámbito:** Todo el software desarrollado en el ecosistema IPVN 7  

---

## 1. Principio Fundamental
El software debe ser seguro en su configuración inicial sin requerir que el operador realice ajustes manuales para proteger el sistema contra ataques triviales.

## 2. Reglas Específicas
1. **Credenciales:** Jamás incluir contraseñas, claves API o tokens por defecto en el código fuente. Si falta configuración, el software debe generar credenciales efímeras seguras en memoria o denegar el arranque.
2. **Escucha de Red:** Todos los servicios administrativos o pasarelas de desarrollo deben vincularse exclusivamente a la interfaz de loopback (`127.0.0.1` o `::1`) por defecto. La vinculación a `0.0.0.0` solo se permite bajo directiva explícita del operador.
3. **Denegación por Defecto:** Cualquier operación que no esté explícitamente permitida por una política de cortafuegos o control de acceso debe ser rechazada de inmediato.
4. **Límites de Recursos:** Toda cola de mensajes, buffer de red o bucle de escucha debe tener cotas máximas de tamaño y concurrencia preconfiguradas.
