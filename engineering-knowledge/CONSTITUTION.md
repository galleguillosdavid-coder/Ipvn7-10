# CONSTITUCIÓN DE INGENIERÍA Y SEGURIDAD — LAIA

**Tipo:** Mandato Inviolable  
**Ámbito:** IPVN 7 y proyectos transversales en Antigravity  

Esta Constitución define los principios fundamentales que ninguna tarea, desarrollo, agente o refactorización puede ignorar o eludir bajo ninguna circunstancia.

---

## 1. La Evidencia Precede a la Declaración de Éxito
- Ningún problema se declara solucionado sin una prueba reproducible ejecutada en vivo cuyo código de salida sea exitoso (0).
- Un test existente que pasa no demuestra por sí solo que una vulnerabilidad haya sido mitigada; debe existir una prueba negativa diseñada específicamente para refutar la solución.

## 2. Autorización Explícita en Operaciones Privilegiadas
- Ningún endpoint, función o herramienta MCP con efectos secundarios sobre el sistema operativo, el hardware, las tablas de enrutamiento o el almacenamiento puede ejecutarse sin autenticación criptográfica explícita.
- La cabecera `Origin` o la procedencia de loopback (`127.0.0.1`) no constituyen por sí solas autorización suficiente para operaciones privilegiadas.

## 3. Cero Secretos Inseguros Predeterminados
- Queda terminantemente prohibido quemar contraseñas, claves privadas, tokens de control o llaves criptográficas estáticas en el código fuente.
- En despliegues donde no se configure una credencial mediante variable de entorno, el sistema debe generar dinámicamente un token aleatorio con entropía criptográfica (mínimo 256 bits) en cada inicio.

## 4. Garantías Vinculadas a Pruebas
- Toda garantía arquitectónica declarada (ej. "Forward Secrecy", "Anti-SSRF", "Transporte Overlay", "Resistencia a MITM") debe estar respaldada por un caso de prueba ejecutable en `tests/`.
- Afirmaciones sin prueba asociada deben clasificarse como `HIPÓTESIS` o `NO VERIFICADO`.

## 5. Documentación de Supuestos en Protocolos
- Todo protocolo de red o intercambio criptográfico debe documentar explícitamente sus condiciones de contorno: qué adversarios modela, qué primitivas utiliza, cómo se autentica la identidad y qué ocurre ante la pérdida de conectividad o desincronización de estado.

## 6. Prevención Transversal Obligatoria
- Ante la detección de una causa raíz en un módulo, el ingeniero o agente tiene la obligación de examinar todos los demás módulos y proyectos accesibles para comprobar si comparten el mismo patrón de fallo y aplicar la prevención correspondiente.

## 7. Trazabilidad Permanente de Cambios Críticos
- Ningún hallazgo histórico de seguridad se elimina. Cuando un defecto se corrige, su estado cambia a `CORREGIDO`, vinculando el commit exacto, las líneas modificadas y la prueba de regresión que lo salvaguarda.

## 8. Declaración Explícita de Limitaciones del Entorno
- Si un análisis o prueba no puede ejecutarse por falta de dependencias, permisos o dispositivos de red, debe declararse explícitamente como limitación técnica. Está prohibido simular o inventar resultados de pruebas no ejecutadas.

## 9. Verificación de Efecto Real vs. Notificación
- Una respuesta HTTP exitosa o un mensaje de control despachado a través de una red no demuestra que los datos hayan transitado por el túnel previsto. El plano de datos debe verificarse mediante la medición real de bytes cursados por el transporte cifrado.
