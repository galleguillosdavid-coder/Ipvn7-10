# POLÍTICA DE INTEGRIDAD Y CADENA DE SUMINISTRO (SUPPLY CHAIN) — LAIA

**ID:** `POL-SEC-005`  
**Ámbito:** Dependencias, Binarios y Workflows de CI/CD en IPVN 7  

---

## 1. Principio Rector
Un hash de archivo detecta alteraciones respecto a un valor conocido, pero por sí solo no garantiza quién lo produjo ni si fue autorizado. La integridad exige procedencia verificable y firmas criptográficas.

## 2. Invariantes de la Cadena de Suministro
1. **Minimización Extrema de Dependencias:** El núcleo de IPVN 7 depende únicamente de la biblioteca estándar de Python y `cryptography`. Queda prohibido añadir dependencias externas sin justificación arquitectónica aprobada.
2. **Binarios en el Repositorio (`wintun.dll`):** Todo binario incluido en el repositorio debe documentar su procedencia oficial (sitio oficial Wintun/WireGuard), su hash SHA-256 inmutable y la firma digital del ejecutable.
3. **Bloqueo de Versiones en CI:** Los workflows de GitHub Actions deben fijar versiones específicas de runners y herramientas para prevenir ataques de envenenamiento de pipeline.
4. **Escaneo Automático:** Ejecución periódica de herramientas de análisis de dependencias (`pip-audit`) y análisis estático en cada pull request.
