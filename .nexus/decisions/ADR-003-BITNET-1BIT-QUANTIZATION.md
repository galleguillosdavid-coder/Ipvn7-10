# ADR-003: Motor de Cuantización Ternaria BitNet b1.58 para Nodos Edge IoT

## Estado
**Aceptado y Activo** (2026-10-20)

## Contexto
En redes soberanas IPVN 7, los nodos de borde (sensores IoT, microcontroladores, routers satelitales) disponen de presupuestos de energía extremadamente limitados (micro-watts) y carecen de unidades de punto flotante (FPU) dedicadas. Para ejecutar modelos de lenguaje o clasificadores locales sin recurrir a servidores cloud, se requería una arquitectura de pesos discretos enteros.

## Decisión
1. **Adopción del Formato Ternario BitNet b1.58 (`ipvn7/crypto/bitnet.py`)**:
   - Cada peso de la matriz se cuantiza en $\{-1, 0, 1\}$ mediante escalamiento por la media absoluta $\gamma = \text{mean}(|W|)$.
   - Empaquetamiento de 2 bits por peso: 4 pesos por byte (`00`=0, `01`=+1, `11`=-1), reduciendo el consumo de memoria en más de un 75% respecto a FP16/FP32.
2. **Inferencia Entera Zero-Multiply**:
   - Activaciones cuantizadas a enteros de 8 bits con signo (`int8` entre -128 y 127).
   - El producto matriz-vector se reduce exclusivamente a sumas y restas de enteros (`acc += x_val` o `acc -= x_val`), eliminando por completo multiplicaciones en el camino crítico.
3. **Contenedor Binario Canónico `IP7B`**:
   - Encabezado binario fijo de 20 bytes con número mágico `0x49503742` (`IP7B`), identificador de modelo y tensor empaquetado.
4. **Herramienta MCP Nativa**:
   - Se expone `ipvn7_bitnet_quantize_and_infer` como la herramienta número 57 del catálogo MCP.

## Consecuencias
- **Positivas:** Inferencia de IA en hardware de borde ultra-económico, nulo consumo en ramas dispersas ($w=0$), compresión sustancial del modelo y compatibilidad absoluta con la filosofía *Zero Third-Party Dependencies*.
- **Cobertura:** Suite de pruebas ampliada a **84/84 tests unitarios aprobados al 100%**.
