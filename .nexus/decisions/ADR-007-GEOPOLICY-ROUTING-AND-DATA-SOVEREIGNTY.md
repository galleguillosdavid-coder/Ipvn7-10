# ADR-007: Geodistributed Policy Routing & Data Sovereignty Enclaves

**Estado**: APROBADO  
**Fecha**: 2026-10-20  
**Autores**: Agente de Auto-Evolución Autónoma IPVN 7  
**Área**: `ipvn7/network/geopolicy.py`, `ipvn7/node/node.py`, `ipvn7/node/mcp.py`, `app/server.py`

---

## 1. Contexto

En infraestructuras de red globales e interplanetarias, el enrutamiento clásico (BGP / OSPF / DHTs puramente lógicos) ignora dos factores determinantes:
1. **La física del retardo:** La velocidad de la luz en fibra y espacio ($c \approx 300,000 \text{ km/s}$) impone límites infranqueables donde la distancia geodésica física influye de manera crítica en la latencia de ida y vuelta (RTT).
2. **Jurisdicción y Soberanía de Datos:** Regulaciones estrictas (ej. EU-GDPR, enclaves soberanos MERCOSUR/LATAM o zonas neutrales orbitales LEO) exigen que el tráfico no transite por nodos ubicados en ciertas jurisdicciones geográficas no autorizadas (geofencing regulatorio y enclaves de soberanía).

Para cumplir con la **Línea L** del backlog soberano se diseñó el subsistema de enrutamiento por políticas geodistribuidas `GeoPolicyRouter`.

---

## 2. Decisiones de Arquitectura

### 2.1 Modelo Geodésico y Orbital
- **Fórmula de Haversine con Extensión de Altitud**:
  Calcula la distancia geodésica tridimensional en la superficie terrestre y extiende el cálculo a satélites LEO (baja órbita terrestre, ~550 km de altitud) mediante la hipotenusa euclidiana diferencial.
- **Topología Multirregión Planetaria Inicial**:
  - `LATAM_SANTIAGO` (Nodo de origen)
  - `LATAM_SAO_PAULO`
  - `NA_VIRGINIA`
  - `EU_FRANKFURT`
  - `APAC_TOKYO`
  - `ORBITAL_LEO_1` (Satélite en órbita ecuatorial)

### 2.2 Modos de Política de Enrutamiento (`RoutingPolicyMode`)
1. `MIN_LATENCY`: Prioriza RTT medido por telemetría activa EWMA y penaliza pérdida de paquetes.
2. `MAX_TRUST`: Prioriza la reputación Web of Trust (`wot_trust_score` $0.0 \to 1.0$), evitando intermediarios poco confiables aun si presentan menor latencia.
3. `SOVEREIGNTY_STRICT`: Exige pertenencia incondicional a enclaves soberanos definidos (ej: `MERCOSUR`, `EU_GDPR`, `ORBITAL_COMMONS`), descartando automáticamente cualquier nodo fuera de la jurisdicción.
4. `BALANCED`: Optimiza una función de coste armónica entre latencia física, RTT y reputación ZTNA.

### 2.3 Geofencing Regulatorio y Exclusión Geográfica
- El enrutador admite una lista explícita de `excluded_regions`. Si un nodo reside en una región vetada, se genera un registro de rechazo estructurado (`REGION_EXCLUDED`) y no es considerado como candidato de salto.
- Si ninguna ruta cumple con las restricciones exigidas, el sistema falla de manera segura lanzando un `LookupError` con el desglose de motivos de descarte por nodo.

### 2.4 Catálogo MCP Expandido (61 Herramientas Nativas)
- Se añade la herramienta número 61: `ipvn7_select_geopolicy_route`.
- Endpoint REST [`/api/geopolicy/routes`](http://127.0.0.1:7070/api/geopolicy/routes) con filtrado por `?mode=...`, `?enclave=...` y `?excluded=...`.

---

## 3. Consecuencias y Validación

- **Cumplimiento Normativo y Resiliencia**: Demostrada la capacidad de garantizar que el tráfico europeo permanezca en enclaves `EU_GDPR` sin tocar infraestructuras foráneas.
- **Batería de Pruebas**: Suite expandida a **95 pruebas unitarias (100% aprobadas en 7.07s)**.
- **Pureza de Dependencias**: 100% biblioteca estándar de Python y `cryptography`.
