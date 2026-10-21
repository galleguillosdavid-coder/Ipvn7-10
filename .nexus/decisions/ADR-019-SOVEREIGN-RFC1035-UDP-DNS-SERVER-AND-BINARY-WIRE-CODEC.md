# ADR-019: Sovereign RFC 1035 UDP DNS Server & Binary Wire Codec (Línea V)

## Estado
Aceptado e Implementado (v7.17.0)

## Fecha
2026-10-21

## Contexto y Motivación
En el documento Génesis (`genesis.md` Sección 2) y en las especificaciones históricas (`0.7/src/pkg/l4/ddns_petnames.go` e `ipvn7  vX7/pkg/l4/ddns_petnames.go`), IPVN 7 establece el desacoplamiento de la identidad soberana de la infraestructura centralizada de nombres de dominio controlada por ICANN y los proveedores de servicios de Internet (ISPs).

Hasta la versión v7.16.0, existía un proxy interno de resolución (`SovereignDNSResolver` en `ipvn7/network/dns_proxy.py`) y una libreta de petnames (`PetnameResolver`), pero:
1. **Ausencia de Servidor UDP a Nivel de Alambre**: Las aplicaciones del sistema operativo (navegadores web, herramientas CLI como `curl` o `dig`, sistemas de resolución del host) no podían consultar directamente al nodo mediante datagramas binarios UDP DNS estándar (RFC 1035 / RFC 3596).
2. **Falta de Códec Binario Nativo**: No se disponía de un empaquetador/desempaquetador de tramas DNS con soporte para compresión de etiquetas, resolución de punteros con protección contra bucles infinitos, y registros A (IPv4) y AAAA (IPv6).
3. **Resolución Inversa PTR**: No se disponía de resolución inversa automática (`.in-addr.arpa` e `.ip6.arpa`) para traducir direcciones sintéticas del overlay (`10.7.0.0/16` y `fd07::/64`) de vuelta a los petnames y DIDs correspondientes.

Para solventar estas carencias y dotar al nodo de un puerto DNS estándar local, se formaliza la **Línea V (v7.17.0)**: **Sovereign RFC 1035 UDP DNS Server & Binary Wire Codec**.

## Decisión de Diseño

Se implementa el subsistema `ipvn7/network/dns_server.py`, coordinado con `IPVN7Node`:

1. **Códec Binario RFC 1035 / RFC 3596 (`DNSPacket`, `encode_domain_name`, `decode_domain_name`)**:
   - Cabecera fija de 12 bytes (`tx_id`, `flags`, `qdcount`, `ancount`, `nscount`, `arcount`).
   - Serialización de etiquetas de nombres de dominio con longitud de byte (hasta 63 bytes por etiqueta) terminadas en `0x00`.
   - Decodificación robusta con soporte para punteros de compresión (`0xC000`) y guardia estricta de saltos (`max_jumps = 16`) que neutraliza ataques de bucle infinito (DoS por puntero circular).
   - Soporte para tipos de registros: `A` (1), `NS` (2), `CNAME` (5), `SOA` (6), `PTR` (12), `TXT` (16), `AAAA` (28) y `ANY` (255).

2. **Intercepción Autoritativa de `.ipv7` (Zero-ISP Leakage)**:
   - Todo datagrama entrante cuya pregunta apunte al dominio `.ipv7` es interceptado incondicionalmente por el nodo sin reenviarse a servidores DNS públicos ni upstream ISPs.
   - Consulta primaria en `PetnameResolver` para extraer la IPv4 sintética (`10.7.0.0/16`) y la IPv6 overlay (`fd07::/64`).
   - Consulta secundaria en `ShadowDeviceRegistry` para dispositivos físicos locales en la LAN.
   - Derivación determinista mediante hash SHA-256 si el petname no cuenta con asignación manual previa.
   - Emisión de registros de respuesta con bandera autoritativa `AA = 1` y código `RCODE_NOERROR`.
   - Para dominios inexistentes fuera del espacio soberano, emisión estricta de `RCODE_NXDOMAIN` (3).

3. **Resolución Inversa PTR (`in-addr.arpa` & `ip6.arpa`)**:
   - Soporte nativo para consultas inversas de direcciones IPv4 overlay: ej. `1.15.7.10.in-addr.arpa` $\to$ reversión de octetos $\to$ `10.7.15.1` $\to$ resolución hacia `gateway.ipv7` o el nombre del dispositivo sombra.

4. **Servidor UDP Concurrente Multihilo (`SovereignDNSServer`)**:
   - Enlace a socket UDP en puerto configurable (por defecto puerto efímero o 1053; 5353/53 con privilegios elevados).
   - Bucle de escucha `_listen_loop` en hilo daemon con temporizador de socket y manejo seguro de excepciones.
   - Almacén de registros estáticos definidos por el usuario (`add_static_record`).
   - Telemetría atómica: consultas totales, `.ipv7` interceptadas, PTRs servidas, registros A/AAAA emitidos y bytes transferidos.

5. **Herramienta MCP 76 (`ipvn7_dns_server`)**:
   - El catálogo de herramientas MCP de IPVN 7 alcanza exactamente 76 herramientas nativas.
   - Acciones soportadas: `get_status`, `resolve_query`, `add_record`, `list_records`, `start_server`, `stop_server`.

6. **Integración REST y Dashboard Web**:
   - Endpoints:
     * `GET /api/dns/server/status`: Devuelve el estado del listener, puerto enlazado y métricas de tráfico.
     * `GET /api/dns/server/records`: Lista todos los registros estáticos configurados.
     * `POST /api/dns/server/query`: Resuelve una consulta wire RFC 1035 sintetizada desde JSON.
     * `POST /api/dns/server/record`: Agrega un registro estático A/AAAA/TXT/PTR.
     * `POST /api/dns/server/start`: Inicia el listener UDP en el puerto indicado.
     * `POST /api/dns/server/stop`: Detiene el listener UDP.
   - UI: Pestaña `tab-dns-server` en el Control Center con tarjetas de control para estado en tiempo real y consola interactiva de consulta wire.

## Consecuencias y Garantías

- **Zero-ISP Leakage**: El 100% de las consultas de nombres soberanos se resuelve localmente en memoria sin emitir paquetes hacia servidores raíz de ICANN.
- **Interoperabilidad Universal**: Cualquier software estándar del host puede utilizar el nodo como su servidor DNS primario apuntando a `127.0.0.1:1053`.
- **Inmunidad DoS por Bucles DNS**: La verificación de punteros de compresión garantiza terminación en tiempo finito ($O(1)$) ante tramas maliciosas o malformadas.
