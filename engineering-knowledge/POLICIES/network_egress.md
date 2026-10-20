# POLÍTICA DE SEGURIDAD EN SALIDAS DE RED (NETWORK EGRESS) — LAIA

**ID:** `POL-SEC-002`  
**Ámbito:** Proxies, SOCKS5, HTTP Clients y Gateways de Salida en IPVN 7  

---

## 1. Alcance
Aplica a cualquier componente del sistema que realice conexiones salientes hacia redes externas, internet o nombres de dominio provistos por usuarios o clientes de red.

## 2. Invariantes de Egress
1. **Validación Centralizada Anti-SSRF:** Todo destino debe ser procesado por `EgressSecurityPolicy.resolve_and_validate_host(host, port)`.
2. **Lista Negra Inviolable:**
   - Loopback: `127.0.0.0/8`, `::1`.
   - Redes privadas: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
   - Enlace local (Link-Local): `169.254.0.0/16`, `fe80::/10`.
   - Direcciones ULA IPv6: `fc00::/7`.
   - Metadatos de proveedores Cloud: `169.254.169.254`.
3. **Fijación de IP (Anti-DNS Rebinding):** La conexión debe abrirse directamente hacia la tupla `(valid_ips[0], port)` resuelta durante la fase de validación.
4. **Control de Redirecciones:** Todo redireccionamiento HTTP (`301`, `302`, `307`, `308`) debe ser interceptado por un `SafeRedirectHandler` que valide la nueva URL antes del salto.
5. **Modo Overlay vs. Directo:** Si el datapath opera en modo `OVERLAY_TUNNELED`, la conexión TCP a internet se ejecuta exclusivamente en el Exit Node remoto mediante tramas `IP7X`.
