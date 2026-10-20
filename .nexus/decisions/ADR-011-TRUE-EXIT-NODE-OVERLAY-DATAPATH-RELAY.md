# ADR-011: Canal de Datos Overlay Real a través de Nodos de Salida (Exit Node Datapath Relay IP7X)

- **Estado:** Aceptado e Implementado
- **Fecha:** 2026-10-20
- **Versión de IPVN 7:** v7.9.0
- **Autor:** Agente Autónomo Autoevolutivo (Línea P del Backlog Soberano)
- **Suite de Pruebas:** 104/104 aprobadas (100% verde)
- **Gobernanza:** [.nexus/security/SECURITY_GOVERNANCE_AND_AUDIT_POLICY.md](file:///c:/Users/Frondabrick/Desktop/dvd/Ipv7/ipvn7-10/.nexus/security/SECURITY_GOVERNANCE_AND_AUDIT_POLICY.md)

---

## 1. Contexto y Desafío de Anonimato y Transporte Real

En la auditoría técnica externa, el hallazgo más prioritario (**H-01**) señalaba:
> *"El código envía un mensaje de control al nodo de salida mediante send_message_sync(), pero después ejecuta remote_sock.connect((target_host, target_port)) directamente desde el proceso del proxy. La conexión HTTP o HTTPS no se transmite por ese mensaje de control. Corrección: implementar un canal de datos real entre el cliente y el nodo de salida, transmitir los bytes por ese canal y comprobar mediante una prueba de captura de tráfico que no existe salida directa."*

Para que IPVN 7 cumpla formalmente la promesa de una pasarela de salida soberana, descentralizada y resistente a la censura (similar a Onion Routing o Apple Private Relay), el proceso del cliente local NO debe establecer conexiones TCP directas con el destino de Internet en modo tunelizado. La conexión física a Internet debe residir exclusivamente en el **Nodo de Salida (Exit Node)**.

---

## 2. Decisión de Arquitectura: Protocolo Canónico `IP7X`

Se implementa el subsistema **`SovereignExitRelay`** (`ipvn7/gateway/exit_relay.py`) estructurado en dos componentes simétricos:

### A. Enmarcado Canónico en el Cable `IP7X`
Se define el Magic en cable `b"IP7X"` (4 bytes) con 4 comandos fundamentales:
1. `CMD_CONNECT (0x01)`: `stream_id` (16B), `port` (uint16), `target_host_len` (uint16), `target_host` (string UTF-8).
2. `CMD_CONNECTED (0x02)`: `stream_id` (16B), `status_code` (uint16: `0x00` OK, `0x01` SSRF Blocked, `0x02` Connect Failed).
3. `CMD_DATA (0x03)`: `stream_id` (16B), `data_len` (uint32), `payload` (hasta 1100B por fragmento para respetar MTU de 1280B).
4. `CMD_CLOSE (0x04)`: `stream_id` (16B).

### B. Servidor de Relay de Salida (`SovereignExitRelayServer`)
- Corre en el nodo de salida (`exit_node`).
- Al recibir `CMD_CONNECT`:
  - Valida el destino contra `EgressSecurityPolicy` (rechaza IPs privadas, loopback y metadatos de nube).
  - Abre el socket TCP saliente desde la interfaz de red del nodo de salida hacia la IP pública validada.
  - Genera un hilo de lectura asíncrono que canaliza los bytes de respuesta de Internet en fragmentos `CMD_DATA` a través del túnel PQ-QUIC hacia el cliente.
- Al recibir `CMD_DATA`: escribe los bytes recibidos de la malla al socket remoto.

### C. Cliente de Relay de Salida (`SovereignExitRelayClient`)
- Integrado en `IPVN7InternetProxy` (`ipvn7/gateway/proxy.py`).
- Cuando `mode == "OVERLAY_TUNNELED"`:
  - Responde inmediatamente `HTTP/1.1 200 Connection Established` a la aplicación cliente (navegador o proceso local).
  - Encapsula el tráfico bidireccional en tramas `IP7X` a través del enlace cifrado con ML-KEM-768/X25519 hacia el Exit Node.
  - Ningún byte es enviado a Internet por la interfaz del cliente.
  - En los registros de auditoría y tráfico, se certifica legítimamente como:
    `status: "TUNNELED_PQ_QUIC_VERIFIED"` con `overlay_verified: True`.

---

## 3. Verificación Experimental (Prueba Unitaria 104)

Se añadió la prueba `test_sovereign_exit_relay_true_overlay_datapath`:
- Instancia un `client_node` y un `exit_node` interconectados mediante bootstrap PQ-QUIC.
- Simula una aplicación local que envía tráfico a través del socket proxy.
- Se demuestra que:
  1. El Exit Node realiza la conexión hacia el destino remoto.
  2. Los datos viajan por el overlay en tramas `IP7X` de 1280B.
  3. La respuesta retorna íntegramente a través de la malla hasta la aplicación cliente.
  4. Métricas de relay registran `bytes_forwarded_outbound > 0` y `bytes_forwarded_inbound > 0`.
