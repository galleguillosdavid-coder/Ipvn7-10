# INVARIANTES DE SEGURIDAD Y PROTOCOLO — LAIA

**Versión:** 1.0  
**Ámbito:** IPVN 7  

Los invariantes son propiedades que deben mantenerse verdaderas en todo estado alcanzable del software. Si en algún momento una de estas propiedades se viola, el sistema se encuentra en un estado corrupto e inseguro.

---

### Invariante 1: Autorización Criptográfica del Plano de Control
$$\forall \text{ op} \in \text{PrivilegedOps}, \quad \text{Execute}(\text{op}) \implies \text{VerifyBearerToken}(\text{req.token}, \text{Token}_{\text{runtime}}) = \text{True}$$
*Ninguna operación del plano de control puede ejecutarse sin presentar un token criptográficamente válido de 256 bits generado en tiempo de ejecución o configurado por el operador.*

---

### Invariante 2: Invarianza de Enlace en Egress (Anti-SSRF / Anti-TOCTOU)
$$\text{ConnectTarget}(\text{ip}, \text{port}) \implies \text{ip} \in \text{EgressPolicy}.\text{Validate}(\text{ip}) \land \text{ip} \notin \text{PrivateRanges}$$
$$\text{ip}_{\text{connected}} \equiv \text{ip}_{\text{validated}}$$
*La dirección IP a la cual se abre el socket de salida debe ser exactamente la misma dirección IP que superó la validación de la política SSRF. Está prohibido re-resolver el dominio entre la validación y la conexión.*

---

### Invariante 3: Vinculación Estricta Transcript-Firma-Identidad (Anti-MITM)
$$\text{AcceptSession}(A, B) \implies \text{VerifySignature}(B_{\text{id\_pub}}, \text{SHA256}(\text{Transcript}_{A \to B}), \text{Sig}_B) = \text{True}$$
*Una sesión híbrida postcuántica entre el cliente A y el servidor B solo puede ser establecida si la firma digital del servidor sobre el transcript completo es válida contra la clave pública de identidad de largo plazo del servidor.*

---

### Invariante 4: Fidelidad de Telemetría de Transporte Overlay
$$\text{Telemetry}.\text{overlay\_verified} = \text{True} \iff \text{BytesTransferred}_{\text{overlay\_mesh}} > 0 \land \text{ExitNode} \neq \text{LocalNode}$$
*Ningún flujo de tráfico puede ser registrado ni informado como "OVERLAY_TUNNELED" o "overlay_verified: true" si los bytes reales de datos transitaron por una conexión TCP directa local sin atravesar el túnel cifrado del Exit Node.*

---

### Invariante 5: Conservación de Buffer en Deserialización de Modelos BitNet
$$\text{len}(\text{packed\_data}) \equiv \left\lfloor \frac{\text{rows} \times \text{cols} + 3}{4} \right\rfloor \land 1 \le \text{rows} \le 4096 \land 1 \le \text{cols} \le 4096$$
*El tamaño del buffer binario de pesos debe coincidir matemáticamente con la dimensión matricial declarada en la cabecera. Cualquier discrepancia aborta con excepción antes de alocar memoria para pesos.*

---

### Invariante 6: Acotación de Concurrencia en Listeners (Anti-DoS)
$$\text{ActiveThreads}_{\text{gateway}} \le \text{MaxConnections} \quad (\text{por defecto } 64)$$
*El número de hilos concurrentes atendiendo peticiones entrantes nunca puede superar el semáforo acotado. Las conexiones excedentes se rechazan inmediatamente en el socket sin instanciar hilos.*

---

### Invariante 7: Censura Absoluta de Secretos Derivados
$$\forall \text{ response} \in \text{APIResponses}, \quad \text{SharedSecret} \not\subset \text{response} \land \text{PrivateKey} \not\subset \text{response}$$
*Ninguna respuesta HTTP o evento de telemetría contendrá jamás representaciones crudas de claves privadas o secretos compartidos derivados.*
