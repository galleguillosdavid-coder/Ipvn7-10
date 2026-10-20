"""
IPVN 7 Model Context Protocol (MCP) Engine
Exposes the IPVN 7 Autonomous Network Operating System control plane to AI agents,
LLMs, and IDE extensions via JSON-RPC 2.0 (Model Context Protocol).
Inspired by ipvn7 vX7 pkg/l3/mcp_server.go and mcp_catalog.go.
"""

from __future__ import annotations
import json
import time
from typing import Dict, Any, List, Optional, Tuple, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from .node import IPVN7Node

from ..network.onion import SphinxHop
from ..access.services import ServiceScope
from ..network.explainable import CandidateMetrics
from ..security.delegation import ExecutionTier
from ..network.hrs_frames import HRSFrame, HRSFrameType


class IPVN7MCPServer:
    """
    Model Context Protocol (JSON-RPC 2.0) Server for IPVN 7.
    Enables autonomous agents and LLMs to interactively query, inspect,
    and command the physical and overlay network layers.
    """

    def __init__(self, node: IPVN7Node):
        self.node = node
        self.start_time = time.time()

    def get_supported_tools(self) -> List[Dict[str, Any]]:
        """Returns the MCP tools catalog according to 2024-11-05 MCP specification."""
        return [
            {
                "name": "get_node_status",
                "description": "Obtiene la telemetría en tiempo real del nodo IPVN 7, DID soberano, puertos y estadísticas criptográficas.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "resolve_did",
                "description": "Resuelve un DID descentralizado did:ipvn7:... consultando la DHT jerárquica Small-World.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "did": {
                            "type": "string",
                            "description": "DID soberano a resolver",
                        }
                    },
                    "required": ["did"],
                },
            },
            {
                "name": "send_pq_datagram",
                "description": "Transmite un datagrama seguro cifrado punto a punto con PQ-QUIC (ML-KEM-768 + ML-DSA-65) hacia un DID destino.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_did": {
                            "type": "string",
                            "description": "DID de destino",
                        },
                        "payload": {
                            "type": "string",
                            "description": "Mensaje de texto o datos a enviar",
                        },
                    },
                    "required": ["target_did", "payload"],
                },
            },
            {
                "name": "route_sphinx_onion",
                "description": "Construye y pela un paquete cebolla Sphinx de 3 saltos (1280 bytes deterministas) con ChaCha20 y protección anti-repetición O(1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Contenido confidencial multi-salto",
                        }
                    },
                    "required": ["payload"],
                },
            },
            {
                "name": "broadcast_plumtree_gossip",
                "description": "Difunde un mensaje de broadcast epidémico a toda la malla mediante el árbol determinista Plumtree.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {
                            "type": "string",
                            "description": "Tópico o canal del mensaje (ej: TOPOLOGY_ALERT)",
                        },
                        "content": {
                            "type": "string",
                            "description": "Cuerpo del mensaje a diseminar",
                        },
                    },
                    "required": ["topic", "content"],
                },
            },
            {
                "name": "probe_peer_swim",
                "description": "Ejecuta sondeo O(1) de detección de caídas SWIM (Direct Probe + Indirect Ping-Req via k intermediarios) sobre un par.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_did": {
                            "type": "string",
                            "description": "DID del par a sondear",
                        }
                    },
                    "required": ["target_did"],
                },
            },
            {
                "name": "trigger_connection_migration",
                "description": "Ejecuta una migración en caliente de interfaz (ej: Wi-Fi a 5G) sin reiniciar la sesión criptográfica PQ-QUIC.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_did": {
                            "type": "string",
                            "description": "DID del par con sesión activa",
                        },
                        "new_ip": {
                            "type": "string",
                            "description": "Nueva dirección IP física",
                        },
                        "new_port": {
                            "type": "integer",
                            "description": "Nuevo puerto UDP",
                        },
                        "interface_name": {
                            "type": "string",
                            "description": "Nombre de la interfaz (ej: wwan5g)",
                        },
                    },
                    "required": ["target_did", "new_ip", "new_port", "interface_name"],
                },
            },
            {
                "name": "ipvn7_firewall_rule",
                "description": "Consulta o autoriza políticas ZTNA Default-Deny para un DID soberano.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "'get' para consultar o 'set' para autorizar",
                            "enum": ["get", "set"],
                        },
                        "did": {
                            "type": "string",
                            "description": "DID objetivo a evaluar o autorizar",
                        },
                        "allow_inbound": {
                            "type": "boolean",
                            "description": "Permitir tráfico entrante (para action 'set')",
                        },
                        "allow_outbound": {
                            "type": "boolean",
                            "description": "Permitir tráfico saliente (para action 'set')",
                        },
                        "allow_relay": {
                            "type": "boolean",
                            "description": "Permitir retransmisión de tránsito (para action 'set')",
                        },
                    },
                    "required": ["action", "did"],
                },
            },
            {
                "name": "ipvn7_wot_vouch",
                "description": "Emite un aval criptográfico de confianza en la Web-of-Trust para un par.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subject_did": {
                            "type": "string",
                            "description": "DID del par que se avala",
                        },
                        "trust_level": {
                            "type": "number",
                            "description": "Nivel de confianza en rango [0.0, 1.0]",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Motivo del aval de confianza",
                        },
                    },
                    "required": ["subject_did", "trust_level", "reason"],
                },
            },
            {
                "name": "ipvn7_get_trust",
                "description": "Calcula la reputación transitiva atenuada entre la identidad local y un DID objetivo.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_did": {
                            "type": "string",
                            "description": "DID objetivo a evaluar",
                        }
                    },
                    "required": ["target_did"],
                },
            },
            {
                "name": "ipvn7_dag_put",
                "description": "Almacena datos inmutables en el DAG direccionado por contenido (CID) y firma con DID.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Contenido a almacenar en el bloque inmutable",
                        },
                        "target_did": {
                            "type": "string",
                            "description": "DID destinatario opcional para cola diferida DTN",
                        },
                    },
                    "required": ["payload"],
                },
            },
            {
                "name": "ipvn7_get_anomalies",
                "description": "Consulta el registro consolidado de huellas de anomalías O(1) clasificadas por criticidad.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Límite máximo de huellas a retornar (default: 20)",
                        },
                    },
                },
            },
            {
                "name": "ipvn7_audit_split_brain",
                "description": "Evalúa el quórum de la malla en tiempo real para detectar y prevenir particiones o split-brain.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ipvn7_register_petname",
                "description": "Registra un nombre legible por humanos (.ipv7) asociado a un DID en la libreta dDNS descentralizada.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Nombre mnemotécnico (ej: workstation.ipv7)",
                        },
                        "did": {
                            "type": "string",
                            "description": "DID soberano al que apuntará el nombre",
                        },
                        "comment": {
                            "type": "string",
                            "description": "Comentario o nota explicativa opcional",
                        },
                    },
                    "required": ["name", "did"],
                },
            },
            {
                "name": "ipvn7_resolve_petname",
                "description": "Resuelve un nombre mnemotécnico local (.ipv7) a su DID soberano y direcciones IP sintéticas.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Nombre a resolver",
                        },
                    },
                    "required": ["name"],
                },
            },
            {
                "name": "ipvn7_get_oob_sas",
                "description": "Deriva un Código Corto de Autenticación SAS (6 dígitos + 4 emojis) para validación visual humana fuera de banda.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "peer_pubkey_hex": {
                            "type": "string",
                            "description": "Clave pública del par remoto en formato hexadecimal",
                        },
                    },
                    "required": ["peer_pubkey_hex"],
                },
            },
            {
                "name": "ipvn7_get_accounting",
                "description": "Audita el estado de contabilidad de tránsito Tit-for-Tat y ratio de reciprocidad de pares.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "peer_did": {
                            "type": "string",
                            "description": "DID específico opcional para auditar; si se omite, retorna el resumen global",
                        },
                    },
                },
            },
            {
                "name": "ipvn7_request_service",
                "description": "Despierta e instancia un microservicio de red Zero-RAM bajo demanda en memoria activa.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Identificador del microservicio (ej: chat_e2ee, socks5_proxy, dag_storage)",
                        },
                        "scope": {
                            "type": "string",
                            "description": "Alcance del microservicio: LOCAL, MESH o GLOBAL",
                        },
                    },
                    "required": ["name"],
                },
            },
            {
                "name": "ipvn7_tls_camouflage",
                "description": "Envuelve un datagrama IPVN 7 en un registro TLS 1.3 legítimo (ApplicationData) o sintetiza un ClientHello con SNI para evasión de DPI.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "'wrap' (encapsular datos) o 'client_hello' (generar saludo TLS)",
                        },
                        "payload": {
                            "type": "string",
                            "description": "Texto o datos binarios a encapsular en el registro TLS",
                        },
                        "sni": {
                            "type": "string",
                            "description": "Server Name Indication simulado (ej: gateway.cloudflare.com)",
                        },
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "ipvn7_blind_rendezvous",
                "description": "Publica o descubre balizas efímeras de punto de encuentro ciego (Zero-Knowledge) para arranque post-apagón.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "'publish' para registrar baliza o 'discover' para consumir baliza",
                        },
                        "endpoint": {
                            "type": "string",
                            "description": "Endpoint o locator a publicar (para acción 'publish')",
                        },
                        "ring_degree": {
                            "type": "integer",
                            "description": "Grado o anillo de vecindad de la baliza (default: 1)",
                        },
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "ipvn7_explain_route",
                "description": "Evalúa y justifica en lenguaje natural y estructurado la elección óptima de ruta y salto entre candidatos observados.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_did": {
                            "type": "string",
                            "description": "DID soberano de destino final",
                        },
                        "candidates": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "peer_did": {"type": "string"},
                                    "latency_ms": {"type": "number"},
                                    "rfc3550_jitter_ms": {"type": "number"},
                                    "packet_loss_pct": {"type": "number"},
                                    "battery_pct": {"type": "integer"},
                                    "trust_tier": {"type": "integer"},
                                },
                                "required": ["peer_did", "latency_ms"],
                            },
                            "description": "Lista de pares candidatos y sus métricas físicas observadas",
                        },
                    },
                    "required": ["target_did", "candidates"],
                },
            },
            {
                "name": "ipvn7_analyze_spectrum",
                "description": "Aplica la Transformada Discreta de Fourier (DFT) sobre una serie de latencias/jitter para detectar resonancias armónicas y micro-ráfagas periódicas.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "signal": {
                            "type": "array",
                            "items": {"type": "number"},
                            "description": "Serie temporal de mediciones de latencia o jitter en milisegundos",
                        },
                        "sampling_rate_hz": {
                            "type": "number",
                            "description": "Frecuencia de muestreo en Hz (default: 100.0)",
                        },
                    },
                    "required": ["signal"],
                },
            },
            {
                "name": "ipvn7_create_delegation",
                "description": "Emite y firma digitalmente un eslabón de delegación de autorización agéntica graduada (APC conforme a IETF).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subject_did": {
                            "type": "string",
                            "description": "DID soberano del agente o satélite delegado",
                        },
                        "scope": {
                            "type": "string",
                            "description": "Alcance de los permisos delegados (ej: route_traffic, read_telemetry, vpn_bridge)",
                        },
                        "tier": {
                            "type": "string",
                            "description": "Nivel de ejecución: 'ordinary', 'escalated', 'quarantine', o 'deny'",
                        },
                        "ttl_seconds": {
                            "type": "number",
                            "description": "Tiempo de vida del token en segundos (default: 3600)",
                        },
                    },
                    "required": ["subject_did", "scope"],
                },
            },
            {
                "name": "ipvn7_anti_replay_check",
                "description": "Evalúa un número de secuencia contra la ventana deslizante RFC 4303 de 1024 bits para validar paquetes o detectar repetición.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sequence_number": {
                            "type": "integer",
                            "description": "Número de secuencia del paquete a validar",
                        },
                    },
                    "required": ["sequence_number"],
                },
            },
            {
                "name": "ipvn7_route_planetary",
                "description": "Enruta un datagrama a través de la malla planetaria de Kleinberg (r=2) estimando latencia relativista por velocidad de la luz c = 299,792 km/s.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "src_node": {
                            "type": "string",
                            "description": "Identificador del nodo satélite o estación origen (ej: sat-000)",
                        },
                        "dst_node": {
                            "type": "string",
                            "description": "Identificador del nodo satélite o estación destino (ej: sat-015)",
                        },
                    },
                    "required": ["src_node", "dst_node"],
                },
            },
            {
                "name": "ipvn7_resilience_status",
                "description": "Audita la telemetría del Guardián de Resiliencia, estado del Circuit Breaker (CLOSED/OPEN/HALF_OPEN) y reintentos con Full Jitter.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ipvn7_toggle_dark_node",
                "description": "Conmuta atómicamente el modo de sigilo Dark Node (Egress-Only, Default-Deny estricto, 3 saltos Sphinx forzados, y micro-jitter).",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ipvn7_send_silent_call",
                "description": "Emite una llamada dirigida unicast silenciosa (Zero Broadcast Noise) hacia un DID par con protección DoS y límite de tasa.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_did": {
                            "type": "string",
                            "description": "DID soberano del par de destino",
                        },
                        "payload": {
                            "type": "string",
                            "description": "Carga útil en texto para la llamada dirigida",
                        },
                    },
                    "required": ["target_did", "payload"],
                },
            },
            {
                "name": "ipvn7_record_link_probe",
                "description": "Evalúa el estado de salud de un enlace P2P aplicando histéresis anti-flapping (RFC 2439) y determinando failover en O(1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "peer_did": {
                            "type": "string",
                            "description": "DID soberano del par evaluado",
                        },
                        "success": {
                            "type": "boolean",
                            "description": "Indica si la sonda o datagrama fue exitoso",
                        },
                        "latency_ms": {
                            "type": "number",
                            "description": "Latencia medida en milisegundos",
                        },
                    },
                    "required": ["peer_did", "success", "latency_ms"],
                },
            },
            {
                "name": "ipvn7_blackout_recovery",
                "description": "Monitorea o avanza la máquina de estados de recuperación post-apagón en 5 fases y calcula el siguiente Jitter descorrelacionado anti-estampida.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "Acción a ejecutar: 'status', 'advance', o 'cold_boot'",
                        },
                    },
                },
            },
            {
                "name": "ipvn7_send_chat_message",
                "description": "Transmite un mensaje soberano P2P cifrado E2EE con firma digital Ed25519 y confirmación de entrega hacia un DID.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_did": {
                            "type": "string",
                            "description": "DID soberano del destinatario",
                        },
                        "text": {
                            "type": "string",
                            "description": "Texto del mensaje soberano",
                        },
                        "sender_name": {
                            "type": "string",
                            "description": "Nombre visible del emisor",
                        },
                    },
                    "required": ["target_did", "text"],
                },
            },
            {
                "name": "ipvn7_get_batcher_stats",
                "description": "Audita la densidad, rendimiento y latencia del agrupador de datagramas (Batcher) de 1280 bytes en el datapath acelerado.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ipvn7_update_mobility_locator",
                "description": "Actualiza el localizador físico de un nodo móvil en el ancla topológica con tickets proactivos 0-RTT, secuencia monótona y soporte Micro-PoW.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node_did": {
                            "type": "string",
                            "description": "DID soberano del nodo móvil",
                        },
                        "physical_ip": {
                            "type": "string",
                            "description": "Nueva dirección IP física",
                        },
                        "physical_port": {
                            "type": "integer",
                            "description": "Nuevo puerto UDP físico",
                        },
                        "seq": {
                            "type": "integer",
                            "description": "Número de secuencia monótono estricto anti-carreras",
                        },
                        "ticket_hex": {
                            "type": "string",
                            "description": "Ticket proactivo HMAC 0-RTT en hexadecimal para handover rápido",
                        },
                        "cold_nonce": {
                            "type": "integer",
                            "description": "Nonce Micro-PoW para arranque en frío bajo ataques de agotamiento",
                        },
                    },
                    "required": ["node_did", "physical_ip", "physical_port"],
                },
            },
            {
                "name": "ipvn7_run_ai_copilot",
                "description": "Ejecuta un ciclo de escaneo del Copiloto IA de Red, infiriendo causa raíz de anomalías (latencia, firewall drops, fluctuación espectral, flapping) y aplicando auto-reparación en bucle cerrado.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "latency_ms": {
                            "type": "number",
                            "description": "Latencia reciente observada en milisegundos",
                        },
                        "firewall_drops": {
                            "type": "integer",
                            "description": "Cantidad de paquetes descartados por el cortafuegos ZTNA",
                        },
                        "peer_did": {
                            "type": "string",
                            "description": "DID objetivo o involucrado en la telemetría",
                        },
                        "spectral_entropy": {
                            "type": "number",
                            "description": "Entropía espectral de Fourier observada (0.0 a 1.0)",
                        },
                        "is_flap_damped": {
                            "type": "boolean",
                            "description": "Indica si el enlace está en amortiguamiento por oscilación repetida",
                        },
                    },
                },
            },
            {
                "name": "ipvn7_schedule_multipath",
                "description": "Selecciona el/los enlace(s) físico(s) para despachar un datagrama según la estrategia configurada (LOWEST_LATENCY, BALANCED, CRITICAL_DUPLICATION) o inyecta duplicación bicast.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": "Carga útil o datagrama a enrutar",
                        },
                        "is_critical": {
                            "type": "boolean",
                            "description": "Si es True, fuerza duplicación concurrente bicast sobre múltiples interfaces",
                        },
                        "strategy": {
                            "type": "string",
                            "description": "Estrategia opcional: 'LOWEST_LATENCY', 'BALANCED', 'CRITICAL_DUPLICATION'",
                        },
                    },
                    "required": ["payload"],
                },
            },
            {
                "name": "ipvn7_resolve_dns_proxy",
                "description": "Resuelve un nombre de dominio estándar o soberano .ipv7 a través del proxy DNS anti-fugas con caché local y sin telemetría hacia el ISP.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Dominio a resolver (ej: 'alicia.ipv7' o 'example.com')",
                        },
                    },
                    "required": ["domain"],
                },
            },
            {
                "name": "ipvn7_nat_hole_punch",
                "description": "Inicia la perforación P2P de NAT UDP hacia el endpoint reflexivo de un par soberano o conmuta automáticamente a nodo relay DERP.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "peer_did": {
                            "type": "string",
                            "description": "DID soberano del par objetivo",
                        },
                        "peer_public_ip": {
                            "type": "string",
                            "description": "IP pública reflexiva observada del par",
                        },
                        "peer_public_port": {
                            "type": "integer",
                            "description": "Puerto público reflexivo observado del par",
                        },
                    },
                    "required": ["peer_did", "peer_public_ip", "peer_public_port"],
                },
            },
            {
                "name": "ipvn7_allocate_memory_budget",
                "description": "Reserva o audita cuotas de memoria RAM protegidas contra ataques DoS/OOM (clases: replay, qos, trust, bindings, other).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "budget_class": {
                            "type": "string",
                            "description": "Clase de presupuesto ('replay', 'qos', 'trust', 'bindings', 'other')",
                        },
                        "num_bytes": {
                            "type": "integer",
                            "description": "Cantidad de bytes a reservar o auditar",
                        },
                    },
                    "required": ["budget_class", "num_bytes"],
                },
            },
            {
                "name": "ipvn7_issue_uin_binding",
                "description": "Emite y firma criptográficamente un BindingRecord delegando autoridad de la entidad soberana (root_id 256 bits) a una clave subordinada rotativa.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subordinate_pubkey_hex": {
                            "type": "string",
                            "description": "Clave pública subordinada o de agente IA en hexadecimal",
                        },
                        "scope": {
                            "type": "integer",
                            "description": "Ámbito de autorización (0=GENERAL, 1=TELEMETRY, 2=CONTROL, 3=AI_AGENT, 4=SETTLEMENT)",
                        },
                        "duration_seconds": {
                            "type": "number",
                            "description": "Duración de validez en segundos (por defecto 86400)",
                        },
                    },
                    "required": ["subordinate_pubkey_hex"],
                },
            },
            {
                "name": "ipvn7_get_uin_passport",
                "description": "Obtiene el pasaporte de identidad universal (UIN Passport) de la entidad con sus registros de vinculación activos y revocaciones.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ipvn7_register_shadow_device",
                "description": "Registra un hardware físico de la LAN local como Dispositivo Sombra con DID determinista did:ipvn7:shadow:<hex16> e IP virtual overlay 10.7.100.X.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Nombre amigable del dispositivo (ej: 'HP-LaserJet-Office' o 'Ollama-RTX4090')",
                        },
                        "physical_ip": {
                            "type": "string",
                            "description": "Dirección IP física en la LAN real (ej: '192.168.1.150')",
                        },
                        "mac": {
                            "type": "string",
                            "description": "Dirección MAC física del dispositivo (ej: 'aa:bb:cc:dd:ee:ff')",
                        },
                        "device_type": {
                            "type": "string",
                            "description": "Tipo de hardware ('printer', 'display', 'camera', 'iot', 'edge_ai', 'generic')",
                        },
                        "allowed_ports": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "Lista de puertos TCP/UDP autorizados para puenteo L4",
                        },
                    },
                    "required": ["name", "physical_ip", "mac"],
                },
            },
            {
                "name": "ipvn7_get_pfo_tree",
                "description": "Recupera el árbol jerárquico ontológico PFO (Principios Axiomáticos -> Funciones Operativas -> Observaciones Empíricas) y tasa de cumplimiento.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ipvn7_probe_wan_link",
                "description": "Emite una trama binaria canónica IP7P de 32 bytes para medir en vivo RTT instantáneo, Min/Max RTT y Jitter RFC 3550.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "peer_did": {
                            "type": "string",
                            "description": "DID soberano del nodo par objetivo",
                        },
                        "endpoint": {
                            "type": "string",
                            "description": "Dirección IP y puerto física del par (ej: '192.168.1.106:7001')",
                        },
                        "simulated_rtt_ms": {
                            "type": "number",
                            "description": "Latencia RTT simulada o medida en ms",
                        },
                    },
                    "required": ["peer_did"],
                },
            },
            {
                "name": "ipvn7_dispatch_remote_input",
                "description": "Inyecta eventos de cursor o pulsaciones de teclado en la sesión activa de escritorio remoto soberano P2P (<100µs wire dispatch).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "event_type": {
                            "type": "string",
                            "description": "Tipo de evento ('mouse_move', 'mouse_click', 'key_down')",
                        },
                        "x": {
                            "type": "number",
                            "description": "Coordenada X del cursor en porcentaje o píxeles",
                        },
                        "y": {
                            "type": "number",
                            "description": "Coordenada Y del cursor en porcentaje o píxeles",
                        },
                        "key": {
                            "type": "string",
                            "description": "Tecla presionada (para key_down)",
                        },
                    },
                    "required": ["event_type"],
                },
            },
            {
                "name": "ipvn7_rotate_session_key",
                "description": "Fuerza la rotación criptográfica de época de la clave de sesión (Forward Secrecy) con derivación unidireccional y ventana de gracia de 30 segundos.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ipvn7_map_upnp_port",
                "description": "Descubre y mapea un puerto UDP en el router residencial local mediante UPnP IGD con estricta validación Anti-SSRF (RFC 1918).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "port": {
                            "type": "integer",
                            "description": "Puerto UDP a mapear externamente",
                        },
                        "description": {
                            "type": "string",
                            "description": "Descripción del mapeo en el router (ej: 'ipvn7-p2p')",
                        },
                    },
                    "required": ["port"],
                },
            },
            {
                "name": "ipvn7_audit_censorship",
                "description": "Evalúa activamente la integridad del tráfico saliente para detectar envenenamiento DNS hacia localhost o inyecciones TCP RST por DPI.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Dominio objetivo para auditar resolución DNS (por defecto 'cloudflare.com')",
                        },
                    },
                },
            },
            {
                "name": "ipvn7_get_buffer_health",
                "description": "Monitorea en tiempo real la salud de la memoria de datagramas de 1280 bytes, tasa de reciclaje, High-Water Mark y alertas tempranas de fugas.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ipvn7_wasm_compute_pow",
                "description": "Calcula el nonce de Micro-PoW para resolución de desafíos anti-Sybil en clientes WebAssembly o arranque en frío.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "did": {
                            "type": "string",
                            "description": "DID soberano del cliente que resuelve el desafío",
                        },
                        "seq": {
                            "type": "integer",
                            "description": "Número de secuencia del desafío",
                        },
                        "difficulty_bits": {
                            "type": "integer",
                            "description": "Bits de dificultad (por defecto 8)",
                        },
                    },
                    "required": ["did"],
                },
            },
            {
                "name": "ipvn7_fsm_trigger_event",
                "description": "Dispara transiciones formales en el autómata finito determinista (FSM) de ciclo de vida del nodo (DISCONNECTED, SYNCING, VALIDATING, ACTIVE, QUARANTINED).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "event": {
                            "type": "string",
                            "description": "Evento FSM: 'NETWORK_SIGNAL', 'SYNC_COMPLETED', 'DID_VERIFIED', 'HEARTBEAT_LOST', 'SECURITY_THREAT', 'RESET'",
                        },
                        "payload": {
                            "description": "Carga útil contextual o metadatos de la transición",
                        },
                    },
                    "required": ["event"],
                },
            },
            {
                "name": "ipvn7_pipeline_process_datagram",
                "description": "Introduce un datagrama binario en la línea de montaje Pipes & Filters con captura de descartes en Dead-Letter Queue.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "raw_hex": {
                            "type": "string",
                            "description": "Datagrama binario en formato hexadecimal",
                        },
                        "source_did": {
                            "type": "string",
                            "description": "DID soberano del remitente (opcional)",
                        },
                        "remote_addr": {
                            "type": "string",
                            "description": "Dirección IP y puerto física remota (ej: '127.0.0.1:9443')",
                        },
                    },
                    "required": ["raw_hex"],
                },
            },
            {
                "name": "ipvn7_get_daily_ephemeral_id",
                "description": "Obtiene o verifica el identificador descentralizado efímero rotativo de 24 horas (did:ipvn7:ephemeral:...) para eliminar el rastreo y fingerprinting en el cable ('La Red Responde, No Grita').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "epoch_day": {
                            "type": "integer",
                            "description": "Día epoch específico (opcional, por defecto el día actual)",
                        },
                        "verify_peer_root_did": {
                            "type": "string",
                            "description": "DID raíz de un par para verificar si un DID efímero le pertenece",
                        },
                        "verify_ephemeral_did": {
                            "type": "string",
                            "description": "DID efímero recibido para validar pertenencia al DID raíz",
                        },
                    },
                },
            },
            {
                "name": "ipvn7_dispatch_hrs_frame",
                "description": "Construye, despacha o decodifica tramas binarias canónicas del sustrato silencioso IPv7-HRS ('IP7H') con 5 opcodes canónicos (ANNOUNCE, QUERY, RESPONSE, HEARTBEAT, STATE_CHANGE).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "Acción: 'create' para generar trama binaria, o 'decode' para analizar hex recibido",
                            "enum": ["create", "decode"],
                        },
                        "frame_type": {
                            "type": "string",
                            "description": "Tipo de trama ('ANNOUNCE', 'QUERY', 'RESPONSE', 'HEARTBEAT', 'STATE_CHANGE')",
                        },
                        "target_did": {
                            "type": "string",
                            "description": "DID soberano destino (para action='create')",
                        },
                        "payload_text": {
                            "type": "string",
                            "description": "Carga útil en texto para la trama (para action='create')",
                        },
                        "raw_hex": {
                            "type": "string",
                            "description": "Trama binaria en formato hexadecimal (para action='decode')",
                        },
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "ipvn7_dispatch_edge_ai_prompt",
                "description": "Enruta transparentemente una consulta o prompt hacia un nodo de cómputo Edge AI local (Ollama/BitNet/Exo) con fallback sintético soberano sobre la malla IPVN 7.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "prompt": {
                            "type": "string",
                            "description": "Texto del prompt o consulta de inferencia",
                        },
                        "did_or_vip": {
                            "type": "string",
                            "description": "DID soberano o VIP 10.7.100.X del nodo Edge AI (opcional, selecciona el primer worker activo si se omite)",
                        },
                        "model": {
                            "type": "string",
                            "description": "Modelo de inferencia (por defecto 'llama3')",
                        },
                    },
                    "required": ["prompt"],
                },
            },
            {
                "name": "ipvn7_dispatch_remote_media_frame",
                "description": "Fragmenta y despacha tramas multimedia de audio/video bidireccional (AV1/H.265/Opus) empaquetadas en datagramas canónicos IP7M de 1280B con verificación CRC32.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "frame_type": {
                            "type": "string",
                            "description": "Tipo de trama ('video_delta', 'video_keyframe', 'audio_opus')",
                        },
                        "raw_data_hex": {
                            "type": "string",
                            "description": "Datos binarios de la trama en hexadecimal (opcional)",
                        },
                        "codec": {
                            "type": "string",
                            "description": "Códec utilizado ('av1', 'h265', 'opus')",
                        },
                    },
                },
            },
            {
                "name": "ipvn7_run_churn_stress_test",
                "description": "Ejecuta una prueba de estrés de resiliencia Small-World ante caídas masivas de nodos (churn), latencias fluctuantes (100ms-2000ms) y pérdidas de paquetes (5%-20%) con conmutación multipath.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node_count": {
                            "type": "integer",
                            "description": "Número de nodos en la topología Small-World simulada (por defecto 50)",
                        },
                        "churn_rate": {
                            "type": "number",
                            "description": "Fracción de nodos caídos repentinamente (ej: 0.20 para 20%)",
                        },
                        "packet_loss_rate": {
                            "type": "number",
                            "description": "Probabilidad de pérdida estocástica de paquetes por salto (ej: 0.10 para 10%)",
                        },
                        "min_latency_ms": {
                            "type": "number",
                            "description": "Latencia mínima por salto en ms (por defecto 100.0)",
                        },
                        "max_latency_ms": {
                            "type": "number",
                            "description": "Latencia máxima por salto en ms (por defecto 2000.0)",
                        },
                    },
                },
            },
            {
                "name": "ipvn7_bitnet_quantize_and_infer",
                "description": "Cuantiza tensores de pesos a formato ternario BitNet b1.58 (-1, 0, +1) y ejecuta inferencia entera para nodos Edge IoT de bajo consumo con cero multiplicaciones de punto flotante.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "x": {
                            "type": "array",
                            "items": {"type": "number"},
                            "description": "Vector de activaciones o entrada flotante",
                        },
                        "weights": {
                            "type": "array",
                            "items": {"type": "array", "items": {"type": "number"}},
                            "description": "Matriz 2D de pesos flotantes a cuantizar",
                        },
                        "bias": {
                            "type": "array",
                            "items": {"type": "number"},
                            "description": "Vector de sesgo opcional",
                        },
                        "model_name": {
                            "type": "string",
                            "description": "Nombre de identificación del contenedor BitNet",
                        },
                    },
                    "required": ["x", "weights"],
                },
            },
            {
                "name": "ipvn7_benchmark_saturation_throughput",
                "description": "Ejecuta benchmark continuo de saturación del pipeline de fragmentación y ensamblado de datagramas canónicos MTU 1280B en memoria y loopback UDP, reportando Gbps y Mpps.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "megabytes": {
                            "type": "number",
                            "description": "Tamaño del buffer a fragmentar y ensamblar en MB (ej: 8.0)",
                        },
                        "use_udp_loopback": {
                            "type": "boolean",
                            "description": "Si es True, transmite los fragmentos a través de socket UDP loopback local",
                        },
                    },
                },
            },
            {
                "name": "ipvn7_compress_telemetry_payload",
                "description": "Comprime datagramas de control y telemetría de menos de 256 bytes utilizando diccionario estático de tokens IPVN 7 y empaquetado de entropía, verificando reconstrucción lossless.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Cadena o JSON de telemetría a comprimir",
                        },
                    },
                    "required": ["text"],
                },
            },
            {
                "name": "ipvn7_orchestrate_silent_rekey",
                "description": "Orquesta una migración silenciosa y continua de claves de sesión PQC (X25519 + ML-KEM-768 ratcheting) con ventana de gracia zero-downtime de 30s y destrucción segura de memoria (zeroization).",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
        ]

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Tuple[bool, Any]:
        """Executes the requested tool and returns (success, result)."""
        try:
            if name == "get_node_status":
                status = self.node.get_status()
                status["uptime_seconds"] = round(time.time() - self.start_time, 1)
                return True, status

            elif name == "resolve_did":
                target_did = arguments.get("did", "")
                locators, hops = self.node.dht.resolve_locator(target_did)
                loc_list = [{"ip": l.ip, "port": l.port, "iface": l.interface_type} for l in locators]
                return True, {
                    "did": target_did,
                    "locators_found": len(locators),
                    "locators": loc_list,
                    "hops_evaluated": hops,
                }

            elif name == "send_pq_datagram":
                target_did = arguments.get("target_did", "")
                payload_str = arguments.get("payload", "")
                ok = self.node.send_message_sync(target_did, payload_str.encode("utf-8"))
                return True, {
                    "success": ok,
                    "target_did": target_did,
                    "bytes_sent": len(payload_str.encode("utf-8")),
                    "security": "NIST FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65",
                }

            elif name == "route_sphinx_onion":
                payload_str = arguments.get("payload", "Confidential Payload")
                hops = [
                    SphinxHop("did:ipvn7:zRelayA", "127.0.0.1:9001", b"A" * 32),
                    SphinxHop("did:ipvn7:zRelayB", "127.0.0.1:9002", b"B" * 32),
                    SphinxHop("did:ipvn7:zExitC", "127.0.0.1:9003", b"C" * 32),
                ]
                res = self.node.route_sphinx_onion(hops, payload_str.encode("utf-8"))
                return True, {
                    "action": res.action,
                    "next_hop": res.next_hop_did,
                    "tag_hash": res.tag_hash[:16] + "...",
                    "elapsed_us": res.elapsed_us,
                    "wire_packet_size": 1280,
                }

            elif name == "broadcast_plumtree_gossip":
                topic = arguments.get("topic", "DEFAULT")
                content = arguments.get("content", "")
                full = f"[{topic}] {content}".encode("utf-8")
                msg = self.node.broadcast_gossip(full)
                return True, {
                    "msg_id": msg.msg_id,
                    "origin_did": msg.origin_did,
                    "hop_count": msg.hop_count,
                    "eager_peers": len(self.node.gossip_engine.eager_peers),
                }

            elif name == "probe_peer_swim":
                target_did = arguments.get("target_did", "")
                res = self.node.probe_swim(target_did)
                return True, {
                    "target_did": res.target_did,
                    "state": res.state.value,
                    "via_indirect": res.via_indirect,
                    "latency_ms": res.latency_ms,
                }

            elif name == "trigger_connection_migration":
                target = arguments.get("target_did", "")
                ip = arguments.get("new_ip", "10.42.0.8")
                port = int(arguments.get("new_port", 54321))
                iface = arguments.get("interface_name", "wwan5g")
                ok = self.node.trigger_migration(target, ip, port, iface)
                return True, {
                    "success": ok,
                    "migrated_to": f"{ip}:{port}",
                    "interface": iface,
                }

            elif name == "ipvn7_firewall_rule":
                action = arguments.get("action", "get")
                did = arguments.get("did", "")
                if action == "get":
                    pol = self.node.firewall.get_policy(did)
                    return True, {
                        "did": did,
                        "default_deny": self.node.firewall.default_deny,
                        "has_explicit_policy": pol is not None,
                        "allow_inbound": pol.allow_inbound if pol else False,
                        "allow_outbound": pol.allow_outbound if pol else False,
                        "allow_relay": pol.allow_relay if pol else False,
                    }
                else:
                    pol = self.node.authorize_peer(
                        peer_did=did,
                        allow_inbound=arguments.get("allow_inbound", True),
                        allow_outbound=arguments.get("allow_outbound", True),
                        allow_relay=arguments.get("allow_relay", False),
                    )
                    return True, {
                        "action": "authorized",
                        "did": did,
                        "allow_inbound": pol.allow_inbound,
                        "allow_outbound": pol.allow_outbound,
                        "allow_relay": pol.allow_relay,
                    }

            elif name == "ipvn7_wot_vouch":
                subject_did = arguments.get("subject_did", "")
                trust = float(arguments.get("trust_level", 0.5))
                reason = arguments.get("reason", "MCP Attestation")
                vouch = self.node.vouch_peer(subject_did, trust, reason)
                return True, {
                    "issuer_did": vouch.issuer_did,
                    "subject_did": vouch.subject_did,
                    "trust_level": vouch.trust_level,
                    "reason": vouch.reason,
                    "has_signature": vouch.signature is not None,
                }

            elif name == "ipvn7_get_trust":
                target_did = arguments.get("target_did", "")
                score = self.node.get_trust_score(target_did)
                return True, {
                    "target_did": target_did,
                    "transitive_trust_score": score,
                    "is_trusted": score >= 0.5,
                }

            elif name == "ipvn7_dag_put":
                payload_str = arguments.get("payload", "")
                target_did = arguments.get("target_did", "")
                block = self.node.put_dag_block(payload_str.encode("utf-8"), target_did=target_did)
                return True, {
                    "cid": block.cid,
                    "author_did": block.author_did,
                    "target_did": block.target_did,
                    "parents": block.parents,
                    "data_bytes": len(block.data),
                    "queued_for_dtn": bool(target_did and target_did != self.node.did),
                }

            elif name == "ipvn7_get_anomalies":
                limit = int(arguments.get("limit", 20))
                fps = self.node.anomaly_detector.get_fingerprints(limit=limit)
                summary = self.node.anomaly_detector.get_summary()
                return True, {
                    "summary": summary,
                    "fingerprints": fps,
                }

            elif name == "ipvn7_audit_split_brain":
                state, reason = self.node.split_brain_guard.audit_liveness()
                health = self.node.split_brain_guard.get_mesh_health()
                return True, {
                    "state": state.value,
                    "reason": reason,
                    "health": health,
                }

            elif name == "ipvn7_register_petname":
                name_arg = arguments.get("name", "")
                did_arg = arguments.get("did", "")
                comment_arg = arguments.get("comment", "")
                rec = self.node.register_petname(name_arg, did_arg, comment_arg)
                return True, {
                    "registered": True,
                    "record": rec.to_dict(),
                }

            elif name == "ipvn7_resolve_petname":
                name_arg = arguments.get("name", "")
                rec = self.node.resolve_petname(name_arg)
                if not rec:
                    return False, f"Petname {name_arg} no encontrado en la libreta dDNS"
                return True, {
                    "resolved": True,
                    "record": rec.to_dict(),
                }

            elif name == "ipvn7_get_oob_sas":
                peer_pub_hex = arguments.get("peer_pubkey_hex", "")
                try:
                    peer_pub = bytes.fromhex(peer_pub_hex)
                except Exception as e:
                    return False, f"Clave hexadecimal inválida: {e}"
                sas = self.node.compute_oob_sas(peer_pub)
                return True, {
                    "digits": sas.digits,
                    "emojis": sas.emojis,
                    "auth_string": sas.auth_string,
                }

            elif name == "ipvn7_get_accounting":
                peer_did = arguments.get("peer_did")
                if peer_did:
                    acc = self.node.accounting.get_peer_account(peer_did)
                    if not acc:
                        return False, f"Peer {peer_did} no encontrado en registros de contabilidad"
                    return True, acc
                else:
                    return True, {
                        "summary": self.node.accounting.get_summary(),
                        "recent_accounts": self.node.accounting.list_accounts(20),
                    }

            elif name == "ipvn7_request_service":
                svc_name = arguments.get("name", "")
                scope_str = arguments.get("scope", "LOCAL").upper()
                try:
                    scope = ServiceScope[scope_str]
                except KeyError:
                    scope = ServiceScope.LOCAL
                svc = self.node.services.request_service(svc_name, scope)
                return True, {
                    "requested": True,
                    "service": svc.to_dict(),
                    "active_services_count": len(self.node.services.get_active_services()),
                }

            elif name == "ipvn7_tls_camouflage":
                action = arguments.get("action", "wrap")
                if action == "client_hello":
                    sni = arguments.get("sni", "gateway.cloudflare.com")
                    raw_ch = self.node.tls_obfuscator.build_client_hello(sni)
                    return True, {
                        "generated": True,
                        "sni": sni,
                        "bytes_length": len(raw_ch),
                        "wire_hex_sample": raw_ch[:32].hex() + "...",
                    }
                else:
                    payload_str = arguments.get("payload", "IPVN7_DATA")
                    wrapped = self.node.build_tls_camouflaged_packet(payload_str.encode("utf-8"))
                    return True, {
                        "wrapped": True,
                        "wire_bytes": len(wrapped),
                        "record_type": "0x17 (ApplicationData)",
                        "version": "0x0303 (TLS 1.2/1.3 Compat)",
                        "wire_hex_sample": wrapped[:16].hex() + "...",
                    }

            elif name == "ipvn7_blind_rendezvous":
                action = arguments.get("action", "publish")
                ring_degree = int(arguments.get("ring_degree", 1))
                if action == "publish":
                    ep = arguments.get("endpoint", f"127.0.0.1:{self.node.bound_port}")
                    topic = self.node.publish_blind_beacon(ep, ring_degree=ring_degree)
                    return True, {
                        "published": True,
                        "topic_id": topic,
                        "endpoint": ep,
                        "ring_degree": ring_degree,
                    }
                else:
                    beacon_data = self.node.discover_blind_beacon(ring_degree=ring_degree)
                    if not beacon_data:
                        return True, {"found": False, "message": "No hay balizas en el tópico temporal"}
                    return True, {
                        "found": True,
                        "beacon": beacon_data,
                    }

            elif name == "ipvn7_explain_route":
                target_did = arguments.get("target_did", "")
                raw_cands = arguments.get("candidates", [])
                candidates = []
                for c in raw_cands:
                    candidates.append(CandidateMetrics(
                        peer_did=c.get("peer_did", ""),
                        latency_ms=float(c.get("latency_ms", 10.0)),
                        rfc3550_jitter_ms=float(c.get("rfc3550_jitter_ms", 1.0)),
                        packet_loss_pct=float(c.get("packet_loss_pct", 0.0)),
                        battery_pct=int(c.get("battery_pct", 100)),
                        trust_tier=int(c.get("trust_tier", 1)),
                    ))
                explanation = self.node.explain_route_selection(target_did, candidates)
                return True, explanation.to_dict()

            elif name == "ipvn7_analyze_spectrum":
                signal = [float(x) for x in arguments.get("signal", [])]
                sampling_rate = float(arguments.get("sampling_rate_hz", 100.0))
                analysis = self.node.analyze_spectral_jitter(signal, sampling_rate_hz=sampling_rate)
                return True, analysis.to_dict()

            elif name == "ipvn7_create_delegation":
                subject_did = arguments.get("subject_did", "")
                scope = arguments.get("scope", "read_telemetry")
                tier_str = arguments.get("tier", "ordinary").lower()
                try:
                    tier = ExecutionTier(tier_str)
                except ValueError:
                    tier = ExecutionTier.ORDINARY
                ttl = float(arguments.get("ttl_seconds", 3600.0))
                link = self.node.create_delegation_link(subject_did, scope, tier=tier, ttl_seconds=ttl)
                return True, {
                    "created": True,
                    "link": link.to_dict(),
                }

            elif name == "ipvn7_anti_replay_check":
                seq = int(arguments.get("sequence_number", 1))
                valid = self.node.validate_packet_replay(seq)
                return True, {
                    "sequence_number": seq,
                    "is_valid": valid,
                    "stats": self.node.anti_replay.get_stats(),
                }

            elif name == "ipvn7_route_planetary":
                src_node = arguments.get("src_node", "sat-000")
                dst_node = arguments.get("dst_node", "sat-015")
                result = self.node.route_planetary_packet(src_node, dst_node)
                return True, result

            elif name == "ipvn7_resilience_status":
                status = self.node.get_resilience_status()
                return True, status

            elif name == "ipvn7_toggle_dark_node":
                status = self.node.toggle_dark_node_mode()
                return True, status

            elif name == "ipvn7_send_silent_call":
                target_did = arguments.get("target_did", "")
                payload_str = arguments.get("payload", "")
                res = self.node.send_silent_call(target_did, payload_str.encode("utf-8"))
                return True, res

            elif name == "ipvn7_record_link_probe":
                peer_did = arguments.get("peer_did", "")
                success = bool(arguments.get("success", True))
                latency_ms = float(arguments.get("latency_ms", 10.0))
                failover, alt_did = self.node.record_link_probe(peer_did, success, latency_ms)
                health = self.node.link_healing.get_peer_health(peer_did)
                return True, {
                    "peer_did": peer_did,
                    "failover_triggered": failover,
                    "alternative_peer": alt_did,
                    "health": health,
                }

            elif name == "ipvn7_blackout_recovery":
                action = arguments.get("action", "status")
                if action == "advance":
                    status = self.node.advance_blackout_phase()
                elif action == "cold_boot":
                    self.node.blackout_recovery.trigger_cold_boot()
                    status = self.node.blackout_recovery.get_status()
                else:
                    status = self.node.blackout_recovery.get_status()
                return True, status

            elif name == "ipvn7_send_chat_message":
                target_did = arguments.get("target_did", "")
                text = arguments.get("text", "")
                sender_name = arguments.get("sender_name", "Este Nodo")
                msg_dict = self.node.send_chat_message(target_did, text, sender_name=sender_name)
                return True, msg_dict

            elif name == "ipvn7_get_batcher_stats":
                return True, self.node.packet_batcher.get_stats()

            elif name == "ipvn7_update_mobility_locator":
                node_did = arguments.get("node_did", "")
                physical_ip = arguments.get("physical_ip", "127.0.0.1")
                physical_port = int(arguments.get("physical_port", 9443))
                seq = int(arguments.get("seq", 0))
                ticket_hex = arguments.get("ticket_hex", "")
                ticket = bytes.fromhex(ticket_hex) if ticket_hex else None
                cold_nonce = int(arguments.get("cold_nonce", 0))
                loc_dict = self.node.update_mobility_locator(
                    node_did=node_did,
                    physical_ip=physical_ip,
                    physical_port=physical_port,
                    seq=seq,
                    challenge_ticket=ticket,
                    cold_nonce=cold_nonce,
                )
                return True, loc_dict

            elif name == "ipvn7_run_ai_copilot":
                lat = float(arguments.get("latency_ms", 12.0))
                drops = int(arguments.get("firewall_drops", 0))
                p_did = arguments.get("peer_did", "")
                entropy = float(arguments.get("spectral_entropy", 1.0))
                flapping = bool(arguments.get("is_flap_damped", False))
                res = self.node.run_copilot_cycle(
                    latency_ms=lat,
                    firewall_drops=drops,
                    peer_did=p_did,
                    spectral_entropy=entropy,
                    is_flap_damped=flapping,
                )
                return True, res

            elif name == "ipvn7_schedule_multipath":
                payload_str = arguments.get("payload", "Data")
                is_crit = bool(arguments.get("is_critical", False))
                strat = arguments.get("strategy")
                if strat:
                    from ..network.multipath import MultipathStrategy
                    try:
                        self.node.multipath.set_strategy(MultipathStrategy[strat.upper()])
                    except KeyError:
                        pass
                paths = self.node.schedule_multipath_packet(payload_str.encode("utf-8"), is_critical=is_crit)
                return True, {
                    "selected_paths": paths,
                    "strategy": self.node.multipath.strategy.value,
                    "is_critical": is_crit,
                }

            elif name == "ipvn7_resolve_dns_proxy":
                domain = arguments.get("domain", "")
                res = self.node.resolve_sovereign_domain(domain)
                return True, res

            elif name == "ipvn7_nat_hole_punch":
                p_did = arguments.get("peer_did", "")
                p_ip = arguments.get("peer_public_ip", "127.0.0.1")
                p_port = int(arguments.get("peer_public_port", 9443))
                punch_res = self.node.punch_nat_hole(p_did, p_ip, p_port)
                return True, punch_res

            elif name == "ipvn7_allocate_memory_budget":
                b_class = arguments.get("budget_class", "other")
                n_bytes = int(arguments.get("num_bytes", 1024))
                alloc_res = self.node.allocate_memory_budget(b_class, n_bytes)
                return True, alloc_res

            elif name == "ipvn7_issue_uin_binding":
                sub_pub = arguments.get("subordinate_pubkey_hex", "")
                scope = int(arguments.get("scope", 0))
                duration = float(arguments.get("duration_seconds", 86400.0))
                binding_res = self.node.issue_uin_binding(sub_pub, scope=scope, duration_seconds=duration)
                return True, binding_res

            elif name == "ipvn7_get_uin_passport":
                passport = self.node.get_uin_passport()
                return True, passport

            elif name == "ipvn7_register_shadow_device":
                dev_name = arguments.get("name", "LAN-Device")
                phys_ip = arguments.get("physical_ip", "")
                mac_addr = arguments.get("mac", "")
                d_type = arguments.get("device_type", "generic")
                ports = arguments.get("allowed_ports", [80, 443])
                reg_res = self.node.register_shadow_device(
                    name=dev_name,
                    physical_ip=phys_ip,
                    mac=mac_addr,
                    device_type=d_type,
                    allowed_ports=ports,
                )
                return True, reg_res

            elif name == "ipvn7_get_pfo_tree":
                pfo_tree = self.node.get_pfo_tree()
                return True, pfo_tree

            elif name == "ipvn7_probe_wan_link":
                peer_did = arguments.get("peer_did", "")
                ep = arguments.get("endpoint", "127.0.0.1")
                sim_rtt = arguments.get("simulated_rtt_ms")
                probe_res = self.node.probe_wan_link(peer_did, endpoint=ep, simulated_rtt_ms=sim_rtt)
                return True, probe_res

            elif name == "ipvn7_dispatch_remote_input":
                evt_type = arguments.get("event_type", "mouse_move")
                x = float(arguments.get("x", 0.0))
                y = float(arguments.get("y", 0.0))
                k = arguments.get("key", "")
                input_res = self.node.dispatch_remote_input(evt_type, x=x, y=y, key=k)
                return True, input_res

            elif name == "ipvn7_rotate_session_key":
                rot_res = self.node.rotate_session_key()
                return True, rot_res

            elif name == "ipvn7_map_upnp_port":
                p = int(arguments.get("port", 7001))
                d = arguments.get("description", "ipvn7-p2p")
                map_res = self.node.map_upnp_port(p, desc=d)
                return True, map_res

            elif name == "ipvn7_audit_censorship":
                dom = arguments.get("domain", "cloudflare.com")
                audit_res = self.node.audit_censorship(domain=dom)
                return True, audit_res

            elif name == "ipvn7_get_buffer_health":
                buf_res = self.node.get_buffer_health()
                return True, buf_res

            elif name == "ipvn7_wasm_compute_pow":
                d = arguments.get("did", self.node.did)
                s = int(arguments.get("seq", 1))
                diff = int(arguments.get("difficulty_bits", 8))
                pow_res = self.node.compute_wasm_pow(d, seq=s, difficulty_bits=diff)
                return True, pow_res

            elif name == "ipvn7_fsm_trigger_event":
                ev = arguments.get("event", "NETWORK_SIGNAL")
                pl = arguments.get("payload")
                fsm_res = self.node.trigger_fsm_event(ev, payload=pl)
                return True, fsm_res

            elif name == "ipvn7_pipeline_process_datagram":
                raw_hex = arguments.get("raw_hex", "0701020304")
                s_did = arguments.get("source_did", "")
                r_addr = arguments.get("remote_addr", "127.0.0.1:9443")
                raw_bytes = bytes.fromhex(raw_hex)
                pipe_res = self.node.process_pipeline_datagram(raw_bytes, source_did=s_did, remote_addr=r_addr)
                return True, pipe_res

            elif name == "ipvn7_get_daily_ephemeral_id":
                epoch_day = arguments.get("epoch_day")
                record = self.node.ephemeral_identity.derive_ephemeral_did(epoch_day)
                res: Dict[str, Any] = {
                    "root_did": record.root_did,
                    "active_ephemeral_did": record.ephemeral_did,
                    "epoch_day": record.epoch_day,
                    "expires_at": record.expires_at,
                    "rotation_frequency_hours": 24,
                }
                v_peer = arguments.get("verify_peer_root_did")
                v_eph = arguments.get("verify_ephemeral_did")
                if v_peer and v_eph:
                    res["verification_result"] = self.node.ephemeral_identity.verify_peer_ephemeral_did(
                        ephemeral_did=v_eph,
                        peer_root_did=v_peer,
                    )
                return True, res

            elif name == "ipvn7_dispatch_hrs_frame":
                action = arguments.get("action", "create")
                if action == "create":
                    ft_str = arguments.get("frame_type", "QUERY").upper()
                    try:
                        ft_enum = HRSFrameType[ft_str]
                    except KeyError:
                        ft_enum = HRSFrameType.QUERY

                    target = arguments.get("target_did", "did:ipvn7:broadcast:quiet")
                    payload = arguments.get("payload_text", "").encode("utf-8")
                    frame = self.node.hrs_dispatcher.create_frame(
                        frame_type=ft_enum,
                        target_did=target,
                        payload=payload,
                    )
                    encoded = frame.encode()
                    return True, {
                        "action": "created",
                        "frame_type": ft_enum.name,
                        "sequence_id": frame.sequence_id,
                        "source_did": frame.source_did,
                        "target_did": frame.target_did,
                        "bytes_length": len(encoded),
                        "wire_hex": encoded.hex(),
                    }
                elif action == "decode":
                    raw_hex = arguments.get("raw_hex", "")
                    raw_bytes = bytes.fromhex(raw_hex)
                    decoded = HRSFrame.decode(raw_bytes)
                    return True, {
                        "action": "decoded",
                        "frame_type": decoded.frame_type.name,
                        "sequence_id": decoded.sequence_id,
                        "source_did": decoded.source_did,
                        "target_did": decoded.target_did,
                        "payload_text": decoded.payload.decode("utf-8", errors="replace"),
                        "timestamp": decoded.timestamp,
                        "crc32_valid": True,
                    }
                return False, f"Acción inválida: {action}"

            elif name == "ipvn7_dispatch_edge_ai_prompt":
                prompt = arguments.get("prompt", "")
                did_or_vip = arguments.get("did_or_vip", "")
                model = arguments.get("model", "llama3")
                res = self.node.dispatch_edge_ai_prompt(did_or_vip, prompt, model)
                return True, res

            elif name == "ipvn7_dispatch_remote_media_frame":
                frame_type = arguments.get("frame_type", "video_delta")
                raw_hex = arguments.get("raw_data_hex")
                codec = arguments.get("codec", "av1")
                res = self.node.dispatch_remote_media_frame(frame_type, raw_hex, codec)
                return True, res

            elif name == "ipvn7_run_churn_stress_test":
                node_count = int(arguments.get("node_count", 50))
                churn_rate = float(arguments.get("churn_rate", 0.20))
                packet_loss_rate = float(arguments.get("packet_loss_rate", 0.10))
                min_lat = float(arguments.get("min_latency_ms", 100.0))
                max_lat = float(arguments.get("max_latency_ms", 2000.0))
                res = self.node.run_churn_stress_test(
                    node_count=node_count,
                    churn_rate=churn_rate,
                    packet_loss_rate=packet_loss_rate,
                    min_latency_ms=min_lat,
                    max_latency_ms=max_lat,
                )
                return True, res

            elif name == "ipvn7_bitnet_quantize_and_infer":
                x = arguments.get("x", [0.5, -0.2, 0.8, -0.9])
                weights = arguments.get("weights", [[0.4, -0.1, 0.7, -0.8], [-0.5, 0.2, -0.3, 0.9]])
                bias = arguments.get("bias")
                model_name = arguments.get("model_name", "bitnet-edge-worker")
                res = self.node.execute_bitnet_forward(x, weights, bias=bias, model_name=model_name)
                return True, res

            elif name == "ipvn7_benchmark_saturation_throughput":
                mb = float(arguments.get("megabytes", 8.0))
                use_udp = bool(arguments.get("use_udp_loopback", False))
                res = self.node.benchmark_saturation(megabytes=mb, use_udp=use_udp)
                return True, res

            elif name == "ipvn7_compress_telemetry_payload":
                text = arguments.get("text", "")
                res = self.node.compress_telemetry_payload(text)
                return True, res

            elif name == "ipvn7_orchestrate_silent_rekey":
                res = self.node.orchestrate_silent_rekey()
                return True, res

            else:
                return False, f"Herramienta desconocida: {name}"

        except Exception as e:
            return False, f"Error al ejecutar herramienta {name}: {str(e)}"

    def handle_jsonrpc(self, request_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Handles standard JSON-RPC 2.0 MCP request."""
        req_id = request_dict.get("id")
        method = request_dict.get("method", "")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "ipvn7-mcp-engine",
                        "version": "7.0.0",
                    },
                    "capabilities": {
                        "tools": {"listChanged": True},
                    },
                },
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.get_supported_tools(),
                },
            }

        elif method == "tools/call":
            params = request_dict.get("params", {})
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})

            success, res = self.execute_tool(tool_name, tool_args)
            if not success:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": str(res)},
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(res, indent=2) if isinstance(res, (dict, list)) else str(res),
                        }
                    ]
                },
            }

        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Método no implementado: {method}"},
            }
