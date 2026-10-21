"""
IPVN 7 Interactive Web Dashboard & Real-Time Protocol Control Center
Integrates actual hardware-accelerated Post-Quantum Cryptography (NIST FIPS 203/204),
Small-World DHT, live PQ-QUIC socket streaming, and Windows Traffic Interceptor / Internet Gateway.
"""

from __future__ import annotations
import os
import sys
import threading
import secrets
import hashlib

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time
import socket
import urllib.request
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa

from ipvn7.node.node import IPVN7Node
from ipvn7.crypto.pqc import PQCKeyPair
from ipvn7.identity.did import IPVN7Identity
from ipvn7.network.dht import DHTRoutingTier
from ipvn7.simulation.churn import SmallWorldChurnSimulator
from ipvn7.benchmark.bench import run_performance_benchmarks
from ipvn7.gateway.proxy import IPVN7InternetProxy
from ipvn7.gateway.socks5 import IPVN7SOCKS5Gateway
from ipvn7.network.onion import SphinxHop, ACTION_DELIVER, ACTION_FORWARD
from ipvn7.access.services import ServiceScope
from ipvn7.network.explainable import CandidateMetrics
from ipvn7.security.delegation import ExecutionTier
from ipvn7.crypto.bitnet import BitNetQuantizer
from ipvn7.security.egress_policy import EgressSecurityPolicy, SafeRedirectHandler

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Audit 3 H-01: Zero Static Credentials - Dynamic Cryptographic Token Generation
_env_token = os.environ.get("IPVN7_CONTROL_TOKEN")
if _env_token and _env_token.strip():
    CONTROL_AUTH_TOKEN = _env_token.strip()
else:
    # High-entropy random token generated on startup; never hardcoded publicly
    CONTROL_AUTH_TOKEN = secrets.token_urlsafe(32)
    try:
        _runtime_dir = os.path.join(os.path.dirname(__file__), "..", ".nexus", "runtime")
        os.makedirs(_runtime_dir, exist_ok=True)
        with open(os.path.join(_runtime_dir, "control.token"), "w", encoding="utf-8") as _tf:
            _tf.write(CONTROL_AUTH_TOKEN)
    except Exception:
        pass

REQUEST_SEMAPHORE = threading.BoundedSemaphore(32)

# History of packets/messages
PACKET_LOGS = []

# Instantiate primary control node
PRIMARY_NODE = IPVN7Node(alias="Genesis-Gateway", bind_host="127.0.0.1")
PRIMARY_NODE.start_background_listener()

# Instantiate secondary peer node for live interaction demonstrations
PEER_NODE = IPVN7Node(alias="Sat-Node-Orbiter", bind_host="127.0.0.1")
PEER_NODE.start_background_listener()

# Mutual bootstrap
PRIMARY_NODE.bootstrap_peer(PEER_NODE.did, "127.0.0.1", PEER_NODE.bound_port)
PEER_NODE.bootstrap_peer(PRIMARY_NODE.did, "127.0.0.1", PRIMARY_NODE.bound_port)


def on_message_received(src_did: str, data: bytes):
    PACKET_LOGS.append({
        "time": time.strftime("%H:%M:%S"),
        "from": src_did,
        "payload": data.decode("utf-8", errors="replace"),
        "status": "DELIVERED_1RTT_PQC",
    })


PRIMARY_NODE.register_message_handler(on_message_received)
PEER_NODE.register_message_handler(on_message_received)


def on_windows_traffic_intercepted(event_info: Dict[str, Any]):
    # Audit H-01: Honest datapath status reporting
    PACKET_LOGS.append({
        "time": event_info["time"],
        "event": "WINDOWS_TRAFFIC_INTERCEPTED",
        "from": event_info["client"],
        "to": f"{event_info['target_host']}:{event_info['target_port']}",
        "payload": f"{event_info['method']} {event_info['target_host']}",
        "status": "CONTROL_NOTIFIED_DIRECT_EGRESS",
    })


# Start Windows Internet Proxy Gateway on port 8888
INTERNET_PROXY = IPVN7InternetProxy(
    local_node=PRIMARY_NODE,
    exit_node=PEER_NODE,
    listen_host="127.0.0.1",
    listen_port=8888,
    traffic_logger=on_windows_traffic_intercepted,
)
INTERNET_PROXY.start()

def on_socks5_traffic_intercepted(event_info: Dict[str, Any]):
    # Audit H-02: Explicit egress security logging
    PACKET_LOGS.append({
        "time": event_info["time"],
        "event": "SOCKS5_INTERCEPTED",
        "from": event_info["client"],
        "to": f"{event_info['target_host']}:{event_info['target_port']}",
        "payload": f"RFC 1928 TCP Stream -> {event_info['target_host']}",
        "status": "DIRECT_LOCAL_EGRESS_VALIDATED",
    })

# Start Universal RFC 1928 SOCKS5 Proxy Gateway on port 10807
SOCKS5_GATEWAY = IPVN7SOCKS5Gateway(
    local_node=PRIMARY_NODE,
    exit_node=PEER_NODE,
    listen_host="127.0.0.1",
    listen_port=10807,
    traffic_logger=on_socks5_traffic_intercepted,
)
SOCKS5_GATEWAY.start()


class IPVN7DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def _validate_host_header(self) -> bool:
        """H-03/H-04: Prevent DNS Rebinding attacks by validating Host header."""
        host = self.headers.get("Host", "").split(":")[0].lower()
        return host in ("127.0.0.1", "localhost", "[::1]", "")

    def _validate_control_auth(self, require_explicit_token: bool = False) -> Tuple[bool, str]:
        """
        H-03/H-04: Mandatory authentication for MCP control plane and sensitive operations.
        Requires high-entropy Bearer token or trusted same-origin local session.
        """
        # 1. Check Authorization Bearer header
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr[7:].strip()
            if secrets.compare_digest(token, CONTROL_AUTH_TOKEN):
                return True, "Authorized (Bearer Token)"

        # 2. Check custom header X-IPVN7-Auth
        x_auth = self.headers.get("X-IPVN7-Auth", "").strip()
        if x_auth and secrets.compare_digest(x_auth, CONTROL_AUTH_TOKEN):
            return True, "Authorized (X-IPVN7-Auth)"

        # 3. Allow trusted local dashboard origin ONLY if not explicitly requiring token and Sec-Fetch-Site is same-origin
        if not require_explicit_token:
            origin = self.headers.get("Origin", "")
            sec_site = self.headers.get("Sec-Fetch-Site", "")
            trusted_origins = {"http://127.0.0.1:7070", "http://localhost:7070"}
            if origin in trusted_origins and self._validate_host_header():
                if sec_site in ("same-origin", "none", ""):
                    return True, "Authorized (Local Dashboard Same-Origin)"

        return False, "Unauthorized: MCP Control Plane requires valid cryptographic Bearer token"

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))

        # H-04: Security boundary - Restrict CORS to trusted local dashboard origins
        origin = self.headers.get("Origin", "")
        allowed_origins = {
            "http://127.0.0.1:7070",
            "http://localhost:7070",
        }
        if origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests with strict origin control."""
        self.send_response(204)
        origin = self.headers.get("Origin", "")
        allowed_origins = {
            "http://127.0.0.1:7070",
            "http://localhost:7070",
        }
        if origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-IPVN7-Auth")
            self.send_header("Access-Control-Max-Age", "86400")
            self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self):
        if not self._validate_host_header():
            self._send_json({"error": "Bad Request: Invalid Host header (Anti-DNS Rebinding Protection)", "success": False}, status=400)
            return

        if not REQUEST_SEMAPHORE.acquire(blocking=True, timeout=5.0):
            self._send_json({"error": "Service Busy: Request concurrency limit reached", "success": False}, status=503)
            return

        try:
            self._handle_get_internal()
        finally:
            REQUEST_SEMAPHORE.release()

    def _handle_get_internal(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            status_data = {
                "primary": PRIMARY_NODE.get_status(),
                "peer": PEER_NODE.get_status(),
                "proxy": {
                    "bound_port": INTERNET_PROXY.bound_port,
                    "stats": INTERNET_PROXY.stats,
                },
                "socks5": {
                    "bound_port": SOCKS5_GATEWAY.bound_port,
                    "stats": SOCKS5_GATEWAY.stats,
                },
                "recent_packets": PACKET_LOGS[-25:],
            }
            self._send_json(status_data)

        elif path == "/api/benchmark":
            bench = run_performance_benchmarks()
            self._send_json(bench)

        elif path == "/api/pqc/live_demo":
            t0 = time.perf_counter_ns()
            k_priv = mlkem.MLKEM768PrivateKey.generate()
            k_pub = k_priv.public_key()
            t_kem_keygen = (time.perf_counter_ns() - t0) / 1e6

            raw_k_pub = k_pub.public_bytes_raw()

            t0 = time.perf_counter_ns()
            ss1, ct = k_pub.encapsulate()
            t_kem_encap = (time.perf_counter_ns() - t0) / 1e6

            t0 = time.perf_counter_ns()
            ss2 = k_priv.decapsulate(ct)
            t_kem_decap = (time.perf_counter_ns() - t0) / 1e6

            # MLDSA
            t0 = time.perf_counter_ns()
            d_priv = mldsa.MLDSA65PrivateKey.generate()
            d_pub = d_priv.public_key()
            t_dsa_keygen = (time.perf_counter_ns() - t0) / 1e6

            raw_d_pub = d_pub.public_bytes_raw()
            test_msg = b"IPVN 7 Real Cryptographic Handshake Verification"

            t0 = time.perf_counter_ns()
            sig = d_priv.sign(test_msg)
            t_dsa_sign = (time.perf_counter_ns() - t0) / 1e6

            t0 = time.perf_counter_ns()
            d_pub.verify(sig, test_msg)
            t_dsa_verify = (time.perf_counter_ns() - t0) / 1e6

            self._send_json({
                "ml_kem_768": {
                    "public_key_len": len(raw_k_pub),
                    "public_key_hex_sample": raw_k_pub[:32].hex() + "...",
                    "ciphertext_len": len(ct),
                    "ciphertext_hex_sample": ct[:32].hex() + "...",
                    "shared_secret_len": len(ss1),
                    "shared_secret_fingerprint": hashlib.sha256(ss1).hexdigest()[:16] + "...",
                    "decapsulated_matches": ss1 == ss2,
                    "keygen_time_ms": round(t_kem_keygen, 3),
                    "encap_time_ms": round(t_kem_encap, 3),
                    "decap_time_ms": round(t_kem_decap, 3),
                },
                "ml_dsa_65": {
                    "public_key_len": len(raw_d_pub),
                    "public_key_hex_sample": raw_d_pub[:32].hex() + "...",
                    "signature_len": len(sig),
                    "signature_hex_sample": sig[:32].hex() + "...",
                    "verified": True,
                    "keygen_time_ms": round(t_dsa_keygen, 3),
                    "sign_time_ms": round(t_dsa_sign, 3),
                    "verify_time_ms": round(t_dsa_verify, 3),
                }
            })

        elif path == "/api/simulation/small-world":
            qs = parse_qs(parsed.query)
            try:
                raw_nodes = int(qs.get("nodes", [60])[0])
            except (ValueError, TypeError):
                raw_nodes = 60
            try:
                raw_churn = float(qs.get("churn", [0.2])[0])
            except (ValueError, TypeError):
                raw_churn = 0.2
            # Audit H-05: Strict bounds against resource exhaustion
            nodes = max(5, min(raw_nodes, 120))
            churn = max(0.0, min(raw_churn, 0.85))
            sim = SmallWorldChurnSimulator(node_count=nodes, seed=int(time.time()) % 1000)
            stats = sim.run_benchmark(sample_pairs=30, churn_rate=churn)
            self._send_json({
                "total_nodes": stats.total_nodes,
                "churn_ratio": stats.churn_ratio,
                "avg_hops_baseline": stats.avg_hops_baseline,
                "avg_hops_post_churn": stats.avg_hops_post_churn,
                "delivery_success_baseline": stats.delivery_success_baseline,
                "delivery_success_post_churn": stats.delivery_success_post_churn,
                "theoretical_kleinberg_bound": stats.theoretical_kleinberg_bound,
            })

        elif path == "/api/firewall/rules":
            policies = [
                {
                    "did": p.did,
                    "allow_inbound": p.allow_inbound,
                    "allow_outbound": p.allow_outbound,
                    "allow_relay": p.allow_relay,
                    "allowed_ports": p.allowed_ports,
                    "created_at": p.created_at,
                    "is_expired": p.is_expired(),
                }
                for p in PRIMARY_NODE.firewall.policies.values()
            ]
            self._send_json({
                "default_deny": PRIMARY_NODE.firewall.default_deny,
                "policies": policies,
                "stats": PRIMARY_NODE.firewall.stats,
            })

        elif path == "/api/wot/status":
            vouches = PRIMARY_NODE.wot.get_vouches_received(PRIMARY_NODE.did)
            self._send_json({
                "local_did": PRIMARY_NODE.did,
                "peer_did": PEER_NODE.did,
                "vouches_received": vouches,
                "trust_to_peer": PRIMARY_NODE.get_trust_score(PEER_NODE.did),
            })

        elif path == "/api/dag/blocks":
            self._send_json({
                "heads": PRIMARY_NODE.dag.heads,
                "stats": PRIMARY_NODE.dag.stats,
                "blocks": PRIMARY_NODE.dag.get_recent_blocks(15),
                "pending_dtn_bundles": {
                    did: len(bundles) for did, bundles in PRIMARY_NODE.dag.pending_dtn_queue.items()
                },
            })

        elif path == "/api/diagnostics/anomalies":
            self._send_json({
                "summary": PRIMARY_NODE.anomaly_detector.get_summary(),
                "fingerprints": PRIMARY_NODE.anomaly_detector.get_fingerprints(limit=25),
            })

        elif path == "/api/diagnostics/split_brain":
            state, reason = PRIMARY_NODE.split_brain_guard.audit_liveness()
            self._send_json({
                "state": state.value,
                "reason": reason,
                "health": PRIMARY_NODE.split_brain_guard.get_mesh_health(),
            })

        elif path == "/api/petnames":
            self._send_json({
                "records": PRIMARY_NODE.petnames.list_records(),
                "count": len(PRIMARY_NODE.petnames.records),
            })

        elif path == "/api/petnames/resolve":
            qs = parse_qs(parsed.query)
            name = qs.get("name", [""])[0]
            rec = PRIMARY_NODE.resolve_petname(name)
            if rec:
                self._send_json({"found": True, "record": rec.to_dict()})
            else:
                self._send_json({"found": False, "error": "Petname no encontrado"}, status=404)

        elif path == "/api/oob/profile":
            frames = PRIMARY_NODE.generate_oob_profile()
            self._send_json({
                "did": PRIMARY_NODE.did,
                "alias": PRIMARY_NODE.alias,
                "ur_frames": frames,
                "frames_count": len(frames),
            })

        elif path == "/api/accounting":
            self._send_json({
                "summary": PRIMARY_NODE.accounting.get_summary(),
                "accounts": PRIMARY_NODE.accounting.list_accounts(50),
            })

        elif path == "/api/settlement/summary":
            self._send_json(PRIMARY_NODE.get_settlement_ledger_summary())

        elif path == "/api/services":
            self._send_json({
                "services": PRIMARY_NODE.services.list_services(),
                "stats": PRIMARY_NODE.services.stats,
            })

        elif path == "/api/tls/stats":
            self._send_json({
                "stats": PRIMARY_NODE.tls_obfuscator.stats,
                "default_sni": PRIMARY_NODE.tls_obfuscator.default_sni,
            })

        elif path == "/api/rendezvous/stats":
            self._send_json({
                "circuit_breaker_tripped": PRIMARY_NODE.blind_rendezvous.circuit_breaker_tripped,
                "active_beacons": PRIMARY_NODE.blind_rendezvous.active_beacons,
                "stats": PRIMARY_NODE.blind_rendezvous.stats,
            })

        elif path == "/api/antireplay/stats":
            self._send_json(PRIMARY_NODE.anti_replay.get_stats())

        elif path == "/api/planetary/metrics":
            self._send_json(PRIMARY_NODE.planetary_mesh.get_mesh_metrics())

        elif path == "/api/planetary/topology":
            self._send_json(PRIMARY_NODE.planetary_mesh.get_topology_snapshot())

        elif path == "/api/bitnet/demo":
            qs = parse_qs(parsed.query)
            rows = int(qs.get("rows", [8])[0])
            cols = int(qs.get("cols", [8])[0])
            seed = int(qs.get("seed", [42])[0])
            rows = max(2, min(32, rows))
            cols = max(2, min(32, cols))
            demo_res = BitNetQuantizer.run_demo_pipeline(rows, cols, seed)
            self._send_json(demo_res)

        elif path == "/api/benchmark/saturation":
            qs = parse_qs(parsed.query)
            mb = float(qs.get("mb", [4.0])[0])
            use_udp = qs.get("udp", ["0"])[0] in ("1", "true", "True")
            mb = max(0.5, min(32.0, mb))
            res = PRIMARY_NODE.benchmark_saturation(megabytes=mb, use_udp=use_udp)
            self._send_json(res)

        elif path == "/api/compression/benchmark":
            qs = parse_qs(parsed.query)
            sample_text = qs.get("text", [""])[0]
            if sample_text:
                res = PRIMARY_NODE.compress_telemetry_payload(sample_text)
            else:
                from ipvn7.network.compression import SovereignHeaderCompressor
                res = SovereignHeaderCompressor.benchmark_sample()
            self._send_json(res)

        elif path == "/api/resilience/status":
            self._send_json(PRIMARY_NODE.resilience_guardian.get_health_status())

        elif path == "/api/darknode/status":
            self._send_json(PRIMARY_NODE.dark_node.get_status())

        elif path == "/api/silent/stats":
            self._send_json(PRIMARY_NODE.silent_dispatcher.get_stats())

        elif path == "/api/healing/summary":
            self._send_json(PRIMARY_NODE.link_healing.get_summary())

        elif path == "/api/blackout/status":
            self._send_json(PRIMARY_NODE.blackout_recovery.get_status())

        elif path == "/api/chat/contacts":
            self._send_json(PRIMARY_NODE.chat_manager.list_contacts())

        elif path == "/api/chat/messages":
            qs = parse_qs(parsed.query)
            peer = qs.get("peer", [PEER_NODE.did])[0]
            self._send_json(PRIMARY_NODE.chat_manager.get_conversation(peer))

        elif path == "/api/batcher/stats":
            self._send_json(PRIMARY_NODE.packet_batcher.get_stats())

        elif path == "/api/mobility/summary":
            self._send_json(PRIMARY_NODE.mobility_anchor.get_summary())

        elif path == "/api/copilot/status":
            self._send_json(PRIMARY_NODE.ai_copilot.get_summary())

        elif path == "/api/multipath/summary":
            self._send_json(PRIMARY_NODE.multipath.get_summary())

        elif path == "/api/dns/summary":
            self._send_json(PRIMARY_NODE.dns_proxy.get_summary())

        elif path == "/api/nat/summary":
            self._send_json(PRIMARY_NODE.nat_traversal.get_summary())

        elif path == "/api/memory/summary":
            self._send_json(PRIMARY_NODE.memory_arbiter.get_summary())

        elif path == "/api/uin/passport":
            self._send_json(PRIMARY_NODE.get_uin_passport())

        elif path == "/api/shadow/devices":
            self._send_json(PRIMARY_NODE.shadow_registry.summary())

        elif path == "/api/pfo/tree":
            self._send_json(PRIMARY_NODE.get_pfo_tree())

        elif path == "/api/wan/stats":
            self._send_json(PRIMARY_NODE.wan_prober.get_summary())

        elif path == "/api/remote_desktop/status":
            self._send_json(PRIMARY_NODE.get_remote_desktop_status())

        elif path == "/api/key_rotation/status":
            self._send_json(PRIMARY_NODE.key_rotation.summary())

        elif path == "/api/key_rotation/rekey":
            # Audit H-07: Key rotation modifies cryptographic state; GET is prohibited by HTTP spec.
            self._send_json({
                "error": "Method Not Allowed: /api/key_rotation/rekey modifies cryptographic state and must be invoked via POST.",
                "success": False
            }, status=405)

        elif path == "/api/geopolicy/routes":
            qs = parse_qs(parsed.query)
            target = qs.get("target", ["did:ipvn7:destination"])[0]
            mode = qs.get("mode", ["BALANCED"])[0]
            enclave = qs.get("enclave", [None])[0]
            excl_raw = qs.get("excluded", [""])[0]
            excluded = [e.strip() for e in excl_raw.split(",") if e.strip()] if excl_raw else None
            try:
                res = PRIMARY_NODE.select_geopolicy_route(target, mode=mode, enclave=enclave, excluded_regions=excluded)
                self._send_json(res)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
        elif path == "/api/dht/sync/summary":
            self._send_json(PRIMARY_NODE.dht_sync.get_summary())

        elif path == "/api/tunnel/telemetry":
            self._send_json(PRIMARY_NODE.tunnel_telemetry.get_summary())

        elif path == "/api/settlement/summary":
            self._send_json(PRIMARY_NODE.get_settlement_ledger_summary())

        elif path == "/api/tee/status":
            self._send_json(PRIMARY_NODE.enclave.get_enclave_status())

        elif path == "/api/formal/verify":
            self._send_json(PRIMARY_NODE.run_formal_verification())

        elif path == "/api/zkp/status":
            from ipvn7.crypto.zkp import _Q, _G, _H
            self._send_json({
                "status": "OPERATIONAL",
                "version": "7.13.0",
                "group": "Zq (252-bit Ed25519 scalar field)",
                "prime_order_q": hex(_Q),
                "generator_g": hex(_G),
                "generator_h": hex(_H),
                "wire_protocols": {
                    "zk_schnorr": {"type": "0x01", "magic": "IP7Z", "mtu": 1280},
                    "range_proof": {"type": "0x02", "magic": "IP7Z", "mtu": 1280},
                    "ring_signature": {"type": "0x10", "magic": "IP7S", "mtu": 1280},
                },
                "security_invariants": [
                    "ZERO_FIAT_SHAMIR_REUSE",
                    "SOUNDNESS_128BIT",
                    "ZERO_VALUE_LEAKAGE",
                    "ANONYMITY_AOS02",
                    "DOUBLE_SIGN_NULLIFIER_DETECTION",
                ],
            })

        elif path == "/api/xdp/stats":
            self._send_json(PRIMARY_NODE.get_xdp_stats())

        elif path == "/api/xdp/export_c":
            c_code = PRIMARY_NODE.export_xdp_c_program()
            self._send_json({
                "success": True,
                "c_code": c_code,
                "lines": len(c_code.splitlines()),
                "mesh_port": PRIMARY_NODE.bound_port or PRIMARY_NODE.requested_port,
                "compiler_flags": "clang -O2 -target bpf -c xdp_ipvn7.c -o xdp_ipvn7.o",
            })

        elif path == "/api/mode/status":
            self._send_json(PRIMARY_NODE.get_operating_mode_status())

        elif path == "/api/mode/history":
            history = PRIMARY_NODE.get_operating_mode_history()
            self._send_json({
                "success": True,
                "history": history,
                "count": len(history),
            })

        elif path == "/api/ota/status":
            self._send_json(PRIMARY_NODE.get_ota_status())

        elif path == "/api/ota/modules":
            modules = PRIMARY_NODE.list_ota_modules()
            self._send_json({
                "success": True,
                "modules": modules,
                "count": len(modules),
            })

        elif path == "/api/upnp/status":
            self._send_json(PRIMARY_NODE.upnp_mapper.get_summary())

        elif path == "/api/censorship/summary":
            self._send_json(PRIMARY_NODE.censorship_detector.get_summary())

        elif path == "/api/buffer/health":
            self._send_json(PRIMARY_NODE.buffer_monitor.summary())

        elif path in ("/api/mcp", "/mcp"):
            # Audit H-03: Mandatory identity verification on MCP control plane
            auth_ok, auth_reason = self._validate_control_auth()
            if not auth_ok:
                self._send_json({"error": auth_reason, "code": 401, "success": False}, status=401)
                return

            self._send_json({
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "ipvn7-mcp-engine", "version": "7.3.0"},
                "tools_count": len(PRIMARY_NODE.mcp_server.get_supported_tools()),
                "tools": PRIMARY_NODE.mcp_server.get_supported_tools(),
            })

        else:
            super().do_GET()

    def do_POST(self):
        if not self._validate_host_header():
            self._send_json({"error": "Bad Request: Invalid Host header (Anti-DNS Rebinding Protection)", "success": False}, status=400)
            return

        if not REQUEST_SEMAPHORE.acquire(blocking=True, timeout=5.0):
            self._send_json({"error": "Service Busy: Request concurrency limit reached", "success": False}, status=503)
            return

        try:
            self._handle_post_internal()
        finally:
            REQUEST_SEMAPHORE.release()

    def _handle_post_internal(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))

        # H-04: Strict DoS payload limit boundary (1 MB maximum body)
        if length > 1_048_576:
            self._send_json({"error": "Payload Too Large: Maximum request body is 1MB", "success": False}, status=413)
            return

        post_data = self.rfile.read(length) if length > 0 else b"{}"

        try:
            body = json.loads(post_data.decode("utf-8"))
        except Exception:
            body = {}

        if path == "/api/send":
            msg_text = body.get("message", "IPVN 7 Quantum Secure Datagram")
            target = body.get("target", PEER_NODE.did)
            success = PRIMARY_NODE.send_message_sync(target, msg_text.encode("utf-8"))
            PACKET_LOGS.append({
                "time": time.strftime("%H:%M:%S"),
                "from": PRIMARY_NODE.did,
                "to": target,
                "payload": msg_text,
                "status": "SENT_PQ_QUIC" if success else "FAILED",
            })
            self._send_json({"success": success, "target": target})

        elif path == "/api/internet/fetch":
            target_url = body.get("url", "http://example.com/")

            # Audit H-04: Robust centralized SSRF validation (ipaddress RFC parsing, DNS rebinding prevention)
            is_safe, reason = EgressSecurityPolicy.validate_url(target_url)
            if not is_safe:
                self._send_json({
                    "success": False,
                    "error": f"SSRF Blocked: {reason}",
                }, status=403)
                return

            t0 = time.perf_counter()

            # Transmit the egress notification datagram across overlay to PEER_NODE
            egress_envelope = json.dumps({
                "action": "OVERLAY_EGRESS_FETCH",
                "target_url": target_url,
                "requester": PRIMARY_NODE.did,
                "timestamp": time.time(),
            }).encode("utf-8")

            control_sent = PRIMARY_NODE.send_message_sync(PEER_NODE.did, egress_envelope)

            # Retrieve active PQ-QUIC session fingerprint between PRIMARY and PEER
            quic_conn = PRIMARY_NODE.quic_connections.get(PEER_NODE.did)
            has_active_pqc = quic_conn is not None and bool(quic_conn.shared_key)
            session_key_fp = quic_conn.shared_key[:8].hex() if has_active_pqc else None

            # Audit H-04: SafeRedirectHandler validates each redirect hop against SSRF
            opener = urllib.request.build_opener(SafeRedirectHandler())

            try:
                req = urllib.request.Request(
                    target_url,
                    headers={"User-Agent": "IPVN7-Client/7.0 (Windows NT 10.0; Win64; x64; PQC-Verified)"}
                )
                with opener.open(req, timeout=6.0) as resp:
                    resp_data = resp.read(8192)
                    status_code = resp.getcode()
                    headers_dict = dict(resp.headers.items())

                elapsed = time.perf_counter() - t0

                # Audit H-01 & H-06: Honest datapath status reporting
                overlay_path_desc = (
                    f"{PRIMARY_NODE.did[:16]}... -> [PQ-QUIC fp:{session_key_fp}] -> {PEER_NODE.did[:16]}... (Exit Node) -> Target"
                    if has_active_pqc else
                    f"{PRIMARY_NODE.did[:16]}... -> [CONTROL_NOTIFIED_DIRECT_EGRESS] -> Target"
                )

                # Audit 3 H-10: Transparent and honest datapath reporting
                self._send_json({
                    "success": True,
                    "url": target_url,
                    "status_code": status_code,
                    "elapsed_ms": round(elapsed * 1000, 1),
                    "bytes_received": len(resp_data),
                    "body_preview": resp_data.decode("utf-8", errors="replace")[:1000],
                    "headers": {k: v for k, v in list(headers_dict.items())[:6]},
                    "overlay_path": overlay_path_desc,
                    "datapath_mode": "LOCAL_EGRESS_WITH_OVERLAY_CONTROL_NOTIFICATION",
                    "data_tunneled_over_overlay": False,
                    "control_plane_notified_over_overlay": bool(control_sent),
                    "overlay_verified": False,
                    "control_delivered": control_sent,
                    "session_key_fp": session_key_fp,
                    "pqc_hardening": "CONTROL_PLANE_NOTIFICATION_ONLY (LOCAL_DATA_PLANE)",
                })
            except Exception as e:
                self._send_json({
                    "success": False,
                    "url": target_url,
                    "error": str(e),
                    "overlay_verified": False,
                    "control_delivered": control_sent,
                    "session_key_fp": session_key_fp,
                }, status=500)

        elif path == "/api/quic/live_stream_test":
            num_packets = int(body.get("packets", 50))
            chunk_size = int(body.get("chunk_size", 1400))
            payload = b"Q" * chunk_size

            rx_packets = []
            def track_rx(src, data):
                rx_packets.append(len(data))

            PEER_NODE.register_message_handler(track_rx)

            t0 = time.perf_counter()
            sent_count = 0
            for _ in range(num_packets):
                ok = PRIMARY_NODE.send_message_sync(PEER_NODE.did, payload)
                if ok:
                    sent_count += 1

            time.sleep(0.04)
            elapsed = time.perf_counter() - t0
            bytes_transferred = sum(rx_packets)
            mb_sec = (bytes_transferred / (1024 * 1024)) / elapsed if elapsed > 0 else 0

            PACKET_LOGS.append({
                "time": time.strftime("%H:%M:%S"),
                "event": "PQ_QUIC_STREAM_BURST",
                "details": f"Transferred {sent_count} packets ({bytes_transferred} bytes) in {elapsed*1000:.1f}ms",
                "status": f"{mb_sec:.2f} MB/s OVER UDP",
            })

            self._send_json({
                "packets_sent": sent_count,
                "packets_received": len(rx_packets),
                "bytes_transferred": bytes_transferred,
                "elapsed_sec": round(elapsed, 4),
                "throughput_mb_sec": round(mb_sec, 2),
                "src_socket": f"{PRIMARY_NODE.bind_host}:{PRIMARY_NODE.bound_port}",
                "dst_socket": f"{PEER_NODE.bind_host}:{PEER_NODE.bound_port}",
            })

        elif path == "/api/migrate":
            new_ip = body.get("new_ip", "10.42.100.99")
            new_port = int(body.get("new_port", 54321))
            interface_name = body.get("interface", "5g-nr-direct")
            mig_ok = PRIMARY_NODE.trigger_migration(PEER_NODE.did, new_ip, new_port, interface_name)
            PACKET_LOGS.append({
                "time": time.strftime("%H:%M:%S"),
                "event": "CONNECTION_MIGRATION",
                "details": f"Handed off to {interface_name} ({new_ip}:{new_port})",
                "status": "SEAMLESS_CONTINUITY",
            })
            self._send_json({"success": mig_ok, "interface": interface_name})

        elif path == "/api/compression/benchmark":
            text_payload = body.get("text", "did:ipvn7:genesis:node:control:signal:pqc:heartbeat")
            res = PRIMARY_NODE.compress_telemetry_payload(text_payload)
            self._send_json(res)

        elif path == "/api/onion/route":
            msg_text = body.get("payload", "Sphinx Confidential Datagram Payload")
            # Construct 3-hop circuit: Hop 1 (Relay Alpha) -> Hop 2 (Relay Beta) -> Hop 3 (Exit/Peer)
            s1 = os.urandom(32)
            s2 = os.urandom(32)
            s3 = os.urandom(32)
            hops = [
                SphinxHop(node_did="did:ipvn7:zRelayAlpha1111111111111111111111111", locator="127.0.0.1:9001", shared_secret=s1),
                SphinxHop(node_did="did:ipvn7:zRelayBeta22222222222222222222222222", locator="127.0.0.1:9002", shared_secret=s2),
                SphinxHop(node_did=PEER_NODE.did, locator=f"127.0.0.1:{PEER_NODE.bound_port}", shared_secret=s3),
            ]

            t0 = time.perf_counter()
            onion_pkt = PRIMARY_NODE.sphinx_router.build_packet(hops, msg_text.encode("utf-8"))
            build_time_us = (time.perf_counter() - t0) * 1e6

            # Peel Hop 1
            p1 = PRIMARY_NODE.sphinx_router.peel_layer(onion_pkt, s1)
            # Peel Hop 2
            p2 = PRIMARY_NODE.sphinx_router.peel_layer(p1.next_packet, s2)
            # Peel Hop 3 (Exit)
            p3 = PRIMARY_NODE.sphinx_router.peel_layer(p2.next_packet, s3)

            PACKET_LOGS.append({
                "time": time.strftime("%H:%M:%S"),
                "event": "SPHINX_ONION_ROUTING",
                "from": PRIMARY_NODE.did[:16] + "...",
                "to": PEER_NODE.did[:16] + "...",
                "payload": f"3-Hop Sphinx [{len(onion_pkt.serialize())} bytes fixed]",
                "status": "UNWRAPPED_DELIVERED",
            })

            self._send_json({
                "success": True,
                "packet_size": len(onion_pkt.serialize()),
                "hops_count": 3,
                "build_time_us": round(build_time_us, 1),
                "peel_hop1": {"action": p1.action, "next_did": p1.next_hop_did, "elapsed_us": round(p1.elapsed_us, 1)},
                "peel_hop2": {"action": p2.action, "next_did": p2.next_hop_did, "elapsed_us": round(p2.elapsed_us, 1)},
                "peel_hop3": {
                    "action": p3.action,
                    "delivered_payload": p3.delivered_payload.decode("utf-8", errors="replace"),
                    "elapsed_us": round(p3.elapsed_us, 1),
                },
                "tag_hash": p1.tag_hash[:16] + "...",
            })

        elif path == "/api/gossip/broadcast":
            topic = body.get("topic", "GLOBAL_MESH_ALERT")
            content = body.get("content", "Quantum-Resistant DHT Sync Initiated")
            full_msg = f"[{topic}] {content}".encode("utf-8")

            gossip_msg = PRIMARY_NODE.broadcast_gossip(full_msg)
            # Simulate peer tree absorption
            PEER_NODE.gossip_engine.handle_eager_message(
                sender_did=PRIMARY_NODE.did,
                msg_id=gossip_msg.msg_id,
                origin_did=gossip_msg.origin_did,
                payload_bytes=gossip_msg.payload,
                hop_count=0,
            )

            PACKET_LOGS.append({
                "time": time.strftime("%H:%M:%S"),
                "event": "PLUMTREE_GOSSIP_BROADCAST",
                "from": PRIMARY_NODE.did[:16] + "...",
                "payload": f"ID:{gossip_msg.msg_id} {topic}",
                "status": "EPIDEMIC_TREE_DISSEMINATED",
            })

            self._send_json({
                "success": True,
                "msg_id": gossip_msg.msg_id,
                "origin_did": gossip_msg.origin_did,
                "hop_count": gossip_msg.hop_count,
                "eager_tree_size": len(PRIMARY_NODE.gossip_engine.eager_peers),
                "lazy_tree_size": len(PRIMARY_NODE.gossip_engine.lazy_peers),
                "stats": PRIMARY_NODE.gossip_engine.stats,
            })

        elif path == "/api/swim/probe":
            target = body.get("target_did", PEER_NODE.did)
            probe_res = PRIMARY_NODE.probe_swim(target, active_mesh=[PEER_NODE.did])

            self._send_json({
                "success": True,
                "target_did": probe_res.target_did,
                "state": probe_res.state.value,
                "via_indirect": probe_res.via_indirect,
                "intermediary_did": probe_res.intermediary_did,
                "latency_ms": probe_res.latency_ms,
            })

        elif path == "/api/socks5/test":
            dest_host = body.get("dest_host", "example.com")
            dest_port = int(body.get("dest_port", 80))
            t0 = time.perf_counter()

            # Perform client-side SOCKS5 negotiation to 127.0.0.1:10807
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect(("127.0.0.1", SOCKS5_GATEWAY.bound_port))

                # Step 1: Handshake (Version 5, 1 Method, No Auth)
                s.sendall(b"\x05\x01\x00")
                ver_resp = s.recv(2)
                if len(ver_resp) < 2 or ver_resp[0] != 0x05 or ver_resp[1] != 0x00:
                    raise RuntimeError("SOCKS5 handshake authentication rejected")

                # Step 2: CONNECT via Domain (ATYP 0x03)
                d_bytes = dest_host.encode("utf-8")
                req = bytes([0x05, 0x01, 0x00, 0x03, len(d_bytes)]) + d_bytes + dest_port.to_bytes(2, "big")
                s.sendall(req)

                conn_resp = s.recv(10)
                if len(conn_resp) < 4 or conn_resp[1] != 0x00:
                    raise RuntimeError(f"SOCKS5 server returned error code: {conn_resp[1] if len(conn_resp) > 1 else 'empty'}")

                # Step 3: Send HTTP GET
                http_get = f"GET / HTTP/1.1\r\nHost: {dest_host}\r\nUser-Agent: IPVN7-SOCKS5-Tunnel/7.0\r\nConnection: close\r\n\r\n".encode("utf-8")
                s.sendall(http_get)

                data = s.recv(1024)
                s.close()
                elapsed = (time.perf_counter() - t0) * 1000.0

                self._send_json({
                    "success": True,
                    "dest_host": dest_host,
                    "dest_port": dest_port,
                    "gateway_port": SOCKS5_GATEWAY.bound_port,
                    "latency_ms": round(elapsed, 1),
                    "bytes_received": len(data),
                    "response_preview": data.decode("utf-8", errors="replace")[:400],
                    "route": f"Windows Client -> SOCKS5 (:10807) -> {PRIMARY_NODE.did[:16]}... -> {PEER_NODE.did[:16]}... -> {dest_host}:{dest_port}",
                })
            except Exception as e:
                self._send_json({
                    "success": False,
                    "error": str(e),
                    "gateway_port": SOCKS5_GATEWAY.bound_port,
                }, status=500)

        elif path == "/api/key_rotation/rekey":
            # Audit H-07: Key rotation state changes are executed strictly via POST
            res = PRIMARY_NODE.orchestrate_silent_rekey()
            self._send_json({"success": True, "result": res})

        elif path == "/api/firewall/policy":
            did = body.get("did", PEER_NODE.did)
            allow_in = bool(body.get("allow_inbound", True))
            allow_out = bool(body.get("allow_outbound", True))
            allow_relay = bool(body.get("allow_relay", False))
            ports = body.get("allowed_ports", [])
            pol = PRIMARY_NODE.authorize_peer(did, allow_in, allow_out, allow_relay)
            if ports:
                pol.allowed_ports = [int(p) for p in ports]
            self._send_json({"success": True, "policy": pol.__dict__})

        elif path == "/api/firewall/toggle_default_deny":
            enable = bool(body.get("enabled", True))
            PRIMARY_NODE.firewall.set_default_deny(enable)
            self._send_json({"success": True, "default_deny": PRIMARY_NODE.firewall.default_deny})

        elif path == "/api/wot/vouch":
            subject_did = body.get("subject_did", PEER_NODE.did)
            trust_level = float(body.get("trust_level", 0.9))
            reason = body.get("reason", "Verified Peer Identity via Post-Quantum Handshake")
            vouch = PRIMARY_NODE.vouch_peer(subject_did, trust_level, reason)
            self._send_json({
                "success": True,
                "vouch": {
                    "issuer": vouch.issuer_did,
                    "subject": vouch.subject_did,
                    "trust_level": vouch.trust_level,
                    "reason": vouch.reason,
                    "signature": vouch.signature.hex() if vouch.signature else None,
                },
                "computed_trust": PRIMARY_NODE.get_trust_score(subject_did),
            })

        elif path == "/api/dag/put":
            data_str = body.get("data", "Immutable IPVN 7 DAG Manifest")
            target_did = body.get("target_did", "")
            block = PRIMARY_NODE.put_dag_block(data_str.encode("utf-8"), target_did=target_did)
            self._send_json({
                "success": True,
                "block": block.to_dict(),
            })

        elif path == "/api/petnames/register":
            name = body.get("name", "")
            did = body.get("did", PEER_NODE.did)
            comment = body.get("comment", "Mnemonic Alias")
            if not name:
                self._send_json({"error": "Nombre requerido"}, status=400)
            else:
                rec = PRIMARY_NODE.register_petname(name, did, comment)
                self._send_json({"success": True, "record": rec.to_dict()})

        elif path == "/api/oob/sas":
            peer_pub_hex = body.get("peer_pubkey_hex", "")
            if not peer_pub_hex:
                peer_pub = PEER_NODE.identity.keypair.ed25519_pub.public_bytes_raw()
            else:
                try:
                    peer_pub = bytes.fromhex(peer_pub_hex)
                except Exception:
                    peer_pub = PEER_NODE.identity.keypair.ed25519_pub.public_bytes_raw()

            sas = PRIMARY_NODE.compute_oob_sas(peer_pub)
            self._send_json({
                "success": True,
                "digits": sas.digits,
                "emojis": sas.emojis,
                "auth_string": sas.auth_string,
            })

        elif path == "/api/services/request":
            svc_name = body.get("name", "chat_e2ee")
            scope_str = body.get("scope", "LOCAL").upper()
            try:
                scope = ServiceScope[scope_str]
            except KeyError:
                scope = ServiceScope.LOCAL
            svc = PRIMARY_NODE.services.request_service(svc_name, scope)
            self._send_json({
                "success": True,
                "service": svc.to_dict(),
                "active_services_count": len(PRIMARY_NODE.services.get_active_services()),
            })

        elif path == "/api/accounting/record":
            did = body.get("did", PEER_NODE.did)
            direction = body.get("direction", "tx")
            bytes_val = int(body.get("bytes", 1024))
            if direction == "rx":
                tier = PRIMARY_NODE.accounting.record_rx(did, bytes_val)
            else:
                tier = PRIMARY_NODE.accounting.record_tx(did, bytes_val)
            self._send_json({
                "success": True,
                "did": did,
                "direction": direction,
                "bytes": bytes_val,
                "tier": tier.value,
                "account": PRIMARY_NODE.accounting.get_peer_account(did),
            })

        elif path == "/api/tls/camouflage":
            action = body.get("action", "wrap")
            if action == "client_hello":
                sni = body.get("sni", "gateway.cloudflare.com")
                raw_ch = PRIMARY_NODE.tls_obfuscator.build_client_hello(sni)
                self._send_json({
                    "success": True,
                    "action": "client_hello",
                    "sni": sni,
                    "length": len(raw_ch),
                    "sample_hex": raw_ch[:32].hex() + "...",
                })
            else:
                payload_str = body.get("payload", "QUANTUM_PAYLOAD")
                wrapped = PRIMARY_NODE.build_tls_camouflaged_packet(payload_str.encode("utf-8"))
                self._send_json({
                    "success": True,
                    "action": "wrap",
                    "length": len(wrapped),
                    "header_hex": wrapped[:5].hex(),
                    "record_type": "ApplicationData (0x17)",
                    "sample_hex": wrapped[:20].hex() + "...",
                })

        elif path == "/api/rendezvous/publish":
            ring = int(body.get("ring_degree", 1))
            ep = body.get("endpoint", f"127.0.0.1:{PRIMARY_NODE.bound_port}")
            topic = PRIMARY_NODE.publish_blind_beacon(ep, ring_degree=ring)
            self._send_json({
                "success": bool(topic),
                "topic_id": topic,
                "endpoint": ep,
                "circuit_breaker_tripped": PRIMARY_NODE.blind_rendezvous.circuit_breaker_tripped,
            })

        elif path == "/api/rendezvous/discover":
            ring = int(body.get("ring_degree", 1))
            found = PRIMARY_NODE.discover_blind_beacon(ring_degree=ring)
            self._send_json({
                "success": found is not None,
                "beacon": found,
            })

        elif path == "/api/routing/explain":
            target = body.get("target_did", PEER_NODE.did)
            raw_cands = body.get("candidates", [])
            if not raw_cands:
                raw_cands = [
                    {"peer_did": PEER_NODE.did, "latency_ms": 12.5, "rfc3550_jitter_ms": 1.2, "packet_loss_pct": 0.0, "battery_pct": 95, "trust_tier": 4},
                    {"peer_did": "did:ipvn7:zNeighborAlternative", "latency_ms": 18.0, "rfc3550_jitter_ms": 3.4, "packet_loss_pct": 1.5, "battery_pct": 60, "trust_tier": 2},
                ]
            candidates = [
                CandidateMetrics(
                    peer_did=c["peer_did"],
                    latency_ms=float(c.get("latency_ms", 10.0)),
                    rfc3550_jitter_ms=float(c.get("rfc3550_jitter_ms", 1.0)),
                    packet_loss_pct=float(c.get("packet_loss_pct", 0.0)),
                    battery_pct=int(c.get("battery_pct", 100)),
                    trust_tier=int(c.get("trust_tier", 1)),
                )
                for c in raw_cands
            ]
            explanation = PRIMARY_NODE.explain_route_selection(target, candidates)
            self._send_json({"success": True, "explanation": explanation.to_dict()})

        elif path == "/api/diagnostics/spectral":
            signal = [float(x) for x in body.get("signal", [10.0, 15.0, 10.0, 15.0, 10.0, 15.0, 10.0, 15.0])]
            rate = float(body.get("sampling_rate_hz", 100.0))
            analysis = PRIMARY_NODE.analyze_spectral_jitter(signal, sampling_rate_hz=rate)
            self._send_json({"success": True, "analysis": analysis.to_dict()})

        elif path == "/api/antireplay/check":
            seq = int(body.get("sequence_number", 1))
            valid = PRIMARY_NODE.validate_packet_replay(seq)
            self._send_json({
                "sequence_number": seq,
                "is_valid": valid,
                "stats": PRIMARY_NODE.anti_replay.get_stats(),
            })

        elif path == "/api/delegation/create":
            subject_did = body.get("subject_did", PEER_NODE.did)
            scope = body.get("scope", "route_traffic")
            tier_str = body.get("tier", "ordinary").lower()
            try:
                tier = ExecutionTier(tier_str)
            except ValueError:
                tier = ExecutionTier.ORDINARY
            ttl = float(body.get("ttl_seconds", 3600.0))
            link = PRIMARY_NODE.create_delegation_link(subject_did, scope, tier=tier, ttl_seconds=ttl)
            self._send_json({
                "success": True,
                "link": link.to_dict(),
            })

        elif path == "/api/planetary/route":
            src = body.get("src", "sat-000")
            dst = body.get("dst", "sat-015")
            try:
                res = PRIMARY_NODE.route_planetary_packet(src, dst)
                self._send_json({"success": True, "route": res})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/darknode/toggle":
            new_status = PRIMARY_NODE.toggle_dark_node_mode()
            self._send_json({"success": True, "dark_node": new_status})

        elif path == "/api/silent/call":
            target = body.get("target_did", PEER_NODE.did)
            payload_str = body.get("payload", "Directed Silent Call")
            try:
                res = PRIMARY_NODE.send_silent_call(target, payload_str.encode("utf-8"))
                self._send_json({"success": True, "result": res})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/healing/probe":
            peer_did = body.get("peer_did", PEER_NODE.did)
            success = bool(body.get("success", True))
            latency = float(body.get("latency_ms", 12.0))
            failover, alt_did = PRIMARY_NODE.record_link_probe(peer_did, success, latency)
            health = PRIMARY_NODE.link_healing.get_peer_health(peer_did)
            self._send_json({
                "success": True,
                "peer_did": peer_did,
                "failover_triggered": failover,
                "alternative_peer": alt_did,
                "health": health,
            })

        elif path == "/api/blackout/advance":
            status = PRIMARY_NODE.advance_blackout_phase()
            self._send_json({"success": True, "status": status})

        elif path == "/api/chat/send":
            target = body.get("target_did", PEER_NODE.did)
            text = body.get("text", "")
            sender = body.get("sender_name", "Este Nodo")
            try:
                msg_dict = PRIMARY_NODE.send_chat_message(target, text, sender_name=sender)
                self._send_json({"success": True, "message": msg_dict})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/mobility/update":
            node_did = body.get("node_did", PEER_NODE.did)
            physical_ip = body.get("physical_ip", "192.168.1.106")
            physical_port = int(body.get("physical_port", 9443))
            seq = int(body.get("seq", 1))
            ticket_hex = body.get("ticket_hex", "")
            ticket = bytes.fromhex(ticket_hex) if ticket_hex else None
            cold_nonce = int(body.get("cold_nonce", 0))
            try:
                loc = PRIMARY_NODE.update_mobility_locator(
                    node_did=node_did,
                    physical_ip=physical_ip,
                    physical_port=physical_port,
                    seq=seq,
                    challenge_ticket=ticket,
                    cold_nonce=cold_nonce,
                )
                self._send_json({"success": True, "locator": loc})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/copilot/cycle":
            lat = float(body.get("latency_ms", 12.0))
            drops = int(body.get("firewall_drops", 0))
            p_did = body.get("peer_did", PEER_NODE.did)
            entropy = float(body.get("spectral_entropy", 1.0))
            flapping = bool(body.get("is_flap_damped", False))
            res = PRIMARY_NODE.run_copilot_cycle(
                latency_ms=lat,
                firewall_drops=drops,
                peer_did=p_did,
                spectral_entropy=entropy,
                is_flap_damped=flapping,
            )
            self._send_json({"success": True, "result": res})

        elif path == "/api/multipath/schedule":
            payload_str = body.get("payload", "Multipath Striped Payload")
            is_crit = bool(body.get("is_critical", False))
            strat_str = body.get("strategy")
            if strat_str:
                from ipvn7.network.multipath import MultipathStrategy
                try:
                    PRIMARY_NODE.multipath.set_strategy(MultipathStrategy[strat_str.upper()])
                except KeyError:
                    pass
            paths = PRIMARY_NODE.schedule_multipath_packet(payload_str.encode("utf-8"), is_critical=is_crit)
            self._send_json({
                "success": True,
                "strategy": PRIMARY_NODE.multipath.strategy.value,
                "is_critical": is_crit,
                "selected_paths": paths,
            })

        elif path == "/api/dns/resolve":
            domain = body.get("domain", "gateway.ipv7")
            res = PRIMARY_NODE.resolve_sovereign_domain(domain)
            self._send_json({"success": res["success"], "result": res})

        elif path == "/api/nat/punch":
            peer_did = body.get("peer_did", PEER_NODE.did)
            peer_ip = body.get("peer_public_ip", "127.0.0.1")
            peer_port = int(body.get("peer_public_port", 9443))
            res = PRIMARY_NODE.punch_nat_hole(peer_did, peer_ip, peer_port)
            self._send_json({"success": True, "result": res})

        elif path == "/api/memory/reserve":
            b_class = body.get("budget_class", "replay")
            n_bytes = int(body.get("num_bytes", 1024))
            res = PRIMARY_NODE.allocate_memory_budget(b_class, n_bytes)
            self._send_json({"success": res["allowed"], "result": res})

        elif path == "/api/uin/bind":
            sub_pub = body.get("subordinate_pubkey_hex", "")
            if not sub_pub:
                import os
                sub_pub = os.urandom(32).hex()
            scope = int(body.get("scope", 0))
            duration = float(body.get("duration_seconds", 86400.0))
            res = PRIMARY_NODE.issue_uin_binding(sub_pub, scope=scope, duration_seconds=duration)
            self._send_json({"success": True, "result": res})

        elif path == "/api/shadow/register":
            name = body.get("name", "Local-Printer")
            phys_ip = body.get("physical_ip", "192.168.1.50")
            mac = body.get("mac", "00:11:22:33:44:55")
            dtype = body.get("device_type", "generic")
            ports = body.get("allowed_ports", [80, 443])
            res = PRIMARY_NODE.register_shadow_device(name, phys_ip, mac, device_type=dtype, allowed_ports=ports)
            self._send_json({"success": True, "result": res})

        elif path == "/api/wan/probe":
            peer_did = body.get("peer_did", PEER_NODE.did)
            ep = body.get("endpoint", f"127.0.0.1:{PEER_NODE.bound_port}")
            rtt = body.get("simulated_rtt_ms")
            res = PRIMARY_NODE.probe_wan_link(peer_did, endpoint=ep, simulated_rtt_ms=rtt)
            self._send_json({"success": True, "result": res})

        elif path == "/api/remote_desktop/input":
            evt_type = body.get("event_type", "mouse_move")
            x = float(body.get("x", 0.0))
            y = float(body.get("y", 0.0))
            k = body.get("key", "")
            res = PRIMARY_NODE.dispatch_remote_input(evt_type, x=x, y=y, key=k)
            self._send_json({"success": True, "result": res})

        elif path == "/api/key_rotation/rotate":
            res = PRIMARY_NODE.rotate_session_key()
            self._send_json({"success": True, "result": res})

        elif path == "/api/upnp/map":
            port = int(body.get("port", 7001))
            desc = body.get("description", "ipvn7-p2p")
            res = PRIMARY_NODE.map_upnp_port(port, desc=desc)
            self._send_json({"success": True, "result": res})

        elif path == "/api/censorship/audit":
            domain = body.get("domain", "cloudflare.com")
            inc = PRIMARY_NODE.censorship_detector.check_dns_integrity(domain)
            self._send_json({
                "success": True,
                "domain": domain,
                "incident_detected": inc is not None,
                "incident": inc.to_dict() if inc else None,
                "summary": PRIMARY_NODE.censorship_detector.get_summary(),
            })

        elif path == "/api/remote_desktop/media_frame":
            frame_type = body.get("frame_type", "video_delta")
            raw_hex = body.get("raw_data_hex")
            codec = body.get("codec", "av1")
            res = PRIMARY_NODE.dispatch_remote_media_frame(frame_type=frame_type, raw_data_hex=raw_hex, codec=codec)
            self._send_json({"success": True, "result": res})

        elif path == "/api/edge_ai/prompt":
            prompt = body.get("prompt", "¿Cuál es el principio ontológico de IPVN 7?")
            did_or_vip = body.get("did_or_vip", "")
            model = body.get("model", "llama3")
            res = PRIMARY_NODE.dispatch_edge_ai_prompt(did_or_vip=did_or_vip, prompt=prompt, model=model)
            self._send_json({"success": True, "result": res})

        elif path == "/api/bitnet/infer":
            x = body.get("x", [0.5, -0.2, 0.8, -0.9])
            weights = body.get("weights", [[0.4, -0.1, 0.7, -0.8], [-0.5, 0.2, -0.3, 0.9]])
            bias = body.get("bias")
            model_name = body.get("model_name", "iot-edge-worker")
            res = PRIMARY_NODE.execute_bitnet_forward(x, weights, bias=bias, model_name=model_name)
            self._send_json({"success": True, "result": res})

        elif path == "/api/dht/sync":
            peer_reg = body.get("peer_region", "region-europe-central")
            res = PRIMARY_NODE.sync_interregion_dht(peer_region=peer_reg)
            self._send_json({"success": True, "result": res})

        elif path == "/api/tunnel/telemetry/probe":
            tid = body.get("tunnel_id", "tun0-wintun")
            rtt = float(body.get("sample_rtt_ms", 12.5))
            lost = bool(body.get("packet_lost", False))
            pmtu_sz = body.get("pmtu_probe_size")
            if pmtu_sz is not None:
                pmtu_sz = int(pmtu_sz)
            pmtu_ok = bool(body.get("pmtu_probe_success", True))
            res = PRIMARY_NODE.probe_tunnel_telemetry(
                tunnel_id=tid,
                sample_rtt_ms=rtt,
                packet_lost=lost,
                pmtu_probe_size=pmtu_sz,
                pmtu_probe_success=pmtu_ok,
            )
            self._send_json({"success": True, "result": res})

        elif path == "/api/settlement/issue":
            ben_did = body.get("beneficiary_did", PEER_NODE.did)
            credits_val = int(body.get("bandwidth_credits", 1048576))
            try:
                res = PRIMARY_NODE.issue_reciprocity_token(ben_did, credits_val)
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/settlement/settle":
            token_dict = body.get("token")
            if not token_dict:
                self._send_json({"success": False, "error": "Missing token payload"}, status=400)
                return
            pub_hex = body.get("issuer_pubkey_hex")
            if pub_hex:
                pub_bytes = bytes.fromhex(pub_hex)
            elif token_dict.get("issuer_did") == PRIMARY_NODE.did:
                pub_bytes = PRIMARY_NODE.identity.keypair.ed25519_pub.public_bytes_raw()
            else:
                pub_bytes = PEER_NODE.identity.keypair.ed25519_pub.public_bytes_raw()
            res = PRIMARY_NODE.settle_reciprocity_token(token_dict, pub_bytes)
            if body.get("remediate_quota", False) and res.get("success"):
                rem = PRIMARY_NODE.remediate_quota_with_reciprocity(token_dict.get("beneficiary_did", PRIMARY_NODE.did))
                res["remediation"] = rem
            self._send_json(res)

        elif path == "/api/tee/attest":
            nonce = body.get("challenge_nonce", "")
            rep = PRIMARY_NODE.attest_enclave(challenge_nonce=nonce)
            self._send_json({"success": True, "report": rep})

        elif path == "/api/tee/verify_attestation":
            rep_dict = body.get("report")
            if not rep_dict:
                self._send_json({"success": False, "error": "Missing 'report' payload"}, status=400)
                return
            expected_nonce = body.get("challenge_nonce")
            valid, reason = PRIMARY_NODE.verify_enclave_attestation(rep_dict, expected_nonce=expected_nonce)
            self._send_json({"success": True, "valid": valid, "reason": reason})

        elif path == "/api/enclave/frame":
            action = body.get("action", "encode")
            if action == "encode":
                opcode = body.get("opcode", "OP_ATTESTATION_CHALLENGE")
                payload = body.get("payload", {})
                raw_bytes = PRIMARY_NODE.dispatch_enclave_frame(opcode, payload)
                self._send_json({
                    "success": True,
                    "frame_hex": raw_bytes.hex(),
                    "frame_len": len(raw_bytes),
                    "mtu_valid": len(raw_bytes) <= 1280,
                })
            else:
                raw_hex = body.get("raw_frame_hex", "")
                if not raw_hex:
                    self._send_json({"success": False, "error": "Missing raw_frame_hex"}, status=400)
                    return
                parsed_frame = PRIMARY_NODE.parse_enclave_frame(bytes.fromhex(raw_hex))
                self._send_json({"success": True, "parsed": parsed_frame})

        elif path == "/api/zkp/schnorr/prove":
            from ipvn7.crypto.zkp import SovereignZKSchnorr
            sk_hex = body.get("sk_hex")
            pk_hex = body.get("pk_hex")
            ctx = body.get("context", "web-dashboard")
            if not sk_hex or not pk_hex:
                x, Y = SovereignZKSchnorr.keygen()
            else:
                x, Y = int(sk_hex, 16), int(pk_hex, 16)
            proof = SovereignZKSchnorr.prove(x, Y, context=ctx)
            wire = SovereignZKSchnorr.to_wire(proof)
            self._send_json({
                "success": True,
                "pk_hex": hex(Y),
                "wire_hex": wire.hex(),
                "wire_len": len(wire),
                "mtu_valid": len(wire) <= 1280,
                "proof": proof.to_dict(),
            })

        elif path == "/api/zkp/schnorr/verify":
            from ipvn7.crypto.zkp import SovereignZKSchnorr, ZKSchnorrProof
            wire_hex = body.get("wire_hex")
            if wire_hex:
                wire = bytes.fromhex(wire_hex)
                proof = SovereignZKSchnorr.from_wire(wire)
            else:
                proof_dict = body.get("proof", {})
                proof = ZKSchnorrProof.from_dict(proof_dict)
            valid = SovereignZKSchnorr.verify(proof)
            self._send_json({"success": True, "valid": valid, "pk_hex": proof.pk_hex})

        elif path == "/api/zkp/range/prove":
            from ipvn7.crypto.zkp import SovereignBulletproof
            val = int(body.get("value", 42))
            n_bits = int(body.get("n_bits", 8))
            ctx = body.get("context", "balance-proof")
            engine = SovereignBulletproof(n_bits=n_bits)
            try:
                proof = engine.prove(val, context=ctx)
                wire = SovereignBulletproof.to_wire(proof)
                self._send_json({
                    "success": True,
                    "commitment_hex": proof.commitment_hex,
                    "wire_hex": wire.hex(),
                    "wire_len": len(wire),
                    "mtu_valid": len(wire) <= 1280,
                    "n_bits": n_bits,
                })
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/zkp/range/verify":
            from ipvn7.crypto.zkp import SovereignBulletproof
            wire_hex = body.get("wire_hex")
            n_bits = int(body.get("n_bits", 8))
            engine = SovereignBulletproof(n_bits=n_bits)
            if not wire_hex:
                self._send_json({"success": False, "error": "Missing wire_hex"}, status=400)
                return
            proof = SovereignBulletproof.from_wire(bytes.fromhex(wire_hex))
            valid = engine.verify(proof)
            self._send_json({
                "success": True,
                "valid": valid,
                "commitment_hex": proof.commitment_hex,
                "n_bits": proof.n_bits,
            })

        elif path == "/api/ring/sign":
            from ipvn7.security.ring_signature import SovereignRingSignature, RingMember
            msg = body.get("message", "IPVN7_ANONYMOUS_VOTE").encode("utf-8")
            ring_size = max(2, min(8, int(body.get("ring_size", 4))))
            members = [RingMember.generate() for _ in range(ring_size)]
            signer_idx = int(body.get("signer_index", 0)) % ring_size
            signer = members[signer_idx]
            epoch = body.get("epoch", "2026-10-21:00")
            ctx = body.get("ring_context", "GOVERNANCE_VOTE")
            sig = SovereignRingSignature.sign(msg, signer, members, epoch=epoch, ring_context=ctx)
            wire = SovereignRingSignature.to_wire(sig)
            self._send_json({
                "success": True,
                "wire_hex": wire.hex(),
                "wire_len": len(wire),
                "mtu_valid": len(wire) <= 1280,
                "ring_pks": sig.ring_pks,
                "key_image_hex": sig.key_image_hex,
                "epoch": sig.epoch,
            })

        elif path == "/api/ring/verify":
            from ipvn7.security.ring_signature import SovereignRingSignature
            wire_hex = body.get("wire_hex")
            msg = body.get("message", "IPVN7_ANONYMOUS_VOTE").encode("utf-8")
            if not wire_hex:
                self._send_json({"success": False, "error": "Missing wire_hex"}, status=400)
                return
            sig = SovereignRingSignature.from_wire(bytes.fromhex(wire_hex))
            valid = SovereignRingSignature.verify(sig, msg)
            self._send_json({
                "success": True,
                "valid": valid,
                "key_image_hex": sig.key_image_hex,
                "ring_size": len(sig.ring_pks),
                "epoch": sig.epoch,
            })

        elif path == "/api/xdp/filter":
            frame_hex = body.get("frame_hex")
            payload_hex = body.get("payload_hex")
            if frame_hex:
                frame_bytes = bytes.fromhex(frame_hex)
                action, reason = PRIMARY_NODE.process_xdp_frame(frame_bytes)
                self._send_json({
                    "success": True,
                    "action": action.name,
                    "action_code": int(action),
                    "reason": reason,
                    "frame_len": len(frame_bytes),
                    "stats": PRIMARY_NODE.get_xdp_stats(),
                })
            elif payload_hex:
                payload_bytes = bytes.fromhex(payload_hex)
                action, reason = PRIMARY_NODE.process_xdp_payload(payload_bytes)
                self._send_json({
                    "success": True,
                    "action": action.name,
                    "action_code": int(action),
                    "reason": reason,
                    "payload_len": len(payload_bytes),
                    "stats": PRIMARY_NODE.get_xdp_stats(),
                })
            else:
                self._send_json({"success": False, "error": "Requiere 'frame_hex' o 'payload_hex'"}, status=400)

        elif path == "/api/xdp/reset":
            PRIMARY_NODE.reset_xdp_stats()
            self._send_json({"success": True, "stats": PRIMARY_NODE.get_xdp_stats()})

        elif path == "/api/xdp/synthesize":
            magic_str = body.get("magic", "IP7H")
            size = int(body.get("payload_size", 64))
            from ipvn7.access.xdp_switch import XDPKernelSimulator
            payload = magic_str.encode("ascii") + b"\x00" * max(0, size - len(magic_str))
            frame = XDPKernelSimulator.synthesize_ethernet_frame(payload)
            action, reason = PRIMARY_NODE.process_xdp_frame(frame)
            self._send_json({
                "success": True,
                "magic": magic_str,
                "frame_hex": frame.hex(),
                "frame_len": len(frame),
                "action": action.name,
                "action_code": int(action),
                "reason": reason,
                "stats": PRIMARY_NODE.get_xdp_stats(),
            })

        elif path == "/api/mode/set":
            mode_str = body.get("mode")
            if not mode_str:
                self._send_json({"success": False, "error": "Requiere campo 'mode' (MODE_OPEN, MODE_SAFE, MODE_DEGRADED)"}, status=400)
                return
            reason = body.get("reason", "api_request")
            try:
                status = PRIMARY_NODE.set_operating_mode(mode_str, reason=reason)
                self._send_json({"success": True, "status": status})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/mode/evaluate":
            loss_pct = float(body.get("loss_pct", 0.0))
            drop_ratio_pct = float(body.get("drop_ratio_pct", 0.0))
            buffer_util_pct = float(body.get("buffer_util_pct", 0.0))
            status = PRIMARY_NODE.evaluate_operating_health(loss_pct, drop_ratio_pct, buffer_util_pct)
            self._send_json({"success": True, "status": status})

        elif path == "/api/ota/package":
            mod_name = body.get("module_name")
            ver = body.get("version", "1.0.0")
            code_str = body.get("code")
            target = body.get("target_subsystem", "custom")
            if not mod_name or not code_str:
                self._send_json({"success": False, "error": "Requiere 'module_name' y 'code'"}, status=400)
                return
            try:
                res = PRIMARY_NODE.package_ota_module(
                    module_name=mod_name,
                    version=ver,
                    code_str=code_str,
                    target_subsystem=target,
                )
                self._send_json({"success": True, "manifest": res})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/ota/install":
            manifest_dict = body.get("manifest")
            exp_class = body.get("expected_class")
            if not manifest_dict:
                self._send_json({"success": False, "error": "Requiere 'manifest' dict"}, status=400)
                return
            try:
                res = PRIMARY_NODE.install_ota_module(manifest_dict, expected_class_name=exp_class)
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif path == "/api/ota/rollback":
            mod_name = body.get("module_name")
            if not mod_name:
                self._send_json({"success": False, "error": "Requiere 'module_name'"}, status=400)
                return
            reason = body.get("reason", "api_request")
            res = PRIMARY_NODE.rollback_ota_module(mod_name, reason=reason)
            self._send_json(res)

        elif path in ("/api/mcp", "/mcp"):
            # Audit H-03: Mandatory authentication for MCP JSON-RPC control plane
            auth_ok, auth_reason = self._validate_control_auth()
            if not auth_ok:
                req_id = body.get("id") if isinstance(body, dict) else None
                self._send_json({
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": auth_reason},
                    "id": req_id
                }, status=401)
                return

            rpc_response = PRIMARY_NODE.mcp_server.handle_jsonrpc(body)
            self._send_json(rpc_response)

        else:
            self._send_json({"error": "Endpoint not found"}, status=404)


def run_server(port: int = 7070):
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, IPVN7DashboardHandler)
    print(f"[IPVN 7 Web Dashboard] Server running at http://127.0.0.1:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    run_server(7070)
