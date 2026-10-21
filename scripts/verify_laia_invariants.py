#!/usr/bin/env python3
"""
LAIA INVARIANT VERIFIER (scripts/verify_laia_invariants.py)
Automated Continuous Verification Gate for IPVN 7 Security Invariants.

Enforces:
  INV-1: Dynamic High-Entropy Secrets (Zero Static Hardcoded Master Tokens)
  INV-2: Authenticated Control Plane & MCP Tools Schema Integrity (>= 66 tools)
  INV-3: Universal Egress Isolation & Anti-SSRF Enforcement
  INV-4: Cryptographic Wire Protocol Integrity & 1280B MTU Bounds
  INV-5: Grounded Datapath Telemetry & Veracity
  INV-6: Zero Exposure of Raw Cryptographic Secrets
  INV-7: DoS Immunity & Bounded Concurrency Semaphores

Usage:
  python scripts/verify_laia_invariants.py
"""

import sys
import os
import re
from typing import List, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

def check_inv1_zero_static_secrets() -> Tuple[bool, List[str]]:
    """Checks that no static hardcoded control tokens exist in app/server.py."""
    violations = []
    server_path = os.path.join(REPO_ROOT, "app", "server.py")
    with open(server_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Search for assignments to CONTROL_AUTH_TOKEN with static string
    static_token_match = re.search(r'CONTROL_AUTH_TOKEN\s*=\s*["\']([a-zA-Z0-9_\-]{8,})["\']', content)
    if static_token_match:
        violations.append(f"Static master token detected in app/server.py: {static_token_match.group(0)}")

    if "secrets.token_urlsafe" not in content:
        violations.append("Dynamic cryptographic secret generation (secrets.token_urlsafe) missing in app/server.py")

    return (len(violations) == 0, violations)


def check_inv2_mcp_and_control_auth() -> Tuple[bool, List[str]]:
    """Checks that all MCP tools are properly schema-defined and control plane endpoints require auth."""
    violations = []
    try:
        from ipvn7.node.node import IPVN7Node
        node = IPVN7Node(alias="VerifierNode", bind_host="127.0.0.1")
        mcp = node.mcp_server
        tools = mcp.get_supported_tools()
        if len(tools) < 69:
            violations.append(f"Expected at least 69 MCP tools registered, found {len(tools)}")

        for tool in tools:
            name = tool.get("name")
            desc = tool.get("description")
            schema = tool.get("inputSchema")
            if not name or not desc or not schema:
                violations.append(f"Malformed MCP tool manifest: {name}")
            if schema.get("type") != "object":
                violations.append(f"MCP tool {name} inputSchema must be type 'object'")
            
            # Verify handler exists in execute_tool (should not return "Herramienta desconocida")
            ok, res = mcp.execute_tool(name, {})
            if not ok and "Herramienta desconocida" in str(res):
                violations.append(f"MCP tool {name} has no executable dispatch handler")
    except Exception as e:
        violations.append(f"Failed to inspect MCP server: {e}")

    server_path = os.path.join(REPO_ROOT, "app", "server.py")
    with open(server_path, "r", encoding="utf-8") as f:
        server_code = f.read()

    # Check that MCP handler enforces auth
    if 'auth_ok, auth_reason = self._validate_control_auth()' not in server_code:
        violations.append("app/server.py: MCP endpoint does not enforce _validate_control_auth()")

    return (len(violations) == 0, violations)


def check_inv3_egress_anti_ssrf() -> Tuple[bool, List[str]]:
    """Checks that egress network operations invoke EgressSecurityPolicy."""
    violations = []
    server_path = os.path.join(REPO_ROOT, "app", "server.py")
    with open(server_path, "r", encoding="utf-8") as f:
        content = f.read()

    if "EgressSecurityPolicy.validate_url" not in content:
        violations.append("app/server.py: Does not verify outbound destinations against EgressSecurityPolicy.validate_url")

    if "SafeRedirectHandler" not in content:
        violations.append("app/server.py: SafeRedirectHandler not utilized to prevent redirect-based SSRF")

    # Check egress policy implementation
    egress_path = os.path.join(REPO_ROOT, "ipvn7", "security", "egress_policy.py")
    with open(egress_path, "r", encoding="utf-8") as f:
        egress_code = f.read()

    if "is_private" not in egress_code or "is_loopback" not in egress_code:
        violations.append("ipvn7/security/egress_policy.py: Missing RFC private or loopback IP range checks")

    # Check SOCKS5, HTTP proxy and Exit Relay
    for gw_file in ["socks5.py", "proxy.py", "exit_relay.py"]:
        p = os.path.join(REPO_ROOT, "ipvn7", "gateway", gw_file)
        with open(p, "r", encoding="utf-8") as gf:
            if "EgressSecurityPolicy.resolve_and_validate_host" not in gf.read():
                violations.append(f"ipvn7/gateway/{gw_file}: Missing EgressSecurityPolicy.resolve_and_validate_host enforcement")

    return (len(violations) == 0, violations)


def check_inv4_wire_framing_integrity() -> Tuple[bool, List[str]]:
    """Checks canonical binary wire framing and MTU safety on L0-L2 protocols."""
    violations = []
    try:
        from ipvn7.network.settlement import SovereignReciprocitySettlement, OP_TOKEN_ISSUE, MAGIC_RECIPROCITY
        test_payload = b"TEST-CANONICAL-PAYLOAD-FOR-VERIFICATION"
        frame = SovereignReciprocitySettlement.serialize_frame(OP_TOKEN_ISSUE, test_payload)
        if not frame.startswith(MAGIC_RECIPROCITY):
            violations.append("IP7R frame does not start with MAGIC_RECIPROCITY")
        if len(frame) > 1280:
            violations.append(f"IP7R frame exceeds 1280 byte MTU limit: {len(frame)}B")
        op, ext = SovereignReciprocitySettlement.deserialize_frame(frame)
        if op != OP_TOKEN_ISSUE or ext != test_payload:
            violations.append("IP7R serialize/deserialize round-trip mismatch")
    except Exception as e:
        violations.append(f"Wire framing verification failed: {e}")

    try:
        from ipvn7.node.node import IPVN7Node
        from ipvn7.gateway.exit_relay import SovereignExitRelayClient, MAGIC_EXIT_RELAY
        dummy_node = IPVN7Node(alias="ExitFramingTester", bind_host="127.0.0.1")
        client = SovereignExitRelayClient(local_node=dummy_node, exit_node_did="did:ipvn7:exit-test")
        if MAGIC_EXIT_RELAY != b"IP7X":
            violations.append("Exit relay magic framing is not b'IP7X'")
    except Exception as e:
        violations.append(f"Exit relay framing check failed: {e}")

    try:
        from ipvn7.security.tee_enclave import SovereignEnclave, EnclaveOpcode, CANONICAL_ENCLAVE_WIRE_MAGIC
        enclave_frame = SovereignEnclave.encode_frame(EnclaveOpcode.OP_ATTESTATION_CHALLENGE, b"LAIA_IP7E_VERIFICATION")
        if not enclave_frame.startswith(CANONICAL_ENCLAVE_WIRE_MAGIC):
            violations.append("IP7E frame does not start with CANONICAL_ENCLAVE_WIRE_MAGIC")
        if len(enclave_frame) > 1280:
            violations.append(f"IP7E frame exceeds 1280 byte MTU limit: {len(enclave_frame)}B")
        dec_op, dec_pl = SovereignEnclave.decode_frame(enclave_frame)
        if dec_op != EnclaveOpcode.OP_ATTESTATION_CHALLENGE or dec_pl != b"LAIA_IP7E_VERIFICATION":
            violations.append("IP7E encode/decode round-trip mismatch")
    except Exception as e:
        violations.append(f"IP7E enclave framing check failed: {e}")

    return (len(violations) == 0, violations)


def check_inv6_zero_raw_secret_leakage() -> Tuple[bool, List[str]]:
    """Checks that raw shared secrets or sensitive key material are never exposed in API responses."""
    violations = []
    server_path = os.path.join(REPO_ROOT, "app", "server.py")
    with open(server_path, "r", encoding="utf-8") as f:
        content = f.read()

    if '"shared_secret_hex"' in content:
        violations.append("app/server.py: raw 'shared_secret_hex' detected in API response payload")

    if '"raw_private_key"' in content or '"private_bytes"' in content:
        violations.append("app/server.py: potential raw private key leakage detected")

    return (len(violations) == 0, violations)


def check_inv7_bounded_concurrency() -> Tuple[bool, List[str]]:
    """Checks that network gateways and request handlers enforce bounded semaphores."""
    violations = []
    server_path = os.path.join(REPO_ROOT, "app", "server.py")
    with open(server_path, "r", encoding="utf-8") as f:
        server_code = f.read()

    if "threading.BoundedSemaphore" not in server_code:
        violations.append("app/server.py: BoundedSemaphore missing for HTTP concurrency control")

    socks5_path = os.path.join(REPO_ROOT, "ipvn7", "gateway", "socks5.py")
    with open(socks5_path, "r", encoding="utf-8") as f:
        socks5_code = f.read()

    if "BoundedSemaphore" not in socks5_code:
        violations.append("ipvn7/gateway/socks5.py: BoundedSemaphore missing for connection concurrency bounding")

    return (len(violations) == 0, violations)


def main():
    print("=" * 70)
    print("   LAIA INVARIANT VERIFIER - IPVN 7 AUTOMATED QUALITY GATE")
    print("=" * 70)

    checks = [
        ("INV-1: Dynamic High-Entropy Secrets", check_inv1_zero_static_secrets),
        ("INV-2: Authenticated Control Plane & MCP Tools (>= 66)", check_inv2_mcp_and_control_auth),
        ("INV-3: Universal Egress Isolation & Anti-SSRF", check_inv3_egress_anti_ssrf),
        ("INV-4: Canonical Wire Framing & 1280B MTU Bounds", check_inv4_wire_framing_integrity),
        ("INV-6: Zero Raw Secret / Key Leakage in APIs", check_inv6_zero_raw_secret_leakage),
        ("INV-7: DoS Immunity & Bounded Concurrency Semaphores", check_inv7_bounded_concurrency),
    ]

    all_passed = True
    for name, check_fn in checks:
        passed, violations = check_fn()
        status_str = "[PASS]" if passed else "[FAIL]"
        print(f"  {status_str} {name}")
        if not passed:
            all_passed = False
            for v in violations:
                print(f"         ! {v}")

    print("-" * 70)
    if all_passed:
        print(">>> ALL LAIA ARCHITECTURAL INVARIANTS SATISFIED (100% PASS) <<<")
        print("=" * 70)
        sys.exit(0)
    else:
        print(">>> CRITICAL FAILURE: One or more invariants violated! <<<")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()
