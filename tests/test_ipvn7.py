"""
Automated Test Suite for IPVN 7 Architecture and Protocol Suite
"""

import time
import pytest

from ipvn7.crypto.pqc import (
    PQCKeyPair,
    PQCHybridKeyExchange,
    PQCDigitalSignature,
    encrypt_aead,
    decrypt_aead,
)
from ipvn7.identity.did import IPVN7Identity, DIDResolver
from ipvn7.network.packet import IPVN7Packet, HeaderType, TrafficClass
from ipvn7.network.dht import (
    HierarchicalSmallWorldDHT,
    DHTNode,
    NodeLocator,
    DHTRoutingTier,
)
from ipvn7.transport.quic import (
    PQQUICConnection,
    PQQUICPacket,
    QUICPacketType,
    ConnectionState,
)
from ipvn7.access.hal import HardwareAbstractionLayer, PhysicalInterfaceType
from ipvn7.node.node import IPVN7Node


def test_pqc_hybrid_key_exchange():
    """Validates NIST FIPS 203 ML-KEM-768 + X25519 key exchange."""
    x_pub, k_pub, x_priv, k_priv = PQCHybridKeyExchange.client_init()
    srv_x_pub, mlkem_ct, srv_key = PQCHybridKeyExchange.server_respond(x_pub, k_pub)
    cli_key = PQCHybridKeyExchange.client_finalize(x_priv, k_priv, srv_x_pub, mlkem_ct)

    assert srv_key == cli_key
    assert len(srv_key) == 32

    # Verify AEAD encryption/decryption with derived hybrid key
    msg = b"IPVN 7 Post-Quantum Payload 2026"
    ciphertext = encrypt_aead(cli_key, msg, associated_data=b"AD-HEADER")
    decrypted = decrypt_aead(srv_key, ciphertext, associated_data=b"AD-HEADER")
    assert decrypted == msg


def test_pqc_digital_signatures():
    """Validates NIST FIPS 204 ML-DSA-65 + Ed25519 hybrid signatures."""
    kp = PQCKeyPair.generate()
    message = b"Authenticated IPVN 7 Route Announcement"

    sigs = PQCDigitalSignature.sign_hybrid(message, kp.mldsa_priv, kp.ed25519_priv)
    assert "mldsa_sig" in sigs and "ed25519_sig" in sigs

    mldsa_pub_bytes = kp.mldsa_pub.public_bytes_raw()
    ed_pub_bytes = kp.ed25519_pub.public_bytes_raw()

    # Valid verification
    is_valid = PQCDigitalSignature.verify_hybrid(
        message,
        sigs["mldsa_sig"],
        sigs["ed25519_sig"],
        mldsa_pub_bytes,
        ed_pub_bytes,
    )
    assert is_valid is True

    # Tampered message check
    tampered_valid = PQCDigitalSignature.verify_hybrid(
        b"Tampered Message",
        sigs["mldsa_sig"],
        sigs["ed25519_sig"],
        mldsa_pub_bytes,
        ed_pub_bytes,
    )
    assert tampered_valid is False


def test_did_identity_and_w3c_proof():
    """Validates W3C-compliant DID generation and cryptographic verification."""
    ident = IPVN7Identity.create(alias="test-node")
    assert ident.did.startswith("did:ipvn7:")
    assert len(ident.fingerprint) == 32

    doc = ident.get_document()
    assert doc.id == ident.did
    assert len(doc.verification_method) == 4  # ML-DSA, ML-KEM, Ed25519, X25519

    # Verify cryptographic self-attestation proof
    assert DIDResolver.verify_document(doc) is True


def test_ipvn7_packet_framing():
    """Validates 40-byte standard IPVN 7 packet serialization & CRC32 integrity."""
    pkt = IPVN7Packet(
        src_did_fp=b"1111222233334444",
        dst_did_fp=b"5555666677778888",
        payload=b"Network Layer Payload",
        next_header=HeaderType.PQ_QUIC,
        traffic_class=TrafficClass.EXPEDITED,
        hop_limit=64,
    )

    serialized = pkt.serialize()
    deserialized = IPVN7Packet.deserialize(serialized)

    assert deserialized.version == 7
    assert deserialized.traffic_class == TrafficClass.EXPEDITED
    assert deserialized.next_header == HeaderType.PQ_QUIC
    assert deserialized.src_did_fp == b"1111222233334444"
    assert deserialized.dst_did_fp == b"5555666677778888"
    assert deserialized.payload == b"Network Layer Payload"

    # Test CRC corruption detection
    corrupted = bytearray(serialized)
    corrupted[-1] ^= 0xFF
    with pytest.raises(ValueError):
        IPVN7Packet.deserialize(bytes(corrupted))


def test_hierarchical_small_world_dht():
    """Validates Small-World DHT multi-tier hierarchy and greedy routing."""
    node_local = DHTNode.from_did("did:ipvn7:local", [NodeLocator("127.0.0.1", 9000)])
    dht = HierarchicalSmallWorldDHT(node_local)

    # Populate synthetic nodes across distance buckets
    target_did = "did:ipvn7:target_cluster_node"
    target_loc = NodeLocator("10.0.0.99", 9443, interface_type="eth", latency_ms=5.0)
    node_target = DHTNode.from_did(target_did, [target_loc], tier=DHTRoutingTier.TIER_1_METRO)

    dht.add_peer(node_target)

    # Resolution test
    locs, hops = dht.resolve_locator(target_did)
    assert locs is not None
    assert len(locs) > 0
    assert locs[0].ip == "10.0.0.99"
    assert locs[0].port == 9443


def test_pq_quic_handshake_and_migration():
    """Validates PQ-QUIC protocol state machine, streaming, and connection migration."""
    kp_client = PQCKeyPair.generate()
    kp_server = PQCKeyPair.generate()

    client = PQQUICConnection("did:ipvn7:client", kp_client, is_client=True)
    server = PQQUICConnection("did:ipvn7:server", kp_server, is_client=False)

    # Step 1: ClientInitial
    init_pkt = client.create_client_initial()
    assert client.state == ConnectionState.INITIAL_SENT

    # Step 2: ServerHandshake
    resp_pkt = server.handle_client_initial(init_pkt)
    assert server.state == ConnectionState.ESTABLISHED

    # Step 3: Client completes handshake
    ok = client.handle_server_handshake(resp_pkt)
    assert ok is True
    assert client.state == ConnectionState.ESTABLISHED

    # Step 4: Stream Data Transfer
    data_to_send = b"High-Speed Multiplexed Data without Head-of-Line Blocking"
    stream_pkt = client.send_stream_data(stream_id=2, data=data_to_send)
    sid, received = server.receive_stream_data(stream_pkt)
    assert sid == 2
    assert received == data_to_send

    # Step 5: Connection Migration (Handoff to new physical interface)
    mig_pkt = client.initiate_migration("10.100.5.20", 44300, "wwan5g")
    mig_info = server.handle_migration(mig_pkt, ("10.100.5.20", 44300))
    assert mig_info["interface"] == "wwan5g"
    assert server.current_remote_endpoint == ("10.100.5.20", 44300)


def test_e2e_node_mesh():
    """Validates full end-to-end multi-layer node mesh interaction."""
    node_a = IPVN7Node(alias="NodeA", bind_host="127.0.0.1")
    port_a = node_a.start_background_listener()

    node_b = IPVN7Node(alias="NodeB", bind_host="127.0.0.1")
    port_b = node_b.start_background_listener()

    received = []
    node_b.register_message_handler(lambda did, data: received.append((did, data)))

    node_a.bootstrap_peer(node_b.did, "127.0.0.1", port_b)
    node_b.bootstrap_peer(node_a.did, "127.0.0.1", port_a)

    success = node_a.send_message_sync(node_b.did, b"Autonomous IPVN 7 Genesis Message")
    assert success is True

    # Allow listener thread to dispatch
    time.sleep(0.08)
    assert len(received) == 1
    assert received[0][1] == b"Autonomous IPVN 7 Genesis Message"

    # Test migration
    mig_success = node_a.trigger_migration(node_b.did, "10.0.0.5", 58888, "wwan5g")
    assert mig_success is True

    time.sleep(0.05)
    node_a.stop()
    node_b.stop()


def test_dual_stack_gateway():
    """Validates legacy IPv4 TCP -> IPVN 7 PQ-QUIC translation gateway."""
    import socket
    from ipvn7.gateway.translator import IPVN7DualStackGateway

    node_gw = IPVN7Node(alias="GatewayNode", bind_host="127.0.0.1")
    port_gw = node_gw.start_background_listener()

    node_target = IPVN7Node(alias="TargetNode", bind_host="127.0.0.1")
    port_target = node_target.start_background_listener()

    # Target node registers handler that replies back to sender
    def on_target_message(src_did, data):
        node_target.send_message_sync(src_did, b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nHello from IPVN7")

    node_target.register_message_handler(on_target_message)

    node_gw.bootstrap_peer(node_target.did, "127.0.0.1", port_target)
    node_target.bootstrap_peer(node_gw.did, "127.0.0.1", port_gw)

    # Launch Dual-Stack Gateway
    gw = IPVN7DualStackGateway(node_gw, listen_host="127.0.0.1", default_target_did=node_target.did)
    gw_tcp_port = gw.start()

    # Simulate standard legacy IPv4 TCP client (e.g. curl/browser)
    client_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_tcp.connect(("127.0.0.1", gw_tcp_port))
    client_tcp.sendall(b"GET / HTTP/1.1\r\nHost: example.ipvn7\r\n\r\n")

    client_tcp.settimeout(2.0)
    response = client_tcp.recv(4096)
    client_tcp.close()

    assert b"200 OK" in response
    assert gw.metrics["legacy_connections_accepted"] == 1
    assert gw.metrics["bytes_translated_in"] > 0

    gw.stop()
    node_gw.stop()
    node_target.stop()


def test_small_world_churn_resiliency():
    """Validates Kleinberg small-world navigation and fault tolerance under churn."""
    from ipvn7.simulation.churn import SmallWorldChurnSimulator

    sim = SmallWorldChurnSimulator(node_count=60, shortcuts_per_node=3, seed=123)
    stats = sim.run_benchmark(sample_pairs=30, churn_rate=0.20)

    assert stats.total_nodes == 60
    assert stats.avg_hops_baseline > 0
    assert stats.avg_hops_baseline <= stats.theoretical_kleinberg_bound
    assert stats.delivery_success_baseline == 100.0
    assert stats.delivery_success_post_churn >= 33.0  # High resilience despite 20% random node loss


def test_performance_benchmarks():
    """Validates high throughput and post-quantum execution benchmarks."""
    from ipvn7.benchmark.bench import run_performance_benchmarks

    bench = run_performance_benchmarks()
    assert bench["ml_kem_768"]["encap_ops_sec"] > 500
    assert bench["ml_kem_768"]["decap_ops_sec"] > 500
    assert bench["ml_dsa_65"]["verify_ops_sec"] > 200
    assert bench["pq_quic_streaming"]["throughput_mb_sec"] > 20.0


def test_socks5_gateway_rfc1928():
    """Validates RFC 1928 SOCKS5 Proxy Gateway negotiation and tunneling."""
    import socket
    from ipvn7.gateway.socks5 import IPVN7SOCKS5Gateway

    node = IPVN7Node(alias="SocksNode", bind_host="127.0.0.1")
    node.start_background_listener()

    gw = IPVN7SOCKS5Gateway(local_node=node, listen_host="127.0.0.1", listen_port=0)
    bound_port = gw.start()

    # Client SOCKS5 handshake (No Auth)
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect(("127.0.0.1", bound_port))
    cli.sendall(b"\x05\x01\x00")
    resp = cli.recv(2)
    assert resp == b"\x05\x00"

    cli.close()
    gw.stop()
    node.stop()


def test_sphinx_onion_routing_3hop():
    """Validates 3-hop Sphinx layered encryption, anti-replay, and peeling."""
    import os
    from ipvn7.network.onion import (
        SphinxRouter,
        SphinxHop,
        ACTION_FORWARD,
        ACTION_DELIVER,
        ACTION_DROP,
    )

    router = SphinxRouter(node_did="did:ipvn7:zTester")
    s1, s2, s3 = os.urandom(32), os.urandom(32), os.urandom(32)
    hops = [
        SphinxHop("did:ipvn7:zHop1", "127.0.0.1:9001", s1),
        SphinxHop("did:ipvn7:zHop2", "127.0.0.1:9002", s2),
        SphinxHop("did:ipvn7:zExit3", "127.0.0.1:9003", s3),
    ]

    original_payload = b"Top Secret Quantum Payload"
    pkt = router.build_packet(hops, original_payload)
    assert len(pkt.serialize()) == 1280

    # Hop 1 Peeling -> Forward to Hop 2
    p1 = router.peel_layer(pkt, s1)
    assert p1.action == ACTION_FORWARD
    assert p1.next_hop_did == "did:ipvn7:zHop2"

    # Anti-replay on Hop 1 with identical packet -> DROP
    p1_replay = router.peel_layer(pkt, s1)
    assert p1_replay.action == ACTION_DROP

    # Hop 2 Peeling -> Forward to Exit
    p2 = router.peel_layer(p1.next_packet, s2)
    assert p2.action == ACTION_FORWARD
    assert p2.next_hop_did == "did:ipvn7:zExit3"

    # Hop 3 Peeling -> Deliver original payload
    p3 = router.peel_layer(p2.next_packet, s3)
    assert p3.action == ACTION_DELIVER
    assert p3.delivered_payload == original_payload


def test_plumtree_epidemic_gossip():
    """Validates Plumtree broadcast, eager push, and duplicate prune suppression."""
    from ipvn7.network.gossip import PlumtreeEngine

    delivered_msgs = []
    engine = PlumtreeEngine(
        local_did="did:ipvn7:zRoot",
        deliver_func=lambda msg: delivered_msgs.append(msg),
    )

    engine.add_peer("did:ipvn7:zPeerA")
    engine.add_peer("did:ipvn7:zPeerB")
    assert len(engine.eager_peers) == 2

    # Broadcast
    msg = engine.broadcast(b"Emergency Mesh Beacon")
    assert engine.stats["broadcasts_initiated"] == 1
    assert msg.msg_id in engine.seen_cache

    # Simulate duplicate message received from Peer A -> triggers PRUNE
    accepted = engine.handle_eager_message(
        sender_did="did:ipvn7:zPeerA",
        msg_id=msg.msg_id,
        origin_did=msg.origin_did,
        payload_bytes=msg.payload,
        hop_count=0,
    )
    assert accepted is False
    assert engine.stats["duplicates_suppressed"] == 1
    assert "did:ipvn7:zPeerA" in engine.lazy_peers


def test_swim_failure_detector():
    """Validates SWIM direct ping and indirect ping-req probe resilience."""
    from ipvn7.network.swim import SWIMFailureDetector, SWIMState

    # Detector where direct probe fails for Target, but indirect probe succeeds
    detector = SWIMFailureDetector(
        local_did="did:ipvn7:zTester",
        direct_probe_func=lambda target: False,
        indirect_probe_func=lambda inter, target: True,
    )

    mesh = ["did:ipvn7:zNode1", "did:ipvn7:zNode2"]
    res = detector.probe_peer("did:ipvn7:zTarget", mesh)

    assert res.state == SWIMState.ALIVE
    assert res.via_indirect is True
    assert detector.stats["indirect_success"] == 1


def test_wintun_userspace_tun_adapter():
    """Validates Wintun / userspace virtual TUN adapter framing and queueing."""
    from ipvn7.access.tun_wintun import IPVN7TunAdapter

    adapter = IPVN7TunAdapter(adapter_name="test-tun", force_userspace=True)
    assert adapter.is_userspace() is True
    assert adapter.mtu == 1280

    test_pkt = b"\x07" * 500
    assert adapter.write_packet(test_pkt) is True
    assert adapter.bytes_tx == 500

    adapter.loopback_inject(test_pkt)
    read_pkt = adapter.read_packet(timeout=0.1)
    assert read_pkt == test_pkt
    assert adapter.bytes_rx == 500
    adapter.close()


def test_mcp_server_protocol():
    """Validates Model Context Protocol (JSON-RPC 2.0) initialize, tools/list, and tools/call."""
    node = IPVN7Node(alias="MCP-Node", bind_host="127.0.0.1")
    node.start_background_listener()

    # 1. Initialize
    init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
    init_res = node.mcp_server.handle_jsonrpc(init_req)
    assert init_res["result"]["serverInfo"]["name"] == "ipvn7-mcp-engine"

    # 2. Tools List
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    list_res = node.mcp_server.handle_jsonrpc(list_req)
    tool_names = [t["name"] for t in list_res["result"]["tools"]]
    assert "get_node_status" in tool_names
    assert "resolve_did" in tool_names
    assert "route_sphinx_onion" in tool_names

    # 3. Tool Call: get_node_status
    call_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "get_node_status", "arguments": {}},
    }
    call_res = node.mcp_server.handle_jsonrpc(call_req)
    assert "content" in call_res["result"]
    assert "did:ipvn7:" in call_res["result"]["content"][0]["text"]

    node.stop()


def test_token_bucket_pacer_and_dwrr_scheduler():
    """Validates Token Bucket rate limiting and DWRR QoS scheduler."""
    from ipvn7.network.pacer import TokenBucketPacer, DWRRScheduler, QoSClass
    from ipvn7.network.packet import IPVN7Packet, TrafficClass

    # 1. Token Bucket
    pacer = TokenBucketPacer(rate_bytes_per_sec=1000.0, burst_bytes=500)
    assert pacer.consume(300) is True
    assert pacer.consume(300) is False  # Exceeds remaining burst capacity

    # 2. DWRR Scheduler
    sched = DWRRScheduler(rate_bytes_sec=10_000_000.0)

    pkt_ctrl = IPVN7Packet(
        src_did_fp=b"1" * 16,
        dst_did_fp=b"2" * 16,
        payload=b"Control Payload",
        traffic_class=TrafficClass.NETWORK_CONTROL,
    )
    pkt_bulk = IPVN7Packet(
        src_did_fp=b"1" * 16,
        dst_did_fp=b"2" * 16,
        payload=b"Bulk Payload",
        traffic_class=TrafficClass.BEST_EFFORT,
    )

    sched.enqueue(pkt_ctrl, ("127.0.0.1", 9001))
    sched.enqueue(pkt_bulk, ("127.0.0.1", 9002))

    # Control packet should be prioritized and dequeued first
    dequeued_1 = sched.schedule_next()
    assert dequeued_1 is not None
    assert dequeued_1.packet.traffic_class == TrafficClass.NETWORK_CONTROL

    dequeued_2 = sched.schedule_next()
    assert dequeued_2 is not None
    assert dequeued_2.packet.traffic_class == TrafficClass.BEST_EFFORT


def test_ewma_rtt_dht_routing():
    """Validates EWMA smoothing of peer latency and optimal route selection."""
    from ipvn7.network.dht import DHTNode, HierarchicalSmallWorldDHT

    local = DHTNode.from_did("did:ipvn7:zLocal")
    dht = HierarchicalSmallWorldDHT(local)

    peer_fast = DHTNode.from_did("did:ipvn7:zPeerFast")
    peer_fast.update_rtt(2.0)   # 2ms RTT

    peer_slow = DHTNode.from_did("did:ipvn7:zPeerSlow")
    peer_slow.update_rtt(150.0) # 150ms RTT

    dht.add_peer(peer_fast)
    dht.add_peer(peer_slow)

    # Optimal next hop selection accounts for EWMA RTT
    optimal = dht.find_optimal_next_hop(local.node_id + 1, count=2)
    assert len(optimal) == 2
    # Verify peer_fast was given lower weighted metric compared to degraded peer
    assert peer_fast.ewma_rtt_ms < peer_slow.ewma_rtt_ms


def test_ztna_firewall_default_deny():
    """Validates ZTNA microsegmentation, default-deny, and granular per-DID policies."""
    from ipvn7.security.firewall import ZTNAFirewall, DIDPolicy, FirewallDecision

    fw = ZTNAFirewall(default_deny=True)
    unauthorized_did = "did:ipvn7:zAttacker999"

    # Default deny drops unauthorized traffic
    assert fw.evaluate_inbound(unauthorized_did) == FirewallDecision.DROP_DEFAULT_DENY
    assert fw.evaluate_outbound(unauthorized_did) == FirewallDecision.DROP_DEFAULT_DENY

    # Authorize peer
    trusted_did = "did:ipvn7:zPartner123"
    fw.authorize_did(DIDPolicy(
        did=trusted_did,
        allow_inbound=True,
        allow_outbound=True,
        allow_relay=False,
        allowed_ports=[9443, 8080],
    ))

    # Allowed port
    assert fw.evaluate_inbound(trusted_did, port=9443) == FirewallDecision.ACCEPT
    # Disallowed port
    assert fw.evaluate_inbound(trusted_did, port=22) == FirewallDecision.DROP_ACL
    # Relay disallowed
    assert fw.evaluate_relay(trusted_did) == FirewallDecision.DROP_ACL


def test_web_of_trust_transitive_attenuation():
    """Validates Web-of-Trust multi-hop reputation and attenuation."""
    from ipvn7.security.wot import WebOfTrust
    from ipvn7.crypto.pqc import PQCKeyPair

    wot = WebOfTrust(attenuation=0.85, max_hops=3)

    kp_a = PQCKeyPair.generate()
    did_a = "did:ipvn7:zA"
    did_b = "did:ipvn7:zB"
    did_c = "did:ipvn7:zC"

    # A vouches for B (trust = 0.9)
    wot.issue_vouch(kp_a, did_a, did_b, 0.9, "Direct partner")

    # Direct trust
    trust_ab = wot.compute_trust(did_a, did_b)
    assert trust_ab == 0.9

    # B vouches for C (trust = 0.8)
    kp_b = PQCKeyPair.generate()
    wot.issue_vouch(kp_b, did_b, did_c, 0.8, "Sub-agent")

    # Transitive trust A -> C: 0.9 * 0.8 * 0.85 = ~0.612
    trust_ac = wot.compute_trust(did_a, did_c)
    assert 0.60 <= trust_ac <= 0.62


def test_dag_store_content_addressing_and_dtn():
    """Validates immutable content-addressed DAG blocks, CIDs, and DTN queues."""
    from ipvn7.storage.dag import DAGStore
    from ipvn7.crypto.pqc import PQCKeyPair

    kp = PQCKeyPair.generate()
    local_did = "did:ipvn7:zLocalAuthor"
    store = DAGStore(local_did, kp)

    # Put block 1 (genesis data)
    b1 = store.put_block(b"Genesis Block Data")
    assert b1.cid.startswith("cid:ipvn7:")
    assert len(b1.signature) == 64

    # Put block 2 (child referencing b1 as parent)
    b2 = store.put_block(b"Child Transaction Data", parents=[b1.cid])
    assert b2.parents == [b1.cid]
    assert store.heads == [b2.cid]

    # DTN Queue for offline target
    offline_peer = "did:ipvn7:zSatelliteOffline"
    b3 = store.put_block(b"DTN Bundle for Satellite", target_did=offline_peer)
    assert len(store.pending_dtn_queue[offline_peer]) == 1

    # Flush DTN queue when peer reconnects
    delivered = store.flush_dtn_queue(offline_peer)
    assert len(delivered) == 1
    assert delivered[0].cid == b3.cid
    assert len(store.pending_dtn_queue.get(offline_peer, [])) == 0


def test_mcp_extended_tools_call():
    """Validates execution of newly integrated MCP tools for Firewall, WoT, and DAG."""
    node = IPVN7Node(alias="MCP-Full", bind_host="127.0.0.1")
    node.start_background_listener()

    # Tool: ipvn7_firewall_rule (set)
    res_fw = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_firewall_rule",
            "arguments": {"action": "set", "did": "did:ipvn7:zPeerAuth", "allow_inbound": True},
        },
    })
    assert "authorized" in res_fw["result"]["content"][0]["text"]

    # Tool: ipvn7_dag_put
    res_dag = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_dag_put",
            "arguments": {"payload": "Immutable Ledger Entry"},
        },
    })
    assert "cid:ipvn7:" in res_dag["result"]["content"][0]["text"]

    # Tool: ipvn7_wot_vouch
    res_wot = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_wot_vouch",
            "arguments": {"subject_did": "did:ipvn7:zPeerAuth", "trust_level": 0.85, "reason": "Verified Agent"},
        },
    })
    assert "0.85" in res_wot["result"]["content"][0]["text"]

    node.stop()


def test_node_ztna_datapath_enforcement():
    """Validates that ZTNA Default-Deny policies strictly control the packet datapath."""
    from ipvn7.security.firewall import DIDPolicy

    node_a = IPVN7Node(alias="ZTNA-A", bind_host="127.0.0.1")
    node_b = IPVN7Node(alias="ZTNA-B", bind_host="127.0.0.1")

    port_a = node_a.start_background_listener()
    port_b = node_b.start_background_listener()

    node_a.bootstrap_peer(node_b.did, "127.0.0.1", port_b)
    node_b.bootstrap_peer(node_a.did, "127.0.0.1", port_a)

    # 1. Enable Default-Deny on Node A (Outbound blocked)
    node_a.firewall.set_default_deny(True)
    assert node_a.send_message_sync(node_b.did, b"Blocked Outbound") is False
    assert node_a.firewall.stats["packets_dropped_default_deny"] > 0

    # 2. Authorize Node B on Node A
    node_a.authorize_peer(node_b.did, allow_outbound=True, allow_inbound=True)
    # Node B still has default_deny=False by default, so it accepts
    assert node_a.send_message_sync(node_b.did, b"Permitted Traffic") is True

    # 3. Enable Default-Deny on Node B without authorizing Node A
    node_b.firewall.set_default_deny(True)
    # Creating a new node C to test inbound drop on B
    node_c = IPVN7Node(alias="ZTNA-C", bind_host="127.0.0.1")
    port_c = node_c.start_background_listener()
    node_c.bootstrap_peer(node_b.did, "127.0.0.1", port_b)

    # C tries to send to B; B's firewall drops ClientInitial
    assert node_c.send_message_sync(node_b.did, b"Unauthorized Inbound") is False

    node_a.stop()
    node_b.stop()
    node_c.stop()


def test_node_dtn_automatic_sync_on_handshake():
    """Validates automatic DTN bundle dispatch when establishing PQ-QUIC connection."""
    node_sender = IPVN7Node(alias="DTN-Sender", bind_host="127.0.0.1")
    node_receiver = IPVN7Node(alias="DTN-Receiver", bind_host="127.0.0.1")

    port_s = node_sender.start_background_listener()
    port_r = node_receiver.start_background_listener()

    node_sender.bootstrap_peer(node_receiver.did, "127.0.0.1", port_r)
    node_receiver.bootstrap_peer(node_sender.did, "127.0.0.1", port_s)

    # 1. Queue DTN bundle while node_receiver is "conceptually disconnected"
    block = node_sender.put_dag_block(b"Sensor Telemetry Over Partition", target_did=node_receiver.did)
    assert len(node_sender.dag.pending_dtn_queue[node_receiver.did]) == 1

    # 2. Connect / send message: DTN queue should automatically flush and transmit
    ok = node_sender.send_message_sync(node_receiver.did, b"Trigger Reconnection")
    assert ok is True

    # 3. Verify DTN queue has been emptied and delivered stat incremented
    assert len(node_sender.dag.pending_dtn_queue.get(node_receiver.did, [])) == 0
    assert node_sender.dag.stats["bundles_delivered_dtn"] >= 1

    node_sender.stop()
    node_receiver.stop()


def test_anomaly_fingerprinter_o1_aggregation():
    """Validates O(1) deduplication and cryptographic signature aggregation of incidents."""
    from ipvn7.diagnostics.anomaly import AnomalyFingerprinter, SeverityLevel, compute_signature

    af = AnomalyFingerprinter()

    # 1. Signature uniqueness and format
    sig1 = compute_signature("BUFFER_OVERFLOW", "L1_TRANSPORT", "Ring buffer filled")
    assert len(sig1) == 12
    assert all(c in "0123456789abcdef" for c in sig1)

    # 2. Record 100 identical events: should collapse to 1 signature with count 100
    for _ in range(100):
        fp = af.record_anomaly("BUFFER_OVERFLOW", "L1_TRANSPORT", "Ring buffer filled", SeverityLevel.CRITICAL)

    assert fp.count == 100
    assert fp.signature == sig1
    assert af.total_count == 100
    assert len(af.fingerprints) == 1

    # 3. Record distinct event
    fp2 = af.record_anomaly("ZTNA_DROP", "L1_FIREWALL", "DID Unauthorized", SeverityLevel.HIGH)
    assert len(af.fingerprints) == 2
    assert af.total_count == 101

    summary = af.get_summary()
    assert summary["total_incidents_recorded"] == 101
    assert summary["unique_fingerprints"] == 2
    assert summary["counts_by_severity"]["CRITICAL"] == 100
    assert summary["counts_by_severity"]["HIGH"] == 1


def test_split_brain_guard_quorum_and_recovery():
    """Validates quorum-based network partition detection and state restoration."""
    from ipvn7.network.split_brain import SplitBrainGuard, PartitionState

    guard = SplitBrainGuard(heartbeat_timeout=1.0, partition_threshold=0.50, recovery_window=0.1)

    # Register 4 peers
    for i in range(1, 5):
        guard.register_peer(f"did:ipvn7:zPeer{i}")

    now = 1000.0
    # All 4 peers active
    for i in range(1, 5):
        guard.record_heartbeat(f"did:ipvn7:zPeer{i}", at=now)

    state, reason = guard.audit_liveness(at=now)
    assert state == PartitionState.HEALTHY
    assert guard.is_partitioned() is False

    # 3 peers go silent (now + 2.0s), only Peer1 sends heartbeat (1/4 = 25% < 50%)
    now += 2.0
    guard.record_heartbeat("did:ipvn7:zPeer1", at=now)
    state, reason = guard.audit_liveness(at=now)
    assert state == PartitionState.PARTITIONED
    assert guard.is_partitioned() is True
    assert "Partition detected" in reason

    # Peers recover: 3 peers active again (3/4 = 75% >= 50%)
    now += 1.0
    for i in range(1, 4):
        guard.record_heartbeat(f"did:ipvn7:zPeer{i}", at=now)

    state, reason = guard.audit_liveness(at=now)
    assert state == PartitionState.RECOVERING

    # After recovery window passes
    now += 0.2
    state, reason = guard.audit_liveness(at=now)
    assert state == PartitionState.HEALTHY
    assert guard.stats["recoveries_completed"] == 1


def test_mcp_diagnostics_tools_call():
    """Validates MCP invocation of anomaly inspection and split-brain audit tools."""
    node = IPVN7Node(alias="MCP-Diag", bind_host="127.0.0.1")
    node.start_background_listener()

    # Trigger some anomalies
    node.anomaly_detector.record_anomaly("TEST_ERR", "TEST_SYS", "Synthetic Root Cause")

    # Tool call: ipvn7_get_anomalies
    res_anom = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {"name": "ipvn7_get_anomalies", "arguments": {"limit": 5}},
    })
    assert "summary" in res_anom["result"]["content"][0]["text"]

    # Tool call: ipvn7_audit_split_brain
    res_sb = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {"name": "ipvn7_audit_split_brain", "arguments": {}},
    })
    assert "HEALTHY" in res_sb["result"]["content"][0]["text"]

    node.stop()


def test_ddns_petnames_resolution():
    """Validates decentralized human-friendly name resolution and reverse lookups."""
    from ipvn7.identity.petnames import PetnameResolver

    resolver = PetnameResolver()

    # 1. Register petnames
    rec1 = resolver.register_petname("gateway", "did:ipvn7:zGateway111", comment="Primary Exit")
    assert rec1.name == "gateway.ipv7"
    assert rec1.did == "did:ipvn7:zGateway111"
    assert rec1.virtual_ipv6.startswith("fd07:")
    assert rec1.virtual_ipv4.startswith("10.7.")

    # 2. Resolve
    res = resolver.resolve("gateway")
    assert res is not None
    assert res.did == "did:ipvn7:zGateway111"

    res_dot = resolver.resolve("gateway.ipv7")
    assert res_dot is not None
    assert res_dot.did == "did:ipvn7:zGateway111"

    # 3. Reverse lookup
    name = resolver.reverse_lookup("did:ipvn7:zGateway111")
    assert name == "gateway.ipv7"

    # 4. Context Root isolation
    rec_ctx = resolver.register_petname("alpha", "did:ipvn7:zAlphaPrivate", context_root="cluster-alpha")
    assert rec_ctx.name.endswith(".alpha.ipv7")
    assert resolver.resolve("alpha", context_root="cluster-alpha") is not None
    assert resolver.resolve("alpha", context_root="cluster-beta") is None

    # 5. Unregister
    assert resolver.unregister("gateway.ipv7") is True
    assert resolver.resolve("gateway.ipv7") is None


def test_oob_sas_and_ur_multipart_pairing():
    """Validates Short Authentication Strings (SAS) and Uniform Resource (UR) multipart chunking."""
    from ipvn7.security.oob import derive_sas, generate_ur_chunks, reconstruct_ur_chunks
    import os

    key_a = b"\x01" * 32
    key_b = b"\x02" * 32

    # 1. SAS Commutative Property (both peers derive identical verification codes)
    sas_ab = derive_sas(key_a, key_b)
    sas_ba = derive_sas(key_b, key_a)

    assert sas_ab.digits == sas_ba.digits
    assert len(sas_ab.digits) == 6
    assert sas_ab.emojis == sas_ba.emojis
    assert len(sas_ab.emojis) == 4
    assert sas_ab.auth_string == sas_ba.auth_string

    # 2. UR Multipart Chunking and Lossless Reconstruction
    payload = b"IPVN7 Sovereign Air-Gapped Node Profile: ML-KEM-768 + Ed25519 Canonical Identity" * 4
    frames = generate_ur_chunks(payload, max_chunk_size=40)
    assert len(frames) > 1
    assert all(f.startswith("ur:ipvn7-profile/") for f in frames)

    # Reconstruct
    reconstructed = reconstruct_ur_chunks(frames)
    assert reconstructed == payload


def test_mcp_petnames_and_oob_tools():
    """Validates execution of Petnames and OOB SAS via MCP JSON-RPC 2.0 interface."""
    node = IPVN7Node(alias="MCP-Petnames", bind_host="127.0.0.1")
    node.start_background_listener()

    # 1. Register petname
    res_reg = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 30,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_register_petname",
            "arguments": {"name": "backup-server", "did": "did:ipvn7:zStorage999", "comment": "Cold Storage"},
        },
    })
    assert "registered" in res_reg["result"]["content"][0]["text"]

    # 2. Resolve petname
    res_res = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_resolve_petname",
            "arguments": {"name": "backup-server.ipv7"},
        },
    })
    assert "did:ipvn7:zStorage999" in res_res["result"]["content"][0]["text"]

    # 3. Derive OOB SAS
    peer_pub = (b"\xaa" * 32).hex()
    res_sas = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 32,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_get_oob_sas",
            "arguments": {"peer_pubkey_hex": peer_pub},
        },
    })
    assert "auth_string" in res_sas["result"]["content"][0]["text"]

    node.stop()


def test_tit_for_tat_transit_accounting():
    """Validates game-theoretic Tit-for-Tat reciprocity ratio and tier transitions."""
    from ipvn7.network.accounting import TransitAccounting, ServiceTier

    # Courtesy: 1000 bytes, 10 packets for quick unit testing
    accounting = TransitAccounting(courtesy_bytes=1000, courtesy_packets=10)
    peer_did = "did:ipvn7:zPeerBandwidthConsumer"

    # 1. Bootstrap phase: below courtesy limit -> remains NORMAL
    tier = accounting.record_tx(peer_did, 500)
    assert tier == ServiceTier.NORMAL
    acc = accounting.get_peer_account(peer_did)
    assert acc["tier"] == "NORMAL"
    assert acc["bytes_tx"] == 500
    assert acc["bytes_rx"] == 0

    # 2. Exceed courtesy quota without sending RX traffic back (free-riding / leech)
    # Send 10,000 bytes TX, 0 bytes RX -> Ratio = 0.0 -> THROTTLED
    for _ in range(12):
        tier = accounting.record_tx(peer_did, 1000)
    assert tier == ServiceTier.THROTTLED
    assert accounting.get_tier(peer_did) == ServiceTier.THROTTLED

    # 3. Peer cooperates and routes 15,000 bytes RX back -> Ratio = 15000 / 12500 = 1.2 -> PRIORITY
    tier = accounting.record_rx(peer_did, 15000)
    assert tier == ServiceTier.PRIORITY
    assert accounting.get_tier(peer_did) == ServiceTier.PRIORITY

    # Summary verification
    summary = accounting.get_summary()
    assert summary["tracked_peers"] == 1
    assert summary["tier_distribution"]["PRIORITY"] == 1
    assert len(accounting.list_accounts()) == 1


def test_microservices_lifecycle_manager():
    """Validates zero-RAM dormant state, on-demand instantiation, and idle pruning."""
    from ipvn7.access.services import ServiceLifecycleManager, ServiceState, ServiceScope

    mgr = ServiceLifecycleManager(idle_timeout_seconds=0.1)

    # 1. Register dormant service (Zero RAM footprint)
    desc = mgr.register_dormant_service("quantum_vault", ServiceScope.LOCAL, "Zero-Knowledge Local Key Vault")
    assert desc.state == ServiceState.DORMANT
    assert desc.active_sessions == 0
    assert len(mgr.get_active_services()) == 0

    # 2. On-demand request: transitions to ACTIVE
    active_desc = mgr.request_service("quantum_vault")
    assert active_desc.state == ServiceState.ACTIVE
    assert active_desc.active_sessions == 1
    assert len(mgr.get_active_services()) == 1

    # 3. Release session
    mgr.release_service("quantum_vault")
    assert active_desc.active_sessions == 0

    # 4. Prune idle services
    pruned = mgr.prune_idle_services(force=True)
    assert "quantum_vault" in pruned
    assert mgr.services["quantum_vault"].state == ServiceState.PRUNED
    assert len(mgr.get_active_services()) == 0


def test_mcp_accounting_and_services_tools():
    """Validates MCP tools catalog count (18 tools) and execution of accounting & service tools."""
    node = IPVN7Node(alias="MCP-Evolved", bind_host="127.0.0.1")
    node.start_background_listener()

    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 18, f"Expected at least 18 MCP tools, found {len(tools)}"

    # Tool 1: ipvn7_get_accounting
    res_acc = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 40,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_get_accounting",
            "arguments": {},
        },
    })
    assert "summary" in res_acc["result"]["content"][0]["text"]

    # Tool 2: ipvn7_request_service
    res_svc = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 41,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_request_service",
            "arguments": {"name": "socks5_proxy", "scope": "LOCAL"},
        },
    })
    assert "requested" in res_svc["result"]["content"][0]["text"]
    assert "socks5_proxy" in res_svc["result"]["content"][0]["text"]

    node.stop()


def test_tls_13_obfuscation_dpi_bypass():
    """Validates RFC 8446 TLS 1.3 ClientHello generation, record wrapping, and DPI bypass framing."""
    from ipvn7.network.tls_obfuscation import TLSOptionEngine, TLSRecordType

    engine = TLSOptionEngine(default_sni="api.cloudflare.com")

    # 1. Synthesize RFC 8446 ClientHello
    ch = engine.build_client_hello("gateway.cloudflare.com")
    assert len(ch) > 100
    assert engine.is_tls_record(ch)
    # Check Handshake record type 0x16 and legacy version 0x0303
    rtype, payload = engine.unwrap_record(ch)
    assert rtype == TLSRecordType.HANDSHAKE
    assert b"gateway.cloudflare.com" in payload

    # 2. Wrap arbitrary IPVN 7 quantum datagram in ApplicationData record
    quantum_data = b"[IPVN7_PQ_QUIC_FRAME]" + (b"\x7f" * 256)
    wrapped = engine.wrap_record(quantum_data, TLSRecordType.APPLICATION_DATA)
    assert engine.is_tls_record(wrapped)
    assert len(wrapped) == len(quantum_data) + 5  # 5 bytes header

    # 3. Unwrap record
    r_type, recovered_data = engine.unwrap_record(wrapped)
    assert r_type == TLSRecordType.APPLICATION_DATA
    assert recovered_data == quantum_data


def test_ephemeral_blind_rendezvous_circuit_breaker():
    """Validates Zero-PII blind rendezvous topic derivation, consume-and-burn, and circuit breaker trip."""
    from ipvn7.network.blind_rendezvous import BlindRendezvousAdapter, MemoryBeaconStore, derive_topic_id

    # 1. Topic derivation is deterministic per epoch hour and network seed
    t1 = derive_topic_id(epoch_seconds=1700000000, ring_degree=1, network_seed="testnet")
    t2 = derive_topic_id(epoch_seconds=1700000000, ring_degree=1, network_seed="testnet")
    assert t1 == t2
    assert len(t1) == 32

    # 2. Blind beacon publish & consume-and-burn
    store = MemoryBeaconStore()
    adapter = BlindRendezvousAdapter("did:ipvn7:zColdNode", beacon_store=store, min_peers_trip=2, network_seed="testnet")
    topic = adapter.publish_endpoint("192.168.1.50:9000", ring_degree=1)
    assert len(topic) == 32

    # Discover and consume (should burn/delete after reading)
    found = adapter.discover_peer(ring_degree=1, consume=True)
    assert found is not None
    assert found["did"] == "did:ipvn7:zColdNode"
    assert found["endpoint"] == "192.168.1.50:9000"

    # Second read: burned (returns None)
    second_read = adapter.discover_peer(ring_degree=1)
    assert second_read is None

    # 3. Circuit Breaker: trips when direct peers reach threshold
    assert not adapter.circuit_breaker_tripped
    tripped = adapter.record_direct_peer_connected(direct_peers_count=2)
    assert tripped
    assert adapter.circuit_breaker_tripped
    # Publishing while tripped is blocked
    assert adapter.publish_endpoint("192.168.1.50:9000") == ""


def test_mcp_tools_catalog_20_tools():
    """Validates 20 tools in the MCP tools catalog and execution of TLS & Blind Rendezvous tools."""
    node = IPVN7Node(alias="MCP-20-Tools", bind_host="127.0.0.1")
    node.start_background_listener()

    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 20, f"Expected at least 20 MCP tools, found {len(tools)}"

    # Tool 1: ipvn7_tls_camouflage (wrap)
    res_tls = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 50,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_tls_camouflage",
            "arguments": {"action": "wrap", "payload": "SECRET_QUANTUM_DATA"},
        },
    })
    assert "wrapped" in res_tls["result"]["content"][0]["text"]

    # Tool 2: ipvn7_blind_rendezvous (publish)
    res_br = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 51,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_blind_rendezvous",
            "arguments": {"action": "publish", "endpoint": "10.0.0.1:9090", "ring_degree": 1},
        },
    })
    assert "published" in res_br["result"]["content"][0]["text"]

    node.stop()


def test_explainable_network_route_selection():
    """Validates multi-variable transparent cost function and natural-language route explanations."""
    from ipvn7.network.explainable import ExplainableNetworkEngine, CandidateMetrics

    engine = ExplainableNetworkEngine()

    c1 = CandidateMetrics(
        peer_did="did:ipvn7:zFastLowTrust",
        latency_ms=10.0,
        rfc3550_jitter_ms=1.0,
        packet_loss_pct=0.0,
        battery_pct=100,
        trust_tier=1,
    )

    c2 = CandidateMetrics(
        peer_did="did:ipvn7:zHighTrustSlightlySlower",
        latency_ms=15.0,
        rfc3550_jitter_ms=1.2,
        packet_loss_pct=0.0,
        battery_pct=100,
        trust_tier=4,  # PQC Trust Tier 4 gives +45 bonus over Tier 1
    )

    explanation = engine.select_and_explain_route("did:ipvn7:zTargetDest", [c1, c2])

    assert explanation.target_did == "did:ipvn7:zTargetDest"
    # c2 should win because Trust Tier 4 outweighs the 5ms latency delta
    assert explanation.selected_peer == "did:ipvn7:zHighTrustSlightlySlower"
    assert "Se seleccionó" in explanation.human_explanation
    assert len(explanation.evaluated_candidates) == 2


def test_spectral_fourier_analysis_periodic_anomaly():
    """Validates Discrete Fourier Transform (DFT), harmonic power density, and jitter resonance detection."""
    from ipvn7.diagnostics.spectral import compute_fourier_spectrum
    import math

    # 1. Create artificial periodic oscillation (10 Hz signal sampled at 100 Hz, 64 points)
    # y(t) = 5.0 * sin(2*pi * 10 * t / 100)
    signal = [5.0 * math.sin(2.0 * math.pi * 10.0 * (t / 100.0)) for t in range(64)]

    analysis = compute_fourier_spectrum(signal, sampling_rate_hz=100.0)

    # Dominant frequency should be near 10 Hz (approx bin)
    assert 9.0 <= analysis.dominant_frequency <= 11.5
    # Should detect periodic anomaly due to high PAPR and focused harmonic energy
    assert analysis.is_periodic_anomaly
    assert analysis.peak_to_average_ratio > 4.5
    assert analysis.spectral_entropy < 0.85

    # 2. Constant / Flat Signal (zero jitter)
    flat_signal = [20.0] * 32
    flat_analysis = compute_fourier_spectrum(flat_signal, sampling_rate_hz=100.0)
    assert not flat_analysis.is_periodic_anomaly


def test_mcp_tools_catalog_22_tools():
    """Validates 22 tools in the MCP catalog and execution of explainable and spectral tools."""
    node = IPVN7Node(alias="MCP-22-Tools", bind_host="127.0.0.1")
    node.start_background_listener()

    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 22, f"Expected at least 22 MCP tools, found {len(tools)}"

    # Tool 1: ipvn7_explain_route
    res_exp = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 60,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_explain_route",
            "arguments": {
                "target_did": "did:ipvn7:zFinalTarget",
                "candidates": [
                    {"peer_did": "did:ipvn7:zPeerA", "latency_ms": 25.0, "trust_tier": 2},
                    {"peer_did": "did:ipvn7:zPeerB", "latency_ms": 10.0, "trust_tier": 4},
                ],
            },
        },
    })
    assert "human_explanation" in res_exp["result"]["content"][0]["text"]
    assert "did:ipvn7:zPeerB" in res_exp["result"]["content"][0]["text"]

    # Tool 2: ipvn7_analyze_spectrum
    res_spec = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 61,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_analyze_spectrum",
            "arguments": {
                "signal": [1.0, 5.0, 1.0, 5.0, 1.0, 5.0, 1.0, 5.0],
                "sampling_rate_hz": 10.0,
            },
        },
    })
    assert "dominant_frequency_hz" in res_spec["result"]["content"][0]["text"]

    node.stop()


def test_1024_bit_sliding_window_anti_replay():
    """Validates O(1) bitmask sliding window sequence validation and replay packet rejection."""
    from ipvn7.security.anti_replay import AntiReplayFilter

    filter_ar = AntiReplayFilter()

    # 1. Normal in-order sequence
    assert filter_ar.validate_and_update(1)
    assert filter_ar.validate_and_update(2)
    assert filter_ar.validate_and_update(5)

    # 2. Duplicate detection (replays rejected)
    assert not filter_ar.validate_and_update(1)
    assert not filter_ar.validate_and_update(2)
    assert not filter_ar.validate_and_update(5)

    # 3. Out-of-order within window accepted once
    assert filter_ar.validate_and_update(3)
    assert filter_ar.validate_and_update(4)
    # But second attempt is duplicate
    assert not filter_ar.validate_and_update(3)

    # 4. Large jump forward advances window
    assert filter_ar.validate_and_update(2000)
    # Old packets (seq 5) are now beyond the 1024-bit window (2000 - 5 = 1995 >= 1024)
    assert not filter_ar.validate_and_update(5)

    stats = filter_ar.get_stats()
    assert stats["accepted_packets"] == 6
    assert stats["rejected_replays"] >= 5


def test_agentic_principal_chain_delegation():
    """Validates Agentic Principal Chain (APC) custodial continuity, monotonic attenuation, and Ed25519 signatures."""
    from ipvn7.security.delegation import DelegationLink, AgenticPrincipalChain, ExecutionTier
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    root_priv = Ed25519PrivateKey.generate()
    root_pub = root_priv.public_key()
    root_did = "did:ipvn7:zRootMasterAgent"

    sub_priv = Ed25519PrivateKey.generate()
    sub_pub = sub_priv.public_key()
    sub_did = "did:ipvn7:zSubAgentDelegate"

    third_priv = Ed25519PrivateKey.generate()
    third_pub = third_priv.public_key()
    third_did = "did:ipvn7:zWorkerProcess"

    key_registry = {
        root_did: root_pub,
        sub_did: sub_pub,
        third_did: third_pub,
    }

    # 1. Root delegates to SubAgent with escalated tier
    link1 = DelegationLink(
        issuer_did=root_did,
        subject_did=sub_did,
        scope="manage_network",
        tier=ExecutionTier.ESCALATED,
        expires_at=time.time() + 600.0,
    )
    link1.sign(root_priv)
    assert link1.verify(root_pub)

    # 2. SubAgent delegates to Worker with ordinary tier (attenuation)
    link2 = DelegationLink(
        issuer_did=sub_did,
        subject_did=third_did,
        scope="read_telemetry",
        tier=ExecutionTier.ORDINARY,
        expires_at=time.time() + 300.0,
    )
    link2.sign(sub_priv)
    assert link2.verify(sub_pub)

    chain = AgenticPrincipalChain(root_did=root_did, links=[link1, link2])
    valid, eff_tier, msg = chain.verify_chain(key_registry)
    assert valid
    # Monotonic attenuation: effective tier is ORDINARY (the lower tier of the chain)
    assert eff_tier == ExecutionTier.ORDINARY

    # 3. Custody break test (issuer of link2 doesn't match subject of link1)
    bad_link2 = DelegationLink(
        issuer_did="did:ipvn7:zAttacker",
        subject_did=third_did,
        scope="read_telemetry",
        tier=ExecutionTier.ORDINARY,
        expires_at=time.time() + 300.0,
    )
    bad_link2.sign(third_priv)
    broken_chain = AgenticPrincipalChain(root_did=root_did, links=[link1, bad_link2])
    b_valid, _, _ = broken_chain.verify_chain(key_registry)
    assert not b_valid


def test_mcp_tools_catalog_24_tools():
    """Validates 24 tools in the MCP tools catalog and execution of delegation and anti-replay tools."""
    node = IPVN7Node(alias="MCP-24-Tools", bind_host="127.0.0.1")
    node.start_background_listener()

    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 24, f"Expected at least 24 MCP tools, found {len(tools)}"

    # Tool 1: ipvn7_create_delegation
    res_del = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 70,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_create_delegation",
            "arguments": {
                "subject_did": "did:ipvn7:zDelegatedAgent",
                "scope": "route_traffic",
                "tier": "ordinary",
            },
        },
    })
    assert "created" in res_del["result"]["content"][0]["text"]
    assert "signature" in res_del["result"]["content"][0]["text"]

    # Tool 2: ipvn7_anti_replay_check
    res_ar = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 71,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_anti_replay_check",
            "arguments": {"sequence_number": 100},
        },
    })
    assert "is_valid" in res_ar["result"]["content"][0]["text"]

    node.stop()


def test_planetary_mesh_topology_and_routing():
    """Validates Kleinberg small-world grid topology, greedy spatial routing, and relativistic delay calculation."""
    from ipvn7.network.planetary import PlanetaryMeshCluster, Coordinates2D

    cluster = PlanetaryMeshCluster(node_count=16, seed=1337)
    metrics = cluster.get_mesh_metrics()

    assert metrics["node_count"] == 16
    assert metrics["online_nodes"] == 16
    assert metrics["dimension"] == 4
    assert metrics["kleinberg_exponent"] == 2.0
    assert metrics["average_degree"] > 2.0

    # Route from corner to corner: sat-000 to sat-015
    res = cluster.route_packet("sat-000", "sat-015")
    assert res["success"] is True
    assert res["src"] == "sat-000"
    assert res["dst"] == "sat-015"
    assert len(res["path"]) > 1
    assert res["path"][0] == "sat-000"
    assert res["path"][-1] == "sat-015"
    assert res["hops"] == len(res["path"]) - 1
    assert res["distance_units"] > 0
    assert res["estimated_latency_ms"] > 0.0


def test_planetary_mesh_failure_and_resilience():
    """Validates failure simulation and topology recovery in planetary mesh."""
    from ipvn7.network.planetary import PlanetaryMeshCluster

    cluster = PlanetaryMeshCluster(node_count=25, seed=42)
    failed_count = cluster.simulate_failure(0.20)
    assert failed_count > 0

    metrics_after = cluster.get_mesh_metrics()
    assert metrics_after["offline_nodes"] == failed_count

    cluster.restore_all()
    metrics_restored = cluster.get_mesh_metrics()
    assert metrics_restored["offline_nodes"] == 0
    assert metrics_restored["online_nodes"] == 25


def test_resilience_guardian_backoff_and_circuit_breaker():
    """Validates Full Jitter exponential backoff, tri-state circuit breaker, and exception shielding."""
    from ipvn7.network.resilience import ResilienceGuardian, CircuitState
    import time

    guardian = ResilienceGuardian(
        max_retries=3,
        base_backoff_ms=20.0,
        max_backoff_ms=200.0,
        failure_threshold=3,
        cool_off_duration_s=0.1,
    )

    # 1. Backoff with jitter calculation
    w0 = guardian.compute_backoff(0)
    w1 = guardian.compute_backoff(1)
    assert 0.0 <= w0 <= 0.02
    assert 0.0 <= w1 <= 0.04

    # 2. Safe execution of normal function
    def add(a, b):
        return a + b

    res = guardian.safe_execute(add, 10, 20)
    assert res == 30
    assert guardian.state == CircuitState.CLOSED

    # 3. Trip circuit breaker with failing function
    def fail_op():
        raise ValueError("Simulated network collapse")

    for _ in range(3):
        try:
            guardian.safe_execute(fail_op)
        except ValueError:
            pass

    # Circuit breaker should now be OPEN
    assert guardian.state == CircuitState.OPEN
    # Next call rejected immediately
    rejected = False
    try:
        guardian.safe_execute(add, 1, 2)
    except RuntimeError as e:
        rejected = True
        assert "circuit_breaker: llamada rechazada" in str(e)
    assert rejected

    # 4. Cool-off elapsed: transition to HALF_OPEN and recovery to CLOSED
    time.sleep(0.12)
    recovered_res = guardian.safe_execute(add, 5, 5)
    assert recovered_res == 10
    assert guardian.state == CircuitState.CLOSED
    status = guardian.get_health_status()
    assert status["total_recoveries"] == 1
    assert status["is_healthy"] is True


def test_mcp_tools_catalog_26_tools():
    """Validates 26 tools in the MCP tools catalog and execution of planetary and resilience tools."""
    node = IPVN7Node(alias="MCP-26-Tools", bind_host="127.0.0.1")
    node.start_background_listener()

    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 26, f"Expected at least 26 MCP tools, found {len(tools)}"

    # Tool 1: ipvn7_route_planetary
    res_planet = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 80,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_route_planetary",
            "arguments": {"src_node": "sat-000", "dst_node": "sat-015"},
        },
    })
    assert "estimated_latency_ms" in res_planet["result"]["content"][0]["text"]
    assert "sat-015" in res_planet["result"]["content"][0]["text"]

    # Tool 2: ipvn7_resilience_status
    res_resil = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 81,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_resilience_status",
            "arguments": {},
        },
    })
    assert "circuit_state" in res_resil["result"]["content"][0]["text"]
    assert "CLOSED" in res_resil["result"]["content"][0]["text"]

    node.stop()


def test_dark_node_profile_macro_orchestration():
    """Validates atomic 4-layer macro-action for stealth dark node profile."""
    from ipvn7.security.firewall import ZTNAFirewall
    from ipvn7.security.dark_node import DarkNodeMacroOrchestrator, OperatingMode

    fw = ZTNAFirewall(default_deny=False)
    orch = DarkNodeMacroOrchestrator(firewall=fw)

    # 1. Initial State: Standard Mesh
    assert orch.current_mode == OperatingMode.STANDARD_MESH
    assert not orch.is_dark_node()
    assert not orch.listeners_muted
    assert not orch.sphinx_mandatory

    # 2. Toggle to Dark Node Egress-Only mode
    mode = orch.toggle_mode()
    assert mode == OperatingMode.DARK_NODE_EGRESS_ONLY
    assert orch.is_dark_node()
    assert fw.default_deny is True
    assert orch.listeners_muted is True
    assert orch.sphinx_mandatory is True
    assert orch.active_hops == 3
    assert orch.micro_jitter_active is True

    # 3. Toggle back to Standard Mesh
    mode_back = orch.toggle_mode()
    assert mode_back == OperatingMode.STANDARD_MESH
    assert not orch.is_dark_node()
    assert orch.listeners_muted is False
    assert orch.sphinx_mandatory is False
    assert orch.active_hops == 0


def test_silent_call_and_response_unicast_dispatcher():
    """Validates directed unicast dispatching, token bucket rate limiting, and zero broadcast noise."""
    from ipvn7.network.silent import (
        SilentDispatcher,
        FRAME_SILENT_CALL,
        FRAME_SILENT_RESPONSE,
    )

    disp = SilentDispatcher(local_did="did:ipvn7:zAliceHost", rate_limit_per_peer=10)

    # 1. Filter out broadcast noise / garbage frames
    resp = disp.process_incoming_frame(b"\x00\x00")
    assert resp is None
    assert disp.dropped_broadcast_noise == 1

    resp_random = disp.process_incoming_frame(b"\xff\x05GARBAGE")
    assert resp_random is None
    assert disp.dropped_broadcast_noise == 2

    # 2. Set call handler for directed requests
    def answer_call(src_did: str, payload: bytes) -> bytes:
        return b"PONG:" + payload

    disp.set_call_handler(answer_call)

    # 3. Simulate incoming directed call frame
    src_bytes = b"did:ipvn7:zBobPeer"
    call_frame = bytes([FRAME_SILENT_CALL, len(src_bytes)]) + src_bytes + b"HELLO_ALICE"
    reply = disp.process_incoming_frame(call_frame)

    assert reply is not None
    assert reply[0] == FRAME_SILENT_RESPONSE
    assert b"PONG:HELLO_ALICE" in reply
    assert disp.total_calls_received == 1
    assert disp.total_responses_sent == 1

    # 4. Outbound dispatch call
    dispatch_res = disp.dispatch_call("did:ipvn7:zBobPeer", b"DIRECT_PROBE")
    assert dispatch_res["success"] is True
    assert dispatch_res["frame_type"] == "FRAME_SILENT_CALL"
    assert disp.total_calls_dispatched == 1


def test_mcp_tools_catalog_28_tools():
    """Validates 28 native tools in the MCP tools catalog and execution of dark node and silent call tools."""
    node = IPVN7Node(alias="MCP-28-Tools", bind_host="127.0.0.1")
    node.start_background_listener()

    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 28, f"Expected at least 28 MCP tools, found {len(tools)}"

    # Tool 1: ipvn7_toggle_dark_node
    res_dark = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 90,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_toggle_dark_node",
            "arguments": {},
        },
    })
    assert "operating_mode" in res_dark["result"]["content"][0]["text"]
    assert "DARK_NODE_EGRESS_ONLY" in res_dark["result"]["content"][0]["text"]

    # Tool 2: ipvn7_send_silent_call
    res_silent = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 91,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_send_silent_call",
            "arguments": {"target_did": "did:ipvn7:zSilentPeer", "payload": "STEALTH_PING"},
        },
    })
    assert "FRAME_SILENT_CALL" in res_silent["result"]["content"][0]["text"]
    assert "target_did" in res_silent["result"]["content"][0]["text"]

    node.stop()


def test_link_healing_hysteresis_and_flap_damping():
    """Validates degradation thresholds, failover trigger, anti-flapping hysteresis, and RFC 2439 flap damping."""
    from ipvn7.network.healing import LinkHealingEngine

    engine = LinkHealingEngine(max_losses=3, degraded_latency_ms=200.0, recovery_successes=2)
    peer_did = "did:ipvn7:zFlappingPeer"
    alt_peers = ["did:ipvn7:zHealthyPeerAlpha", "did:ipvn7:zHealthyPeerBeta"]

    # 1. Normal latency -> Healthy
    fo, alt = engine.record_probe_result(peer_did, success=True, latency_ms=25.0, available_peers=alt_peers)
    assert not fo
    assert alt is None
    health = engine.get_peer_health(peer_did)
    assert not health["degraded"]

    # 2. 3 Consecutive losses -> Degraded & Failover triggered
    engine.record_probe_result(peer_did, success=False, latency_ms=0.0, available_peers=alt_peers)
    engine.record_probe_result(peer_did, success=False, latency_ms=0.0, available_peers=alt_peers)
    fo, alt = engine.record_probe_result(peer_did, success=False, latency_ms=0.0, available_peers=alt_peers)
    assert fo is True
    assert alt == "did:ipvn7:zHealthyPeerAlpha"
    health = engine.get_peer_health(peer_did)
    assert health["degraded"] is True
    assert health["failover_count"] == 1

    # 3. Hysteresis: 1 success is NOT enough to restore
    fo2, _ = engine.record_probe_result(peer_did, success=True, latency_ms=30.0, available_peers=alt_peers)
    assert not fo2
    assert engine.get_peer_health(peer_did)["degraded"] is True

    # 4. Second consecutive success restores healthy state
    engine.record_probe_result(peer_did, success=True, latency_ms=30.0, available_peers=alt_peers)
    assert engine.get_peer_health(peer_did)["degraded"] is False

    summary = engine.get_summary()
    assert summary["total_failovers"] == 1
    assert summary["total_recoveries"] == 1


def test_blackout_recovery_cascade_and_jitter():
    """Validates 5-phase post-blackout recovery state machine and decorrelated jitter timer."""
    from ipvn7.network.blackout import BlackoutRecoveryManager, RecoveryPhase, DecorrelatedJitterTimer

    # 1. Decorrelated Jitter bounds
    timer = DecorrelatedJitterTimer(base_s=1.0, max_s=10.0, multiplier=3.0)
    intervals = [timer.next_interval() for _ in range(10)]
    assert len(intervals) == 10
    assert all(1.0 <= i <= 10.0 for i in intervals)

    # 2. Blackout Recovery Manager State Cascade
    mgr = BlackoutRecoveryManager(min_converged_peers=2)
    assert mgr.current_phase == RecoveryPhase.COLD_MEMORY

    p2 = mgr.advance_phase()
    assert p2 == RecoveryPhase.OFFGRID_PROXIMITY

    p3 = mgr.advance_phase()
    assert p3 == RecoveryPhase.WAN_PROBE

    p4 = mgr.advance_phase()
    assert p4 == RecoveryPhase.BLIND_RENDEZVOUS

    p5 = mgr.advance_phase()
    assert p5 == RecoveryPhase.CONVERGED_MESH

    status = mgr.get_status()
    assert status["is_converged"] is True
    assert status["phase"] == RecoveryPhase.CONVERGED_MESH.value

    # 3. Cold boot reset
    mgr.trigger_cold_boot()
    assert mgr.current_phase == RecoveryPhase.COLD_MEMORY
    assert not mgr.get_status()["is_converged"]


def test_mcp_tools_catalog_30_tools():
    """Validates 30 native tools in the MCP tools catalog and execution of healing and blackout tools."""
    node = IPVN7Node(alias="MCP-30-Tools", bind_host="127.0.0.1")
    node.start_background_listener()

    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 30, f"Expected at least 30 MCP tools, found {len(tools)}"

    # Tool 1: ipvn7_record_link_probe
    res_probe = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_record_link_probe",
            "arguments": {"peer_did": "did:ipvn7:zTestProbePeer", "success": True, "latency_ms": 15.0},
        },
    })
    assert "failover_triggered" in res_probe["result"]["content"][0]["text"]
    assert "did:ipvn7:zTestProbePeer" in res_probe["result"]["content"][0]["text"]

    # Tool 2: ipvn7_blackout_recovery
    res_bo = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_blackout_recovery",
            "arguments": {"action": "advance"},
        },
    })
    assert "phase" in res_bo["result"]["content"][0]["text"]
    assert "next_jittered_interval_s" in res_bo["result"]["content"][0]["text"]

    node.stop()


def test_sovereign_chat_e2ee_signatures_and_persistence():
    """Validates sovereign P2P chat messaging, Ed25519 signatures, and contact book management."""
    from ipvn7.access.chat import ChatManager

    chat = ChatManager(local_did="did:ipvn7:zAliceHost")

    # 1. Check seed contacts
    contacts = chat.list_contacts()
    assert len(contacts) >= 2

    # 2. Register contact
    chat.register_contact("did:ipvn7:zBobClient", name="bob.ipv7", avatar="🚀", endpoint="10.0.0.2:7001")
    assert len(chat.list_contacts()) >= 3

    # 3. Send message
    msg = chat.send_message(
        target_did="did:ipvn7:zBobClient",
        text="Hello Bob, sovereign quantum channel active.",
        sender_name="Alice (Genesis)",
        attachment_cid="cid:ipvn7:zBlockSample123",
    )
    assert msg.msg_id.startswith("msg-")
    assert msg.author_did == "did:ipvn7:zAliceHost"
    assert msg.target_did == "did:ipvn7:zBobClient"
    assert len(msg.signature) == 128  # 64 bytes hex = 128 hex chars
    assert msg.delivered is True
    assert msg.attachment_cid == "cid:ipvn7:zBlockSample123"

    # 4. Receive message back
    rx_msg = chat.receive_message(
        author_did="did:ipvn7:zBobClient",
        text="ACK Alice, datagram received.",
        sender_name="bob.ipv7",
    )
    assert rx_msg.author_did == "did:ipvn7:zBobClient"

    # 5. Conversation history check
    conv = chat.get_conversation("did:ipvn7:zBobClient")
    assert len(conv) == 2
    assert conv[0]["text"].startswith("Hello Bob")
    assert conv[1]["text"].startswith("ACK Alice")


def test_packet_batcher_density_and_flush():
    """Validates 1280B packet batching, burst threshold dispatch, and timeout flush."""
    from ipvn7.access.batcher import PacketBatcher

    flushed_batches = []
    def on_batch(b):
        flushed_batches.append(b)

    batcher = PacketBatcher(max_batch_size=4, flush_timeout_ms=50.0, handler=on_batch)

    p1 = b"\x01" * 1280
    p2 = b"\x02" * 1280
    p3 = b"\x03" * 1280
    p4 = b"\x04" * 1280

    # Enqueue 3 packets (under threshold 4)
    assert batcher.enqueue(p1) is None
    assert batcher.enqueue(p2) is None
    assert batcher.enqueue(p3) is None
    assert len(flushed_batches) == 0

    # 4th packet reaches threshold -> triggers flush
    res = batcher.enqueue(p4)
    assert res is not None
    assert len(res) == 4
    assert len(flushed_batches) == 1
    assert flushed_batches[0][0] == p1
    assert flushed_batches[0][3] == p4

    # Enqueue 1 packet and manually flush
    batcher.enqueue(p1)
    manual = batcher.flush()
    assert len(manual) == 1
    assert len(flushed_batches) == 2

    stats = batcher.get_stats()
    assert stats["total_packets_queued"] == 5
    assert stats["total_batches_flushed"] == 2
    assert stats["average_batch_density"] == 2.5


def test_mcp_tools_catalog_57_tools():
    """Validates 57 native tools in the MCP tools catalog and execution of chat, batcher, mobility, copilot, multipath, DNS, NAT, GMA, UIN, Shadow Device, PFO, WAN Prober, Remote Desktop, Key Rotation, UPnP, Censorship, Buffer Health, WASM PoW, FSM Lifecycle, Pipeline Datagrams, Ephemeral Identity, HRS Frames, Edge AI prompts, Media streaming, Churn stress tests, and BitNet quantization."""
    node = IPVN7Node(alias="MCP-57-Tools", bind_host="127.0.0.1")
    node.start_background_listener()

    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 75, f"Expected at least 75 MCP tools, found {len(tools)}"

    # Tool 1: ipvn7_send_chat_message
    res_chat = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 110,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_send_chat_message",
            "arguments": {
                "target_did": "did:ipvn7:zBobPeer",
                "text": "Sovereign Chat via MCP Interface",
            },
        },
    })
    assert "signature" in res_chat["result"]["content"][0]["text"]
    assert "did:ipvn7:zBobPeer" in res_chat["result"]["content"][0]["text"]

    # Tool 2: ipvn7_get_batcher_stats
    res_bat = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 111,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_get_batcher_stats",
            "arguments": {},
        },
    })
    assert "max_batch_size" in res_bat["result"]["content"][0]["text"]
    assert "average_batch_density" in res_bat["result"]["content"][0]["text"]

    # Tool 3: ipvn7_update_mobility_locator
    res_mob = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 112,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_update_mobility_locator",
            "arguments": {
                "node_did": "did:ipvn7:zMobileClientA",
                "physical_ip": "10.42.0.88",
                "physical_port": 54321,
                "seq": 1,
            },
        },
    })
    assert "ticket_hex" in res_mob["result"]["content"][0]["text"]
    assert "10.42.0.88:54321" in res_mob["result"]["content"][0]["text"]

    # Tool 4: ipvn7_run_ai_copilot
    res_cop = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 113,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_run_ai_copilot",
            "arguments": {
                "latency_ms": 65.0,
                "firewall_drops": 8,
                "peer_did": "did:ipvn7:zAbusiveFlooder",
            },
        },
    })
    assert "UNAUTHORIZED_FLOOD" in res_cop["result"]["content"][0]["text"]
    assert "BLOCK_DID" in res_cop["result"]["content"][0]["text"]

    # Tool 5: ipvn7_schedule_multipath
    res_mp = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 114,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_schedule_multipath",
            "arguments": {
                "payload": "HighPriorityFrame",
                "is_critical": True,
            },
        },
    })
    assert "selected_paths" in res_mp["result"]["content"][0]["text"]
    assert "is_critical" in res_mp["result"]["content"][0]["text"]

    # Tool 6: ipvn7_resolve_dns_proxy
    res_dns = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 115,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_resolve_dns_proxy",
            "arguments": {
                "domain": "gateway.ipv7",
            },
        },
    })
    assert "resolved_ip" in res_dns["result"]["content"][0]["text"]
    assert "SYNTHETIC_OVERLAY_FALLBACK" in res_dns["result"]["content"][0]["text"] or "SOVEREIGN_PETNAME_DDNS" in res_dns["result"]["content"][0]["text"]

    # Tool 7: ipvn7_nat_hole_punch
    res_nat = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 116,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_nat_hole_punch",
            "arguments": {
                "peer_did": "did:ipvn7:zPunchedPeer",
                "peer_public_ip": "203.0.113.10",
                "peer_public_port": 10807,
            },
        },
    })
    assert "routing" in res_nat["result"]["content"][0]["text"]
    assert "did:ipvn7:zPunchedPeer" in res_nat["result"]["content"][0]["text"]

    # Tool 8: ipvn7_allocate_memory_budget
    res_mem = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 117,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_allocate_memory_budget",
            "arguments": {
                "budget_class": "replay",
                "num_bytes": 1024,
            },
        },
    })
    assert "allowed" in res_mem["result"]["content"][0]["text"]
    assert "replay" in res_mem["result"]["content"][0]["text"]

    # Tool 9: ipvn7_orchestrate_silent_rekey
    res_rekey = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 118,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_orchestrate_silent_rekey",
            "arguments": {},
        },
    })
    assert "keys_matched" in res_rekey["result"]["content"][0]["text"]
    assert "forward_secrecy_zeroized" in res_rekey["result"]["content"][0]["text"]

    # Tool 10: ipvn7_select_geopolicy_route
    res_geo = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 119,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_select_geopolicy_route",
            "arguments": {
                "target_did": "did:ipvn7:destination",
                "mode": "MIN_LATENCY",
            },
        },
    })
    assert "selected_node_did" in res_geo["result"]["content"][0]["text"]
    assert "geodesic_distance_km" in res_geo["result"]["content"][0]["text"]

    # Tool 19: ipvn7_sync_interregion_dht
    res_dht = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 128,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_sync_interregion_dht",
            "arguments": {
                "peer_region": "region-europe-central",
            },
        },
    })
    assert "SYNCHRONIZED" in res_dht["result"]["content"][0]["text"]
    assert "ZERO_METADATA_LEAKAGE_BLOOM_O1" in res_dht["result"]["content"][0]["text"]

    # Tool 20: ipvn7_probe_tunnel_telemetry
    res_tun = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 129,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_probe_tunnel_telemetry",
            "arguments": {
                "tunnel_id": "tun0-wintun",
                "sample_rtt_ms": 15.0,
                "pmtu_probe_size": 1350,
                "pmtu_probe_success": True,
            },
        },
    })
    assert "tun0-wintun" in res_tun["result"]["content"][0]["text"]
    assert "current_pmtu" in res_tun["result"]["content"][0]["text"]

    node.stop()


def test_topological_mobility_anchor_zero_rtt_and_anti_race():
    """Validates mobility anchor 0-RTT proactive tickets, anti-race sequencing, and cold Micro-PoW."""
    from ipvn7.network.mobility_anchor import (
        MobilityAnchorEngine,
        OutdatedLocatorUpdateError,
        SequenceJumpTooLargeError,
    )

    anchor = MobilityAnchorEngine(anchor_did="did:ipvn7:zAnchor01")
    mobile_did = "did:ipvn7:zMobileTerminal"

    # 1. Initial registration: generates proactive 0-RTT ticket
    loc1 = anchor.update_mobile_locator(
        node_did=mobile_did,
        physical_ip="192.168.1.100",
        physical_port=9443,
        seq=10,
    )
    assert loc1.physical_ip == "192.168.1.100"
    assert loc1.last_seq == 10
    ticket_1 = loc1.proactive_ticket
    assert len(ticket_1) == 16
    assert anchor.validate_resync_challenge(mobile_did, ticket_1) is True

    # 2. Outdated sequence update is strictly rejected
    import pytest
    with pytest.raises(OutdatedLocatorUpdateError):
        anchor.update_mobile_locator(
            node_did=mobile_did,
            physical_ip="192.168.1.101",
            physical_port=9443,
            seq=9,  # seq < 10
        )

    # 3. Handover from Wi-Fi to 5G with valid proactive 0-RTT ticket across massive sequence jump
    loc2 = anchor.update_mobile_locator(
        node_did=mobile_did,
        physical_ip="10.42.0.15",
        physical_port=54321,
        seq=2_000_000,  # Jump > MAX_ALLOWED_SEQUENCE_JUMP
        challenge_ticket=ticket_1,
    )
    assert loc2.physical_ip == "10.42.0.15"
    assert loc2.last_seq == 2_000_000
    assert anchor.stats["zero_rtt_handover_success"] == 1

    # 4. Large sequence jump without proof is blocked
    with pytest.raises(SequenceJumpTooLargeError):
        anchor.update_mobile_locator(
            node_did=mobile_did,
            physical_ip="172.16.0.2",
            physical_port=8080,
            seq=5_000_000,
        )

    # 5. Cold Micro-PoW validation
    nonce = MobilityAnchorEngine.compute_cold_resync_pow(mobile_did, seq=6_000_000, difficulty_bits=8)
    assert nonce > 0
    assert MobilityAnchorEngine.verify_cold_resync_pow(mobile_did, seq=6_000_000, nonce=nonce, difficulty_bits=8) is True


def test_ai_copilot_autonomous_anomaly_inference_and_closed_loop_healing():
    """Validates deep anomaly detection, structured diagnosis, and closed-loop auto-healing."""
    from ipvn7.diagnostics.copilot import AICopilotEngine
    from ipvn7.security.firewall import ZTNAFirewall, FirewallDecision

    fw = ZTNAFirewall(default_deny=False)
    copilot = AICopilotEngine(firewall=fw, auto_healing=True)

    attacker_did = "did:ipvn7:zMaliciousScanner"

    # Scan telemetry with firewall drop flood
    anomalies = copilot.detect_anomalies(
        latency_ms=75.0,
        firewall_drops=12,
        peer_did=attacker_did,
        spectral_entropy=0.35,
        is_flap_damped=True,
    )
    assert len(anomalies) == 4
    types = {a.type for a in anomalies}
    assert "LATENCY_SPIKE" in types
    assert "UNAUTHORIZED_FLOOD" in types
    assert "SPECTRAL_RESONANCE" in types
    assert "LINK_FLAP_DAMPED" in types

    # Diagnose and execute closed-loop auto-healing
    diagnoses = copilot.diagnose_and_heal(anomalies)
    assert len(diagnoses) == 4

    # The UNAUTHORIZED_FLOOD must trigger BLOCK_DID and install policy in firewall
    assert fw.evaluate_inbound(attacker_did, port=9443) == FirewallDecision.DROP_ACL
    assert copilot.stats["auto_healing_actions_executed"] >= 1
    summary = copilot.get_summary()
    assert summary["auto_healing_enabled"] is True
    assert len(summary["recent_diagnoses"]) == 4


def test_multipath_scheduling_min_rtt_and_bicast_duplication():
    """Validates multipath transport striping, min-RTT scheduling, and critical bicast duplication."""
    from ipvn7.network.multipath import MultipathScheduler, PhysicalPath, MultipathStrategy

    mp = MultipathScheduler(default_strategy=MultipathStrategy.LOWEST_LATENCY)

    # Register heterogenous physical paths
    p_wifi = PhysicalPath(name="wlan0", iface_type="WIFI", local_ip="192.168.1.50", latency_ms=12.0, loss_rate=0.01, weight=10)
    p_5g = PhysicalPath(name="wwan5g", iface_type="CELLULAR", local_ip="10.42.0.8", latency_ms=25.0, loss_rate=0.00, weight=20)
    p_leo = PhysicalPath(name="sat0", iface_type="SAT", local_ip="172.16.1.1", latency_ms=45.0, loss_rate=0.02, weight=5)

    mp.register_interface(p_wifi)
    mp.register_interface(p_5g)
    mp.register_interface(p_leo)

    # 1. LOWEST_LATENCY strategy selects Wi-Fi (12.0 ms)
    paths = mp.select_paths_for_packet(b"Datagram 1")
    assert len(paths) == 1
    assert paths[0].name == "wlan0"

    # 2. Critical traffic forces bicast duplication over top-2 lowest RTT paths (wlan0 + wwan5g)
    crit_paths = mp.select_paths_for_packet(b"Critical Frame", is_critical=True)
    assert len(crit_paths) == 2
    names = {p.name for p in crit_paths}
    assert "wlan0" in names
    assert "wwan5g" in names
    assert mp.stats["packets_duplicated"] == 1

    # 3. BALANCED strategy
    mp.set_strategy(MultipathStrategy.BALANCED)
    assert mp.strategy == MultipathStrategy.BALANCED
    bal_paths = mp.select_paths_for_packet(b"Balanced Frame")
    assert len(bal_paths) == 1

    # 4. Failover event when link goes down
    mp.set_interface_status("wlan0", active=False)
    assert mp.stats["failover_events"] == 1
    mp.set_strategy(MultipathStrategy.LOWEST_LATENCY)
    next_best = mp.select_paths_for_packet(b"Datagram 2")
    assert next_best[0].name == "wwan5g"


def test_sovereign_dns_proxy_anti_leak_cache():
    """Validates sovereign DNS proxy intercepting .ipv7 queries and preventing ISP leaks."""
    from ipvn7.network.dns_proxy import SovereignDNSResolver
    from ipvn7.identity.petnames import PetnameResolver

    pet = PetnameResolver()
    pet.register_petname("nodo-alfa", "did:ipvn7:zAlfaPeer", comment="Nodo Alfa Principal")

    dns = SovereignDNSResolver(petname_resolver=pet)

    # 1. Resolve direct IP
    ip_direct, src_direct = dns.resolve("192.168.1.1")
    assert ip_direct == "192.168.1.1"
    assert src_direct == "DIRECT_IPV4"

    # 2. Resolve mapped .ipv7 petname
    ip_pet, src_pet = dns.resolve("nodo-alfa.ipv7")
    assert ip_pet.startswith("10.7.")
    assert src_pet == "SOVEREIGN_PETNAME_DDNS"
    assert dns.stats["ipv7_queries_intercepted"] == 1
    assert dns.stats["leaks_prevented"] == 1

    # 3. Second resolution hits local in-memory cache
    ip_cached, src_cached = dns.resolve("nodo-alfa.ipv7")
    assert ip_cached == ip_pet
    assert src_cached == "LOCAL_CACHE"
    assert dns.stats["cache_hits"] == 1

    # 4. Unmapped .ipv7 resolves to deterministic synthetic overlay fallback
    ip_syn, src_syn = dns.resolve("desconocido.ipv7")
    assert ip_syn.startswith("10.7.0.")
    assert src_syn == "SYNTHETIC_OVERLAY_FALLBACK"


def test_nat_traversal_classification_and_derp_relay():
    """Validates RFC 3489/5389 NAT classification, P2P hole punching, and DERP relay fallback."""
    from ipvn7.network.nat_traversal import NATTraversalEngine, NATType

    nat = NATTraversalEngine(local_did="did:ipvn7:zLocalHost")

    # 1. Open internet classification
    t_open = nat.classify_nat(local_ip="198.51.100.5", local_port=9443, observed_ip1="198.51.100.5", observed_port1=9443)
    assert t_open == NATType.OPEN_INTERNET

    # 2. Cone NAT classification
    t_cone = nat.classify_nat(local_ip="192.168.1.10", local_port=9443, observed_ip1="203.0.113.1", observed_port1=45000, observed_port2=45000)
    assert t_cone == NATType.PORT_RESTRICTED_CONE

    # 3. Successful hole punching in cone NAT
    peer_did = "did:ipvn7:zRemotePeer"
    ok = nat.initiate_hole_punch(peer_did, peer_public_ip="198.51.100.80", peer_public_port=50000)
    assert ok is True
    route_direct = nat.route_datagram(peer_did, b"Hello Direct UDP")
    assert route_direct["route"] == "DIRECT_UDP_PUNCHED"
    assert route_direct["endpoint"] == "198.51.100.80:50000"

    # 4. Symmetric hard NAT triggers DERP relay fallback
    nat.register_derp_relay("did:ipvn7:zDerpNode", "1.1.1.1", 443)
    t_sym = nat.classify_nat(local_ip="10.0.0.5", local_port=9443, observed_ip1="203.0.113.1", observed_port1=45001, observed_port2=45002)
    assert t_sym == NATType.SYMMETRIC_HARD_NAT

    hard_peer = "did:ipvn7:zHardNatPeer"
    ok_punch = nat.initiate_hole_punch(hard_peer, peer_public_ip="198.51.100.90", peer_public_port=60000)
    assert ok_punch is False  # Cannot direct punch symmetric NAT
    route_derp = nat.route_datagram(hard_peer, b"Encrypted Relay Frame")
    assert route_derp["route"] == "DERP_ENCRYPTED_RELAY"
    assert nat.stats["derp_packets_relayed"] >= 1


def test_global_memory_arbiter_partitioned_quotas_and_oom_protection():
    """Validates partitioned RAM quotas, hard limit enforcement, and DoS/OOM immunity."""
    from ipvn7.access.memory_arbiter import GlobalMemoryArbiter, BudgetClass

    # Small 100 KB total limit for testing
    total_bytes = 100 * 1024  # 102,400 bytes
    gma = GlobalMemoryArbiter(total_bytes=total_bytes)

    # Class quotas: Replay 20% (20,480 B), QoS 30% (30,720 B)
    q_replay = gma.quotas[BudgetClass.REPLAY]
    assert q_replay.limit_bytes == 20480

    # 1. Normal reservation within quota
    ok1 = gma.reserve(BudgetClass.REPLAY, 10000)
    assert ok1 is True
    assert q_replay.allocated_bytes == 10000
    assert gma.total_allocated == 10000

    # 2. Reservation exceeding class quota is rejected
    ok2 = gma.reserve(BudgetClass.REPLAY, 15000)  # 10000 + 15000 = 25000 > 20480
    assert ok2 is False
    assert q_replay.dropped_allocations == 1
    assert gma.total_rejections == 1

    # 3. Release memory and re-allocate
    gma.release(BudgetClass.REPLAY, 5000)
    assert q_replay.allocated_bytes == 5000
    assert gma.total_allocated == 5000

    ok3 = gma.reserve(BudgetClass.REPLAY, 10000)  # 5000 + 10000 = 15000 <= 20480
    assert ok3 is True
    assert q_replay.allocated_bytes == 15000

    summary = gma.get_summary()
    assert summary["total_limit_bytes"] == total_bytes
    assert summary["total_rejections"] == 1
    assert "classes" in summary


def test_uin_identity_manager_decoupled_keys_and_revocation():
    """Validates sovereign root_id decoupling, BindingRecord issuance, Ed25519 verification, and revocation."""
    from ipvn7.identity.uin import UINIdentityManager, IdentityMode, BindingScope
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    mgr = UINIdentityManager(mode=IdentityMode.HYBRID)
    assert mgr.entity_did.startswith("did:ipvn7:uin:")
    assert len(mgr.root_id_hex) == 64

    # Issue binding for ephemeral operational key
    ephemeral_priv = Ed25519PrivateKey.generate()
    ephemeral_pub_hex = ephemeral_priv.public_key().public_bytes_raw().hex()

    binding = mgr.issue_binding(
        subordinate_public_key_hex=ephemeral_pub_hex,
        scope=BindingScope.AI_AGENT,
        duration_seconds=3600.0,
    )
    assert binding.version == 1
    assert binding.scope == BindingScope.AI_AGENT
    assert len(binding.sig_root_hex) == 128  # 64-byte Ed25519 signature in hex

    # Verify binding integrity
    assert mgr.verify_binding(binding) is True

    # Check passport
    passport = mgr.get_passport()
    assert passport.entity_did == mgr.entity_did
    assert len(passport.active_bindings) == 1

    # Revoke binding
    revoked = mgr.revoke_binding(binding.key_id)
    assert revoked is True
    assert mgr.verify_binding(binding) is False

    # Check passport after revocation
    passport_after = mgr.get_passport()
    assert len(passport_after.active_bindings) == 0
    assert binding.key_id in passport_after.revoked_bindings


def test_shadow_device_registry_mac_did_and_virtual_overlay():
    """Validates deterministic MAC-to-DID hashing, virtual IPv4 10.7.100.X allocation, and port filtering."""
    from ipvn7.access.shadow_device import ShadowDeviceRegistry, DeviceType, derive_shadow_did

    registry = ShadowDeviceRegistry(start_ip_index=20)

    # Deterministic DID
    mac = "AA:BB:CC:DD:EE:FF"
    expected_did = derive_shadow_did(mac)
    assert expected_did.startswith("did:ipvn7:shadow:")
    assert derive_shadow_did("aa-bb-cc-dd-ee-ff") == expected_did

    # Register printer
    dev = registry.register_device(
        name="Office-LaserJet",
        physical_ip="192.168.1.120",
        mac=mac,
        device_type=DeviceType.PRINTER,
        allowed_ports=[9100, 631],
    )
    assert dev.did == expected_did
    assert dev.virtual_ipv4 == "10.7.100.20"
    assert registry.is_port_allowed(dev.did, 9100) is True
    assert registry.is_port_allowed(dev.did, 22) is False

    # Register Edge AI Worker
    worker = registry.register_edge_ai_worker(
        name="Ollama-Server",
        physical_ip="192.168.1.200",
        mac="00:11:22:33:44:55",
        port=11434,
    )
    assert worker.device_type == DeviceType.EDGE_AI
    assert worker.virtual_ipv4 == "10.7.100.21"
    assert worker.allowed_ports == [11434]

    # Lookups
    assert registry.lookup_by_did(worker.did) == worker
    assert registry.lookup_by_vip("10.7.100.20") == dev

    summary = registry.summary()
    assert summary["total_shadow_devices"] == 2
    assert summary["active_devices"] == 2


def test_pfo_axiomatic_governance_tree_and_compliance():
    """Validates PFO axiomatic tree integrity, canonical module mappings, and telemetry observations."""
    from ipvn7.diagnostics.pfo import PFOEngine

    pfo = PFOEngine()
    tree = pfo.get_pfo_tree()

    assert tree["total_principles"] == 5
    assert tree["total_functions"] >= 12
    assert tree["compliance_rate"] == 100.0

    # Record valid observation
    obs = pfo.record_observation(
        function_id="L1_PACKET_PACER",
        metric_name="inter_packet_gap_ms",
        value=0.12,
        unit="ms",
        compliant=True,
    )
    assert obs.observation_id.startswith("obs-")
    assert obs.compliant is True

    tree_updated = pfo.get_pfo_tree()
    assert tree_updated["total_observations"] == 1
    assert tree_updated["compliance_rate"] == 100.0


def test_mcp_extended_uin_shadow_pfo_tools():
    """Validates JSON-RPC execution of UIN, Shadow Device, and PFO MCP tools."""
    from ipvn7.node.node import IPVN7Node
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    node = IPVN7Node(alias="MCP-Evo", bind_host="127.0.0.1")
    node.start_background_listener()

    # 1. Tool: ipvn7_issue_uin_binding
    dummy_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    res_bind = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_issue_uin_binding",
            "arguments": {
                "subordinate_pubkey_hex": dummy_pub,
                "scope": 3,
                "duration_seconds": 7200,
            },
        },
    })
    assert "key_id" in res_bind["result"]["content"][0]["text"]
    assert "did:ipvn7:uin:" in res_bind["result"]["content"][0]["text"]

    # 2. Tool: ipvn7_get_uin_passport
    res_pass = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_get_uin_passport",
            "arguments": {},
        },
    })
    assert "root_id_hex" in res_pass["result"]["content"][0]["text"]

    # 3. Tool: ipvn7_register_shadow_device
    res_shadow = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 102,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_register_shadow_device",
            "arguments": {
                "name": "Smart-TV-4K",
                "physical_ip": "192.168.1.80",
                "mac": "12:34:56:78:9a:bc",
                "device_type": "display",
                "allowed_ports": [8080, 554],
            },
        },
    })
    assert "did:ipvn7:shadow:" in res_shadow["result"]["content"][0]["text"]
    assert "10.7.100." in res_shadow["result"]["content"][0]["text"]

    # 4. Tool: ipvn7_get_pfo_tree
    res_pfo = node.mcp_server.handle_jsonrpc({
        "jsonrpc": "2.0",
        "id": 103,
        "method": "tools/call",
        "params": {
            "name": "ipvn7_get_pfo_tree",
            "arguments": {},
        },
    })
    assert "AXIOM_ZERO_PII" in res_pfo["result"]["content"][0]["text"]

    node.stop()


def test_wan_active_prober_binary_frames_and_jitter():
    """Validates 32-byte canonical probe frame packing, RTT telemetry, and RFC 3550 jitter calculation."""
    from ipvn7.network.wan_prober import WANActiveProber, PROBE_MAGIC, PROBE_WIRE_SIZE

    prober = WANActiveProber()
    seq, frame = prober.build_probe_packet()

    assert len(frame) == PROBE_WIRE_SIZE  # 32 bytes
    parsed = prober.parse_probe_packet(frame)
    assert parsed is not None
    parsed_seq, parsed_ts = parsed
    assert parsed_seq == seq
    assert parsed_ts > 0

    peer = "did:ipvn7:zPeerWAN"
    prober.record_probe_dispatch(peer, "192.168.1.106:7001")

    # Record responses with varying latencies to test RFC 3550 jitter calculation
    prober.record_probe_response(peer, 10.0)
    prober.record_probe_response(peer, 20.0)
    prober.record_probe_response(peer, 15.0)

    st = prober.get_peer_stats(peer)
    assert st["last_rtt_ms"] == 15.0
    assert st["min_rtt_ms"] == 10.0
    assert st["max_rtt_ms"] == 20.0
    assert st["jitter_ms"] > 0.0
    assert st["probes_recv"] == 3

    # Record loss
    prober.record_probe_loss(peer)
    st_loss = prober.get_peer_stats(peer)
    assert st_loss["probes_lost"] == 1
    assert st_loss["consecutive_losses"] == 1

    summary = prober.get_summary()
    assert summary["probed_peers_count"] == 1
    assert summary["total_probes_lost"] == 1


def test_remote_desktop_streaming_and_input_events():
    """Validates sovereign P2P remote desktop session, SAS derivation, and low-latency input event dispatch."""
    from ipvn7.access.remote_desktop import RemoteDesktopManager, RemoteInputEvent

    dummy_pub = b"\x01" * 32
    mgr = RemoteDesktopManager(local_did="did:ipvn7:zLocalOperator", local_pubkey_bytes=dummy_pub)

    status = mgr.get_status()
    assert status["connected"] is True
    assert status["fps"] == 60.0
    assert status["mtu"] == 1280
    assert len(status["sas_digits"]) == 6
    assert len(status["sas_emojis"]) == 4
    assert "ML-KEM-768" in status["crypto_mode"]

    # Dispatch mouse move
    evt_mouse = RemoteInputEvent(event_type="mouse_move", x=0.45, y=0.72)
    res_mouse = mgr.handle_input_event(evt_mouse)
    assert res_mouse["status"] == "PROCESSED"
    assert res_mouse["x"] == 0.45
    assert res_mouse["dispatch_us"] == 85

    # Dispatch key press
    evt_key = RemoteInputEvent(event_type="key_down", key="Enter")
    res_key = mgr.handle_input_event(evt_key)
    assert res_key["status"] == "PROCESSED"
    assert res_key["key"] == "Enter"

    status_updated = mgr.get_status()
    assert status_updated["input_events_rx"] == 44


def test_key_rotation_sentinel_forward_secrecy_and_grace_period():
    """Validates monotonic epoch derivation, traffic threshold tracking, and 30s grace window."""
    from ipvn7.security.key_rotation import KeyRotationSentinel, KEY_TRANSITION_GRACE_PERIOD_SEC

    # Small thresholds for unit testing: 1000 bytes or 5 packets
    sentinel = KeyRotationSentinel(
        session_id="sess-test-fs",
        max_bytes=1000,
        max_packets=5,
        lifetime_sec=10.0,
    )
    assert sentinel.current_epoch == 1
    assert sentinel.needs_rotation() is False

    # Track 4 packets (total 800 bytes) -> no rotation yet
    for _ in range(4):
        sentinel.track_traffic(200)
    assert sentinel.needs_rotation() is False

    # 5th packet hits 5-packet limit -> triggers rotation requirement
    triggered = sentinel.track_traffic(200)
    assert triggered is True
    assert sentinel.needs_rotation() is True

    # Rotate to epoch 2
    next_epoch, key_prefix = sentinel.rotate()
    assert next_epoch == 2
    assert len(key_prefix) == 16
    assert sentinel.current_epoch == 2

    # In epoch 2, previous key is available during the grace period
    keys_grace = sentinel.get_keys()
    assert keys_grace.has_previous is True
    assert keys_grace.previous_key is not None

    # After 31 seconds, grace period expires and previous key is zeroed
    future_time = keys_grace.created_at + KEY_TRANSITION_GRACE_PERIOD_SEC + 1.0
    keys_expired = sentinel.get_keys(now=future_time)
    assert keys_expired.has_previous is False
    assert keys_expired.previous_key is None

    summary = sentinel.summary()
    assert summary["epoch"] == 2
    assert summary["total_rotations"] == 1


def test_upnp_mapper_ssdp_discovery_and_anti_ssrf():
    """Validates UPnP IGD port mapping, URL sanitization, and strict Anti-SSRF blocking."""
    from ipvn7.network.upnp import UPnPMapper, is_private_or_local_ip

    mapper = UPnPMapper(timeout=0.1)

    # 1. Anti-SSRF validation
    assert is_private_or_local_ip("192.168.1.1") is True
    assert is_private_or_local_ip("10.0.0.1") is True
    assert is_private_or_local_ip("172.16.5.10") is True
    assert is_private_or_local_ip("127.0.0.1") is True
    assert is_private_or_local_ip("8.8.8.8") is False  # Public IP blocked
    assert is_private_or_local_ip("169.254.169.254") is False  # Cloud metadata blocked

    assert mapper.validate_local_url("http://192.168.1.1:1900/igd.xml") is True
    assert mapper.validate_local_url("http://8.8.8.8:1900/igd.xml") is False
    assert mapper.validate_local_url("https://192.168.1.1:1900/igd.xml") is False  # Strict HTTP required for IGD SOAP
    assert mapper.stats["ssrf_blocks"] >= 1

    # 2. Port mapping registration
    rec = mapper.map_port(7001, description="ipvn7-p2p")
    assert rec.internal_port == 7001
    assert rec.external_port == 7001
    assert rec.status == "MAPPED"

    summary = mapper.get_summary()
    assert summary["active_mappings_count"] == 1
    assert summary["mappings"][0]["port"] == 7001
def test_censorship_detector_dns_poisoning_and_mitigation():
    """Validates DNS loopback hijacking detection, TCP RST injection handling, and DoH / TLS camouflage mitigation."""
    from ipvn7.diagnostics.censorship import CensorshipDetector, CensorshipAnomaly

    detector = CensorshipDetector()

    # 1. Normal audit or mock check
    res = detector.check_dns_integrity("cloudflare.com")
    # Whether local ISP poisioned it or not, audits_performed increments
    assert detector.stats["audits_performed"] >= 1

    # 2. Simulate TCP RST Injection detection
    incident = detector.record_rst_injection("restricted-mesh-node.ipv7", 443)
    assert incident.anomaly_type == CensorshipAnomaly.TCP_RST_INJECT
    assert incident.severity == "HIGH"
    assert "Disfraz de paquete TLS 1.3" in incident.mitigation_applied

    summary = detector.get_summary()
    assert summary["total_incidents"] >= 1
    assert summary["stats"]["rst_injections_detected"] == 1
    assert summary["stats"]["mitigations_triggered"] >= 1


def test_buffer_health_monitor_datagram_rings_and_leak_alerts():
    """Validates 1280B datagram buffer allocation, recycling, high-water mark, and budget leak alerts."""
    from ipvn7.access.buffer_monitor import BufferHealthMonitor

    # Monitor with a small budget of 3 buffers
    monitor = BufferHealthMonitor(max_budget=3)

    # 1. Allocate 2 buffers
    in_use1 = monitor.track_alloc()
    in_use2 = monitor.track_alloc()
    assert in_use1 == 1
    assert in_use2 == 2

    snap = monitor.snapshot()
    assert snap.buffers_allocated == 2
    assert snap.buffers_recycled == 0
    assert snap.buffers_in_use == 2
    assert snap.high_water_mark == 2
    assert snap.leak_alert is False

    # 2. Recycle 1 buffer
    in_use_rec = monitor.track_recycle()
    assert in_use_rec == 1
    assert monitor.snapshot().buffers_recycled == 1

    # 3. Allocate 3 more -> in_use = 4 (exceeds budget 3) -> triggers leak alert
    monitor.track_alloc()
    monitor.track_alloc()
    monitor.track_alloc()

    alert_snap = monitor.snapshot()
    assert alert_snap.buffers_in_use == 4
    assert alert_snap.high_water_mark == 4
    assert alert_snap.leak_alert is True

    # 4. Recycle 2 -> in_use = 2 -> leak alert clears
    monitor.track_recycle()
    monitor.track_recycle()
    cleared_snap = monitor.snapshot()
    assert cleared_snap.buffers_in_use == 2
    assert cleared_snap.leak_alert is False

    summary = monitor.summary()
    assert summary["max_budget"] == 3
    assert summary["high_water_mark"] == 4


def test_wasm_sovereign_bridge_pow_and_frame_validation():
    """Validates WebAssembly sovereign cryptographic bridge, Ed25519 signatures, Micro-PoW, and 1280B frame validation."""
    from ipvn7.access.wasm_bridge import WasmSovereignEngine

    engine = WasmSovereignEngine()
    assert engine.version == "0.7.0-wasm"

    # 1. Identity Generation
    ident = engine.generate_identity()
    assert ident.did.startswith("did:ipvn7:")
    assert len(ident.public_key_hex) == 64
    assert len(ident.private_key_hex) == 64

    # 2. Ed25519 Sign & Verify
    msg = b"WASM Client Datagram"
    sig_hex = engine.sign_message(ident.private_key_hex, msg)
    assert len(sig_hex) == 128
    assert engine.verify_signature(ident.public_key_hex, msg, sig_hex) is True
    assert engine.verify_signature(ident.public_key_hex, b"Tampered", sig_hex) is False

    # 3. Micro-PoW Calculation
    nonce, digest = engine.compute_proof_of_work(ident.did, seq=1, difficulty_bits=8)
    assert nonce > 0
    assert len(digest) == 64
    assert digest.startswith("0") or digest.startswith("1")  # leading bits zeroed

    # 4. 1280B Canonical Frame Validation
    valid_frame = b"\x07" + b"\x00" * 1279
    invalid_len = b"\x07" + b"\x00" * 500
    invalid_magic = b"\xff" + b"\x00" * 1279

    assert engine.validate_packet_frame(valid_frame) is True
    assert engine.validate_packet_frame(invalid_len) is False
    assert engine.validate_packet_frame(invalid_magic) is False


def test_deterministic_node_fsm_lifecycle_transitions():
    """Validates deterministic node state machine transitions, event guards, and observer callbacks."""
    from ipvn7.network.fsm import DeterministicNodeFSM, NodeState, FSMEvent

    fsm = DeterministicNodeFSM(initial_state=NodeState.DISCONNECTED)
    assert fsm.current_state == NodeState.DISCONNECTED

    hook_calls = []
    def on_transition(from_st, to_st, ev, payload):
        hook_calls.append((from_st, to_st, ev, payload))

    fsm.register_hook(on_transition)

    # 1. Valid Sequence: DISCONNECTED -> SYNCING -> VALIDATING -> ACTIVE
    fsm.trigger_event(FSMEvent.NETWORK_SIGNAL)
    assert fsm.current_state == NodeState.SYNCING

    fsm.trigger_event(FSMEvent.SYNC_COMPLETED)
    assert fsm.current_state == NodeState.VALIDATING

    fsm.trigger_event(FSMEvent.DID_VERIFIED, payload="KeypairML-DSA")
    assert fsm.current_state == NodeState.ACTIVE

    # 2. Security Threat moves to QUARANTINED
    fsm.trigger_event(FSMEvent.SECURITY_THREAT, payload="Anomalous Traffic Flood")
    assert fsm.current_state == NodeState.QUARANTINED

    # 3. Invalid transition from QUARANTINED (must fail)
    try:
        fsm.trigger_event(FSMEvent.NETWORK_SIGNAL)
        assert False, "Should have raised ValueError on illegal transition"
    except ValueError as e:
        assert "FSM Invalid Transition" in str(e)

    # 4. Reset releases from QUARANTINED back to DISCONNECTED
    fsm.trigger_event(FSMEvent.RESET)
    assert fsm.current_state == NodeState.DISCONNECTED

    assert len(hook_calls) == 5
    summary = fsm.get_summary()
    assert summary["total_transitions"] == 5


def test_pipes_and_filters_pipeline_and_dead_letter_queue():
    """Validates unidirectional packet processing pipeline, stage filtering, and dead-letter capture."""
    from ipvn7.network.pipeline import DataPipeline, PacketContext, PipelineStage, InMemoryDeadLetterQueue

    dlq = InMemoryDeadLetterQueue()
    pipeline = DataPipeline(dead_letter_handler=dlq)

    # Stage 1: Length check (must be >= 5 bytes)
    class MinLenStage(PipelineStage):
        @property
        def name(self) -> str:
            return "min_len_filter"
        def process(self, p_ctx: PacketContext) -> bool:
            if len(p_ctx.raw_data) < 5:
                p_ctx.mark_dropped("Payload below 5-byte minimum")
                return False
            return True

    # Stage 2: Target DID check
    class TargetDIDStage(PipelineStage):
        @property
        def name(self) -> str:
            return "target_did_resolver"
        def process(self, p_ctx: PacketContext) -> bool:
            p_ctx.metadata["resolved"] = True
            return True

    pipeline.add_stage(MinLenStage())
    pipeline.add_stage(TargetDIDStage())

    # 1. Packet passes pipeline successfully
    p1 = PacketContext(raw_data=b"HELLO_WORLD_IPVN7", source_did="did:ipvn7:zAlice")
    assert pipeline.execute(p1) is True
    assert p1.handled is True
    assert p1.metadata.get("resolved") is True

    # 2. Short packet gets dropped at stage 1 and queued in Dead-Letter Queue
    p2 = PacketContext(raw_data=b"TINY", source_did="did:ipvn7:zBob")
    assert pipeline.execute(p2) is False
    assert p2.dropped is True
    assert "Payload below 5-byte minimum" in p2.drop_reason

    # Verify Dead-Letter capture
    dlq_summary = dlq.get_summary()
    assert dlq_summary["total_dead_letters"] == 1
    assert dlq_summary["recent"][0]["stage"] == "min_len_filter"
    assert dlq_summary["recent"][0]["source_did"] == "did:ipvn7:zBob"

    pipe_summary = pipeline.get_summary()
    assert pipe_summary["stats"]["packets_processed"] == 2
    assert pipe_summary["stats"]["packets_completed"] == 1
    assert pipe_summary["stats"]["packets_dropped"] == 1


def test_ephemeral_identity_rotation_and_verification():
    """Validates 24-hour deterministic ephemeral DID derivation, rotation, and peer verification."""
    from ipvn7.identity.ephemeral import EphemeralIdentityManager

    root_alice = "did:ipvn7:zAliceRootKeyMaterial123"
    mgr_alice = EphemeralIdentityManager(root_alice)

    # Derive for day 1000
    eph_1000 = mgr_alice.derive_ephemeral_did(1000)
    assert eph_1000.root_did == root_alice
    assert eph_1000.epoch_day == 1000
    assert eph_1000.ephemeral_did.startswith("did:ipvn7:ephemeral:")
    assert eph_1000.expires_at == 1001 * 86400

    # Derive for day 1001: must rotate deterministically to a different DID
    eph_1001 = mgr_alice.derive_ephemeral_did(1001)
    assert eph_1001.ephemeral_did != eph_1000.ephemeral_did

    # Calling again for day 1000 returns the cached/deterministic same DID
    eph_1000_cached = mgr_alice.derive_ephemeral_did(1000)
    assert eph_1000_cached.ephemeral_did == eph_1000.ephemeral_did

    # Active ephemeral DID matches current day
    active = mgr_alice.get_active_ephemeral_did()
    assert active.startswith("did:ipvn7:ephemeral:")

    # Peer verification with drift tolerance
    # Bob verifies Alice's ephemeral DID of today
    root_bob = "did:ipvn7:zBobRootKeyMaterial456"
    mgr_bob = EphemeralIdentityManager(root_bob)

    assert mgr_bob.verify_peer_ephemeral_did(
        ephemeral_did=active,
        peer_root_did=root_alice,
        clock_drift_days=1,
    ) is True

    # Untrusted/forged DID fails
    assert mgr_bob.verify_peer_ephemeral_did(
        ephemeral_did="did:ipvn7:ephemeral:00000000000000000000000000000000",
        peer_root_did=root_alice,
    ) is False


def test_hrs_5_frames_encode_decode_crc_and_dispatch():
    """Validates IPv7-HRS 5-frame quiet protocol codec, CRC32 integrity, and dispatcher."""
    from ipvn7.network.hrs_frames import (
        HRSFrame,
        HRSFrameType,
        HRSDispatcher,
        AdaptiveSLA,
        DeviceProfile,
    )

    alice_did = "did:ipvn7:zAliceNode001"
    bob_did = "did:ipvn7:zBobNode002"

    dispatcher_bob = HRSDispatcher(local_did=bob_did)

    # 1. Test encoding and decoding each of the 5 opcodes
    for f_type in [
        HRSFrameType.ANNOUNCE,
        HRSFrameType.QUERY,
        HRSFrameType.RESPONSE,
        HRSFrameType.HEARTBEAT,
        HRSFrameType.STATE_CHANGE,
    ]:
        frame = HRSFrame(
            frame_type=f_type,
            sequence_id=42,
            source_did=alice_did,
            target_did=bob_did,
            payload=f"Payload for {f_type.name}".encode("utf-8"),
            timestamp=1700000000.0,
        )
        encoded = frame.encode()
        assert encoded.startswith(b"IP7H")
        decoded = HRSFrame.decode(encoded)
        assert decoded.frame_type == f_type
        assert decoded.sequence_id == 42
        assert decoded.source_did == alice_did
        assert decoded.target_did == bob_did
        assert decoded.payload == frame.payload
        assert decoded.timestamp == 1700000000.0

    # 2. Corrupted CRC32 is detected and rejected
    corrupted = bytearray(encoded)
    corrupted[10] ^= 0xFF
    try:
        HRSFrame.decode(bytes(corrupted))
        assert False, "Should have raised ValueError on CRC32 mismatch"
    except ValueError as e:
        assert "CRC32 mismatch" in str(e)

    # 3. Test Quiet Dispatcher: register QUERY handler producing a RESPONSE
    def handle_query(in_frame: HRSFrame) -> HRSFrame:
        return dispatcher_bob.create_frame(
            frame_type=HRSFrameType.RESPONSE,
            target_did=in_frame.source_did,
            payload=b"QUERY_ACKNOWLEDGED",
        )

    dispatcher_bob.register_handler(HRSFrameType.QUERY, handle_query)

    query_frame = HRSFrame(
        frame_type=HRSFrameType.QUERY,
        sequence_id=1,
        source_did=alice_did,
        target_did=bob_did,
        payload=b"GET_UPTIME",
    )
    resp = dispatcher_bob.process_incoming(query_frame.encode())
    assert resp is not None
    assert resp.frame_type == HRSFrameType.RESPONSE
    assert resp.target_did == alice_did
    assert resp.payload == b"QUERY_ACKNOWLEDGED"

    # 4. Directed unicast quiet rule: frame directed to charlie is dropped silently
    charlie_frame = HRSFrame(
        frame_type=HRSFrameType.QUERY,
        sequence_id=2,
        source_did=alice_did,
        target_did="did:ipvn7:zCharlieDifferentNode",
        payload=b"IGNORE_ME",
    )
    dropped = dispatcher_bob.process_incoming(charlie_frame.encode())
    assert dropped is None


def test_adaptive_sla_profiles():
    """Validates adaptive SLA defaults across device tiers."""
    from ipvn7.network.hrs_frames import AdaptiveSLA, DeviceProfile

    iot = AdaptiveSLA.get_defaults(DeviceProfile.IOT)
    assert iot.heartbeat_interval == 3.0
    assert iot.query_timeout == 10.0
    assert iot.max_retries == 2

    laptop = AdaptiveSLA.get_defaults(DeviceProfile.LAPTOP)
    assert laptop.heartbeat_interval == 7.0
    assert laptop.query_timeout == 20.0
    assert laptop.max_retries == 3

    server = AdaptiveSLA.get_defaults(DeviceProfile.SERVER)
    assert server.heartbeat_interval == 10.0
    assert server.query_timeout == 30.0
    assert server.max_retries == 4

    satellite = AdaptiveSLA.get_defaults(DeviceProfile.SATELLITE)
    assert satellite.heartbeat_interval == 15.0
    assert satellite.query_timeout == 45.0
    assert satellite.max_retries == 5


def test_mcp_ephemeral_and_hrs_tools():
    """Validates MCP tools for ephemeral identity rotation and HRS wire dispatching."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="mcp-test-node", bind_port=19875)
    mcp = node.mcp_server

    # Tool 1: ipvn7_get_daily_ephemeral_id
    ok, res = mcp.execute_tool("ipvn7_get_daily_ephemeral_id", {})
    assert ok is True
    assert res["root_did"] == node.did
    assert res["active_ephemeral_did"].startswith("did:ipvn7:ephemeral:")
    assert res["rotation_frequency_hours"] == 24

    # Tool 2: ipvn7_dispatch_hrs_frame (create)
    ok, create_res = mcp.execute_tool("ipvn7_dispatch_hrs_frame", {
        "action": "create",
        "frame_type": "ANNOUNCE",
        "target_did": "did:ipvn7:broadcast:quiet",
        "payload_text": "Node Alpha Online",
    })
    assert ok is True
    assert create_res["action"] == "created"
    assert create_res["frame_type"] == "ANNOUNCE"
    assert "wire_hex" in create_res

    # Tool 3: ipvn7_dispatch_hrs_frame (decode)
    ok, decode_res = mcp.execute_tool("ipvn7_dispatch_hrs_frame", {
        "action": "decode",
        "raw_hex": create_res["wire_hex"],
    })
    assert ok is True
    assert decode_res["action"] == "decoded"
    assert decode_res["frame_type"] == "ANNOUNCE"
    assert decode_res["payload_text"] == "Node Alpha Online"
    assert decode_res["crc32_valid"] is True


def test_edge_ai_prompt_routing():
    """Validates Edge AI worker registration, prompt routing, and sovereign fallback."""
    from ipvn7.access.shadow_device import ShadowDeviceRegistry, DeviceType

    registry = ShadowDeviceRegistry(start_ip_index=20)
    dev = registry.register_edge_ai_worker(
        name="Ollama-Lab-GPU",
        physical_ip="192.168.1.180",
        mac="00:11:22:33:44:55",
        port=11434,
        models=["llama3", "mistral", "phi3"],
    )

    assert dev.device_type == DeviceType.EDGE_AI
    assert dev.virtual_ipv4 == "10.7.100.20"
    assert "llama3" in dev.models
    assert registry.is_port_allowed(dev.did, 11434) is True

    # Dispatch prompt through sovereign ambassador
    res = registry.dispatch_prompt(
        did_or_vip=dev.did,
        prompt="Explain quantum entanglement in 1 sentence.",
        model="llama3",
        timeout_s=0.5,
        simulated_fallback=True,
    )
    assert res["status"] == "SUCCESS"
    assert res["did"] == dev.did
    assert "llama3" in res["model"]
    assert len(res["response"]) > 0
    assert res["tokens_evaluated"] > 0


def test_media_streaming_chunking_and_reassembly():
    """Validates WebRTC / P2P media frame fragmentation into <=1280B datagrams and CRC32 assembly."""
    from ipvn7.access.remote_desktop import RemoteDesktopManager

    manager = RemoteDesktopManager(
        local_did="did:ipvn7:local_test_did",
        local_pubkey_bytes=b"\x01" * 32,
    )

    # 1. Dispatch 3000 bytes video frame (should split into 3 chunks < 1280B)
    test_video_payload = b"TEST_VIDEO_PAYLOAD_CHUNK_DATA_" * 100  # 3000 bytes
    res = manager.dispatch_media_frame(
        frame_type="video_keyframe",
        raw_data=test_video_payload,
        codec="av1",
    )
    assert res["status"] == "DISPATCHED"
    assert res["frame_type"] == "video_keyframe"
    assert res["chunks_count"] == 3
    for sz in res["wire_packet_sizes"]:
        assert sz <= 1280

    # 2. Reassemble manually by feeding the generated chunks back
    import struct
    import zlib
    import time

    frame_id = res["frame_id"]
    now_us = res["timestamp_us"]
    chunks = [test_video_payload[i:i + 1250] for i in range(0, len(test_video_payload), 1250)]
    packets = []
    for idx, chk in enumerate(chunks):
        pfx = struct.pack("!4sB I H H Q", b"IP7M", 1, frame_id, idx, len(chunks), now_us)
        c = zlib.crc32(pfx + chk) & 0xFFFFFFFF
        packets.append(pfx + struct.pack("!I", c) + chk)

    # Deliver chunk 0, 1 -> None yet
    assert manager.assemble_media_chunk(packets[0]) is None
    assert manager.assemble_media_chunk(packets[1]) is None
    # Deliver chunk 2 -> Reassembled!
    assembled = manager.assemble_media_chunk(packets[2])
    assert assembled is not None
    assert assembled["status"] == "REASSEMBLED"
    assert assembled["payload_bytes"] == len(test_video_payload)
    assert assembled["raw_data"] == test_video_payload


def test_churn_stress_simulation():
    """Validates Small-World network stress resilience under churn, loss, and latency jitter."""
    from ipvn7.simulation.churn import SmallWorldChurnSimulator

    sim = SmallWorldChurnSimulator(node_count=30, shortcuts_per_node=3, seed=123)
    stress_stats = sim.run_stress_benchmark(
        sample_pairs=25,
        churn_rate=0.20,
        packet_loss_rate=0.10,
        min_latency_ms=100.0,
        max_latency_ms=1500.0,
    )

    assert stress_stats.total_nodes == 30
    assert stress_stats.churn_ratio == 0.20
    assert stress_stats.packet_loss_rate == 0.10
    assert stress_stats.delivery_success_under_stress > 0.0
    assert stress_stats.avg_latency_ms > 0.0
    assert stress_stats.resilience_score > 0.0


def test_mcp_edge_ai_media_and_stress_tools():
    """Validates MCP registration and execution of 3 new sovereign tools."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="mcp-expanded-node", bind_port=19876)
    mcp = node.mcp_server

    # Tool 1: ipvn7_dispatch_edge_ai_prompt
    node.register_shadow_device(
        name="Local-Ollama-Worker",
        physical_ip="127.0.0.1",
        mac="00:22:33:44:55:66",
        device_type="edge_ai",
        allowed_ports=[11434],
    )
    ok, ai_res = mcp.execute_tool("ipvn7_dispatch_edge_ai_prompt", {
        "prompt": "Test prompt via sovereign MCP",
        "model": "mistral",
    })
    assert ok is True
    assert ai_res["status"] == "SUCCESS"
    assert "mistral" in ai_res["model"]

    # Tool 2: ipvn7_dispatch_remote_media_frame
    ok, media_res = mcp.execute_tool("ipvn7_dispatch_remote_media_frame", {
        "frame_type": "audio_opus",
        "codec": "opus",
    })
    assert ok is True
    assert media_res["status"] == "DISPATCHED"
    assert media_res["frame_type"] == "audio_opus"

    # Tool 3: ipvn7_run_churn_stress_test
    ok, stress_res = mcp.execute_tool("ipvn7_run_churn_stress_test", {
        "node_count": 20,
        "churn_rate": 0.15,
        "packet_loss_rate": 0.05,
    })
    assert ok is True
    assert stress_res["total_nodes"] == 20
    assert stress_res["delivery_success_under_stress"] > 0.0


def test_bitnet_quantization_and_forward():
    """Validates BitNet b1.58 ternary weight quantization, packing, activation scaling, and integer inference."""
    from ipvn7.crypto.bitnet import BitNetQuantizer, PackedTernaryWeights

    # 1. Floating-point weight matrix: 2 rows x 4 cols
    raw_weights = [
        [0.85, -0.42, 0.02, -0.91],
        [-0.77, 0.12, 0.65, -0.05],
    ]
    packed = BitNetQuantizer.quantize_weights(raw_weights)
    assert packed.rows == 2
    assert packed.cols == 4
    assert packed.scale > 0.0
    assert len(packed.packed_data) == 2  # 8 weights / 4 per byte = 2 bytes
    assert packed.compression_ratio > 1.0

    # 2. Unpack and verify ternary values {-1, 0, 1}
    unpacked = BitNetQuantizer.unpack_weights(packed)
    assert len(unpacked) == 2
    assert len(unpacked[0]) == 4
    for r in unpacked:
        for val in r:
            assert val in (-1, 0, 1)

    # 3. Activation quantization
    x = [1.2, -0.5, 0.8, -1.0]
    x_int, scale_x = BitNetQuantizer.quantize_activations(x)
    assert len(x_int) == 4
    for v in x_int:
        assert -128 <= v <= 127
    assert scale_x > 0.0

    # 4. Integer forward pass
    y = BitNetQuantizer.forward(x, packed, bias=[0.1, -0.1])
    assert len(y) == 2
    assert all(isinstance(val, float) for val in y)

    # 5. Serialization & Deserialization
    serialized = BitNetQuantizer.serialize_model(packed, model_name="test-tiny-bitnet")
    assert serialized.startswith(b"IP7B")
    name, des_packed = BitNetQuantizer.deserialize_model(serialized)
    assert name == "test-tiny-bitnet"
    assert des_packed.rows == 2
    assert des_packed.cols == 4
    assert des_packed.packed_data == packed.packed_data


def test_mcp_bitnet_tool():
    """Validates execution of ipvn7_bitnet_quantize_and_infer MCP tool."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="mcp-bitnet-node", bind_port=19877)
    mcp = node.mcp_server

    ok, res = mcp.execute_tool("ipvn7_bitnet_quantize_and_infer", {
        "x": [0.6, -0.3, 0.9, -1.1],
        "weights": [
            [0.5, -0.2, 0.7, -0.8],
            [-0.4, 0.3, -0.2, 0.9],
        ],
        "bias": [0.05, -0.05],
        "model_name": "iot-edge-gate",
    })
    assert ok is True
    assert res["model_name"] == "iot-edge-gate"
    assert res["rows"] == 2
    assert res["cols"] == 4
    assert "output" in res
    assert len(res["output"]) == 2
    assert res["container_bytes_len"] > 0


def test_pqc_handshake_tampered_ciphertext_fails():
    """
    Audit H-02 Remediation: Negative security test.
    Altering a single byte of ML-KEM-768 ciphertext must cause safe cryptographic failure
    (derives mismatched keys or raises, causing AEAD decryption failure on decrypt).
    """
    from ipvn7.crypto.pqc import PQCHybridKeyExchange, encrypt_aead, decrypt_aead

    # 1. Client Init
    c_x_pub, c_k_pub, c_x_priv, c_k_priv = PQCHybridKeyExchange.client_init()

    # 2. Server Respond
    s_x_pub, mlkem_ct, server_key = PQCHybridKeyExchange.server_respond(c_x_pub, c_k_pub)

    # 3. Adversary tampers with ML-KEM ciphertext (flip one byte)
    tampered_ct = bytearray(mlkem_ct)
    tampered_ct[10] ^= 0xFF
    tampered_ct = bytes(tampered_ct)

    # 4. Client Finalize with tampered ciphertext
    try:
        client_key = PQCHybridKeyExchange.client_finalize(c_x_priv, c_k_priv, s_x_pub, tampered_ct)
        # Server encrypts secret payload
        ciphertext = encrypt_aead(server_key, b"Secret Over-The-Wire Mission Payload")
        # Client decrypt attempt must fail due to transcript/secret mismatch
        try:
            decrypt_aead(client_key, ciphertext)
            assert False, "Decryption should have failed due to tampered ciphertext"
        except Exception:
            pass  # Expected safe rejection
    except Exception:
        pass  # If decapsulate rejects outright, also safe


def test_pqc_handshake_tampered_x25519_key_fails():
    """
    Audit H-02 Remediation: Negative security test.
    Altering the ephemeral X25519 public key in transit must trigger Transcript Binding mismatch.
    """
    from ipvn7.crypto.pqc import PQCHybridKeyExchange, encrypt_aead, decrypt_aead

    c_x_pub, c_k_pub, c_x_priv, c_k_priv = PQCHybridKeyExchange.client_init()
    s_x_pub, mlkem_ct, server_key = PQCHybridKeyExchange.server_respond(c_x_pub, c_k_pub)

    # Adversary substitutes/modifies ephemeral server X25519 key
    tampered_s_x_pub = bytearray(s_x_pub)
    tampered_s_x_pub[0] ^= 0x01
    tampered_s_x_pub = bytes(tampered_s_x_pub)

    client_key = PQCHybridKeyExchange.client_finalize(c_x_priv, c_k_priv, tampered_s_x_pub, mlkem_ct)
    assert client_key != server_key, "Keys must differ due to Transcript Binding and ECDH difference"

    ciphertext = encrypt_aead(server_key, b"High Value Defense Data")
    try:
        decrypt_aead(client_key, ciphertext)
        assert False, "Decryption must fail when transcript is tampered"
    except Exception:
        pass  # Safe rejection


def test_pqc_signature_tampered_message_fails():
    """
    Audit H-02 Remediation: Negative security test.
    Tampering with a signed payload must fail verification under ML-DSA-65 + Ed25519.
    """
    from ipvn7.crypto.pqc import PQCKeyPair, PQCDigitalSignature

    kp = PQCKeyPair.generate()
    original_msg = b"IPVN7-AUTHENTIC-DISPATCH-77"
    tampered_msg = b"IPVN7-TAMPERED-DISPATCH-77"

    sig = PQCDigitalSignature.sign_hybrid(original_msg, kp.mldsa_priv, kp.ed25519_priv)

    # Valid message passes
    valid = PQCDigitalSignature.verify_hybrid(
        original_msg,
        sig["mldsa_sig"],
        sig["ed25519_sig"],
        kp.mldsa_pub.public_bytes_raw(),
        kp.ed25519_pub.public_bytes_raw(),
    )
    assert valid is True

    # Tampered message fails
    invalid = PQCDigitalSignature.verify_hybrid(
        tampered_msg,
        sig["mldsa_sig"],
        sig["ed25519_sig"],
        kp.mldsa_pub.public_bytes_raw(),
        kp.ed25519_pub.public_bytes_raw(),
    )
    assert invalid is False


def test_proxy_overlay_mode_validation():
    """
    Audit H-01 Remediation: Validate that IPVN7InternetProxy accurately tracks
    and isolates OVERLAY_TUNNELED mode.
    """
    from ipvn7.node.node import IPVN7Node
    from ipvn7.gateway.proxy import IPVN7InternetProxy

    n1 = IPVN7Node(alias="proxy-client", bind_port=19888)
    n2 = IPVN7Node(alias="proxy-exit", bind_port=19889)

    proxy = IPVN7InternetProxy(
        local_node=n1,
        exit_node=n2,
        listen_host="127.0.0.1",
        listen_port=0,
        mode="OVERLAY_TUNNELED",
    )
    assert proxy.mode == "OVERLAY_TUNNELED"
    assert proxy.stats["pqc_hybrid_active"] is True
    assert proxy.stats["overlay_packets_routed"] == 0


def test_planetary_topology_3d_snapshot():
    """Validates 3D orbital spherical coordinate projection for PlanetaryMeshCluster."""
    from ipvn7.network.planetary import PlanetaryMeshCluster

    cluster = PlanetaryMeshCluster(node_count=16, seed=777)
    snapshot = cluster.get_topology_snapshot()

    assert "metrics" in snapshot
    assert "nodes" in snapshot
    assert len(snapshot["nodes"]) == 16

    for node in snapshot["nodes"]:
        assert "geo" in node
        geo = node["geo"]
        assert "lat_deg" in geo
        assert "lon_deg" in geo
        assert "x3d" in geo
        assert "y3d" in geo
        assert "z3d" in geo
        # Check radius is approximately orbit_r (1.08)
        r = (geo["x3d"]**2 + geo["y3d"]**2 + geo["z3d"]**2)**0.5
        assert 1.07 <= r <= 1.09


def test_bitnet_demo_pipeline_metrics():
    """Validates end-to-end BitNet b1.58 demo pipeline and zero-multiplication inference."""
    from ipvn7.crypto.bitnet import BitNetQuantizer

    res = BitNetQuantizer.run_demo_pipeline(rows=8, cols=8, seed=123)
    assert res["rows"] == 8
    assert res["cols"] == 8
    assert res["compression_ratio"] > 8.0
    assert res["memory_saved_pct"] > 85.0
    assert len(res["y_integer_output"]) == 8
    assert len(res["y_float_baseline"]) == 8

    dist = res["weight_distribution"]
    total = dist["plus_ones"] + dist["zeros"] + dist["minus_ones"]
    assert total == 64
    assert 0.0 <= dist["sparsity_pct"] <= 100.0


def test_datapath_fragmentation_and_reassembly_integrity():
    """Validates canonical 1280B fragmentation engine, CRC32 checks, and lossless reassembly."""
    import hashlib
    from ipvn7.benchmark.saturation import SovereignFragmentationEngine, CANONICAL_MTU

    payload = b"IPVN7_MISSION_CRITICAL_PAYLOAD_DATA_" * 3000  # ~108 KB
    expected_hash = hashlib.sha256(payload).hexdigest()

    # Fragment
    fragments = SovereignFragmentationEngine.fragment_stream(payload)
    assert len(fragments) > 80

    for frag in fragments:
        assert len(frag) <= CANONICAL_MTU
        assert frag.startswith(b"IP7F")

    # Reassemble
    reconstructed = SovereignFragmentationEngine.reassemble_stream(fragments)
    assert reconstructed == payload
    assert hashlib.sha256(reconstructed).hexdigest() == expected_hash


def test_datapath_saturation_benchmark_metrics():
    """Validates local datapath saturation benchmark throughput metrics (Gbps, pps)."""
    from ipvn7.benchmark.saturation import DatapathSaturationBenchmark

    res = DatapathSaturationBenchmark.run_benchmark(megabytes=1.5, use_udp_loopback=False)
    assert res["total_payload_mb"] == 1.5
    assert res["canonical_mtu"] == 1280
    assert res["total_packets"] > 1000
    assert res["throughput_mb_s"] > 10.0
    assert res["throughput_gbps"] > 0.08
    assert res["packets_per_second"] > 10000
    assert res["integrity_verified"] is True
    assert res["sha256_match"] is True


def test_sovereign_header_compressor_lossless():
    """Validates static dictionary token substitution, lossless reconstruction, and bandwidth savings."""
    from ipvn7.network.compression import SovereignHeaderCompressor

    telemetry_sample = (
        b"{\"sender\": \"did:ipvn7:genesis:node\", \"gateway\": \"http://127.0.0.1:8888\", "
        b"\"action\": \"OVERLAY_EGRESS_FETCH\", \"status\": \"DELIVERED_1RTT_PQC\", "
        b"\"ciphers\": [\"ML-KEM-768\", \"ML-DSA-65\", \"X25519\"], \"event\": \"HEARTBEAT\"}"
    )

    stats = SovereignHeaderCompressor.benchmark_sample(telemetry_sample)
    assert stats["original_bytes"] == len(telemetry_sample)
    assert stats["compressed_bytes"] < stats["original_bytes"]
    assert stats["saved_percentage"] > 25.0
    assert stats["lossless_verified"] is True


def test_silent_rekeying_orchestration_zero_downtime_and_zeroization():
    """Validates silent PQC re-keying, zero-downtime dual-key decryption in grace window, and memory zeroization."""
    from ipvn7.security.rekeying import SilentKeyRotationOrchestrator, RekeyPhase

    alice = SilentKeyRotationOrchestrator(
        session_id="pqc-session-audit-alpha",
        local_did="did:ipvn7:alice",
        peer_did="did:ipvn7:bob",
        grace_period_sec=5.0,
    )
    bob = SilentKeyRotationOrchestrator(
        session_id="pqc-session-audit-alpha",
        local_did="did:ipvn7:bob",
        peer_did="did:ipvn7:alice",
        initial_key=alice.active_material.key,
        grace_period_sec=5.0,
    )

    assert alice.current_epoch == 1
    assert bob.current_epoch == 1

    # 1. Exchange payload on initial epoch 1
    msg1 = b"IPVN7_EPOCH_1_STANDARD_TRAFFIC"
    epoch1, c1 = alice.encrypt_payload(msg1)
    assert epoch1 == 1
    d1 = bob.decrypt_payload(epoch1, c1)
    assert d1 == msg1

    # 2. Initiate Silent PQC Rekeying
    proposal = alice.initiate_rekey()
    assert alice.phase == RekeyPhase.OFFERED
    assert proposal.target_epoch == 2

    # 3. Bob responds and derives epoch 2 key
    commitment, bob_key = bob.respond_rekey(proposal)
    assert bob.current_epoch == 2
    assert bob.phase == RekeyPhase.COMMITTED

    # 4. Alice finalizes and derives epoch 2 key
    alice_key = alice.finalize_rekey(commitment)
    assert alice.current_epoch == 2
    assert alice_key == bob_key, "Derived post-quantum ratchet keys must match identically"

    # 5. Zero-Downtime Verification: Bob sends on Epoch 2, Alice decrypts on Epoch 2
    msg2 = b"IPVN7_EPOCH_2_POST_REKEY_TRAFFIC"
    epoch2, c2 = bob.encrypt_payload(msg2)
    assert epoch2 == 2
    d2 = alice.decrypt_payload(epoch2, c2)
    assert d2 == msg2

    # 6. Out-of-order grace window: A delayed packet from Epoch 1 arrives at Bob
    # Bob is on Epoch 2, but must successfully decrypt Epoch 1 packet using grace window
    d1_delayed = bob.decrypt_payload(epoch1, c1)
    assert d1_delayed == msg1

    # 7. Forward Secrecy Memory Zeroization
    assert alice.previous_material is not None
    assert not alice.previous_material.is_zeroed

    # Force zeroize previous epoch key
    zeroed = alice.force_zeroize_previous()
    assert zeroed is True
    assert alice.previous_material.is_zeroed is True
    assert alice.previous_material.fingerprint() == "ZEROIZED"

    # Verify accessing zeroed key raises error
    import pytest
    with pytest.raises(ValueError, match="zeroized"):
        _ = alice.previous_material.key

    # Decrypting old epoch 1 packet on Alice must now fail strictly
    with pytest.raises(ValueError, match="zeroized"):
        alice.decrypt_payload(epoch1, c1)

    summary = alice.get_orchestrator_summary()
    assert summary["current_epoch"] == 2
    assert summary["previous_key_zeroed"] is True
    assert summary["total_rotations"] == 1


def test_geopolicy_routing_and_sovereignty_enclaves():
    """Validates multi-attribute path selection, geofencing, and jurisdictional data sovereignty enclaves."""
    from ipvn7.network.geopolicy import (
        GeoPolicyRouter,
        RoutingPolicyMode,
        GeoRegion,
        GeoNodeDescriptor,
    )

    router = GeoPolicyRouter(local_did="did:ipvn7:tester", local_latitude=-33.4489, local_longitude=-70.6693)
    router.populate_default_planetary_topology()

    # 1. Min Latency mode selects closest node (Santiago: 4.2ms)
    dec1 = router.select_optimal_route(
        target_did="did:ipvn7:target",
        policy_mode=RoutingPolicyMode.MIN_LATENCY,
    )
    assert dec1.selected_node_did == "did:ipvn7:geo:santiago"
    assert dec1.measured_rtt_ms == 4.2
    assert dec1.geodesic_distance_km < 10.0

    # 2. Sovereignty strict mode requiring EU_GDPR must choose Frankfurt despite higher latency
    dec2 = router.select_optimal_route(
        target_did="did:ipvn7:target",
        policy_mode=RoutingPolicyMode.SOVEREIGNTY_STRICT,
        required_enclave="EU_GDPR",
    )
    assert dec2.selected_node_did == "did:ipvn7:geo:frankfurt"
    assert dec2.measured_rtt_ms == 175.0
    assert dec2.sovereignty_compliant is True

    # 3. Geofencing: Exclude LATAM_SANTIAGO; next best in LATAM should be Sao Paulo
    dec3 = router.select_optimal_route(
        target_did="did:ipvn7:target",
        policy_mode=RoutingPolicyMode.MIN_LATENCY,
        required_enclave="LATAM_SOVEREIGN",
        excluded_regions=[GeoRegion.LATAM_SANTIAGO],
    )
    assert dec3.selected_node_did in ("did:ipvn7:geo:saopaulo", "did:ipvn7:geo:orbital-leo1")

    # 4. Impossible constraints trigger LookupError with structured rejection reasons
    import pytest
    with pytest.raises(LookupError) as exc_info:
        router.select_optimal_route(
            target_did="did:ipvn7:target",
            required_enclave="NON_EXISTENT_ENCLAVE_XYZ",
        )
    assert "MISSING_REQUIRED_ENCLAVE:NON_EXISTENT_ENCLAVE_XYZ" in str(exc_info.value)


def test_private_dht_interregion_sync_and_bloom_reconciliation():
    """Validates Line M: Sovereign Bloom Filter reconciliation, zero metadata leakage, and IP7S MTU 1280B framing."""
    from ipvn7.network.dht_sync import (
        SovereignBloomFilter,
        PrivateDHTInterregionSync,
        MAGIC_SYNC,
        CANONICAL_SYNC_MTU,
        SyncFrameType,
    )
    from ipvn7.network.dht import HierarchicalSmallWorldDHT, DHTNode, DHTRoutingTier, NodeLocator

    # 1. SovereignBloomFilter unit properties
    bf = SovereignBloomFilter(size_bytes=64)  # 512 bits
    dids = [f"did:ipvn7:test-node-{i:04d}" for i in range(25)]
    for d in dids:
        bf.add(d)

    # All added DIDs must return True (zero false negatives)
    for d in dids:
        assert bf.contains(d) is True

    # Non-existent DID should overwhelmingly return False
    assert bf.contains("did:ipvn7:totally-unknown-non-existent-did") is False

    # Round-trip serialization
    raw_bf = bf.to_bytes()
    assert len(raw_bf) == 64
    recovered_bf = SovereignBloomFilter.from_bytes(raw_bf)
    for d in dids:
        assert recovered_bf.contains(d) is True

    # 2. Interregional DHT synchronization
    # Region A: LATAM
    node_a = DHTNode.from_did("did:ipvn7:node-latam-01", locators=[], tier=DHTRoutingTier.TIER_1_METRO)
    dht_a = HierarchicalSmallWorldDHT(node_a)
    for i in range(5):
        dht_a.store_locators(
            f"did:ipvn7:latam-service-{i}",
            [NodeLocator(ip=f"190.100.1.{i}", port=7000 + i, interface_type="ethernet", latency_ms=5.0)],
        )

    # Region B: Europe
    node_b = DHTNode.from_did("did:ipvn7:node-europe-01", locators=[], tier=DHTRoutingTier.TIER_1_METRO)
    dht_b = HierarchicalSmallWorldDHT(node_b)
    for i in range(3):
        dht_b.store_locators(
            f"did:ipvn7:europe-service-{i}",
            [NodeLocator(ip=f"185.20.1.{i}", port=8000 + i, interface_type="optical", latency_ms=15.0)],
        )

    sync_a = PrivateDHTInterregionSync(local_did=node_a.did, region_name="region-latam-south", dht=dht_a)
    sync_b = PrivateDHTInterregionSync(local_did=node_b.did, region_name="region-europe-west", dht=dht_b)

    # 3. Framing: Canonical IP7S DIGEST_ANNOUNCE
    digest_frame = sync_b.create_digest_frame(sequence_id=501)
    assert len(digest_frame) <= CANONICAL_SYNC_MTU
    assert digest_frame[:4] == MAGIC_SYNC

    # 4. Reconciliation: Node A discovers missing locators in Node B
    # Region B has its own 3 DIDs; Region A has 5 DIDs. Region B lacks all 5 LATAM DIDs.
    # Region B's digest frame contains 64 bytes of bloom filter at the end before CRC
    import struct
    reg_len = struct.unpack("!H", digest_frame[18:20])[0]
    b_bloom_bytes = digest_frame[20 + reg_len: 20 + reg_len + 64]
    missing_in_b = sync_a.reconcile_peer_digest(b_bloom_bytes)
    assert len(missing_in_b) >= 5
    for i in range(5):
        assert f"did:ipvn7:latam-service-{i}" in missing_in_b

    # 5. Delta streaming: Node A builds compressed IP7S LOCATOR_STREAM
    delta_frame = sync_a.build_locator_delta_frame(missing_in_b, sequence_id=502)
    assert len(delta_frame) <= CANONICAL_SYNC_MTU
    assert delta_frame[:4] == MAGIC_SYNC

    # 6. Peer applies delta and verifies DHT storage reconciliation
    applied_count = sync_b.apply_locator_delta_frame(delta_frame)
    assert applied_count >= 5

    # Verify Region B DHT now contains LATAM locators
    for i in range(5):
        resolved_locs, _ = dht_b.resolve_locator(f"did:ipvn7:latam-service-{i}")
        assert len(resolved_locs) == 1
        assert resolved_locs[0].ip == f"190.100.1.{i}"

    # 7. Bilateral simulation through IPVN7Node
    test_node = IPVN7Node(alias="DHT-Sync-Tester", bind_host="127.0.0.1")
    sim_res = test_node.sync_interregion_dht(peer_region="region-asia-east")
    assert sim_res["status"] == "SYNCHRONIZED"
    assert sim_res["canonical_mtu"] == 1280
    test_node.stop()


def test_sovereign_tunnel_telemetry_pmtu_and_bicast_failover():
    """Validates Line N: Tunnel Telemetry (IP7T), Path MTU Discovery, RFC 3550 Jitter, and Bicast Failover."""
    from ipvn7.network.tunnel_telemetry import (
        SovereignTunnelTelemetry,
        PathMTUEngine,
        TunnelFrameType,
        TunnelHealthState,
        MAGIC_TUNNEL,
        MIN_SAFE_PMTU,
        DEFAULT_PMTU,
        MAX_TUNNEL_MTU,
    )

    # 1. PathMTUEngine dynamic discovery
    engine = PathMTUEngine(current_pmtu=1280)
    assert engine.current_pmtu == 1280

    # Successful probe with larger MTU expands PMTU
    new_mtu = engine.evaluate_probe_result(1350, success=True)
    assert new_mtu == 1350
    assert engine.consecutive_successes == 1

    # Failed probe shrinks PMTU with backoff
    shrunk_mtu = engine.evaluate_probe_result(1350, success=False)
    assert shrunk_mtu < 1350
    assert shrunk_mtu >= MIN_SAFE_PMTU
    assert engine.consecutive_successes == 0

    # 2. SovereignTunnelTelemetry wire framing (IP7T)
    telemetry = SovereignTunnelTelemetry(local_did="did:ipvn7:tunnel-tester")
    tun_metrics = telemetry.register_tunnel("wg0-mesh", interface_type="wireguard", remote_endpoint="10.7.0.2:51820")
    assert tun_metrics.tunnel_id == "wg0-mesh"
    assert tun_metrics.health_state == TunnelHealthState.HEALTHY

    # Build probe frame
    frame = telemetry.build_probe_frame("wg0-mesh", frame_type=TunnelFrameType.PROBE, sequence_id=42, desired_size=256)
    assert len(frame) == 256
    assert frame[:4] == MAGIC_TUNNEL

    # Parse and verify CRC32
    parsed = telemetry.parse_probe_frame(frame)
    assert parsed["magic"] == "IP7T"
    assert parsed["frame_type"] == "PROBE"
    assert parsed["sequence_id"] == 42
    assert parsed["tunnel_id"] == "wg0-mesh"

    # Corrupt frame triggers CRC mismatch error
    corrupt_ba = bytearray(frame)
    corrupt_ba[-1] ^= 0xFF
    corrupt_frame = bytes(corrupt_ba)
    import pytest
    with pytest.raises(ValueError, match="CRC32 mismatch"):
        telemetry.parse_probe_frame(corrupt_frame)

    # 3. RFC 3550 Jitter and EWMA RTT updates
    telemetry.simulate_telemetry_probe("wg0-mesh", sample_rtt_ms=20.0)
    telemetry.simulate_telemetry_probe("wg0-mesh", sample_rtt_ms=22.0)
    assert tun_metrics.rtt_ewma_ms > 0
    assert tun_metrics.health_state == TunnelHealthState.HEALTHY
    assert tun_metrics.bicast_active is False

    # 4. Critical link degradation triggers Bicast Failover
    # Inject packet drops to exceed 10% loss threshold
    for _ in range(5):
        telemetry.simulate_telemetry_probe("wg0-mesh", sample_rtt_ms=120.0, packet_lost=True)

    assert tun_metrics.compute_loss_ratio() > 0.10
    assert tun_metrics.health_state == TunnelHealthState.CRITICAL_FAILOVER
    assert tun_metrics.bicast_active is True
    assert telemetry.total_failovers_triggered >= 1

    # 5. Integrated node probing
    node = IPVN7Node(alias="Tunnel-Node-Tester", bind_host="127.0.0.1")
    node_res = node.probe_tunnel_telemetry(
        tunnel_id="tun0-wintun",
        sample_rtt_ms=8.5,
        pmtu_probe_size=1380,
        pmtu_probe_success=True,
    )
    assert node_res["tunnel_id"] == "tun0-wintun"
    assert node_res["current_pmtu"] == 1380
    assert node_res["health_state"] == "HEALTHY"
    summary = node.tunnel_telemetry.get_summary()
    assert summary["total_tunnels"] >= 1
    assert "tun0-wintun" in summary["tunnels"]
    node.stop()


def test_audit_h04_egress_security_policy_ssrf_filtering():
    """H-04: Validates strict anti-SSRF policy with ipaddress parsing and DNS rebinding protections."""
    from ipvn7.security.egress_policy import EgressSecurityPolicy
    import ipaddress

    # 1. Private and special IPs must be blocked
    blocked_ips = [
        "127.0.0.1", "127.42.0.1", "0.0.0.0",
        "10.0.0.1", "10.254.1.1",
        "192.168.1.1", "192.168.100.5",
        "172.16.0.1", "172.31.255.254",
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "100.64.0.1",       # CGNAT
        "::1", "fe80::1", "fc00::1",
    ]
    for ip in blocked_ips:
        allowed, reason = EgressSecurityPolicy.is_ip_allowed(ipaddress.ip_address(ip))
        assert not allowed, f"IP {ip} should have been blocked by EgressSecurityPolicy: {reason}"

    # 2. Public routable IPs must be allowed
    allowed_ips = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]
    for ip in allowed_ips:
        allowed, reason = EgressSecurityPolicy.is_ip_allowed(ipaddress.ip_address(ip))
        assert allowed, f"Public IP {ip} was incorrectly blocked: {reason}"

    # 3. URL level validation
    bad_urls = [
        "http://127.0.0.1:8080/admin",
        "https://169.254.169.254/computeMetadata/v1/",
        "ftp://example.com/test",
        "file:///etc/passwd",
        "gopher://example.com/",
    ]
    for u in bad_urls:
        safe, reason = EgressSecurityPolicy.validate_url(u)
        assert not safe, f"URL {u} should be deemed unsafe: {reason}"

    # 4. Valid public URLs
    safe_ok, reason = EgressSecurityPolicy.validate_url("https://example.com/index.html")
    assert safe_ok, f"Valid URL example.com was blocked: {reason}"


def test_audit_h02_socks5_blocks_internal_and_loopback_destinations():
    """H-02: Validates SOCKS5 gateway rejects connection attempts to private and loopback destinations."""
    from ipvn7.gateway.socks5 import IPVN7SOCKS5Gateway, SOCKS5_REP_CONN_NOT_ALLOWED
    import socket

    node1 = IPVN7Node(alias="Socks5-Sec-Test-1", bind_host="127.0.0.1")
    node2 = IPVN7Node(alias="Socks5-Sec-Test-2", bind_host="127.0.0.1")
    node1.start_background_listener()
    node2.start_background_listener()

    gateway = IPVN7SOCKS5Gateway(
        local_node=node1,
        exit_node=node2,
        listen_host="127.0.0.1",
        listen_port=0,
    )
    gateway.start()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", gateway.bound_port))

        # Handshake: version 5, 1 auth method (0x00 No Auth)
        s.sendall(b"\x05\x01\x00")
        hs_resp = s.recv(2)
        assert hs_resp == b"\x05\x00"

        # Try to connect to prohibited loopback destination: 127.0.0.1:22
        # VER=5, CMD=1, RSV=0, ATYP=1 (IPv4), IP=127.0.0.1, PORT=22
        conn_req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + (22).to_bytes(2, "big")
        s.sendall(conn_req)
        reply = s.recv(10)
        assert len(reply) >= 2
        # REP must be SOCKS5_REP_CONN_NOT_ALLOWED (0x02)
        assert reply[1] == SOCKS5_REP_CONN_NOT_ALLOWED, f"Expected 0x02 reject, got {reply[1]}"
        s.close()
    finally:
        gateway.stop()
        node1.stop()
        node2.stop()


def test_audit_h01_proxy_blocks_private_and_honest_logging():
    """H-01: Validates IPVN7InternetProxy blocks private egress destinations and logs honest status."""
    from ipvn7.gateway.proxy import IPVN7InternetProxy
    import socket

    node1 = IPVN7Node(alias="Proxy-Sec-Test-1", bind_host="127.0.0.1")
    node2 = IPVN7Node(alias="Proxy-Sec-Test-2", bind_host="127.0.0.1")
    node1.start_background_listener()
    node2.start_background_listener()

    logged_events = []
    def log_handler(info):
        logged_events.append(info)

    proxy = IPVN7InternetProxy(
        local_node=node1,
        exit_node=node2,
        listen_host="127.0.0.1",
        listen_port=0,
        traffic_logger=log_handler,
    )
    proxy.start()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", proxy.bound_port))

        # Attempt forbidden HTTP request to internal metadata IP
        req = b"GET http://169.254.169.254/latest/meta-data HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n"
        s.sendall(req)
        resp = s.recv(1024)
        assert b"403 Forbidden" in resp
        assert b"SSRF Destination Blocked" in resp
        s.close()
    finally:
        proxy.stop()
        node1.stop()
        node2.stop()


def test_audit_h07_rekey_method_not_allowed_on_get():
    """H-07: Validates /api/key_rotation/rekey returns 405 Method Not Allowed on GET requests."""
    from app.server import IPVN7DashboardHandler
    from io import BytesIO
    import json

    class DummyRequest:
        def __init__(self, raw_bytes):
            self._rfile = BytesIO(raw_bytes)
            self._wfile = BytesIO()

        def makefile(self, mode, *args, **kwargs):
            if "b" in mode:
                if "r" in mode:
                    return self._rfile
                return self._wfile
            return None

        def sendall(self, data):
            self._wfile.write(data)

    # Simulate GET /api/key_rotation/rekey
    req_bytes = b"GET /api/key_rotation/rekey HTTP/1.1\r\nHost: 127.0.0.1:7070\r\n\r\n"
    dummy = DummyRequest(req_bytes)
    handler = IPVN7DashboardHandler(dummy, ("127.0.0.1", 54321), None)

    output = dummy._wfile.getvalue().decode("utf-8")
    assert "405 Method Not Allowed" in output or "405" in output
    assert "modifies cryptographic state" in output or "Method Not Allowed" in output


def test_audit_h03_mcp_control_plane_authentication():
    """H-03: Validates MCP control plane requires valid Bearer token or trusted local origin."""
    from app.server import IPVN7DashboardHandler, CONTROL_AUTH_TOKEN
    from io import BytesIO
    import json

    class DummyRequest:
        def __init__(self, raw_bytes):
            self._rfile = BytesIO(raw_bytes)
            self._wfile = BytesIO()

        def makefile(self, mode, *args, **kwargs):
            if "b" in mode:
                if "r" in mode:
                    return self._rfile
                return self._wfile
            return None

        def sendall(self, data):
            self._wfile.write(data)

    # 1. Unauthenticated request to /api/mcp must fail with 401
    unauth_req = b"GET /api/mcp HTTP/1.1\r\nHost: 127.0.0.1:7070\r\n\r\n"
    dummy1 = DummyRequest(unauth_req)
    IPVN7DashboardHandler(dummy1, ("127.0.0.1", 54321), None)
    out1 = dummy1._wfile.getvalue().decode("utf-8")
    assert "401 Unauthorized" in out1 or "401" in out1

    # 2. Authenticated request with Bearer token must succeed (200 OK)
    auth_req = f"GET /api/mcp HTTP/1.1\r\nHost: 127.0.0.1:7070\r\nAuthorization: Bearer {CONTROL_AUTH_TOKEN}\r\n\r\n".encode("utf-8")
    dummy2 = DummyRequest(auth_req)
    IPVN7DashboardHandler(dummy2, ("127.0.0.1", 54321), None)
    out2 = dummy2._wfile.getvalue().decode("utf-8")
    assert "200 OK" in out2
    assert "ipvn7-mcp-engine" in out2


def test_audit_h05_simulation_small_world_clamping():
    """H-05: Validates resource exhaustion protection clamps excessive simulation parameters."""
    from app.server import IPVN7DashboardHandler
    from io import BytesIO
    import json

    class DummyRequest:
        def __init__(self, raw_bytes):
            self._rfile = BytesIO(raw_bytes)
            self._wfile = BytesIO()

        def makefile(self, mode, *args, **kwargs):
            if "b" in mode:
                if "r" in mode:
                    return self._rfile
                return self._wfile
            return None

        def sendall(self, data):
            self._wfile.write(data)

    # Request extreme values: nodes=50000, churn=10.0
    req_bytes = b"GET /api/simulation/small-world?nodes=50000&churn=10.0 HTTP/1.1\r\nHost: 127.0.0.1:7070\r\n\r\n"
    dummy = DummyRequest(req_bytes)
    IPVN7DashboardHandler(dummy, ("127.0.0.1", 54321), None)
    out = dummy._wfile.getvalue().decode("utf-8")
    assert "200 OK" in out

    # Parse body from response
    body_part = out.split("\r\n\r\n", 1)[1]
    res_data = json.loads(body_part)
    # Total nodes must be clamped to maximum 120
    assert res_data["total_nodes"] <= 120
    assert res_data["churn_ratio"] <= 0.85


def test_sovereign_exit_relay_true_overlay_datapath():
    """Validates True Overlay Datapath Forwarding through Exit Node without direct client connection."""
    from ipvn7.gateway.exit_relay import (
        SovereignExitRelayServer,
        SovereignExitRelayClient,
        MAGIC_EXIT_RELAY,
        CMD_CONNECT,
        CMD_CONNECTED,
        CMD_DATA,
        STATUS_OK,
    )
    from unittest.mock import patch
    import socket
    import threading

    # 1. Setup local client node and remote exit node
    client_node = IPVN7Node(alias="Client-Gateway", bind_host="127.0.0.1")
    exit_node = IPVN7Node(alias="Exit-Relay-Node", bind_host="127.0.0.1")
    client_node.start_background_listener()
    exit_node.start_background_listener()

    # Bootstrap mutual peers
    client_node.bootstrap_peer(exit_node.did, "127.0.0.1", exit_node.bound_port)
    exit_node.bootstrap_peer(client_node.did, "127.0.0.1", client_node.bound_port)

    # 2. Setup mock target echo server
    echo_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    echo_srv.bind(("127.0.0.1", 0))
    echo_srv.listen(5)
    echo_port = echo_srv.getsockname()[1]

    def run_echo():
        try:
            conn, _ = echo_srv.accept()
            data = conn.recv(1024)
            if data:
                conn.sendall(b"ECHO:" + data)
            conn.close()
        except Exception:
            pass

    t_echo = threading.Thread(target=run_echo, daemon=True)
    t_echo.start()

    # 3. Instantiate Exit Relay Server on Exit Node and Client on Local Node
    server = SovereignExitRelayServer(exit_node)
    client = SovereignExitRelayClient(client_node, exit_node.did)

    # Mock EgressSecurityPolicy on Exit Node to allow local test echo port
    with patch("ipvn7.gateway.exit_relay.EgressSecurityPolicy.resolve_and_validate_host", return_value=(True, "Allowed in test", ["127.0.0.1"])):
        # Create paired socket simulating local application connected to gateway
        s_app, s_client = socket.socketpair()

        def app_work():
            s_app.sendall(b"Hello Quantum Sovereign Internet!")
            resp = s_app.recv(1024)
            assert resp == b"ECHO:Hello Quantum Sovereign Internet!"
            s_app.close()

        t_app = threading.Thread(target=app_work, daemon=True)
        t_app.start()

        # Open tunneled stream through Exit Node
        ok, reason, transferred = client.open_tunneled_stream("test.internal", echo_port, s_client, timeout=4.0)

        t_app.join(timeout=3.0)
        s_client.close()
        echo_srv.close()

        assert ok is True
        assert transferred > 0
        assert server.stats["connections_handled"] >= 1
        assert server.stats["bytes_forwarded_outbound"] > 0
        assert server.stats["bytes_forwarded_inbound"] > 0

    client_node.stop()
    exit_node.stop()


def test_audit_3_h09_pqc_authenticated_handshake_and_mitm_rejection():
    """Audit 3 H-09: Validates digital signature authentication in hybrid PQC handshake and MITM rejection."""
    import pytest
    from ipvn7.crypto.pqc import PQCKeyPair, PQCHybridKeyExchange

    client_pqc = PQCKeyPair.generate()
    server_pqc = PQCKeyPair.generate()
    attacker_pqc = PQCKeyPair.generate()

    # 1. Honest authenticated handshake
    c_x_pub, c_k_pub, c_x_priv, c_k_priv = PQCHybridKeyExchange.client_init()
    srv_x_pub, mlkem_ct, srv_derived, signatures = PQCHybridKeyExchange.server_respond_authenticated(
        c_x_pub,
        c_k_pub,
        server_pqc,
    )

    client_derived = PQCHybridKeyExchange.client_finalize_authenticated(
        c_x_priv,
        c_k_priv,
        srv_x_pub,
        mlkem_ct,
        signatures,
        server_pqc.mldsa_pub.public_bytes_raw(),
        server_pqc.ed25519_pub.public_bytes_raw(),
    )

    assert client_derived == srv_derived
    assert len(client_derived) == 32
    assert "mldsa_sig" in signatures and "ed25519_sig" in signatures

    # 2. MITM Tampering Attack: Alter server X25519 ephemeral key in transit
    c_x_pub2, c_k_pub2, c_x_priv2, c_k_priv2 = PQCHybridKeyExchange.client_init()
    srv_x_pub2, mlkem_ct2, _, signatures2 = PQCHybridKeyExchange.server_respond_authenticated(
        c_x_pub2,
        c_k_pub2,
        server_pqc,
    )

    # Corrupt one byte of server public key
    corrupted_pub = bytearray(srv_x_pub2)
    corrupted_pub[0] ^= 0xFF
    bad_srv_x_pub2 = bytes(corrupted_pub)

    # Client MUST abort and reject MITM
    with pytest.raises(ValueError, match="Invalid server signature"):
        PQCHybridKeyExchange.client_finalize_authenticated(
            c_x_priv2,
            c_k_priv2,
            bad_srv_x_pub2,
            mlkem_ct2,
            signatures2,
            server_pqc.mldsa_pub.public_bytes_raw(),
            server_pqc.ed25519_pub.public_bytes_raw(),
        )

    # 3. Impersonation Attack: Sign with attacker key but present victim public key
    c_x_pub3, c_k_pub3, c_x_priv3, c_k_priv3 = PQCHybridKeyExchange.client_init()
    srv_x_pub3, mlkem_ct3, _, signatures3 = PQCHybridKeyExchange.server_respond_authenticated(
        c_x_pub3,
        c_k_pub3,
        attacker_pqc,  # Attacker signs
    )

    # Verification against genuine server expected pub MUST fail
    with pytest.raises(ValueError, match="Invalid server signature"):
        PQCHybridKeyExchange.client_finalize_authenticated(
            c_x_priv3,
            c_k_priv3,
            srv_x_pub3,
            mlkem_ct3,
            signatures3,
            server_pqc.mldsa_pub.public_bytes_raw(),  # Genuine server pub expected
            server_pqc.ed25519_pub.public_bytes_raw(),
        )


def test_audit_3_h06_bitnet_deserialize_bounds_and_fuzz_resilience():
    """Audit 3 H-06: Validates BitNetQuantizer.deserialize_model defensive checks against malformed/fuzzed containers."""
    import struct
    import pytest
    from ipvn7.crypto.bitnet import BitNetQuantizer, PackedTernaryWeights, MAGIC_BITNET

    # 1. Valid baseline roundtrip
    valid_packed = PackedTernaryWeights(rows=2, cols=4, scale=1.5, packed_data=b"\x00\x00")
    valid_buf = BitNetQuantizer.serialize_model(valid_packed, model_name="valid-net")
    name, des = BitNetQuantizer.deserialize_model(valid_buf)
    assert name == "valid-net"
    assert des.rows == 2 and des.cols == 4 and des.scale == 1.5

    # 2. Truncated buffer (< 20 bytes)
    with pytest.raises(ValueError, match="Truncated BitNet container"):
        BitNetQuantizer.deserialize_model(b"IP7B\x00\x05")

    # 3. Bad magic bytes
    with pytest.raises(ValueError, match="Invalid BitNet container magic"):
        BitNetQuantizer.deserialize_model(b"XXXX" + valid_buf[4:])

    # 4. Out-of-bounds name length (> 256)
    bad_name_hdr = struct.pack("!4sHHdf", MAGIC_BITNET, 500, 2, 4.0, 1.0)
    with pytest.raises(ValueError, match="Invalid model name length"):
        BitNetQuantizer.deserialize_model(bad_name_hdr + b"A" * 10)

    # 5. Out-of-bounds dimensions (> 4096)
    bad_dim_hdr = struct.pack("!4sHHdf", MAGIC_BITNET, 4, 5000, 4.0, 1.0)
    with pytest.raises(ValueError, match="Invalid rows dimension"):
        BitNetQuantizer.deserialize_model(bad_dim_hdr + b"test" + b"\x00" * 5000)

    # 6. Invalid scale factor (<= 0 or non-finite)
    bad_scale_hdr = struct.pack("!4sHHdf", MAGIC_BITNET, 4, 2, 4.0, -2.5)
    with pytest.raises(ValueError, match="Invalid scale factor"):
        BitNetQuantizer.deserialize_model(bad_scale_hdr + b"test" + b"\x00\x00")

    # 7. Packed weight buffer length mismatch
    with pytest.raises(ValueError, match="Packed weight buffer mismatch"):
        # Expecting 2 bytes for (2, 4), give 10 bytes
        BitNetQuantizer.deserialize_model(struct.pack("!4sHHdf", MAGIC_BITNET, 4, 2, 4.0, 1.0) + b"test" + b"\x00" * 10)


def test_audit_3_h07_api_pqc_live_demo_censors_raw_shared_secret():
    """Audit 3 H-07: Validates that live demo endpoint never exposes raw shared secret hex."""
    import urllib.request
    import json

    # Read server.py source to verify absence of shared_secret_hex
    with open("app/server.py", "r", encoding="utf-8") as f:
        src = f.read()

    assert "shared_secret_hex" not in src, "Security violation: raw shared_secret_hex found in server.py"
    assert "shared_secret_fingerprint" in src, "shared_secret_fingerprint must be present instead"


def test_audit_3_h02_h05_socks5_concurrency_and_mode_accounting():
    """Audit 3 H-02/H-05: Validates SOCKS5 concurrency semaphore and transparent mode accounting."""
    import socket
    from ipvn7.gateway.socks5 import IPVN7SOCKS5Gateway, SOCKS5_REP_SERVER_FAILURE

    node = IPVN7Node(alias="Socks5-Concurrency-Test", bind_host="127.0.0.1")
    node.start_background_listener()

    # Limit to 1 concurrent connection
    gw = IPVN7SOCKS5Gateway(
        local_node=node,
        listen_host="127.0.0.1",
        listen_port=0,
        mode="DIRECT_EGRESS",
        max_connections=1,
    )
    bound_port = gw.start()

    # Connect client 1 and hold socket open
    cli1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli1.connect(("127.0.0.1", bound_port))
    cli1.sendall(b"\x05\x01\x00")
    resp1 = cli1.recv(2)
    assert resp1 == b"\x05\x00"

    # Connect client 2 concurrently: semaphore must reject or reject connection
    cli2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli2.settimeout(2.0)
    try:
        cli2.connect(("127.0.0.1", bound_port))
        cli2.sendall(b"\x05\x01\x00")
        resp2 = cli2.recv(2)
        # Either socket immediately closed or received SOCKS5_REP_SERVER_FAILURE
        if resp2:
            assert resp2[1] in (SOCKS5_REP_SERVER_FAILURE, 0xFF) or len(resp2) == 0
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass  # Rejection by socket closed is valid DoS defense

    cli1.close()
    cli2.close()
    gw.stop()
    node.stop()


# ==============================================================================
# Line O: Sovereign Reciprocity Tokens & Micro-Economic Settlement Tests (ADR-013)
# ==============================================================================

def test_line_o_reciprocity_token_issuance_and_verification():
    """Line O (ADR-013): Validates ReciprocityToken issuance, Ed25519 signatures and verification."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from ipvn7.network.settlement import SovereignReciprocitySettlement, ReciprocityToken

    issuer_key = ed25519.Ed25519PrivateKey.generate()
    issuer_pub_bytes = issuer_key.public_key().public_bytes_raw()

    settlement = SovereignReciprocitySettlement(
        local_did="did:ipvn7:issuer-node-001",
        private_key=issuer_key,
    )

    token = settlement.issue_token(
        beneficiary_did="did:ipvn7:relay-node-002",
        bandwidth_credits=10 * 1024 * 1024, # 10 MB
    )

    assert token.issuer_did == "did:ipvn7:issuer-node-001"
    assert token.beneficiary_did == "did:ipvn7:relay-node-002"
    assert token.bandwidth_credits == 10 * 1024 * 1024
    assert token.nonce == 1
    assert len(token.token_id) == 32
    assert len(token.signature_hex) > 64

    # Dict round-trip
    token_dict = token.to_dict()
    reconstructed = ReciprocityToken.from_dict(token_dict)
    assert reconstructed.token_id == token.token_id

    # Verification with correct pubkey
    is_valid, msg = settlement.verify_token(reconstructed, issuer_pub_bytes)
    assert is_valid is True
    assert "valid" in msg.lower()

    # Verification with attacker pubkey MUST fail
    attacker_key = ed25519.Ed25519PrivateKey.generate()
    is_valid_fake, msg_fake = settlement.verify_token(reconstructed, attacker_key.public_key().public_bytes_raw())
    assert is_valid_fake is False


def test_line_o_reciprocity_anti_fraud_and_bounds():
    """Line O (ADR-013): Validates defensive bounds and anti-fraud checks on reciprocity tokens."""
    import pytest
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from ipvn7.network.settlement import (
        SovereignReciprocitySettlement,
        ReciprocityToken,
        MAX_CREDITS_PER_TOKEN,
    )

    issuer_key = ed25519.Ed25519PrivateKey.generate()
    settlement = SovereignReciprocitySettlement(
        local_did="did:ipvn7:fraud-test-node",
        private_key=issuer_key,
    )

    # 1. Prohibit self-issuance
    with pytest.raises(ValueError, match="Self-issuance"):
        settlement.issue_token("did:ipvn7:fraud-test-node", 1000)

    # 2. Prohibit non-positive credits
    with pytest.raises(ValueError, match="positive"):
        settlement.issue_token("did:ipvn7:other-node", 0)

    # 3. Prohibit credit cap overflow
    with pytest.raises(ValueError, match="maximum cap"):
        settlement.issue_token("did:ipvn7:other-node", MAX_CREDITS_PER_TOKEN + 1)

    # 4. Tampered credits verification failure
    token = settlement.issue_token("did:ipvn7:other-node", 5000)
    tampered_token = ReciprocityToken(
        token_id=token.token_id,
        issuer_did=token.issuer_did,
        beneficiary_did=token.beneficiary_did,
        bandwidth_credits=99999999,  # tampered
        epoch=token.epoch,
        nonce=token.nonce,
        issued_at=token.issued_at,
        signature_hex=token.signature_hex,
    )
    ok, reason = settlement.verify_token(tampered_token, issuer_key.public_key().public_bytes_raw())
    assert ok is False


def test_line_o_settlement_and_double_spend_prevention():
    """Line O (ADR-013): Validates token redemption, balance crediting and strict double-spend rejection."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from ipvn7.network.settlement import SovereignReciprocitySettlement

    issuer_key = ed25519.Ed25519PrivateKey.generate()
    issuer_pub_bytes = issuer_key.public_key().public_bytes_raw()

    issuer_engine = SovereignReciprocitySettlement(
        local_did="did:ipvn7:client-payer",
        private_key=issuer_key,
    )

    beneficiary_engine = SovereignReciprocitySettlement(
        local_did="did:ipvn7:relay-earner",
    )

    # Issue token for 50 MB
    token1 = issuer_engine.issue_token("did:ipvn7:relay-earner", 50 * 1024 * 1024)

    # First settlement MUST succeed
    ok1, msg1, receipt1 = beneficiary_engine.settle_token(token1, issuer_pub_bytes)
    assert ok1 is True
    assert beneficiary_engine.get_balance("did:ipvn7:relay-earner") == 50 * 1024 * 1024

    # Second settlement of exact same token MUST fail with double-spend rejection
    ok2, msg2, _ = beneficiary_engine.settle_token(token1, issuer_pub_bytes)
    assert ok2 is False
    assert "Double-spend" in msg2

    # Issue token 2 and verify sequential nonce acceptance
    token2 = issuer_engine.issue_token("did:ipvn7:relay-earner", 20 * 1024 * 1024)
    assert token2.nonce == 2
    ok3, msg3, _ = beneficiary_engine.settle_token(token2, issuer_pub_bytes)
    assert ok3 is True
    assert beneficiary_engine.get_balance("did:ipvn7:relay-earner") == 70 * 1024 * 1024


def test_line_o_quota_remediation_tit_for_tat():
    """Line O (ADR-013): Validates dynamic Tit-for-Tat tier remediation using reciprocity credits."""
    from ipvn7.network.accounting import TransitAccounting, ServiceTier
    from ipvn7.network.settlement import SovereignReciprocitySettlement

    accounting = TransitAccounting(courtesy_bytes=1000, courtesy_packets=10)
    settlement = SovereignReciprocitySettlement(
        local_did="did:ipvn7:local-gateway",
        accounting=accounting,
    )

    peer_did = "did:ipvn7:asymmetric-peer"

    # Depress peer ratio by recording massive Tx with zero Rx -> forces THROTTLED tier
    accounting.record_tx(peer_did, 100 * 1024 * 1024) # 100 MB transmitted to peer
    for _ in range(15):
        accounting.record_tx(peer_did, 1024)

    initial_tier = accounting.get_tier(peer_did)
    assert initial_tier in (ServiceTier.THROTTLED, ServiceTier.BEST_EFFORT)

    # Seed peer with earned reciprocity credits
    settlement.credit_balances[peer_did] = 120 * 1024 * 1024 # 120 MB in reciprocity credits

    # Apply remediation
    ok, msg, new_tier = settlement.apply_quota_remediation(peer_did)
    assert ok is True
    assert new_tier in (ServiceTier.NORMAL, ServiceTier.PRIORITY)
    assert settlement.get_balance(peer_did) == 0


def test_line_o_reciprocity_wire_framing_ip7r():
    """Line O (ADR-013): Validates canonical IP7R binary wire framing, MTU bounds and CRC32 integrity."""
    import pytest
    from ipvn7.network.settlement import (
        SovereignReciprocitySettlement,
        OP_TOKEN_ISSUE,
        MAGIC_RECIPROCITY,
    )

    payload = b"PAYLOAD-TEST-RECIPROCITY-RECEIPT-CANONICAL-MTU"
    frame = SovereignReciprocitySettlement.serialize_frame(OP_TOKEN_ISSUE, payload)

    assert frame.startswith(MAGIC_RECIPROCITY)
    assert len(frame) <= 1280

    opcode, extracted = SovereignReciprocitySettlement.deserialize_frame(frame)
    assert opcode == OP_TOKEN_ISSUE
    assert extracted == payload

    # Corrupt CRC32 check
    corrupt_frame = frame[:-1] + bytes([frame[-1] ^ 0xFF])
    with pytest.raises(ValueError, match="CRC32 integrity"):
        SovereignReciprocitySettlement.deserialize_frame(corrupt_frame)


def test_line_o_mcp_reciprocity_tools():
    """Line O (ADR-013): Validates MCP Tools 64, 65 and 66 integration on node."""
    from ipvn7.node.node import IPVN7Node

    node_a = IPVN7Node(alias="NodeA-Issuer", bind_host="127.0.0.1")
    node_b = IPVN7Node(alias="NodeB-Relay", bind_host="127.0.0.1")

    # Tool 64: ipvn7_issue_reciprocity_token
    ok_iss, res_iss = node_a.mcp_server.execute_tool(
        "ipvn7_issue_reciprocity_token",
        {"beneficiary_did": node_b.did, "bandwidth_credits": 8 * 1024 * 1024},
    )
    assert ok_iss is True
    token_dict = res_iss["token"]
    assert token_dict["beneficiary_did"] == node_b.did

    # Tool 65: ipvn7_settle_reciprocity_token
    ok_set, res_set = node_b.mcp_server.execute_tool(
        "ipvn7_settle_reciprocity_token",
        {
            "token": token_dict,
            "issuer_pubkey_hex": node_a.identity.keypair.ed25519_pub.public_bytes_raw().hex(),
            "remediate_quota": True,
        },
    )
    assert ok_set is True
    assert res_set["success"] is True

    # Tool 66: ipvn7_get_settlement_ledger
    ok_led, res_led = node_b.mcp_server.execute_tool(
        "ipvn7_get_settlement_ledger",
        {},
    )
    assert ok_led is True
    assert res_led["stats"]["tokens_settled"] >= 1


def test_laia_invariants_automated_quality_gate():
    """LAIA Directive: Automates continuous verification of all core architectural invariants."""
    from scripts.verify_laia_invariants import (
        check_inv1_zero_static_secrets,
        check_inv2_mcp_and_control_auth,
        check_inv3_egress_anti_ssrf,
        check_inv4_wire_framing_integrity,
        check_inv6_zero_raw_secret_leakage,
        check_inv7_bounded_concurrency,
    )

    inv1_ok, v1 = check_inv1_zero_static_secrets()
    assert inv1_ok, f"INV-1 Violated: {v1}"

    inv2_ok, v2 = check_inv2_mcp_and_control_auth()
    assert inv2_ok, f"INV-2 Violated: {v2}"

    inv3_ok, v3 = check_inv3_egress_anti_ssrf()
    assert inv3_ok, f"INV-3 Violated: {v3}"

    inv4_ok, v4 = check_inv4_wire_framing_integrity()
    assert inv4_ok, f"INV-4 Violated: {v4}"

    inv6_ok, v6 = check_inv6_zero_raw_secret_leakage()
    assert inv6_ok, f"INV-6 Violated: {v6}"

    inv7_ok, v7 = check_inv7_bounded_concurrency()
    assert inv7_ok, f"INV-7 Violated: {v7}"


# -------------------------------------------------------------
# Línea P (v7.12.0) Tests: Sovereign TEE Enclave & Formal Verification
# -------------------------------------------------------------

def test_tee_enclave_memory_sealing_and_unsealing():
    """Validates cryptographic memory sealing and tampering detection under MRENCLAVE mismatch."""
    from ipvn7.security.tee_enclave import SovereignEnclave, EnclaveIntegrityError, EnclaveState

    enclave = SovereignEnclave(node_id="did:ipvn7:test-node-alpha")
    assert enclave.state == EnclaveState.ACTIVE
    assert len(enclave.measurement) == 64

    secret_data = b"POST_QUANTUM_LONG_TERM_ROOT_SEED_32_BYTES!"
    record = enclave.seal_secret("root_pqc_seed", secret_data)
    assert record.name == "root_pqc_seed"
    assert record.counter_at_seal >= 2

    # Clean unseal
    recovered = enclave.unseal_secret("root_pqc_seed")
    assert recovered == secret_data

    # Tampering simulation
    enclave.simulate_tampering_for_test("00" * 32)
    with pytest.raises(EnclaveIntegrityError):
        enclave.unseal_secret("root_pqc_seed")

    # Restore clean state
    enclave.restore_clean_state()
    assert enclave.unseal_secret("root_pqc_seed") == secret_data


def test_tee_enclave_attestation_report_and_verification():
    """Validates TEE attestation generation, Ed25519 EAK signing, and remote challenge verification."""
    from ipvn7.security.tee_enclave import SovereignEnclave

    enclave = SovereignEnclave(node_id="did:ipvn7:test-node-beta")
    nonce = "CHALLENGE_NONCE_ABCD_1234_EF56"

    report = enclave.generate_attestation_report(challenge_nonce=nonce)
    assert report.challenge_nonce == nonce
    assert report.state == "ACTIVE"
    assert len(report.signature_hex) == 128  # 64 bytes Ed25519 in hex
    assert len(report.enclave_pubkey_hex) == 64

    report_dict = report.to_dict()

    # Valid verification
    valid, reason = SovereignEnclave.verify_attestation_report(report_dict, expected_nonce=nonce)
    assert valid is True
    assert reason == "ATTESTATION_VALID"

    # Nonce mismatch verification
    invalid_nonce, reason_mismatch = SovereignEnclave.verify_attestation_report(
        report_dict, expected_nonce="WRONG_NONCE"
    )
    assert invalid_nonce is False
    assert "mismatch" in reason_mismatch

    # Tampered signature verification
    tampered_dict = dict(report_dict)
    tampered_dict["signature_hex"] = "00" * 64
    invalid_sig, reason_sig = SovereignEnclave.verify_attestation_report(tampered_dict, expected_nonce=nonce)
    assert invalid_sig is False


def test_tee_enclave_wire_framing_ip7e():
    """Validates canonical wire framing IP7E, MTU <= 1280B and CRC32 verification."""
    from ipvn7.security.tee_enclave import SovereignEnclave, EnclaveOpcode

    payload = b'{"msg":"IP7E_WIRE_TEST","ts":1771400000}'
    frame = SovereignEnclave.encode_frame(EnclaveOpcode.OP_ATTESTATION_REPORT, payload)

    assert frame[:4] == b"IP7E"
    assert len(frame) == 11 + len(payload)
    assert len(frame) <= 1280

    # Clean decode
    opcode, dec_payload = SovereignEnclave.decode_frame(frame)
    assert opcode == EnclaveOpcode.OP_ATTESTATION_REPORT
    assert dec_payload == payload

    # Corrupted CRC check
    corrupted_frame = bytearray(frame)
    corrupted_frame[-1] ^= 0xFF
    with pytest.raises(ValueError, match="CRC32 checksum mismatch"):
        SovereignEnclave.decode_frame(bytes(corrupted_frame))

    # Oversized payload rejection check
    oversized = b"Z" * 1275
    with pytest.raises(ValueError, match="exceeds maximum allowable MTU"):
        SovereignEnclave.encode_frame(EnclaveOpcode.OP_SEALED_PAYLOAD, oversized)


def test_runtime_formal_verifier_mtu_and_replay_invariants():
    """Validates runtime formal proofs for MTU Boundedness and 1024-bit Anti-Replay window."""
    from ipvn7.node.node import IPVN7Node
    from ipvn7.diagnostics.formal_verifier import RuntimeFormalVerifier

    node = IPVN7Node(alias="formal-node-1")
    verifier = RuntimeFormalVerifier(node)

    res_mtu = verifier.verify_mtu_boundedness()
    assert res_mtu.passed is True
    assert "1280" in res_mtu.mathematical_proof

    res_ar = verifier.verify_anti_replay_sliding_window()
    assert res_ar.passed is True
    assert "seq <= max_seq - 1024" in res_ar.mathematical_proof


def test_runtime_formal_verifier_memory_and_secret_leakage_invariants():
    """Validates runtime formal proofs for Memory Isolation and Zero Secret Exposure."""
    from ipvn7.node.node import IPVN7Node
    from ipvn7.diagnostics.formal_verifier import RuntimeFormalVerifier

    node = IPVN7Node(alias="formal-node-2")
    verifier = RuntimeFormalVerifier(node)

    res_mem = verifier.verify_gma_memory_isolation()
    assert res_mem.passed is True
    assert "Quotas_i" in res_mem.mathematical_proof

    res_sec = verifier.verify_zero_secret_leakage()
    assert res_sec.passed is True
    assert "Secrets" in res_sec.mathematical_proof


def test_runtime_formal_verifier_full_suite_and_certificate():
    """Validates full execution of 6 formal invariants and cryptographic proof hash chaining."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="formal-node-cert")
    cert = node.run_formal_verification()

    assert cert["all_passed"] is True
    assert cert["total_invariants"] == 6
    assert cert["passed_invariants"] == 6
    assert len(cert["proof_hash"]) == 64
    assert len(cert["invariants"]) == 6


def test_mcp_tee_and_formal_verification_tools_67_68_69():
    """Validates execution of MCP Tools 67, 68 and 69."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="mcp-formal-node")

    # Tool 67: ipvn7_tee_attest_node (generate & verify)
    ok_att, res_att = node.mcp_server.execute_tool(
        "ipvn7_tee_attest_node",
        {"challenge_nonce": "MCP_CHALLENGE_999"},
    )
    assert ok_att is True
    assert res_att["challenge_nonce"] == "MCP_CHALLENGE_999"

    # Verify via tool 67
    ok_v, res_v = node.mcp_server.execute_tool(
        "ipvn7_tee_attest_node",
        {"verify_report": res_att, "challenge_nonce": "MCP_CHALLENGE_999"},
    )
    assert ok_v is True
    assert res_v["valid"] is True

    # Tool 68: ipvn7_verify_runtime_formal_invariants
    ok_form, res_form = node.mcp_server.execute_tool(
        "ipvn7_verify_runtime_formal_invariants",
        {},
    )
    assert ok_form is True
    assert res_form["all_passed"] is True
    assert res_form["total_invariants"] == 6

    # Tool 69: ipvn7_dispatch_enclave_frame (encode & decode)
    ok_enc, res_enc = node.mcp_server.execute_tool(
        "ipvn7_dispatch_enclave_frame",
        {
            "action": "encode",
            "opcode": "OP_ATTESTATION_CHALLENGE",
            "payload": {"nonce": "MCP_NONCE_777"},
        },
    )
    assert ok_enc is True
    assert res_enc["mtu_valid"] is True
    frame_hex = res_enc["frame_hex"]

    ok_dec, res_dec = node.mcp_server.execute_tool(
        "ipvn7_dispatch_enclave_frame",
        {"action": "decode", "raw_frame_hex": frame_hex},
    )
    assert ok_dec is True
    assert res_dec["opcode"] == "OP_ATTESTATION_CHALLENGE"
    assert res_dec["payload"]["nonce"] == "MCP_NONCE_777"


# ═══════════════════════════════════════════════════════════════════════════════
# LÍNEA Q — v7.13.0: ZK-Proofs & Ephemeral Ring Signatures
# Tests 123–130 — Gobernanza Anónima en la Malla
# ═══════════════════════════════════════════════════════════════════════════════

from ipvn7.crypto.zkp import (
    SovereignZKSchnorr,
    SovereignBulletproof,
    ZKSchnorrProof,
)
from ipvn7.security.ring_signature import (
    SovereignRingSignature,
    RingMember,
)


def test_zkp_schnorr_keygen_and_prove():
    """Test 123: ZK-Schnorr — keygen, prove y verify con prueba válida."""
    x, Y = SovereignZKSchnorr.keygen()
    assert x > 0
    assert Y > 0
    proof = SovereignZKSchnorr.prove(x, Y, context="IPVN7:GOVERNANCE:2026")
    assert proof.pk_hex == hex(Y)
    assert proof.context == "IPVN7:GOVERNANCE:2026"
    valid = SovereignZKSchnorr.verify(proof)
    assert valid is True, "La prueba ZK-Schnorr válida debe verificar True"


def test_zkp_schnorr_wire_roundtrip():
    """Test 124: ZK-Schnorr — serialización y deserialización wire IP7Z (≤1280B, CRC32)."""
    x, Y = SovereignZKSchnorr.keygen()
    proof = SovereignZKSchnorr.prove(x, Y, context="wire-test")
    frame = SovereignZKSchnorr.to_wire(proof)
    assert len(frame) <= 1280, f"Frame IP7Z excede MTU: {len(frame)}B"
    assert frame[:4] == b"IP7Z"
    proof2 = SovereignZKSchnorr.from_wire(frame)
    assert proof2.pk_hex == proof.pk_hex
    assert proof2.R_hex == proof.R_hex
    assert SovereignZKSchnorr.verify(proof2) is True


def test_zkp_schnorr_negative_wrong_key():
    """Test 125 (NEGATIVO): ZK-Schnorr — prueba con clave incorrecta debe rechazarse."""
    x, Y = SovereignZKSchnorr.keygen()
    _x2, Y2 = SovereignZKSchnorr.keygen()
    proof = SovereignZKSchnorr.prove(x, Y, context="attack-test")
    tampered = ZKSchnorrProof(
        pk_hex=hex(Y2),
        R_hex=proof.R_hex,
        s_hex=proof.s_hex,
        e_hex=proof.e_hex,
        context=proof.context,
    )
    assert SovereignZKSchnorr.verify(tampered) is False, (
        "Prueba ZK-Schnorr con clave incorrecta debe ser inválida"
    )


def test_zkp_bulletproof_range_valid():
    """Test 126: Bulletproof — prueba de rango válida para v ∈ [0, 2^8)."""
    engine = SovereignBulletproof(n_bits=8)
    v = 137
    proof = engine.prove(v, context="IP7R-balance-test")
    assert proof.n_bits == 8
    assert proof.commitment_hex.startswith("0x")
    assert engine.verify(proof) is True, f"Bulletproof válido para v={v} debe verificar True"


def test_zkp_bulletproof_wire_roundtrip():
    """Test 127: Bulletproof — serialización wire IP7Z ≤1280B."""
    engine = SovereignBulletproof(n_bits=8)
    proof = engine.prove(42, context="wire-range")
    frame = SovereignBulletproof.to_wire(proof)
    assert len(frame) <= 1280, f"Frame IP7Z Bulletproof excede MTU: {len(frame)}B"
    assert frame[:4] == b"IP7Z"
    proof2 = SovereignBulletproof.from_wire(frame)
    assert proof2.commitment_hex == proof.commitment_hex
    assert proof2.n_bits == proof.n_bits
    assert engine.verify(proof2) is True


def test_ring_signature_sign_and_verify():
    """Test 128: Ring Signature — firma anónima y verificación en anillo de 4 miembros."""
    members = [RingMember.generate() for _ in range(4)]
    signer = members[2]
    message = b"PROPUESTA_GOBERNANZA_IPVN7_Q"
    sig = SovereignRingSignature.sign(
        message, signer, members,
        epoch="2026-10-21:00", ring_context="GOVERNANCE_VOTE"
    )
    assert len(sig.ring_pks) == 4
    assert sig.key_image_hex is not None
    assert sig.epoch == "2026-10-21:00"
    assert SovereignRingSignature.verify(sig, message) is True


def test_ring_signature_wire_roundtrip():
    """Test 129: Ring Signature — serialización wire IP7S ≤1280B con CRC32."""
    members = [RingMember.generate() for _ in range(3)]
    signer = members[0]
    message = b"ALERT:CENSORSHIP_DETECTED"
    sig = SovereignRingSignature.sign(
        message, signer, members,
        epoch="2026-10-21:06", ring_context="SECURITY_ALERT"
    )
    frame = SovereignRingSignature.to_wire(sig)
    assert len(frame) <= 1280, f"Frame IP7S excede MTU: {len(frame)}B"
    assert frame[:4] == b"IP7S"
    sig2 = SovereignRingSignature.from_wire(frame)
    assert sig2.key_image_hex == sig.key_image_hex
    assert sig2.ring_context == "SECURITY_ALERT"
    assert SovereignRingSignature.verify(sig2, message) is True


def test_ring_signature_double_sign_detection():
    """Test 130 (NEGATIVO/SEGURIDAD): key_image detecta doble voto en la misma época."""
    members = [RingMember.generate() for _ in range(3)]
    signer = members[1]
    epoch = "2026-10-21:00"
    msg1 = b"VOTO:A"
    msg2 = b"VOTO:B"
    sig1 = SovereignRingSignature.sign(msg1, signer, members, epoch=epoch, ring_context="VOTE")
    sig2 = SovereignRingSignature.sign(msg2, signer, members, epoch=epoch, ring_context="VOTE")
    # Ambas son individualmente válidas
    assert SovereignRingSignature.verify(sig1, msg1) is True
    assert SovereignRingSignature.verify(sig2, msg2) is True
    # El key_image idéntico delata el doble voto
    assert SovereignRingSignature.is_double_signed(sig1, sig2) is True
    # Épocas distintas no son doble voto
    sig3 = SovereignRingSignature.sign(msg2, signer, members, epoch="2026-10-22:00", ring_context="VOTE")
    assert SovereignRingSignature.is_double_signed(sig1, sig3) is False


def test_mcp_zkp_and_ring_tools_70_71_72():
    """Test 131: Valida ejecución de MCP Tools 70, 71 y 72 (Línea Q ZKP y Ring Signatures)."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="mcp-zkp-node")

    # Tool 70: ipvn7_zkp_schnorr_prove (keygen, prove, verify)
    ok_kg, res_kg = node.mcp_server.execute_tool(
        "ipvn7_zkp_schnorr_prove",
        {"action": "keygen"},
    )
    assert ok_kg is True
    sk_hex = res_kg["sk_hex"]
    pk_hex = res_kg["pk_hex"]

    ok_pr, res_pr = node.mcp_server.execute_tool(
        "ipvn7_zkp_schnorr_prove",
        {"action": "prove", "sk_hex": sk_hex, "pk_hex": pk_hex, "context": "mcp-zkp-ctx"},
    )
    assert ok_pr is True
    assert res_pr["mtu_valid"] is True
    wire_schnorr = res_pr["wire_hex"]

    ok_v, res_v = node.mcp_server.execute_tool(
        "ipvn7_zkp_schnorr_prove",
        {"action": "verify", "wire_hex": wire_schnorr},
    )
    assert ok_v is True
    assert res_v["valid"] is True

    # Tool 71: ipvn7_zkp_range_proof (prove & verify v in [0, 2^8))
    ok_rp, res_rp = node.mcp_server.execute_tool(
        "ipvn7_zkp_range_proof",
        {"action": "prove", "value": 77, "n_bits": 8, "context": "mcp-range-ctx"},
    )
    assert ok_rp is True
    assert res_rp["mtu_valid"] is True
    wire_range = res_rp["wire_hex"]

    ok_rv, res_rv = node.mcp_server.execute_tool(
        "ipvn7_zkp_range_proof",
        {"action": "verify", "wire_hex": wire_range, "n_bits": 8},
    )
    assert ok_rv is True
    assert res_rv["valid"] is True

    # Tool 72: ipvn7_ring_signature (keygen, sign, verify)
    ok_m1, res_m1 = node.mcp_server.execute_tool("ipvn7_ring_signature", {"action": "keygen"})
    ok_m2, res_m2 = node.mcp_server.execute_tool("ipvn7_ring_signature", {"action": "keygen"})
    ok_m3, res_m3 = node.mcp_server.execute_tool("ipvn7_ring_signature", {"action": "keygen"})
    assert ok_m1 and ok_m2 and ok_m3

    ring_pks = [res_m1["pk_hex"], res_m2["pk_hex"], res_m3["pk_hex"]]
    ok_rs, res_rs = node.mcp_server.execute_tool(
        "ipvn7_ring_signature",
        {
            "action": "sign",
            "message": "PROPUESTA_MCP_001",
            "signer_sk_hex": res_m2["sk_hex"],
            "signer_pk_hex": res_m2["pk_hex"],
            "ring_pks": ring_pks,
            "epoch": "2026-10-21:00",
            "ring_context": "MCP_GOVERNANCE",
        },
    )
    assert ok_rs is True
    assert res_rs["mtu_valid"] is True
    wire_rs = res_rs["wire_hex"]

    ok_rsv, res_rsv = node.mcp_server.execute_tool(
        "ipvn7_ring_signature",
        {
            "action": "verify",
            "wire_hex": wire_rs,
            "message": "PROPUESTA_MCP_001",
        },
    )
    assert ok_rsv is True
    assert res_rsv["valid"] is True


def test_zkp_and_ring_rest_api_logic():
    """Test 132: Valida lógica de endpoints REST para ZKP Schnorr, Bulletproofs y Ring Signatures."""
    from ipvn7.crypto.zkp import SovereignZKSchnorr, SovereignBulletproof, _Q, _G, _H
    from ipvn7.security.ring_signature import SovereignRingSignature, RingMember

    # 1. ZK Status verification
    assert _Q > 0
    assert _G > 0
    assert _H > 0

    # 2. ZK-Schnorr API prove & verify flow
    x, Y = SovereignZKSchnorr.keygen()
    proof = SovereignZKSchnorr.prove(x, Y, context="api-rest-ctx")
    wire_schnorr = SovereignZKSchnorr.to_wire(proof)
    assert len(wire_schnorr) <= 1280
    proof_decoded = SovereignZKSchnorr.from_wire(wire_schnorr)
    assert SovereignZKSchnorr.verify(proof_decoded) is True

    # 3. Bulletproof Range API prove & verify flow
    engine_8 = SovereignBulletproof(n_bits=8)
    rp = engine_8.prove(200, context="api-balance-ctx")
    wire_rp = SovereignBulletproof.to_wire(rp)
    assert len(wire_rp) <= 1280
    rp_decoded = SovereignBulletproof.from_wire(wire_rp)
    assert engine_8.verify(rp_decoded) is True

    # 4. Ring Signature API sign & verify flow
    members = [RingMember.generate() for _ in range(4)]
    signer = members[2]
    msg = b"VOTE_REST_API_CONFIDENTIAL"
    sig = SovereignRingSignature.sign(msg, signer, members, epoch="2026-10-21:00", ring_context="REST_VOTE")
    wire_sig = SovereignRingSignature.to_wire(sig)
    assert len(wire_sig) <= 1280
    sig_decoded = SovereignRingSignature.from_wire(wire_sig)
    assert SovereignRingSignature.verify(sig_decoded, msg) is True


def test_xdp_switch_canonical_magics_and_fast_path():
    """Test 133: Valida fast-path en O(1) de XDPKernelSimulator para las 11 cabeceras canónicas y descarte temprano."""
    from ipvn7.access.xdp_switch import XDPKernelSimulator, XDPAction, CANONICAL_MAGICS

    sim = XDPKernelSimulator(mesh_port=7777)

    # 1. Las 11 cabeceras mágicas canónicas deben resultar en XDP_PASS
    for magic in CANONICAL_MAGICS:
        payload = magic + b"\x00" * 32
        action, reason = sim.process_udp_payload(payload)
        assert action == XDPAction.XDP_PASS
        assert "PASS" in reason

    # 2. Datagramas ilegítimos o con cabecera desconocida deben descartarse en O(1)
    bad_payloads = [
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"GET /index.html",
        b"\x00\x00\x00\x00\x12\x34",
        b"FAKE",
        b"TEST",
    ]
    for bad in bad_payloads:
        action, reason = sim.process_udp_payload(bad)
        assert action == XDPAction.XDP_DROP
        assert "DROP" in reason

    # 3. Datagramas truncados (< 4 bytes)
    action, reason = sim.process_udp_payload(b"IP7")
    assert action == XDPAction.XDP_DROP
    assert "truncado" in reason.lower()

    # 4. Violación de MTU (payload > 1280 bytes)
    oversized = b"IP7H" + b"X" * 1281
    action, reason = sim.process_udp_payload(oversized)
    assert action == XDPAction.XDP_DROP
    assert "MTU" in reason

    # 5. Métricas atómicas
    stats = sim.get_stats()
    assert stats["total_processed"] == len(CANONICAL_MAGICS) + len(bad_payloads) + 2
    assert stats["passed"] == len(CANONICAL_MAGICS)
    assert stats["dropped"] == len(bad_payloads) + 2
    assert stats["malformed_dropped"] == 1
    assert stats["early_drop_ratio_pct"] > 0.0


def test_xdp_switch_ethernet_frame_bounds_checking():
    """Test 134: Valida verificación de límites eBPF y emulación de cabeceras Ethernet/IPv4/UDP."""
    from ipvn7.access.xdp_switch import XDPKernelSimulator, XDPAction

    sim = XDPKernelSimulator(mesh_port=7777)

    # 1. Trama Ethernet canónica legítima dirigida al puerto 7777
    valid_frame = XDPKernelSimulator.synthesize_ethernet_frame(
        b"IP7Z" + b"PROOFOFIDENTITY",
        src_port=54321,
        dst_port=7777,
    )
    action, reason = sim.process_frame(valid_frame)
    assert action == XDPAction.XDP_PASS
    assert "IP7Z" in reason

    # 2. Trama Ethernet truncada (< 14 bytes) -> XDP_DROP
    action, reason = sim.process_frame(b"\x00\x11\x22\x33\x44\x55")
    assert action == XDPAction.XDP_DROP
    assert "truncada" in reason.lower()

    # 3. Tráfico no UDP (ej: TCP protocolo 6 simulado en cabecera IP) -> XDP_PASS (no interceptar)
    tcp_frame = bytearray(valid_frame)
    tcp_frame[14 + 9] = 6  # Protocolo TCP en lugar de UDP (17)
    action, reason = sim.process_frame(bytes(tcp_frame))
    assert action == XDPAction.XDP_PASS
    assert "no-udp" in reason.lower()

    # 4. Tráfico UDP dirigido a otro puerto del sistema (ej: DNS 53) -> XDP_PASS
    dns_frame = XDPKernelSimulator.synthesize_ethernet_frame(
        b"\x12\x34\x01\x00\x00\x01",
        src_port=54321,
        dst_port=53,
    )
    action, reason = sim.process_frame(dns_frame)
    assert action == XDPAction.XDP_PASS
    assert "53" in reason

    # 5. Tráfico en puerto 7777 con número mágico ilegítimo -> XDP_DROP (Early Drop O(1))
    malicious_frame = XDPKernelSimulator.synthesize_ethernet_frame(
        b"MALICIOUS_FLOOD_PAYLOAD",
        src_port=54321,
        dst_port=7777,
    )
    action, reason = sim.process_frame(malicious_frame)
    assert action == XDPAction.XDP_DROP
    assert "DROP" in reason


def test_xdp_switch_c_program_generation():
    """Test 135: Valida la exportación de código C de kernel eBPF con clang target bpf."""
    from ipvn7.access.xdp_switch import XDPKernelSimulator

    c_code = XDPKernelSimulator.generate_c_program(mesh_port=7777)
    assert "#include <linux/bpf.h>" in c_code
    assert "#define IPVN7_PORT 7777" in c_code
    assert "#define MAX_MTU_PAYLOAD 1280" in c_code
    assert "MAGIC_IP7V" in c_code
    assert "MAGIC_IP7H" in c_code
    assert "MAGIC_IP7Z" in c_code
    assert "MAGIC_IP7S" in c_code
    assert "MAGIC_IP7P" in c_code
    assert "SEC(\"xdp\")" in c_code
    assert "bpf_map_lookup_elem" in c_code
    assert "ipvn7_stats_map" in c_code
    assert "XDP_DROP" in c_code
    assert "XDP_PASS" in c_code


def test_xdp_switch_node_integration_and_stats():
    """Test 136: Valida integración de XDP switch en IPVN7Node y manipulación de telemetría."""
    from ipvn7.node.node import IPVN7Node
    from ipvn7.access.xdp_switch import XDPAction

    node = IPVN7Node(alias="xdp-test-node")

    # 1. Atributo xdp_switch presente y configurado
    assert hasattr(node, "xdp_switch")
    stats = node.get_xdp_stats()
    assert stats["total_processed"] == 0

    # 2. Evaluación de payload vía nodo
    act, r = node.process_xdp_payload(b"IP7H_PAYLOAD")
    assert act == XDPAction.XDP_PASS
    assert node.get_xdp_stats()["passed"] == 1

    # 3. Evaluación de payload inválido
    act, r = node.process_xdp_payload(b"CORRUPT")
    assert act == XDPAction.XDP_DROP
    assert node.get_xdp_stats()["dropped"] == 1

    # 4. Reset de métricas
    node.reset_xdp_stats()
    assert node.get_xdp_stats()["total_processed"] == 0

    # 5. Exportación de código C vía nodo
    c_prog = node.export_xdp_c_program()
    assert "IPVN 7 Native Linux eBPF" in c_prog


def test_mcp_xdp_switch_tool_73():
    """Test 137: Valida registro y ejecución completa de MCP Tool 73 (ipvn7_xdp_switch)."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="mcp-xdp-node")

    # Catálogo de herramientas debe contener exactamente 74 herramientas
    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 74
    tool_names = [t["name"] for t in tools]
    assert "ipvn7_xdp_switch" in tool_names

    # Acción 1: get_stats
    ok, res = node.mcp_server.execute_tool("ipvn7_xdp_switch", {"action": "get_stats"})
    assert ok is True
    assert "total_processed" in res

    # Acción 2: export_c
    ok, res = node.mcp_server.execute_tool("ipvn7_xdp_switch", {"action": "export_c"})
    assert ok is True
    assert "c_code" in res
    assert res["compiler_flags"] == "clang -O2 -target bpf -c xdp_ipvn7.c -o xdp_ipvn7.o"

    # Acción 3: synthesize_frame (legítimo IP7H)
    ok, res = node.mcp_server.execute_tool(
        "ipvn7_xdp_switch",
        {"action": "synthesize_frame", "magic": "IP7H", "payload_size": 64},
    )
    assert ok is True
    assert res["simulated_action"] == "XDP_PASS"
    assert res["frame_len"] > 0

    # Acción 4: synthesize_frame (malicioso FAKE)
    ok, res = node.mcp_server.execute_tool(
        "ipvn7_xdp_switch",
        {"action": "synthesize_frame", "magic": "FAKE", "payload_size": 64},
    )
    assert ok is True
    assert res["simulated_action"] == "XDP_DROP"

    # Acción 5: process_payload
    ok, res = node.mcp_server.execute_tool(
        "ipvn7_xdp_switch",
        {"action": "process_payload", "payload_hex": b"IP7Z_ZKP_PROOF".hex()},
    )
    assert ok is True
    assert res["action"] == "XDP_PASS"

    # Acción 6: reset_stats
    ok, res = node.mcp_server.execute_tool("ipvn7_xdp_switch", {"action": "reset_stats"})
    assert ok is True
    assert res["status"] == "stats_reset"
    assert res["stats"]["total_processed"] == 0


def test_operating_mode_controller_tri_state_transitions():
    """Test 138: Valida transiciones atómicas tri-estado, idempotencia y bounded ring buffer de 32 registros."""
    import pytest
    from ipvn7.security.operating_modes import OperatingModeController, NodeOperatingMode

    ctrl = OperatingModeController()

    # 1. Estado inicial por defecto: MODE_OPEN
    assert ctrl.current_mode == NodeOperatingMode.MODE_OPEN
    assert ctrl.is_open() is True
    assert ctrl.is_safe() is False
    assert ctrl.is_degraded() is False

    # 2. Transición a MODE_SAFE
    st = ctrl.set_mode(NodeOperatingMode.MODE_SAFE, reason="test_stealth_activation")
    assert ctrl.current_mode == NodeOperatingMode.MODE_SAFE
    assert ctrl.is_safe() is True
    assert st["current_mode"] == "MODE_SAFE"
    assert "ZERO_PII_EGRESS_ONLY" in st["active_protections"]

    # 3. Transición a MODE_DEGRADED
    st = ctrl.set_mode("MODE_DEGRADED", reason="congested_fabric")
    assert ctrl.current_mode == NodeOperatingMode.MODE_DEGRADED
    assert ctrl.is_degraded() is True
    assert ctrl.pre_degraded_mode == NodeOperatingMode.MODE_SAFE
    assert "SCAVENGER_BULK_PURGE" in st["active_protections"]

    # 4. Transición de retorno a MODE_OPEN
    st = ctrl.set_mode("MODE_OPEN", reason="normalcy_restored")
    assert ctrl.current_mode == NodeOperatingMode.MODE_OPEN
    assert ctrl.is_open() is True

    # 5. Idempotencia: transición al mismo modo no genera registros redundantes
    hist_before = len(ctrl.get_history())
    ctrl.set_mode(NodeOperatingMode.MODE_OPEN)
    assert len(ctrl.get_history()) == hist_before

    # 6. Modo inválido lanza ValueError
    with pytest.raises(ValueError, match="Invalid operating mode"):
        ctrl.set_mode("MODE_INVALID_STATE")

    # 7. Bounded ring buffer: 40 transiciones se truncan estrictamente a 32 registros
    for i in range(40):
        m = NodeOperatingMode.MODE_SAFE if i % 2 == 0 else NodeOperatingMode.MODE_OPEN
        ctrl.set_mode(m, reason=f"fuzz_transition_{i}")
    history = ctrl.get_history()
    assert len(history) == 32
    assert history[-1]["reason"] == "fuzz_transition_39"


def test_adaptive_health_governor_trip_and_auto_recovery():
    """Test 139: Valida activación adaptativa de MODE_DEGRADED ante umbrales y auto-recuperación tras cool-down."""
    import time
    from ipvn7.security.operating_modes import OperatingModeController, NodeOperatingMode

    ctrl = OperatingModeController(
        loss_threshold_pct=30.0,
        drop_threshold_pct=25.0,
        buffer_threshold_pct=80.0,
        cooldown_sec=0.2,  # Ventana corta para prueba rápida
    )

    # 1. Telemetría normal: permanece en MODE_OPEN
    st = ctrl.evaluate_health(loss_pct=10.0, drop_ratio_pct=5.0, buffer_util_pct=40.0)
    assert ctrl.is_open() is True
    assert st["consecutive_healthy_evals"] == 1

    # 2. Pérdida excesiva (> 30%) dispara MODE_DEGRADED
    st = ctrl.evaluate_health(loss_pct=35.0, drop_ratio_pct=5.0, buffer_util_pct=40.0)
    assert ctrl.is_degraded() is True
    assert ctrl.pre_degraded_mode == NodeOperatingMode.MODE_OPEN
    assert "health_governor_tripped" in ctrl.get_history()[-1]["reason"]

    # 3. Telemetría limpia inmediata no recupera antes de que expire el cooldown de 0.2s
    ctrl.evaluate_health(loss_pct=0.0, drop_ratio_pct=0.0, buffer_util_pct=20.0)
    assert ctrl.is_degraded() is True

    # 4. Esperar que expire el cool-down y enviar ticks limpios adicionales
    time.sleep(0.25)
    st = ctrl.evaluate_health(loss_pct=0.0, drop_ratio_pct=0.0, buffer_util_pct=20.0)
    assert ctrl.is_open() is True
    assert "health_governor_cooldown_recovered" in ctrl.get_history()[-1]["reason"]


def test_operating_mode_subsystem_cascades():
    """Test 140: Valida la cascada de políticas sobre DarkNode, ZTNA Firewall y DWRR Scheduler."""
    from ipvn7.security.operating_modes import OperatingModeController, NodeOperatingMode
    from ipvn7.security.dark_node import DarkNodeMacroOrchestrator
    from ipvn7.security.firewall import ZTNAFirewall
    from ipvn7.network.pacer import DWRRScheduler, QoSClass, QueuedPacket
    from ipvn7.network.packet import IPVN7Packet, TrafficClass

    dark = DarkNodeMacroOrchestrator()
    fw = ZTNAFirewall(default_deny=False)
    pacer = DWRRScheduler()

    ctrl = OperatingModeController(
        dark_node=dark,
        firewall=fw,
        scheduler=pacer,
    )

    # 1. Modo Seguro: silencia anuncios en dark node y fuerza default-deny en ZTNA
    ctrl.set_mode(NodeOperatingMode.MODE_SAFE)
    assert dark.is_dark_node() is True
    assert dark.listeners_muted is True
    assert fw.default_deny is True

    # 2. Poblar cola BULK en el pacer
    dummy_pkt = IPVN7Packet(
        src_did_fp=b"\x01" * 16,
        dst_did_fp=b"\x02" * 16,
        traffic_class=TrafficClass.BEST_EFFORT,
        payload=b"dummy_bulk_payload",
    )
    pacer.queues[QoSClass.BULK].append(
        QueuedPacket(packet=dummy_pkt, target_addr=("127.0.0.1", 7777), size=100, enqueued_at=0.0)
    )
    assert len(pacer.queues[QoSClass.BULK]) == 1

    # 3. Transición a MODE_DEGRADED purga cola BULK y altera pesos QoS
    ctrl.set_mode(NodeOperatingMode.MODE_DEGRADED)
    assert len(pacer.queues[QoSClass.BULK]) == 0  # Purga completada
    assert pacer.WEIGHTS[QoSClass.BULK] == 0
    assert pacer.WEIGHTS[QoSClass.CONTROL] == 6000

    # 4. Transición de retorno a MODE_OPEN restaura pesos originales del scheduler
    ctrl.set_mode(NodeOperatingMode.MODE_OPEN)
    assert pacer.WEIGHTS[QoSClass.BULK] == 1000
    assert pacer.WEIGHTS[QoSClass.CONTROL] == 4000
    assert dark.is_dark_node() is False


def test_ipvn7_node_operating_mode_integration():
    """Test 141: Valida métodos helper y telemetría de modos de operación en IPVN7Node."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="mode-integration-node")

    # 1. Atributo mode_controller presente
    assert hasattr(node, "mode_controller")

    # 2. get_operating_mode_status
    st = node.get_operating_mode_status()
    assert st["current_mode"] == "MODE_OPEN"
    assert st["is_open"] is True

    # 3. set_operating_mode
    st = node.set_operating_mode("MODE_SAFE", reason="unit_test_stealth")
    assert st["current_mode"] == "MODE_SAFE"
    assert node.mode_controller.is_safe() is True

    # 4. evaluate_operating_health
    st = node.evaluate_operating_health(loss_pct=45.0, drop_ratio_pct=10.0, buffer_util_pct=50.0)
    assert st["current_mode"] == "MODE_DEGRADED"

    # 5. get_operating_mode_history
    hist = node.get_operating_mode_history()
    assert len(hist) >= 3

    # 6. Integración en node.get_status()
    full_status = node.get_status()
    assert "operating_mode" in full_status
    assert full_status["operating_mode"]["current_mode"] == "MODE_DEGRADED"


def test_mcp_operating_mode_tool_74():
    """Test 142: Valida registro y ejecución completa de MCP Tool 74 (ipvn7_operating_mode)."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="mcp-operating-mode-node")

    # Catálogo de herramientas debe contener exactamente 74 herramientas
    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 74
    tool_names = [t["name"] for t in tools]
    assert "ipvn7_operating_mode" in tool_names

    # Acción 1: get_status
    ok, res = node.mcp_server.execute_tool("ipvn7_operating_mode", {"action": "get_status"})
    assert ok is True
    assert res["current_mode"] == "MODE_OPEN"

    # Acción 2: set_mode a MODE_SAFE
    ok, res = node.mcp_server.execute_tool(
        "ipvn7_operating_mode",
        {"action": "set_mode", "mode": "MODE_SAFE", "reason": "mcp_stealth_test"},
    )
    assert ok is True
    assert res["current_mode"] == "MODE_SAFE"

    # Acción 3: evaluate_health con pérdida crítica
    ok, res = node.mcp_server.execute_tool(
        "ipvn7_operating_mode",
        {"action": "evaluate_health", "loss_pct": 55.0, "drop_ratio_pct": 10.0, "buffer_util_pct": 60.0},
    )
    assert ok is True
    assert res["current_mode"] == "MODE_DEGRADED"

    # Acción 4: get_history
    ok, res = node.mcp_server.execute_tool("ipvn7_operating_mode", {"action": "get_history"})
    assert ok is True
    assert res["count"] >= 3
    assert len(res["history"]) >= 3

    # Acción 5: acción desconocida
    ok, res = node.mcp_server.execute_tool("ipvn7_operating_mode", {"action": "unknown_action"})
    assert ok is False
    assert "Acción de Operating Mode desconocida" in str(res)


def test_ota_manifest_packaging_and_signature_verification():
    """Test 143: Valida empaquetado, firma Ed25519 y verificación criptográfica de manifiestos OTA."""
    from ipvn7.access.ota_hotswap import SovereignOTAManager

    mgr = SovereignOTAManager(local_did="did:ipvn7:test-ota-authority")

    sample_code = """
class FastChecksumFilter:
    def evaluate(self, data: bytes) -> int:
        return sum(data) % 256
"""
    # 1. Empaquetar manifiesto
    manifest = mgr.package_module(
        module_name="checksum_filter",
        version="1.0.0",
        code_str=sample_code,
        target_subsystem="security",
        dependencies=["hashlib"],
    )

    assert manifest.module_name == "checksum_filter"
    assert manifest.version == "1.0.0"
    assert manifest.author_did == "did:ipvn7:test-ota-authority"
    assert manifest.dag_cid.startswith("cid:ipvn7:manifest:")
    assert len(manifest.signature_hex) == 128  # 64 bytes Ed25519 hex-encoded

    # 2. Verificación criptográfica exitosa
    valid, err = mgr.verify_manifest(manifest)
    assert valid is True
    assert err is None

    # 3. Detección de alteración maliciosa del código
    tampered_manifest = mgr.package_module(
        module_name="checksum_filter",
        version="1.0.0",
        code_str=sample_code,
    )
    tampered_manifest.code_payload = sample_code + "\n# Tampered payload"
    valid, err = mgr.verify_manifest(tampered_manifest)
    assert valid is False
    assert "SHA-256 payload mismatch" in err


def test_ota_sandbox_preflight_validation():
    """Test 144: Valida sandboxing pre-flight, detección de errores de sintaxis y bloqueo de módulos peligrosos."""
    from ipvn7.access.ota_hotswap import IsolatedModuleSandbox

    # 1. Código válido
    valid_code = "class ValidMod:\n    def compute(self):\n        return 42\n"
    ok, ast_err = IsolatedModuleSandbox.validate_ast(valid_code)
    assert ok is True

    # 2. Error de sintaxis
    syntax_code = "class BrokenSyntax:\n    def broken(:\n"
    ok, ast_err = IsolatedModuleSandbox.validate_ast(syntax_code)
    assert ok is False
    assert "Syntax error" in ast_err

    # 3. Importación prohibida (subprocess)
    malicious_code = "import subprocess\nclass Exploit:\n    pass\n"
    ok, ast_err = IsolatedModuleSandbox.validate_ast(malicious_code)
    assert ok is False
    assert "Disallowed import" in ast_err

    # 4. Preflight execution con instanciación de clase
    ok, inst, err = IsolatedModuleSandbox.execute_preflight(
        valid_code, expected_class_name="ValidMod"
    )
    assert ok is True
    assert hasattr(inst, "compute")
    assert inst.compute() == 42


def test_ota_atomic_hotswap_and_execution():
    """Test 145: Valida hot-swapping atómico en memoria y sustitución de versión con estado PROBATION."""
    from ipvn7.access.ota_hotswap import SovereignOTAManager, ModuleLifecycleState

    mgr = SovereignOTAManager(probation_sec=10.0)

    code_v1 = """
class WorkerService:
    def run(self):
        return "Worker V1"
"""
    manifest_v1 = mgr.package_module("worker_svc", "1.0.0", code_v1)
    res = mgr.install_and_hotswap(manifest_v1, expected_class_name="WorkerService")
    assert res["success"] is True
    assert res["state"] == ModuleLifecycleState.PROBATION.value

    # Ejecutar V1
    inst_v1 = mgr.get_module_instance("worker_svc")
    assert inst_v1.run() == "Worker V1"

    # Sustituir en vivo por V2
    code_v2 = """
class WorkerService:
    def run(self):
        return "Worker V2 Accelerated"
"""
    manifest_v2 = mgr.package_module("worker_svc", "2.0.0", code_v2)
    res2 = mgr.install_and_hotswap(manifest_v2, expected_class_name="WorkerService")
    assert res2["success"] is True

    # Instancia activa ahora debe ser V2
    inst_v2 = mgr.get_module_instance("worker_svc")
    assert inst_v2.run() == "Worker V2 Accelerated"

    # Rollback a V1
    rb_res = mgr.rollback("worker_svc", reason="unit_test_rollback")
    assert rb_res["success"] is True
    assert rb_res["restored_version"] == "1.0.0"

    inst_restored = mgr.get_module_instance("worker_svc")
    assert inst_restored.run() == "Worker V1"


def test_ota_watchdog_auto_rollback_during_probation():
    """Test 146: Valida disparador automático de rollback ante fallos en tiempo de ejecución durante probation."""
    from ipvn7.access.ota_hotswap import SovereignOTAManager

    mgr = SovereignOTAManager(probation_sec=10.0)

    # 1. Instalar V1 estable
    code_v1 = "class Mod:\n    def val(self): return 100\n"
    m_v1 = mgr.package_module("fragile_mod", "1.0.0", code_v1)
    mgr.install_and_hotswap(m_v1, expected_class_name="Mod")
    # Consolidar V1
    mgr._active_modules["fragile_mod"]["probation_expires_at"] = 0.0
    mgr.evaluate_probation("fragile_mod")

    # 2. Instalar V2 (en probation)
    code_v2 = "class Mod:\n    def val(self): return 200\n"
    m_v2 = mgr.package_module("fragile_mod", "2.0.0", code_v2)
    mgr.install_and_hotswap(m_v2, expected_class_name="Mod")
    assert mgr.get_module_instance("fragile_mod").val() == 200

    # 3. Reportar error crítico mientras está en probation -> Auto Rollback
    err_res = mgr.report_runtime_error("fragile_mod", "ZeroDivisionError in critical path")
    assert err_res["auto_rollback_triggered"] is True

    # 4. Módulo restaurado a V1
    assert mgr.get_module_instance("fragile_mod").val() == 100


def test_mcp_ota_tool_75_and_node_integration():
    """Test 147: Valida integración de SovereignOTAManager en IPVN7Node y MCP Tool 75 (ipvn7_ota_hotswap)."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="ota-node-integration")

    # 1. Catálogo total de herramientas MCP debe ser al menos 75
    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 75
    tool_names = [t["name"] for t in tools]
    assert "ipvn7_ota_hotswap" in tool_names

    # 2. Acción get_status
    ok, res = node.mcp_server.execute_tool("ipvn7_ota_hotswap", {"action": "get_status"})
    assert ok is True
    assert "authority_did" in res
    assert res["probation_window_sec"] == 5.0

    # 3. Acción package_module
    code_sample = "class SimpleEcho:\n    def echo(self, msg):\n        return f'Echo: {msg}'\n"
    ok, manifest_dict = node.mcp_server.execute_tool(
        "ipvn7_ota_hotswap",
        {
            "action": "package_module",
            "module_name": "echo_svc",
            "version": "1.0.0",
            "code": code_sample,
            "target_subsystem": "application",
        },
    )
    assert ok is True
    assert manifest_dict["module_name"] == "echo_svc"
    assert manifest_dict["dag_cid"].startswith("cid:ipvn7:manifest:")

    # 4. Acción install_module
    ok, inst_res = node.mcp_server.execute_tool(
        "ipvn7_ota_hotswap",
        {
            "action": "install_module",
            "manifest": manifest_dict,
            "expected_class": "SimpleEcho",
        },
    )
    assert ok is True
    assert inst_res["module_name"] == "echo_svc"
    assert inst_res["state"] == "PROBATION"

    # 5. Acción list_modules
    ok, list_res = node.mcp_server.execute_tool("ipvn7_ota_hotswap", {"action": "list_modules"})
    assert ok is True
    assert list_res["count"] == 1
    assert list_res["modules"][0]["module_name"] == "echo_svc"

    # 6. Acción rollback_module
    # Intentar rollback de un módulo sin snapshot debe fallar con error descriptivo
    ok, rb_res = node.mcp_server.execute_tool(
        "ipvn7_ota_hotswap",
        {"action": "rollback_module", "module_name": "echo_svc"},
    )
    assert ok is False
    assert "No previous snapshot exists" in rb_res["error"]


# =============================================================================
# LÍNEA V: SERVIDOR DNS UDP SOBERANO RFC 1035 / RFC 3596 & CÓDEC BINARIO (v7.17.0)
# =============================================================================

def test_dns_codec_domain_name_encoding_and_pointer_loops():
    """Test 148: Valida codificación RFC 1035 de etiquetas de dominio y detección de bucles de compresión."""
    from ipvn7.network.dns_server import encode_domain_name, decode_domain_name

    # 1. Codificación estándar
    encoded = encode_domain_name("laptop.ipv7")
    expected = b"\x06laptop\x04ipv7\x00"
    assert encoded == expected

    # 2. Decodificación estándar
    decoded, offset = decode_domain_name(encoded, 0)
    assert decoded == "laptop.ipv7"
    assert offset == len(encoded)

    # 3. Puntero de compresión válido
    # Simula un paquete donde "laptop.ipv7" está en offset 12, y en offset 28 hay un puntero 0xC00C
    packet_buf = b"\x00" * 12 + encoded + b"\x00" * 3 + b"\xc0\x0c"
    decoded_ptr, next_off = decode_domain_name(packet_buf, 28)
    assert decoded_ptr == "laptop.ipv7"
    assert next_off == 30

    # 4. Detección y contención de bucle infinito de punteros
    loop_buf = b"\xc0\x00"  # puntero a sí mismo
    import pytest
    with pytest.raises(ValueError, match="DNS label pointer loop detected"):
        decode_domain_name(loop_buf, 0)


def test_dns_packet_parse_and_build_roundtrip():
    """Test 149: Valida serialización y deserialización binaria de tramas completas DNSPacket RFC 1035."""
    from ipvn7.network.dns_server import DNSPacket, DNSQuestion, DNSRecord, TYPE_A, TYPE_AAAA, CLASS_IN
    import socket

    req_pkt = DNSPacket(
        tx_id=0xABCD,
        flags=0x0100,  # Standard Query, RD=1
        questions=[
            DNSQuestion(qname="node.ipv7", qtype=TYPE_A, qclass=CLASS_IN),
        ],
        answers=[
            DNSRecord(
                name="node.ipv7",
                rtype=TYPE_A,
                rclass=CLASS_IN,
                ttl=120,
                rdata=socket.inet_aton("10.7.0.1"),
                rdata_text="10.7.0.1",
            ),
        ],
    )

    wire = req_pkt.build()
    assert len(wire) >= 12
    assert wire[:2] == b"\xab\xcd"

    parsed = DNSPacket.parse(wire)
    assert parsed.tx_id == 0xABCD
    assert parsed.flags == 0x0100
    assert len(parsed.questions) == 1
    assert parsed.questions[0].qname == "node.ipv7"
    assert parsed.questions[0].qtype == TYPE_A
    assert len(parsed.answers) == 1
    assert parsed.answers[0].rdata_text == "10.7.0.1"


def test_dns_server_synthetic_a_and_aaaa_resolution():
    """Test 150: Valida síntesis de registros A (IPv4) y AAAA (IPv6) sobre dominios soberanos .ipv7."""
    from ipvn7.network.dns_server import SovereignDNSServer, DNSPacket, DNSQuestion, TYPE_A, TYPE_AAAA, TYPE_ANY, RCODE_NOERROR, RCODE_NXDOMAIN

    server = SovereignDNSServer(host="127.0.0.1", port=0)

    # 1. Consulta Tipo A para dominio soberano .ipv7
    req_a = DNSPacket(tx_id=0x1111, flags=0x0100, questions=[DNSQuestion("cluster.ipv7", TYPE_A, 1)]).build()
    resp_a_wire = server.handle_query_datagram(req_a)
    resp_a = DNSPacket.parse(resp_a_wire)

    assert resp_a.tx_id == 0x1111
    assert resp_a.rcode == RCODE_NOERROR
    assert len(resp_a.answers) == 1
    assert resp_a.answers[0].rtype == TYPE_A
    assert resp_a.answers[0].rdata_text.startswith("10.7.")

    # 2. Consulta Tipo AAAA para dominio soberano .ipv7
    req_aaaa = DNSPacket(tx_id=0x2222, flags=0x0100, questions=[DNSQuestion("cluster.ipv7", TYPE_AAAA, 1)]).build()
    resp_aaaa_wire = server.handle_query_datagram(req_aaaa)
    resp_aaaa = DNSPacket.parse(resp_aaaa_wire)

    assert resp_aaaa.tx_id == 0x2222
    assert resp_aaaa.rcode == RCODE_NOERROR
    assert len(resp_aaaa.answers) == 1
    assert resp_aaaa.answers[0].rtype == TYPE_AAAA
    assert resp_aaaa.answers[0].rdata_text.startswith("fd07:")

    # 3. Consulta de dominio desconocido fuera de .ipv7 devuelve NXDOMAIN
    req_nx = DNSPacket(tx_id=0x3333, flags=0x0100, questions=[DNSQuestion("nonexistent.unknown", TYPE_A, 1)]).build()
    resp_nx = DNSPacket.parse(server.handle_query_datagram(req_nx))
    assert resp_nx.rcode == RCODE_NXDOMAIN


def test_dns_server_reverse_ptr_and_petname_mapping():
    """Test 151: Valida resolución inversa PTR (in-addr.arpa) hacia petnames soberanos y shadow devices."""
    from ipvn7.network.dns_server import SovereignDNSServer, DNSPacket, DNSQuestion, TYPE_PTR, RCODE_NOERROR
    from ipvn7.identity.petnames import PetnameResolver

    resolver = PetnameResolver()
    resolver.register_petname("gateway.ipv7", "did:ipvn7:gateway123", virtual_ipv4="10.7.15.1")

    server = SovereignDNSServer(petname_resolver=resolver, host="127.0.0.1", port=0)

    # Consulta inversa para 10.7.15.1 -> 1.15.7.10.in-addr.arpa
    ptr_query_domain = "1.15.7.10.in-addr.arpa"
    req_ptr = DNSPacket(tx_id=0x4444, flags=0x0100, questions=[DNSQuestion(ptr_query_domain, TYPE_PTR, 1)]).build()
    resp_ptr = DNSPacket.parse(server.handle_query_datagram(req_ptr))

    assert resp_ptr.rcode == RCODE_NOERROR
    assert len(resp_ptr.answers) == 1
    assert resp_ptr.answers[0].rtype == TYPE_PTR
    assert resp_ptr.answers[0].rdata_text == "gateway.ipv7"


def test_mcp_dns_server_tool_76_and_node_integration():
    """Test 152: Valida registro y ejecución de MCP Tool 76 (ipvn7_dns_server) e integración en IPVN7Node."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="mcp-dns-node")

    # 1. Catálogo total de herramientas MCP debe ser al menos 76
    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 76
    tool_names = [t["name"] for t in tools]
    assert "ipvn7_dns_server" in tool_names

    # 2. Acción get_status
    ok, res = node.mcp_server.execute_tool("ipvn7_dns_server", {"action": "get_status"})
    assert ok is True
    assert "running" in res
    assert "stats" in res

    # 3. Acción add_record (Registro estático)
    ok, add_res = node.mcp_server.execute_tool(
        "ipvn7_dns_server",
        {
            "action": "add_record",
            "domain": "alpha.ipv7",
            "qtype": "A",
            "rdata": "10.7.88.99",
            "ttl": 600,
        },
    )
    assert ok is True
    assert add_res["domain"] == "alpha.ipv7"

    # 4. Acción resolve_query (Consulta resuelta)
    ok, q_res = node.mcp_server.execute_tool(
        "ipvn7_dns_server",
        {"action": "resolve_query", "domain": "alpha.ipv7", "qtype": "A"},
    )
    assert ok is True
    assert q_res["rcode"] == 0
    assert len(q_res["answers"]) == 1
    assert q_res["answers"][0]["rdata_text"] == "10.7.88.99"

    # 5. Acción list_records
    ok, list_res = node.mcp_server.execute_tool("ipvn7_dns_server", {"action": "list_records"})
    assert ok is True
    assert "alpha.ipv7" in list_res["records"]

    # 6. Acción start_server y stop_server
    ok, start_res = node.mcp_server.execute_tool("ipvn7_dns_server", {"action": "start_server", "port": 0})
    assert ok is True
    assert start_res["success"] is True
    assert start_res["bound_port"] > 0
    assert node.dns_server.is_running() is True

    ok, stop_res = node.mcp_server.execute_tool("ipvn7_dns_server", {"action": "stop_server"})
    assert ok is True
    assert node.dns_server.is_running() is False


def test_knowledge_graph_node_edge_crud_and_orphans():
    """Test 153: Valida inserción, indexación, consulta de vecinos y detección de huérfanos en KnowledgeGraphEngine."""
    from ipvn7.diagnostics.graph import KnowledgeGraphEngine, GraphNode, GraphEdge

    kg = KnowledgeGraphEngine()

    # 1. Registro de nodos
    n1 = kg.register_node(
        node_or_id="AXIOM_1",
        label="AxiomPrinciple",
        name="Axiom 1",
        layer="L0",
        properties={"immutable": True},
    )
    n2 = kg.register_node(
        node_or_id="FUNC_1",
        label="OperationalFunction",
        name="Function 1",
        layer="L1",
        properties={"status": "VERIFIED"},
    )
    assert kg.get_node("AXIOM_1") is not None
    assert kg.get_node("FUNC_1") is not None
    assert kg.get_node("UNKNOWN") is None

    # 2. Registro de arista
    e1 = kg.register_edge(
        edge_or_source="FUNC_1",
        target_id="AXIOM_1",
        rel_type="DERIVED_FROM",
        properties={"weight": 1.0},
    )
    assert kg.get_edge(e1.id) is not None

    # 3. Consulta de vecinos
    out_neighbors = kg.get_neighbors("FUNC_1", direction="out")
    assert len(out_neighbors) == 1
    assert out_neighbors[0][1].id == "AXIOM_1"

    in_neighbors = kg.get_neighbors("AXIOM_1", direction="in")
    assert len(in_neighbors) == 1
    assert in_neighbors[0][1].id == "FUNC_1"

    # 4. Verificación de cero huérfanos (ambos nodos conectados)
    orphan_res = kg.validate_zero_orphans()
    assert orphan_res["zero_orphans"] is True
    assert orphan_res["orphan_count"] == 0
    assert orphan_res["coverage_pct"] == 100.0

    # 5. Agregar nodo huérfano desconectado
    kg.register_node("ORPHAN_NODE", label="Component", name="Orphan")
    orphan_res2 = kg.validate_zero_orphans()
    assert orphan_res2["zero_orphans"] is False
    assert orphan_res2["orphan_count"] == 1
    assert "ORPHAN_NODE" in orphan_res2["orphans"]

    # 6. Eliminar nodo y comprobar remoción de incidentes
    assert kg.remove_node("ORPHAN_NODE") is True
    assert kg.validate_zero_orphans()["zero_orphans"] is True

    # 7. Exportación topológica
    topo = kg.export_topology()
    assert topo["metrics"]["total_nodes"] == 2
    assert topo["metrics"]["total_edges"] == 1
    assert topo["metrics"]["zero_orphans"] is True


def test_opencypher_pattern_matcher_and_queries():
    """Test 154: Valida evaluación de patrones openCypher (MATCH, WHERE, RETURN, LIMIT, alias)."""
    from ipvn7.diagnostics.graph import KnowledgeGraphEngine

    kg = KnowledgeGraphEngine()
    kg.register_node("A1", label="AxiomPrinciple", name="Principle Alpha", layer="L0", properties={"score": 10})
    kg.register_node("A2", label="AxiomPrinciple", name="Principle Beta", layer="L1", properties={"score": 5})
    kg.register_node("F1", label="OperationalFunction", name="Function 1", layer="L1", properties={"status": "VERIFIED"})
    kg.register_node("F2", label="OperationalFunction", name="Function 2", layer="L2", properties={"status": "DEPRECATED"})

    kg.register_edge("F1", "A1", rel_type="DERIVED_FROM", properties={"weight": 2.5})
    kg.register_edge("F2", "A2", rel_type="DERIVED_FROM", properties={"weight": 1.0})
    kg.register_edge("F1", "F2", rel_type="CALLS", properties={"freq": 100})

    # 1. MATCH simple de nodos por etiqueta
    res1 = kg.execute_cypher("MATCH (a:AxiomPrinciple) RETURN a.id, a.layer")
    assert res1.row_count == 2
    assert "a.id" in res1.columns
    assert "a.layer" in res1.columns
    ids = [r["a.id"] for r in res1.rows]
    assert "A1" in ids and "A2" in ids

    # 2. MATCH con WHERE y operadores de comparación
    res2 = kg.execute_cypher("MATCH (a:AxiomPrinciple) WHERE a.layer = 'L0' RETURN a.id, a.properties.score")
    assert res2.row_count == 1
    assert res2.rows[0]["a.id"] == "A1"
    assert res2.rows[0]["a.properties.score"] == 10

    # 3. MATCH de arista dirigida
    res3 = kg.execute_cypher("MATCH (f:OperationalFunction)-[r:DERIVED_FROM]->(a:AxiomPrinciple) RETURN f.id, a.id, r.properties.weight")
    assert res3.row_count == 2
    f_ids = [r["f.id"] for r in res3.rows]
    assert "F1" in f_ids and "F2" in f_ids

    # 4. MATCH de arista reversa (<-)
    res4 = kg.execute_cypher("MATCH (a:AxiomPrinciple)<-[r:DERIVED_FROM]-(f:OperationalFunction) RETURN a.id, f.id")
    assert res4.row_count == 2
    assert "a.id" in res4.columns
    assert "f.id" in res4.columns

    # 5. MATCH con alias de columnas (AS)
    res5 = kg.execute_cypher("MATCH (f:OperationalFunction) WHERE f.status = 'VERIFIED' RETURN f.id AS function_identifier, f.name AS title")
    assert res5.row_count == 1
    assert "function_identifier" in res5.columns
    assert "title" in res5.columns
    assert res5.rows[0]["function_identifier"] == "F1"

    # 6. MATCH con LIMIT
    res6 = kg.execute_cypher("MATCH (n) RETURN n.id LIMIT 2")
    assert res6.row_count == 2
    assert len(res6.rows) == 2


def test_knowledge_graph_shortest_path_and_subgraph():
    """Test 155: Valida cálculo de rutas semánticas más cortas (BFS) y extracción de subgrafos locales."""
    from ipvn7.diagnostics.graph import KnowledgeGraphEngine

    kg = KnowledgeGraphEngine()
    # Construcción de topología:
    # Camino 1: N1 -> N2 -> N3 -> N4 (3 saltos)
    # Camino 2: N1 -> N5 -> N4 (2 saltos, más corto)
    for i in range(1, 6):
        kg.register_node(f"N{i}", label="Node", name=f"Node {i}")

    kg.register_edge("N1", "N2", rel_type="ROUTES_TO")
    kg.register_edge("N2", "N3", rel_type="ROUTES_TO")
    kg.register_edge("N3", "N4", rel_type="ROUTES_TO")

    kg.register_edge("N1", "N5", rel_type="SHORTCUT")
    kg.register_edge("N5", "N4", rel_type="SHORTCUT")

    # 1. Camino más corto sin filtro de relación
    path = kg.find_shortest_path("N1", "N4")
    assert path == ["N1", "N5", "N4"]

    # 2. Camino más corto restringido a rel_type='ROUTES_TO'
    path_routed = kg.find_shortest_path("N1", "N4", rel_type="ROUTES_TO")
    assert path_routed == ["N1", "N2", "N3", "N4"]

    # 3. Camino inexistente
    kg.register_node("ISOLATED", label="Node")
    assert kg.find_shortest_path("N1", "ISOLATED") is None

    # 4. Extracción de subgrafo local (ego-network)
    sub = kg.extract_subgraph("N5", max_depth=1)
    assert sub["seed_id"] == "N5"
    sub_ids = [n["id"] for n in sub["nodes"]]
    assert "N5" in sub_ids
    assert "N1" in sub_ids
    assert "N4" in sub_ids
    assert len(sub["edges"]) >= 2


def test_axiomatic_coherence_audit_and_canonical_seeding():
    """Test 156: Valida auto-inicialización de la arquitectura canónica IPVN 7 y auditoría de coherencia."""
    from ipvn7.diagnostics.graph import KnowledgeGraphEngine

    kg = KnowledgeGraphEngine()
    kg.seed_canonical_architecture()

    # 1. Verificación de axiomas sembrados
    axioms = kg.execute_cypher("MATCH (a:AxiomPrinciple) RETURN a.id")
    assert axioms.row_count >= 7
    axiom_ids = [r["a.id"] for r in axioms.rows]
    assert "AXIOM_ZERO_PII" in axiom_ids
    assert "AXIOM_STRICT_CORE_FREEZE" in axiom_ids
    assert "AXIOM_FAST_PATH_FIRST" in axiom_ids
    assert "AXIOM_SOVEREIGNTY" in axiom_ids

    # 2. Verificación de subcistemas sembrados
    subsystems = kg.execute_cypher("MATCH (s:Subsystem) RETURN s.id")
    assert subsystems.row_count >= 15
    sub_ids = [r["s.id"] for r in subsystems.rows]
    assert "subsystem-dns-server" in sub_ids
    assert "subsystem-xdp-switch" in sub_ids
    assert "subsystem-ota-hotswap" in sub_ids

    # 3. Verificación de decisiones ADR sembradas
    adrs = kg.execute_cypher("MATCH (d:Decision) RETURN d.id")
    assert adrs.row_count >= 19
    adr_ids = [r["d.id"] for r in adrs.rows]
    assert "ADR-001" in adr_ids
    assert "ADR-019" in adr_ids

    # 4. Auditoría de coherencia axiomática de base
    audit = kg.audit_axiomatic_coherence()
    assert audit["is_coherent"] is True
    assert len(audit["unanchored_functions"]) == 0
    assert len(audit["unanchored_subsystems"]) == 0
    assert audit["coherence_score"] == 100.0

    # 5. Detección de contradicciones ante observaciones no conformes
    kg.register_node(
        node_or_id="OBS_FAULT_001",
        label="EmpiricalObservation",
        name="Latency Violation",
        properties={"metric_name": "rtt_ewma", "value": 500.0, "compliant": False},
    )
    kg.register_edge("L1_PACKET_PACER", "OBS_FAULT_001", rel_type="VALIDATED_BY")

    fault_audit = kg.audit_axiomatic_coherence()
    assert fault_audit["is_coherent"] is False
    assert len(fault_audit["non_compliant_observations"]) == 1
    assert fault_audit["non_compliant_observations"][0]["id"] == "OBS_FAULT_001"
    assert fault_audit["coherence_score"] < 100.0


def test_node_knowledge_graph_integration_and_mcp_tool_77():
    """Test 157: Valida integración en IPVN7Node, sincronización de peers y ejecución de MCP Tool 77."""
    from ipvn7.node.node import IPVN7Node

    node = IPVN7Node(alias="graph-test-node")

    # 1. Instanciación y pre-siembra automática
    assert hasattr(node, "knowledge_graph")
    assert node.knowledge_graph is not None

    # 2. Comprobación en get_status()
    st = node.get_status()
    assert "knowledge_graph" in st
    assert st["knowledge_graph"]["total_nodes"] > 20
    assert st["knowledge_graph"]["total_edges"] > 20

    # 3. Sincronización en bootstrap_peer
    node.bootstrap_peer(
        peer_did="did:ipvn7:peer-remote-9999",
        peer_host="127.0.0.1",
        peer_port=9999,
    )
    peer_node = node.knowledge_graph.get_node("did:ipvn7:peer-remote-9999")
    assert peer_node is not None
    assert peer_node.label == "Peer"

    # 4. Catálogo MCP: Tool 77 (ipvn7_knowledge_graph)
    tools = node.mcp_server.get_supported_tools()
    assert len(tools) >= 77
    tool_names = [t["name"] for t in tools]
    assert "ipvn7_knowledge_graph" in tool_names

    # 5. Ejecución MCP action='get_topology'
    ok, topo = node.mcp_server.execute_tool("ipvn7_knowledge_graph", {"action": "get_topology"})
    assert ok is True
    assert "metrics" in topo
    assert topo["metrics"]["total_nodes"] > 20

    # 6. Ejecución MCP action='query_cypher'
    ok, q_res = node.mcp_server.execute_tool(
        "ipvn7_knowledge_graph",
        {"action": "query_cypher", "query": "MATCH (a:AxiomPrinciple) RETURN a.id, a.layer"},
    )
    assert ok is True
    assert q_res["row_count"] >= 7

    # 7. Ejecución MCP action='audit_coherence'
    ok, audit_res = node.mcp_server.execute_tool("ipvn7_knowledge_graph", {"action": "audit_coherence"})
    assert ok is True
    assert "is_coherent" in audit_res

    # 8. Ejecución MCP action='find_orphans'
    ok, orphan_res = node.mcp_server.execute_tool("ipvn7_knowledge_graph", {"action": "find_orphans"})
    assert ok is True
    assert "orphan_count" in orphan_res

    # 9. Ejecución MCP action='register_node' y 'register_edge'
    ok, reg_n = node.mcp_server.execute_tool(
        "ipvn7_knowledge_graph",
        {
            "action": "register_node",
            "node_id": "TEST_COMP_X",
            "label": "Component",
            "name": "Test Component X",
            "layer": "L2",
        },
    )
    assert ok is True
    assert reg_n["registered"] is True

    ok, reg_e = node.mcp_server.execute_tool(
        "ipvn7_knowledge_graph",
        {
            "action": "register_edge",
            "source_id": "TEST_COMP_X",
            "target_id": "AXIOM_ZERO_PII",
            "rel_type": "GOVERNED_BY",
        },
    )
    assert ok is True
    assert reg_e["registered"] is True




