"""
IPVN 7 High-Performance Benchmarking Suite
Measures raw throughput, cryptographic operations per second,
and PQ-QUIC stream transfer rates.
"""

from __future__ import annotations
import time
from typing import Dict, Any

from ..crypto.pqc import (
    PQCKeyPair,
    PQCHybridKeyExchange,
    PQCDigitalSignature,
    encrypt_aead,
    decrypt_aead,
)
from ..transport.quic import (
    PQQUICConnection,
    PQQUICPacket,
    ConnectionState,
)
from ..network.packet import IPVN7Packet, HeaderType


def benchmark_mlkem(iterations: int = 200) -> Dict[str, float]:
    """Measures NIST FIPS 203 ML-KEM-768 operations per second."""
    from cryptography.hazmat.primitives.asymmetric import mlkem

    # Keygen
    t0 = time.perf_counter()
    keys = [mlkem.MLKEM768PrivateKey.generate() for _ in range(iterations)]
    keygen_time = time.perf_counter() - t0

    # Encapsulation
    pubs = [k.public_key() for k in keys]
    t0 = time.perf_counter()
    cts = [p.encapsulate() for p in pubs]
    encap_time = time.perf_counter() - t0

    # Decapsulation
    t0 = time.perf_counter()
    for i in range(iterations):
        keys[i].decapsulate(cts[i][1])
    decap_time = time.perf_counter() - t0

    return {
        "keygen_ops_sec": round(iterations / keygen_time, 2),
        "encap_ops_sec": round(iterations / encap_time, 2),
        "decap_ops_sec": round(iterations / decap_time, 2),
    }


def benchmark_mldsa(iterations: int = 100) -> Dict[str, float]:
    """Measures NIST FIPS 204 ML-DSA-65 operations per second."""
    from cryptography.hazmat.primitives.asymmetric import mldsa

    data = b"IPVN7 Packet Payload Benchmark Authenticity"
    priv = mldsa.MLDSA65PrivateKey.generate()
    pub = priv.public_key()

    # Signing
    t0 = time.perf_counter()
    sigs = [priv.sign(data) for _ in range(iterations)]
    sign_time = time.perf_counter() - t0

    # Verification
    t0 = time.perf_counter()
    for sig in sigs:
        pub.verify(sig, data)
    verify_time = time.perf_counter() - t0

    return {
        "sign_ops_sec": round(iterations / sign_time, 2),
        "verify_ops_sec": round(iterations / verify_time, 2),
    }


def benchmark_quic_throughput(num_megabytes: int = 10) -> Dict[str, float]:
    """Measures encrypted 1-RTT stream throughput in Megabytes/sec."""
    kp1 = PQCKeyPair.generate()
    kp2 = PQCKeyPair.generate()

    client = PQQUICConnection("did:ipvn7:cli", kp1, is_client=True)
    server = PQQUICConnection("did:ipvn7:srv", kp2, is_client=False)

    # Establish handshake
    init_pkt = client.create_client_initial()
    hnd_pkt = server.handle_client_initial(init_pkt)
    client.handle_server_handshake(hnd_pkt)

    chunk_size = 16384  # 16 KB chunks
    total_bytes = num_megabytes * 1024 * 1024
    num_chunks = total_bytes // chunk_size
    dummy_payload = b"X" * chunk_size

    t0 = time.perf_counter()
    total_processed = 0

    for i in range(num_chunks):
        quic_pkt = client.send_stream_data(stream_id=1, data=dummy_payload)
        sid, data = server.receive_stream_data(quic_pkt)
        total_processed += len(data)

    elapsed = time.perf_counter() - t0
    mb_sec = (total_processed / (1024 * 1024)) / elapsed

    return {
        "total_mb": num_megabytes,
        "elapsed_sec": round(elapsed, 4),
        "throughput_mb_sec": round(mb_sec, 2),
    }


def run_performance_benchmarks() -> Dict[str, Any]:
    """Runs the complete suite of performance benchmarks."""
    mlkem_results = benchmark_mlkem()
    mldsa_results = benchmark_mldsa()
    quic_results = benchmark_quic_throughput(num_megabytes=5)

    return {
        "ml_kem_768": mlkem_results,
        "ml_dsa_65": mldsa_results,
        "pq_quic_streaming": quic_results,
    }
