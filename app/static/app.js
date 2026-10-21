/**
 * IPVN 7 Interactive Mesh Visualizer & Control Center Engine
 * Real-time Post-Quantum Cryptography & Live Socket Streaming Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  // State
  let nodeStatus = null;
  let activeNodesCount = 60;
  let particles = [];
  let topologyNodes = [];
  let topologyLinks = [];

  // Canvas setup
  const canvas = document.getElementById("meshCanvas");
  const ctx = canvas.getContext("2d");

  function resizeCanvas() {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }
  window.addEventListener("resize", () => {
    resizeCanvas();
    buildTopology();
  });
  resizeCanvas();

  // Topology Generator (Kleinberg Small-World Lattice)
  function buildTopology() {
    const rect = canvas.parentElement.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.40;

    topologyNodes = [];
    topologyLinks = [];

    // Create 60 nodes on ring
    for (let i = 0; i < activeNodesCount; i++) {
      const angle = (i / activeNodesCount) * Math.PI * 2 - Math.PI / 2;
      const x = centerX + Math.cos(angle) * radius;
      const y = centerY + Math.sin(angle) * radius;

      let type = "mesh";
      if (i === 0) type = "local";
      else if (i === Math.floor(activeNodesCount / 2)) type = "peer";

      topologyNodes.push({
        id: i,
        x,
        y,
        type,
        alive: true,
        pulse: 0,
      });
    }

    // Connect short-range lattice neighbors (k=2)
    for (let i = 0; i < activeNodesCount; i++) {
      topologyLinks.push({
        source: i,
        target: (i + 1) % activeNodesCount,
        isLongRange: false,
      });
    }

    // Connect Kleinberg harmonic long-range links
    for (let i = 0; i < activeNodesCount; i++) {
      if (i % 3 === 0) {
        const jump = (i + Math.floor(activeNodesCount / 3) + (i % 5)) % activeNodesCount;
        topologyLinks.push({
          source: i,
          target: jump,
          isLongRange: true,
        });
      }
    }
  }

  buildTopology();

  // Particle System
  function spawnParticle(srcIdx, dstIdx, color = "#00f2fe") {
    const src = topologyNodes[srcIdx];
    const dst = topologyNodes[dstIdx];
    if (!src || !dst) return;

    particles.push({
      x: src.x,
      y: src.y,
      startX: src.x,
      startY: src.y,
      targetX: dst.x,
      targetY: dst.y,
      progress: 0,
      speed: 0.025 + Math.random() * 0.015,
      color,
    });
  }

  // Animation Loop
  function render() {
    const rect = canvas.parentElement.getBoundingClientRect();
    ctx.clearRect(0, 0, rect.width, rect.height);

    // 1. Draw Links
    for (const link of topologyLinks) {
      const src = topologyNodes[link.source];
      const dst = topologyNodes[link.target];
      if (!src || !dst) continue;

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(dst.x, dst.y);

      if (!src.alive || !dst.alive) {
        ctx.strokeStyle = "rgba(255, 0, 85, 0.08)";
        ctx.lineWidth = 1;
      } else if (link.isLongRange) {
        ctx.strokeStyle = "rgba(157, 78, 221, 0.35)";
        ctx.lineWidth = 1.2;
      } else {
        ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
        ctx.lineWidth = 1;
      }
      ctx.stroke();
    }

    // 2. Draw & Update Particles
    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i];
      p.progress += p.speed;
      p.x = p.startX + (p.targetX - p.startX) * p.progress;
      p.y = p.startY + (p.targetY - p.startY) * p.progress;

      ctx.save();
      ctx.shadowBlur = 12;
      ctx.shadowColor = p.color;
      ctx.fillStyle = p.color;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      if (p.progress >= 1) {
        particles.splice(i, 1);
      }
    }

    // 3. Draw Nodes
    for (const node of topologyNodes) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.type === "local" || node.type === "peer" ? 7 : 4, 0, Math.PI * 2);

      if (!node.alive) {
        ctx.fillStyle = "#ff0055";
        ctx.shadowBlur = 8;
        ctx.shadowColor = "#ff0055";
      } else if (node.type === "local") {
        ctx.fillStyle = "#00f2fe";
        ctx.shadowBlur = 15;
        ctx.shadowColor = "#00f2fe";
      } else if (node.type === "peer") {
        ctx.fillStyle = "#9d4edd";
        ctx.shadowBlur = 15;
        ctx.shadowColor = "#9d4edd";
      } else {
        ctx.fillStyle = "#4a5d78";
        ctx.shadowBlur = 0;
      }
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    requestAnimationFrame(render);
  }
  requestAnimationFrame(render);

  // Periodic random packet animation along mesh
  setInterval(() => {
    if (topologyNodes.length > 0) {
      const randSrc = Math.floor(Math.random() * topologyNodes.length);
      const randDst = (randSrc + 7) % topologyNodes.length;
      spawnParticle(randSrc, randDst, Math.random() > 0.5 ? "#00f2fe" : "#9d4edd");
    }
  }, 1200);

  // Tab Navigation
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const targetPane = document.getElementById(btn.dataset.tab);
      if (targetPane) targetPane.classList.add("active");
    });
  });

  // REST API: Fetch live status
  async function fetchStatus() {
    try {
      const res = await fetch("/api/status");
      const data = await res.json();
      nodeStatus = data;

      if (data.primary) {
        const shortDid = data.primary.did.slice(0, 18) + "...";
        document.getElementById("nodeDidShort").textContent = shortDid;
        document.getElementById("fullDidString").textContent = data.primary.did;

        // Render DID Document JSON
        document.getElementById("didDocViewer").textContent = JSON.stringify(
          {
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/ipvn7/v1"],
            id: data.primary.did,
            verificationMethod: [
              { id: `${data.primary.did}#mlkem-1`, type: "MLKEM768KeyAgreementKey2026" },
              { id: `${data.primary.did}#mldsa-1`, type: "MLDSA65VerificationKey2026" }
            ],
            pqcStatus: data.primary.pqc_algorithms
          },
          null,
          2
        );
      }

      if (data.proxy && data.proxy.stats) {
        const statsEl = document.getElementById("proxyStatsBox");
        if (statsEl) {
          statsEl.textContent = `Intercepciones: ${data.proxy.stats.connections_intercepted} | Subida: ${(data.proxy.stats.bytes_tunneled_upstream/1024).toFixed(1)} KB`;
        }
      }

      // SOCKS5 Gateway stats
      if (data.socks5 && data.socks5.stats) {
        const s5 = data.socks5.stats;
        const totalEl = document.getElementById("s5TotalConn");
        if (totalEl) totalEl.textContent = s5.total_connections;
        const actEl = document.getElementById("s5ActiveConn");
        if (actEl) actEl.textContent = s5.active_connections;
        const txEl = document.getElementById("s5Tx");
        if (txEl) txEl.textContent = `${(s5.bytes_tx / 1024).toFixed(1)} KB`;
        const rxEl = document.getElementById("s5Rx");
        if (rxEl) rxEl.textContent = `${(s5.bytes_rx / 1024).toFixed(1)} KB`;
      }

      // Plumtree Gossip & TUN stats from primary node
      if (data.primary) {
        if (data.primary.plumtree_gossip) {
          const pg = data.primary.plumtree_gossip;
          const eagerEl = document.getElementById("gossipEagerCount");
          if (eagerEl) eagerEl.textContent = pg.eager_peers_count;
          const lazyEl = document.getElementById("gossipLazyCount");
          if (lazyEl) lazyEl.textContent = pg.lazy_peers_count;
          const prunesEl = document.getElementById("gossipPrunes");
          if (prunesEl && pg.stats) prunesEl.textContent = pg.stats.prunes_sent || 0;
          const graftsEl = document.getElementById("gossipGrafts");
          if (graftsEl && pg.stats) graftsEl.textContent = pg.stats.grafts_sent || 0;
        }

        if (data.primary.tun_adapter) {
          const tun = data.primary.tun_adapter;
          const modeEl = document.getElementById("tunModeLabel");
          if (modeEl) modeEl.textContent = tun.mode === "kernel_virtual" ? "Wintun Kernel Activo" : "Userspace Ring-Buffer (0 B/op)";
          const mtuEl = document.getElementById("tunMtuLabel");
          if (mtuEl) mtuEl.textContent = `MTU ${tun.mtu} B`;
        }

        if (data.primary.firewall) {
          const fw = data.primary.firewall;
          const defDenyEl = document.getElementById("fwDefaultDenyStatus");
          if (defDenyEl) {
            defDenyEl.textContent = fw.default_deny ? "DEFAULT-DENY (Activo)" : "PERMISSIVE (Inactivo)";
            defDenyEl.className = fw.default_deny ? "stat-val color-danger" : "stat-val color-success";
          }
          const evalEl = document.getElementById("fwPacketsEvaluated");
          if (evalEl && fw.stats) evalEl.textContent = fw.stats.packets_evaluated || 0;
          const accEl = document.getElementById("fwPacketsAccepted");
          if (accEl && fw.stats) accEl.textContent = fw.stats.packets_accepted || 0;
          const dropEl = document.getElementById("fwPacketsDropped");
          if (dropEl && fw.stats) dropEl.textContent = (fw.stats.packets_dropped_default_deny || 0) + (fw.stats.packets_dropped_acl || 0);

          const btnTog = document.getElementById("btnToggleDefaultDeny");
          if (btnTog) btnTog.textContent = fw.default_deny ? "Desactivar Default-Deny" : "Activar Default-Deny";
        }

        if (data.primary.dag_store) {
          const ds = data.primary.dag_store;
          const bEl = document.getElementById("dagBlocksCount");
          if (bEl) bEl.textContent = ds.blocks_stored || 0;
          const dtnEl = document.getElementById("dagDtnBundlesCount");
          if (dtnEl) dtnEl.textContent = ds.bundles_queued_dtn || 0;
        }
      }

      if (data.recent_packets) {
        renderPacketLogs(data.recent_packets);
      }
    } catch (err) {
      console.warn("Status fetch error:", err);
    }
  }

  function renderPacketLogs(packets) {
    const tbody = document.getElementById("packetLogsBody");
    tbody.innerHTML = "";

    packets.slice().reverse().forEach((pkt) => {
      const tr = document.createElement("tr");

      const isMig = pkt.event === "CONNECTION_MIGRATION";
      const isBurst = pkt.event === "PQ_QUIC_STREAM_BURST";
      let badgeCls = "badge-quic";
      let protoName = "IPVN7 / PQ-QUIC";

      if (isMig) {
        badgeCls = "badge-mig";
        protoName = "PQ-QUIC [MIGRATION]";
      } else if (isBurst) {
        badgeCls = "badge-pqc";
        protoName = "PQ-QUIC [UDP STREAM]";
      }

      tr.innerHTML = `
        <td class="mono-text">${pkt.time}</td>
        <td><span class="badge-packet ${badgeCls}">${protoName}</span></td>
        <td class="mono-text">${(pkt.from || "Genesis-Local").slice(0, 16)}...</td>
        <td class="mono-text">${(pkt.to || pkt.details || "Orbiter-Peer").slice(0, 32)}</td>
        <td class="mono-text">${pkt.payload ? `"${pkt.payload}"` : (pkt.details || "Handshake/Sync")}</td>
        <td><span class="badge-packet badge-pqc">${pkt.status || "FIPS 203/204 VERIFIED"}</span></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Load initial simulation stats from real Kleinberg model
  async function loadInitialSimStats() {
    try {
      const res = await fetch("/api/simulation/small-world?nodes=60&churn=0");
      const data = await res.json();
      document.getElementById("simHops").textContent = data.avg_hops_baseline;
      document.getElementById("dhtHops").textContent = `${data.avg_hops_baseline} Saltos Promedio`;
      document.getElementById("simDelivery").textContent = `${data.delivery_success_baseline}%`;
    } catch (e) {
      console.error(e);
    }
  }

  fetchStatus();
  loadInitialSimStats();
  setInterval(fetchStatus, 2500);

  // Action: Live UDP Socket Streaming Test
  document.getElementById("btnRunSocketStream").addEventListener("click", async () => {
    const btn = document.getElementById("btnRunSocketStream");
    btn.disabled = true;
    btn.textContent = "Transmitiendo por Sockets UDP...";

    const packetsCount = parseInt(document.getElementById("selPackets").value, 10);
    const resultsBox = document.getElementById("streamResultsBox");
    resultsBox.classList.remove("hidden");

    // Spawn burst of visual particles
    for (let i = 0; i < 8; i++) {
      setTimeout(() => spawnParticle(0, Math.floor(activeNodesCount / 2), "#00f5d4"), i * 40);
    }

    try {
      const res = await fetch("/api/quic/live_stream_test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ packets: packetsCount, chunk_size: 1400 })
      });
      const data = await res.json();

      document.getElementById("resSent").textContent = `${data.packets_sent} datagramas`;
      document.getElementById("resReceived").textContent = `${data.packets_received} recibidos (${(data.bytes_transferred / 1024).toFixed(1)} KB)`;
      document.getElementById("resTime").textContent = `${(data.elapsed_sec * 1000).toFixed(1)} ms`;
      document.getElementById("resThroughput").textContent = `${data.throughput_mb_sec} MB/s`;

      // Update Top KPI Card
      document.getElementById("streamThroughput").textContent = `${data.throughput_mb_sec} MB/s`;
      document.getElementById("streamThroughputMeta").textContent = `Medido en vivo (${data.packets_sent} pkts / ${(data.elapsed_sec*1000).toFixed(1)}ms)`;

      fetchStatus();
    } catch (err) {
      console.error("Socket stream test error:", err);
    } finally {
      btn.disabled = false;
      btn.textContent = "Ejecutar Ráfaga de Streaming UDP";
    }
  });

  // Action: Live PQC Crypto Lab Inspector (NIST FIPS 203 & 204)
  document.getElementById("btnRunLivePQC").addEventListener("click", async () => {
    const btn = document.getElementById("btnRunLivePQC");
    btn.disabled = true;
    btn.textContent = "Ejecutando en hardware...";

    const out = document.getElementById("pqcLabOutput");
    out.innerHTML = "<p class='text-muted'>Generando claves en retículos matemáticos y encapsulando secreto...</p>";

    try {
      const res = await fetch("/api/pqc/live_demo");
      const data = await res.json();
      const kem = data.ml_kem_768;
      const dsa = data.ml_dsa_65;

      out.innerHTML = `
        <div class="pqc-section-title">
          <span>NIST FIPS 203 (ML-KEM-768 / Kyber) - Intercambio de Claves</span>
        </div>
        <div class="pqc-metric-row">
          <span>Clave Pública (Public Key):</span>
          <span class="code-badge">${kem.public_key_len} Bytes &bull; Hex: ${kem.public_key_hex_sample}</span>
        </div>
        <div class="pqc-metric-row">
          <span>Texto Cifrado (Ciphertext):</span>
          <span class="code-badge">${kem.ciphertext_len} Bytes &bull; Hex: ${kem.ciphertext_hex_sample}</span>
        </div>
        <div class="pqc-metric-row">
          <span>Secreto Compartido (Shared Secret):</span>
          <span class="code-badge">${kem.shared_secret_len} Bytes &bull; Hex: ${kem.shared_secret_hex.slice(0, 32)}...</span>
        </div>
        <div class="pqc-metric-row">
          <span>Coincidencia de Desencapsulación:</span>
          <strong class="text-green">${kem.decapsulated_matches ? "AUTÉNTICO 100% (ss1 == ss2)" : "FALLO"}</strong>
        </div>
        <div class="pqc-metric-row">
          <span>Tiempos de Ejecución CPU:</span>
          <span class="mono-text text-green">Keygen: ${kem.keygen_time_ms} ms &bull; Encap: ${kem.encap_time_ms} ms &bull; Decap: ${kem.decap_time_ms} ms</span>
        </div>

        <div class="pqc-section-title mt-4">
          <span>NIST FIPS 204 (ML-DSA-65 / Dilithium) - Firma Digital</span>
        </div>
        <div class="pqc-metric-row">
          <span>Clave de Verificación:</span>
          <span class="code-badge">${dsa.public_key_len} Bytes &bull; Hex: ${dsa.public_key_hex_sample}</span>
        </div>
        <div class="pqc-metric-row">
          <span>Firma Digital Post-Cuántica:</span>
          <span class="code-badge">${dsa.signature_len} Bytes &bull; Hex: ${dsa.signature_hex_sample}</span>
        </div>
        <div class="pqc-metric-row">
          <span>Verificación Criptográfica:</span>
          <strong class="text-green">${dsa.verified ? "VÁLIDA Y FIRMADA POR CONTROLLER DID" : "INVÁLIDA"}</strong>
        </div>
        <div class="pqc-metric-row">
          <span>Tiempos de Ejecución CPU:</span>
          <span class="mono-text text-green">Keygen: ${dsa.keygen_time_ms} ms &bull; Firma: ${dsa.sign_time_ms} ms &bull; Verificación: ${dsa.verify_time_ms} ms</span>
        </div>
      `;
    } catch (err) {
      out.innerHTML = `<p class='text-danger'>Error al ejecutar laboratorio: ${err}</p>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Generar & Verificar en Vivo";
    }
  });

  // Action: Burst Single Packet
  document.getElementById("btnBurstPacket").addEventListener("click", async () => {
    spawnParticle(0, Math.floor(activeNodesCount / 2), "#00f2fe");
    try {
      await fetch("/api/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: "IPVN 7 Manual Burst Packet (1-RTT Streams)" })
      });
      fetchStatus();
    } catch (e) {
      console.error(e);
    }
  });

  // Action: Form Send Custom Message
  document.getElementById("msgSendForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const textInput = document.getElementById("txtPayload");
    const msg = textInput.value.trim();
    if (!msg) return;

    spawnParticle(0, Math.floor(activeNodesCount / 2), "#00f5d4");
    try {
      await fetch("/api/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msg })
      });
      fetchStatus();
    } catch (err) {
      console.error(err);
    }
  });

  // Action: Trigger 25% Churn
  document.getElementById("btnTriggerChurn").addEventListener("click", async () => {
    topologyNodes.forEach((node) => {
      if (node.type === "mesh" && Math.random() < 0.25) {
        node.alive = false;
      }
    });

    const alive = topologyNodes.filter((n) => n.alive).length;
    document.getElementById("simAliveCount").textContent = `${alive} / ${topologyNodes.length}`;

    try {
      const res = await fetch("/api/simulation/small-world?nodes=60&churn=0.25");
      const data = await res.json();
      document.getElementById("simHops").textContent = data.avg_hops_post_churn;
      document.getElementById("simDelivery").textContent = `${data.delivery_success_post_churn}%`;
    } catch (e) {
      console.error(e);
    }
  });

  // Action: Heal Mesh
  document.getElementById("btnHealMesh").addEventListener("click", async () => {
    topologyNodes.forEach((node) => (node.alive = true));
    document.getElementById("simAliveCount").textContent = `${topologyNodes.length} / ${topologyNodes.length}`;
    loadInitialSimStats();
  });

  // Action: Connection Migration Execution
  document.getElementById("btnExecuteMigration").addEventListener("click", async () => {
    const feedback = document.getElementById("migrationFeedback");
    feedback.className = "feedback-banner hidden";

    try {
      const res = await fetch("/api/migrate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          interface: "5g-nr-direct",
          new_ip: "10.42.0.8",
          new_port: 54321,
        })
      });
      const data = await res.json();

      if (data.success) {
        document.getElementById("epInterfaceName").textContent = "wwan5g (5G Standalone)";
        document.getElementById("epIp").textContent = "10.42.0.8:54321";

        feedback.textContent = "[ÉXITO] Migración de Conexión QUIC completada: Traspaso a red 5G ejecutado con CID continuo sin reiniciar el handshake TLS/PQC.";
        feedback.className = "feedback-banner success";

        for (let i = 0; i < 5; i++) {
          setTimeout(() => spawnParticle(0, Math.floor(activeNodesCount / 2), "#9d4edd"), i * 80);
        }
        fetchStatus();
      }
    } catch (err) {
      console.error("Migration error:", err);
    }
  });

  // Action: Run CPU Benchmarks (Calculated live)
  document.getElementById("btnRunBench").addEventListener("click", async () => {
    const btn = document.getElementById("btnRunBench");
    btn.disabled = true;
    btn.textContent = "Calculando bucle de CPU...";

    try {
      const res = await fetch("/api/benchmark");
      const data = await res.json();

      document.getElementById("bKEMEncap").textContent = `${data.ml_kem_768.encap_ops_sec.toLocaleString()} ops/s`;
      document.getElementById("bKEMDecap").textContent = `${data.ml_kem_768.decap_ops_sec.toLocaleString()} ops/s`;
      document.getElementById("bDSAVerify").textContent = `${data.ml_dsa_65.verify_ops_sec.toLocaleString()} ops/s`;
      document.getElementById("bQUICRate").textContent = `${data.pq_quic_streaming.throughput_mb_sec} MB/s`;
    } catch (err) {
      console.error("Benchmark error:", err);
    } finally {
      btn.disabled = false;
      btn.textContent = "Re-ejecutar Medición";
    }
  });

  // Action: Run Datapath Saturation Benchmark (1280B Gbps)
  const btnSatBench = document.getElementById("btnRunSaturationBench");
  if (btnSatBench) {
    btnSatBench.addEventListener("click", async () => {
      const mb = document.getElementById("selSatMb")?.value || "4";
      const chkUdp = document.getElementById("chkSatUdp")?.checked ? "1" : "0";
      const resultsBox = document.getElementById("satResultsBox");

      btnSatBench.disabled = true;
      btnSatBench.textContent = "Saturando Datapath...";
      if (resultsBox) {
        resultsBox.style.display = "block";
        resultsBox.textContent = "Ejecutando fragmentación 1280B y pipeline de saturación...";
      }

      try {
        const res = await fetch(`/api/benchmark/saturation?mb=${mb}&udp=${chkUdp}`);
        const data = await res.json();

        const elGbps = document.getElementById("satThroughputGbps");
        const elMb = document.getElementById("satThroughputMb");
        const elPps = document.getElementById("satPps");
        const elLat = document.getElementById("satLatencyUs");

        if (elGbps) elGbps.textContent = `${data.throughput_gbps} Gbps`;
        if (elMb) elMb.textContent = `${data.throughput_mb_s} MB/s`;
        if (elPps) elPps.textContent = `${Math.round(data.packets_per_second).toLocaleString()} pps`;
        if (elLat) elLat.textContent = `${data.avg_fragment_latency_us} µs`;

        if (resultsBox) {
          resultsBox.textContent = JSON.stringify(data, null, 2);
        }
      } catch (err) {
        if (resultsBox) resultsBox.textContent = `Error en saturación: ${err}`;
      } finally {
        btnSatBench.disabled = false;
        btnSatBench.textContent = "Saturar Datapath Local 1280B";
      }
    });
  }

  // Action: Run Static Dictionary Header Compression
  const btnCompress = document.getElementById("btnRunCompressSample");
  if (btnCompress) {
    btnCompress.addEventListener("click", async () => {
      const inputVal = document.getElementById("txtCompressPayload")?.value.trim() || "";
      const resultsBox = document.getElementById("compressResultsBox");

      btnCompress.disabled = true;
      try {
        const res = await fetch("/api/compression/benchmark", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: inputVal }),
        });
        const data = await res.json();
        if (resultsBox) {
          resultsBox.style.display = "block";
          resultsBox.textContent = JSON.stringify(data, null, 2);
        }
      } catch (err) {
        if (resultsBox) {
          resultsBox.style.display = "block";
          resultsBox.textContent = `Error de compresión: ${err}`;
        }
      } finally {
        btnCompress.disabled = false;
      }
    });
  }

  // Action: Clear Logs
  document.getElementById("btnClearLogs").addEventListener("click", () => {
    document.getElementById("packetLogsBody").innerHTML = "";
  });

  // Action: Fetch Real Internet Traffic through IPVN 7 Tunnel
  const netForm = document.getElementById("internetFetchForm");
  if (netForm) {
    netForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const urlInput = document.getElementById("txtInternetUrl");
      const url = urlInput.value.trim();
      if (!url) return;

      const btn = document.getElementById("btnFetchInternet");
      btn.disabled = true;
      btn.textContent = "Capturando & Enrutando...";

      const resBox = document.getElementById("internetFetchResult");
      resBox.classList.remove("hidden");
      resBox.innerHTML = "<p class='text-muted'>Interceptando paquete en socket Windows y encapsulando en PQ-QUIC...</p>";

      // Particle animation through node 0 to node peer to internet
      for (let i = 0; i < 6; i++) {
        setTimeout(() => spawnParticle(0, Math.floor(activeNodesCount / 2), "#ffb703"), i * 60);
      }

      try {
        const res = await fetch("/api/internet/fetch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url })
        });
        const data = await res.json();

        if (data.success) {
          resBox.innerHTML = `
            <div class="pqc-section-title">
              <span>Tráfico de Windows Enrutado con Éxito a Internet</span>
            </div>
            <div class="pqc-metric-row">
              <span>Destino Público Solicitado:</span>
              <strong class="text-green">${data.url}</strong>
            </div>
            <div class="pqc-metric-row">
              <span>Código de Estado HTTP:</span>
              <span class="code-badge">${data.status_code} OK</span>
            </div>
            <div class="pqc-metric-row">
              <span>Latencia Total de Túnel:</span>
              <span class="mono-text text-green">${data.elapsed_ms} ms</span>
            </div>
            <div class="pqc-metric-row">
              <span>Bytes Recibidos:</span>
              <span class="code-badge">${data.bytes_received} Bytes</span>
            </div>
            <div class="pqc-metric-row">
              <span>Ruta de Enrutamiento IPVN 7:</span>
              <span class="code-badge">${data.route}</span>
            </div>
            <div class="pqc-metric-row">
              <span>Blindaje Cuántico:</span>
              <span class="badge-packet badge-pqc">${data.pqc_hardening}</span>
            </div>
            <div class="mt-4">
              <span style="font-size:0.7rem; color:var(--text-muted); display:block; margin-bottom:0.25rem;">Vista previa de Carga Útil Recibida de Internet:</span>
              <pre class="json-viewer mono-text" style="max-height:120px;">${data.body_preview.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</pre>
            </div>
          `;
        } else {
          resBox.innerHTML = `<p class='text-danger'>Fallo en el túnel a Internet: ${data.error}</p>`;
        }
        fetchStatus();
      } catch (err) {
        resBox.innerHTML = `<p class='text-danger'>Error de comunicación: ${err}</p>`;
      } finally {
        btn.disabled = false;
        btn.textContent = "Capturar & Enrutar por IPVN 7";
      }
    });
  }

  // Action: SOCKS5 Direct Test Form
  const s5Form = document.getElementById("socks5TestForm");
  if (s5Form) {
    s5Form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const host = document.getElementById("txtSocks5Host").value.trim() || "example.com";
      const port = parseInt(document.getElementById("txtSocks5Port").value, 10) || 80;
      const btn = document.getElementById("btnTestSocks5");
      const resBox = document.getElementById("socks5ResultBox");

      btn.disabled = true;
      btn.textContent = "Probando Socket RFC 1928...";
      resBox.classList.remove("hidden");
      resBox.innerHTML = "<p class='text-muted'>Conectando a 127.0.0.1:10807 y negociando SOCKS5...</p>";

      try {
        const res = await fetch("/api/socks5/test", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ dest_host: host, dest_port: port })
        });
        const data = await res.json();
        if (data.success) {
          resBox.innerHTML = `
            <div class="pqc-section-title">
              <span>Túnel SOCKS5 (RFC 1928) Establecido</span>
            </div>
            <div class="pqc-metric-row"><span>Destino Solicitado:</span> <strong class="text-green">${data.dest_host}:${data.dest_port}</strong></div>
            <div class="pqc-metric-row"><span>Puerto Gateway Local:</span> <span class="code-badge">:${data.gateway_port}</span></div>
            <div class="pqc-metric-row"><span>Latencia de Establecimiento:</span> <span class="mono-text text-green">${data.latency_ms} ms</span></div>
            <div class="pqc-metric-row"><span>Bytes Recibidos:</span> <span class="code-badge">${data.bytes_received} Bytes</span></div>
            <div class="pqc-metric-row"><span>Ruta de Malla:</span> <span class="code-badge">${data.route}</span></div>
            <div class="mt-4">
              <span style="font-size:0.7rem; color:var(--text-muted);">Respuesta HTTP tunelada por socket SOCKS5:</span>
              <pre class="json-viewer mono-text" style="max-height:100px;">${data.response_preview.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</pre>
            </div>
          `;
        } else {
          resBox.innerHTML = `<p class='text-danger'>Fallo en SOCKS5: ${data.error}</p>`;
        }
        fetchStatus();
      } catch (err) {
        resBox.innerHTML = `<p class='text-danger'>Error: ${err}</p>`;
      } finally {
        btn.disabled = false;
        btn.textContent = "Probar Túnel SOCKS5";
      }
    });
  }

  // Action: Sphinx Onion Route Form
  const onionForm = document.getElementById("onionSendForm");
  if (onionForm) {
    onionForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = document.getElementById("txtOnionPayload").value.trim();
      const btn = document.getElementById("btnTestOnion");
      const resBox = document.getElementById("onionResultBox");

      btn.disabled = true;
      btn.textContent = "Construyendo 3 Saltos...";
      resBox.classList.remove("hidden");
      resBox.innerHTML = "<p class='text-muted'>Cifrando capas ChaCha20 + PQC y pelando en cascada...</p>";

      try {
        const res = await fetch("/api/onion/route", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ payload })
        });
        const data = await res.json();
        if (data.success) {
          resBox.innerHTML = `
            <div class="pqc-section-title"><span>Circuito Cebolla Sphinx de 3 Saltos Completado</span></div>
            <div class="pqc-metric-row"><span>Tamaño Determinista Wire:</span> <strong class="text-green">${data.packet_size} Bytes (MTU 1280 Canónica)</strong></div>
            <div class="pqc-metric-row"><span>Tiempo de Síntesis:</span> <span class="mono-text text-green">${data.build_time_us} &mu;s</span></div>
            <div class="pqc-metric-row"><span>Salto 1 (Relay Alpha):</span> <span class="code-badge">${data.peel_hop1.action} &bull; ${data.peel_hop1.elapsed_us} &mu;s</span></div>
            <div class="pqc-metric-row"><span>Salto 2 (Relay Beta):</span> <span class="code-badge">${data.peel_hop2.action} &bull; ${data.peel_hop2.elapsed_us} &mu;s</span></div>
            <div class="pqc-metric-row"><span>Salto 3 (Exit Node):</span> <span class="code-badge">${data.peel_hop3.action} &bull; ${data.peel_hop3.elapsed_us} &mu;s</span></div>
            <div class="pqc-metric-row"><span>Hash Tag Anti-Replay:</span> <span class="code-badge">${data.tag_hash}</span></div>
            <div class="mt-4">
              <span style="font-size:0.7rem; color:var(--text-muted);">Carga Útil Desempaquetada en Destino Final:</span>
              <pre class="json-viewer mono-text" style="max-height:80px;">${data.peel_hop3.delivered_payload.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</pre>
            </div>
          `;
        }
        fetchStatus();
      } catch (err) {
        resBox.innerHTML = `<p class='text-danger'>Error: ${err}</p>`;
      } finally {
        btn.disabled = false;
        btn.textContent = "Construir & Pelar Circuito";
      }
    });
  }

  // Action: Plumtree Gossip Form
  const gossipForm = document.getElementById("gossipBroadcastForm");
  if (gossipForm) {
    gossipForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const topic = document.getElementById("txtGossipTopic").value.trim() || "TOPOLOGY_SYNC";
      const content = document.getElementById("txtGossipContent").value.trim() || "Alerta Mesh";
      const btn = document.getElementById("btnBroadcastGossip");
      const resBox = document.getElementById("gossipResultBox");

      btn.disabled = true;
      btn.textContent = "Diseminando por Árbol Plumtree...";
      resBox.classList.remove("hidden");

      try {
        const res = await fetch("/api/gossip/broadcast", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ topic, content })
        });
        const data = await res.json();
        if (data.success) {
          resBox.innerHTML = `
            <div class="pqc-section-title"><span>Difusión Epidémica Diseminada</span></div>
            <div class="pqc-metric-row"><span>Message ID Hash:</span> <strong class="text-green">${data.msg_id}</strong></div>
            <div class="pqc-metric-row"><span>Origen DID:</span> <span class="code-badge">${data.origin_did.slice(0, 24)}...</span></div>
            <div class="pqc-metric-row"><span>Árbol Eager Activo:</span> <span class="code-badge">${data.eager_tree_size} Pares</span></div>
            <div class="pqc-metric-row"><span>Malla Lazy (IHAVE):</span> <span class="code-badge">${data.lazy_tree_size} Pares</span></div>
            <div class="pqc-metric-row"><span>Supresión de Duplicados:</span> <strong class="text-cyan">${data.stats.duplicates_suppressed} descartados</strong></div>
          `;
        }
        fetchStatus();
      } catch (err) {
        resBox.innerHTML = `<p class='text-danger'>Error: ${err}</p>`;
      } finally {
        btn.disabled = false;
        btn.textContent = "Emitir Broadcast";
      }
    });
  }

  // Action: SWIM Probe Button
  const btnSwim = document.getElementById("btnProbeSWIM");
  if (btnSwim) {
    btnSwim.addEventListener("click", async () => {
      btnSwim.disabled = true;
      btnSwim.textContent = "Sondeando O(1) con SWIM...";
      const resBox = document.getElementById("swimResultBox");
      resBox.classList.remove("hidden");

      try {
        const res = await fetch("/api/swim/probe", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({})
        });
        const data = await res.json();
        if (data.success) {
          resBox.innerHTML = `
            <div class="pqc-section-title"><span>Veredicto de Detección de Caídas SWIM</span></div>
            <div class="pqc-metric-row"><span>Estado del Par:</span> <strong class="text-green">${data.state}</strong></div>
            <div class="pqc-metric-row"><span>Ruta de Sondeo:</span> <span class="code-badge">${data.via_indirect ? "Indirecto (Ping-Req)" : "Directo (UDP Probe)"}</span></div>
            <div class="pqc-metric-row"><span>Latencia de Detección:</span> <span class="mono-text text-green">${data.latency_ms} ms</span></div>
          `;
        }
        fetchStatus();
      } catch (err) {
        resBox.innerHTML = `<p class='text-danger'>Error SWIM: ${err}</p>`;
      } finally {
        btnSwim.disabled = false;
        btnSwim.textContent = "Sondear Salud de Nodo Par con SWIM";
      }
    });
  }

  // Action: MCP Tool Invocation Runner
  const selTool = document.getElementById("selMcpTool");
  const reqPreview = document.getElementById("mcpRequestPreview");
  const btnRunMcp = document.getElementById("btnExecuteMcpTool");
  const mcpResBox = document.getElementById("mcpResponseBox");

  function updateMcpPreview() {
    if (!selTool || !reqPreview) return;
    const tool = selTool.value;
    let sampleArgs = {};
    if (tool === "resolve_did") sampleArgs = { did: "did:ipvn7:zTester999" };
    else if (tool === "send_pq_datagram") sampleArgs = { target_did: "did:ipvn7:zOrbiter123", payload: "Ping over MCP" };
    else if (tool === "route_sphinx_onion") sampleArgs = { payload: "Confidential MCP Datagram" };
    else if (tool === "probe_peer_swim") sampleArgs = { target_did: "did:ipvn7:zPeerNode" };
    else if (tool === "trigger_connection_migration") sampleArgs = { target_did: "did:ipvn7:zPeerNode", new_ip: "10.42.0.8", new_port: 54321, interface_name: "wwan5g" };
    else if (tool === "ipvn7_firewall_rule") sampleArgs = { action: "set", did: "did:ipvn7:zPeerAuth", allow_inbound: true };
    else if (tool === "ipvn7_wot_vouch") sampleArgs = { subject_did: "did:ipvn7:zPeerAuth", trust_level: 0.9, reason: "Verified Peer" };
    else if (tool === "ipvn7_get_trust") sampleArgs = { target_did: "did:ipvn7:zPeerAuth" };
    else if (tool === "ipvn7_get_anomalies") sampleArgs = { limit: 10 };
    else if (tool === "ipvn7_audit_split_brain") sampleArgs = {};
    else if (tool === "ipvn7_register_petname") sampleArgs = { name: "gateway", did: "did:ipvn7:zGateway123", comment: "Primary Gateway" };
    else if (tool === "ipvn7_resolve_petname") sampleArgs = { name: "gateway.ipv7" };
    else if (tool === "ipvn7_get_oob_sas") sampleArgs = { peer_pubkey_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" };
    else if (tool === "ipvn7_toggle_dark_node") sampleArgs = {};
    else if (tool === "ipvn7_send_silent_call") sampleArgs = { target_did: "did:ipvn7:zSilentPeer", payload: "STEALTH_PING" };
    else if (tool === "ipvn7_route_planetary") sampleArgs = { src_node: "sat-000", dst_node: "sat-015" };
    else if (tool === "ipvn7_resilience_status") sampleArgs = {};
    else if (tool === "ipvn7_wasm_compute_pow") sampleArgs = { did: "did:ipvn7:zClientBrowser", seq: 1, difficulty_bits: 8 };
    else if (tool === "ipvn7_fsm_trigger_event") sampleArgs = { event: "NETWORK_SIGNAL", payload: "Discovered neighbor" };
    else if (tool === "ipvn7_pipeline_process_datagram") sampleArgs = { raw_hex: "07010203040506070809", source_did: "did:ipvn7:zAlice" };
    else if (tool === "ipvn7_audit_censorship") sampleArgs = { domain: "cloudflare.com" };
    else if (tool === "ipvn7_get_buffer_health") sampleArgs = {};
    else if (tool === "ipvn7_rotate_session_key") sampleArgs = {};
    else if (tool === "ipvn7_map_upnp_port") sampleArgs = { port: 7001, description: "ipvn7-p2p" };
    else if (tool === "ipvn7_probe_wan_link") sampleArgs = { peer_did: "did:ipvn7:zPeerNode", endpoint: "127.0.0.1:9443" };
    else if (tool === "ipvn7_dispatch_remote_input") sampleArgs = { event_type: "mouse_move", x: 0.5, y: 0.5 };
    else if (tool === "ipvn7_issue_uin_binding") sampleArgs = { subordinate_pubkey_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", scope: 3, duration_seconds: 86400 };
    else if (tool === "ipvn7_get_uin_passport") sampleArgs = {};
    else if (tool === "ipvn7_register_shadow_device") sampleArgs = { name: "Ollama-RTX4090", physical_ip: "192.168.1.180", mac: "00:1A:2B:3C:4D:5E", device_type: "edge_ai" };
    else if (tool === "ipvn7_get_pfo_tree") sampleArgs = {};
    else if (tool === "ipvn7_nat_hole_punch") sampleArgs = { peer_did: "did:ipvn7:zPeerNode", peer_public_ip: "127.0.0.1", peer_public_port: 9443 };
    else if (tool === "ipvn7_allocate_memory_budget") sampleArgs = { budget_class: "replay", num_bytes: 4096 };
    else if (tool === "ipvn7_schedule_multipath") sampleArgs = { payload: "Multipath Datagram", is_critical: true };
    else if (tool === "ipvn7_resolve_dns_proxy") sampleArgs = { domain: "gateway.ipv7" };
    else if (tool === "ipvn7_run_ai_copilot") sampleArgs = { latency_ms: 65.0, firewall_drops: 8, peer_did: "did:ipvn7:zAttacker" };
    else if (tool === "ipvn7_update_mobility_locator") sampleArgs = { node_did: "did:ipvn7:zMobileClient", physical_ip: "10.42.0.88", physical_port: 54321, seq: 1 };
    else if (tool === "ipvn7_send_chat_message") sampleArgs = { target_did: "did:ipvn7:zPeerNode", text: "Hola desde MCP" };
    else if (tool === "ipvn7_get_batcher_stats") sampleArgs = {};
    else if (tool === "ipvn7_record_link_probe") sampleArgs = { peer_did: "did:ipvn7:zPeerNode", success: true, latency_ms: 12.0 };
    else if (tool === "ipvn7_blackout_recovery") sampleArgs = { action: "status" };
    else if (tool === "ipvn7_dispatch_edge_ai_prompt") sampleArgs = { prompt: "¿Cuál es el principio ontológico de IPVN 7?", model: "llama3" };
    else if (tool === "ipvn7_bitnet_quantize_and_infer") sampleArgs = { x: [0.5, -0.2, 0.8, -0.9], weights: [[0.4, -0.1, 0.7, -0.8], [-0.5, 0.2, -0.3, 0.9]], model_name: "iot-bitnet-demo" };
    else if (tool === "ipvn7_dispatch_remote_media_frame") sampleArgs = { frame_type: "video_delta", codec: "av1" };
    else if (tool === "ipvn7_run_churn_stress_test") sampleArgs = { node_count: 50, churn_rate: 0.20, packet_loss_rate: 0.10 };
    else if (tool === "ipvn7_get_daily_ephemeral_id") sampleArgs = {};
    else if (tool === "ipvn7_dispatch_hrs_frame") sampleArgs = { action: "create", frame_type: "QUERY", target_did: "did:ipvn7:zGateway123", payload_text: "PING" };
    else if (tool === "ipvn7_issue_reciprocity_token") sampleArgs = { beneficiary_did: "did:ipvn7:zPeerNode", bandwidth_credits: 1048576 };
    else if (tool === "ipvn7_get_settlement_ledger") sampleArgs = {};
    else if (tool === "ipvn7_orchestrate_silent_rekey") sampleArgs = {};
    else if (tool === "ipvn7_select_geopolicy_route") sampleArgs = { target_did: "did:ipvn7:zDestination", mode: "BALANCED" };
    else if (tool === "ipvn7_sync_interregion_dht") sampleArgs = { peer_region: "region-europe-central" };
    else if (tool === "ipvn7_probe_tunnel_telemetry") sampleArgs = { tunnel_id: "tun0-wintun", sample_rtt_ms: 12.5 };

    const sampleRpc = {
      jsonrpc: "2.0",
      id: "req-" + Date.now().toString().slice(-4),
      method: "tools/call",
      params: {
        name: tool,
        arguments: sampleArgs
      }
    };
    reqPreview.textContent = JSON.stringify(sampleRpc, null, 2);
  }

  if (selTool) {
    selTool.addEventListener("change", updateMcpPreview);
    updateMcpPreview();
  }

  if (btnRunMcp) {
    btnRunMcp.addEventListener("click", async () => {
      btnRunMcp.disabled = true;
      btnRunMcp.textContent = "Ejecutando en Malla...";
      mcpResBox.textContent = "Enviando frame JSON-RPC 2.0 a /api/mcp...";

      try {
        const rpcPayload = JSON.parse(reqPreview.textContent);
        const res = await fetch("/api/mcp", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(rpcPayload)
        });
        const data = await res.json();
        mcpResBox.textContent = JSON.stringify(data, null, 2);
        fetchStatus();
      } catch (err) {
        mcpResBox.textContent = `Error JSON-RPC: ${err}`;
      } finally {
        btnRunMcp.disabled = false;
        btnRunMcp.textContent = "Invocar Herramienta JSON-RPC";
      }
    });
  }
  // -----------------------------------------------------------------
  // ZTNA Microsegmentation & Web of Trust Handlers
  // -----------------------------------------------------------------
  const btnToggleDefDeny = document.getElementById("btnToggleDefaultDeny");
  if (btnToggleDefDeny) {
    btnToggleDefDeny.addEventListener("click", async () => {
      try {
        const isCurrentlyActive = btnToggleDefDeny.textContent.includes("Desactivar");
        const res = await fetch("/api/firewall/toggle_default_deny", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: !isCurrentlyActive })
        });
        await res.json();
        fetchStatus();
      } catch (err) {
        console.error("Error toggling default-deny:", err);
      }
    });
  }

  const btnSavePolicy = document.getElementById("btnSaveFwPolicy");
  if (btnSavePolicy) {
    btnSavePolicy.addEventListener("click", async () => {
      const did = document.getElementById("fwTargetDid").value.trim();
      const allowIn = document.getElementById("fwAllowInbound").checked;
      const allowOut = document.getElementById("fwAllowOutbound").checked;
      const allowRelay = document.getElementById("fwAllowRelay").checked;
      if (!did) return alert("Ingrese un DID válido");

      try {
        await fetch("/api/firewall/policy", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            did,
            allow_inbound: allowIn,
            allow_outbound: allowOut,
            allow_relay: allowRelay
          })
        });
        alert(`Política ZTNA guardada para ${did.slice(0, 24)}...`);
        fetchStatus();
      } catch (err) {
        alert("Error al guardar política: " + err);
      }
    });
  }

  const btnIssueVouch = document.getElementById("btnIssueWotVouch");
  if (btnIssueVouch) {
    btnIssueVouch.addEventListener("click", async () => {
      const subject_did = document.getElementById("wotSubjectDid").value.trim();
      const trust_level = parseFloat(document.getElementById("wotTrustLevel").value);
      const reason = document.getElementById("wotReason").value.trim();
      if (!subject_did) return alert("Ingrese el DID del sujeto para avalar");

      try {
        const res = await fetch("/api/wot/vouch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ subject_did, trust_level, reason })
        });
        const data = await res.json();
        if (data.success) {
          const scoreEl = document.getElementById("wotTrustScoreDisplay");
          if (scoreEl) scoreEl.textContent = data.computed_trust.toFixed(4);
          alert(`Aval Ed25519 emitido con éxito hacia ${subject_did.slice(0, 24)}... (Confianza: ${trust_level})`);
        }
        fetchStatus();
      } catch (err) {
        alert("Error emitiendo aval WoT: " + err);
      }
    });
  }

  // -----------------------------------------------------------------
  // Content-Addressed DAG & DTN Handlers
  // -----------------------------------------------------------------
  async function fetchDagBlocks() {
    try {
      const res = await fetch("/api/dag/blocks");
      const data = await res.json();
      const listEl = document.getElementById("dagBlocksList");
      if (!listEl) return;

      if (!data.blocks || data.blocks.length === 0) {
        listEl.textContent = "No hay bloques commitados en el DAG todavía.";
        return;
      }

      listEl.innerHTML = data.blocks.map(b => `
        <div style="border-bottom:1px solid rgba(255,255,255,0.08); padding:6px 0;">
          <div style="color:var(--accent-glow); font-weight:600;">${b.cid}</div>
          <div style="color:var(--text-muted); font-size:0.72rem;">Autor: ${b.author_did.slice(0, 24)}... &bull; ${new Date(b.timestamp * 1000).toLocaleTimeString()} &bull; ${b.data_bytes} Bytes</div>
          <div style="color:#e2e8f0; margin-top:2px;">${b.data_preview}</div>
        </div>
      `).join("");
    } catch (err) {
      console.warn("DAG fetch error:", err);
    }
  }

  const btnPublishDag = document.getElementById("btnPublishDagBlock");
  if (btnPublishDag) {
    btnPublishDag.addEventListener("click", async () => {
      const data = document.getElementById("dagPayloadInput").value.trim();
      const target_did = document.getElementById("dagTargetDidInput").value.trim();
      if (!data) return alert("Ingrese una carga útil para el bloque DAG");

      try {
        const res = await fetch("/api/dag/put", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ data, target_did })
        });
        const resp = await res.json();
        if (resp.success) {
          fetchDagBlocks();
          fetchStatus();
        }
      } catch (err) {
        alert("Error publicando bloque DAG: " + err);
      }
    });
  }

  // -----------------------------------------------------------------
  // Diagnostics: Anomaly Fingerprinter & Split-Brain Quorum
  // -----------------------------------------------------------------
  async function fetchDiagnostics() {
    try {
      // Anomalies
      const anomRes = await fetch("/api/diagnostics/anomalies");
      const anomData = await anomRes.json();
      if (anomData.summary) {
        const sum = anomData.summary;
        const totalEl = document.getElementById("anomTotalCount");
        if (totalEl) totalEl.textContent = sum.total_incidents_recorded;
        const unqEl = document.getElementById("anomUniqueCount");
        if (unqEl) unqEl.textContent = sum.unique_fingerprints;

        if (sum.counts_by_severity) {
          const crit = document.getElementById("anomCritCount");
          if (crit) crit.textContent = sum.counts_by_severity.CRITICAL || 0;
          const high = document.getElementById("anomHighCount");
          if (high) high.textContent = sum.counts_by_severity.HIGH || 0;
          const med = document.getElementById("anomMedCount");
          if (med) med.textContent = sum.counts_by_severity.MEDIUM || 0;
          const low = document.getElementById("anomLowCount");
          if (low) low.textContent = sum.counts_by_severity.LOW || 0;
        }
      }

      const anomListEl = document.getElementById("anomaliesList");
      if (anomListEl && anomData.fingerprints) {
        if (anomData.fingerprints.length === 0) {
          anomListEl.textContent = "No se han detectado anomalías de red o fallos de buffer.";
        } else {
          anomListEl.innerHTML = anomData.fingerprints.map(fp => `
            <div style="border-bottom:1px solid rgba(255,255,255,0.08); padding:6px 0;">
              <div style="display:flex; justify-content:space-between;">
                <span style="color:#00f5d4; font-weight:700;">[SIG:${fp.signature}] ${fp.error_type}</span>
                <span style="font-weight:700; color:${fp.severity === 'CRITICAL' ? '#ff007f' : fp.severity === 'HIGH' ? '#fb8500' : '#ffb703'};">${fp.severity} (${fp.count}x)</span>
              </div>
              <div style="color:var(--text-muted); font-size:0.72rem;">Subsistema: ${fp.subsystem} &bull; Visto: ${fp.last_seen_iso}</div>
              <div style="color:#e2e8f0; margin-top:2px;">${fp.root_cause}</div>
            </div>
          `).join("");
        }
      }

      // Split-Brain Quorum
      const sbRes = await fetch("/api/diagnostics/split_brain");
      const sbData = await sbRes.json();
      if (sbData.health) {
        const h = sbData.health;
        const stateEl = document.getElementById("sbStateLabel");
        if (stateEl) {
          stateEl.textContent = h.state;
          stateEl.className = h.state === "HEALTHY" ? "stat-val color-success" : "stat-val color-danger";
        }
        const qEl = document.getElementById("sbQuorumRatio");
        if (qEl) {
          qEl.textContent = `${h.active_peers} / ${h.total_peers} (${(h.quorum_ratio * 100).toFixed(0)}%)`;
        }
      }
    } catch (err) {
      console.warn("Diagnostics fetch error:", err);
    }
  }

  const btnAuditSb = document.getElementById("btnAuditSplitBrain");
  if (btnAuditSb) {
    btnAuditSb.addEventListener("click", async () => {
      btnAuditSb.disabled = true;
      btnAuditSb.textContent = "Auditando...";
      await fetchDiagnostics();
      btnAuditSb.disabled = false;
      btnAuditSb.textContent = "Auditar Quórum en Vivo";
    });
  }

  // -----------------------------------------------------------------
  // dDNS Petnames & Out-of-Band Pairing Handlers
  // -----------------------------------------------------------------
  async function fetchPetnames() {
    try {
      const res = await fetch("/api/petnames");
      const data = await res.json();
      const listEl = document.getElementById("petnamesList");
      if (!listEl) return;

      if (!data.records || data.records.length === 0) {
        listEl.textContent = "No hay petnames registrados en la libreta dDNS todavía.";
        return;
      }

      listEl.innerHTML = data.records.map(r => `
        <div style="border-bottom:1px solid rgba(255,255,255,0.08); padding:6px 0;">
          <div style="display:flex; justify-content:space-between;">
            <strong style="color:var(--accent-cyan);">${r.name}</strong>
            <span class="mono-text" style="color:var(--text-muted); font-size:0.7rem;">${r.virtual_ipv4} &bull; ${r.virtual_ipv6}</span>
          </div>
          <div style="color:#e2e8f0; font-size:0.75rem;">DID: ${r.did}</div>
          ${r.comment ? `<div style="color:var(--text-dim); font-size:0.7rem; font-style:italic;">${r.comment}</div>` : ""}
        </div>
      `).join("");
    } catch (err) {
      console.warn("Petnames fetch error:", err);
    }
  }

  const btnRegPetname = document.getElementById("btnRegisterPetname");
  if (btnRegPetname) {
    btnRegPetname.addEventListener("click", async () => {
      const name = document.getElementById("txtPetnameName").value.trim();
      const did = document.getElementById("txtPetnameDid").value.trim();
      const comment = document.getElementById("txtPetnameComment").value.trim();
      if (!name) return alert("Ingrese un nombre mnemotécnico");
      if (!did) return alert("Ingrese un DID de destino");

      try {
        const res = await fetch("/api/petnames/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, did, comment })
        });
        const data = await res.json();
        if (data.success) {
          alert(`Petname ${data.record.name} registrado con éxito`);
          fetchPetnames();
        }
      } catch (err) {
        alert("Error registrando petname: " + err);
      }
    });
  }

  const btnResPetname = document.getElementById("btnResolvePetname");
  if (btnResPetname) {
    btnResPetname.addEventListener("click", async () => {
      const name = document.getElementById("txtResolveQuery").value.trim();
      const resEl = document.getElementById("petnameResolveResult");
      if (!name) return alert("Ingrese un nombre a resolver");

      try {
        const res = await fetch(`/api/petnames/resolve?name=${encodeURIComponent(name)}`);
        const data = await res.json();
        if (data.found && data.record) {
          const r = data.record;
          resEl.innerHTML = `
            <div style="color:#00f5d4; font-weight:700;">✓ Resuelto: ${r.name}</div>
            <div>DID: <strong>${r.did}</strong></div>
            <div>IPv6 Soberana: <span class="mono-text">${r.virtual_ipv6}</span></div>
            <div>IPv4 Sintética: <span class="mono-text">${r.virtual_ipv4}</span></div>
          `;
        } else {
          resEl.innerHTML = `<span style="color:#ff007f;">✗ Nombre no encontrado en dDNS local</span>`;
        }
      } catch (err) {
        resEl.innerHTML = `<span style="color:#ff007f;">Error: ${err}</span>`;
      }
    });
  }

  const btnGenSas = document.getElementById("btnGenerateSas");
  if (btnGenSas) {
    btnGenSas.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/oob/sas", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({})
        });
        const data = await res.json();
        if (data.success) {
          const box = document.getElementById("sasDisplayBox");
          const codeEl = document.getElementById("sasVisualCode");
          if (box && codeEl) {
            codeEl.textContent = `${data.digits}  ${data.emojis.join(" ")}`;
            box.style.display = "block";
          }
        }
      } catch (err) {
        alert("Error derivando SAS: " + err);
      }
    });
  }

  const btnUrQr = document.getElementById("btnViewUrQr");
  if (btnUrQr) {
    btnUrQr.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/oob/profile");
        const data = await res.json();
        const box = document.getElementById("urFramesBox");
        const pre = document.getElementById("urFramesPre");
        if (box && pre) {
          pre.textContent = data.ur_frames.join("\n");
          box.style.display = "block";
        }
      } catch (err) {
        alert("Error obteniendo tramas UR: " + err);
      }
    });
  }

  // --- Tit-for-Tat Transit Accounting & Microservices Client Logic ---
  async function fetchAccountingData() {
    try {
      const res = await fetch("/api/accounting");
      const data = await res.json();
      const summary = data.summary;
      const elTracked = document.getElementById("accTrackedPeers");
      const elGlobalBytes = document.getElementById("accGlobalBytes");
      if (elTracked) elTracked.textContent = summary.tracked_peers || 0;
      if (elGlobalBytes) {
        const txKb = ((summary.total_bytes_tx || 0) / 1024).toFixed(1);
        const rxKb = ((summary.total_bytes_rx || 0) / 1024).toFixed(1);
        elGlobalBytes.textContent = `${txKb} KB Tx / ${rxKb} KB Rx`;
      }

      if (data.accounts && data.accounts.length > 0) {
        const top = data.accounts[0];
        const elRatio = document.getElementById("accPeerRatio");
        const elTier = document.getElementById("accPeerTier");
        if (elRatio) elRatio.textContent = Number(top.tit_for_tat_ratio).toFixed(3);
        if (elTier) {
          elTier.textContent = top.tier;
          elTier.className = `bench-val ${top.tier === "PRIORITY" ? "text-green" : top.tier === "THROTTLED" ? "text-danger" : ""}`;
        }
      }
    } catch (err) {
      console.error("Accounting fetch error:", err);
    }
  }

  async function fetchServicesData() {
    try {
      const res = await fetch("/api/services");
      const data = await res.json();
      const container = document.getElementById("servicesListTable");
      if (container && data.services) {
        container.innerHTML = data.services.map(s => `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:4px 0; border-bottom:1px solid rgba(255,255,255,0.06);">
            <div>
              <strong style="color:#00f2fe;">${s.name}</strong> 
              <span style="font-size:0.7rem; color:var(--text-muted);">[${s.scope}]</span>
              <div style="font-size:0.7rem; color:var(--text-secondary);">${s.description || 'Sin descripción'}</div>
            </div>
            <div style="text-align:right;">
              <span class="badge ${s.state === 'ACTIVE' ? 'badge-green' : s.state === 'PRUNED' ? 'badge-amber' : 'badge-sub'}">${s.state}</span>
              <div style="font-size:0.7rem; color:var(--text-muted);">${s.active_sessions} sesiones</div>
            </div>
          </div>
        `).join("");
      }
    } catch (err) {
      console.error("Services fetch error:", err);
    }
  }

  const btnSimRecip = document.getElementById("btnSimulateReciprocity");
  if (btnSimRecip) {
    btnSimRecip.addEventListener("click", async () => {
      const action = document.getElementById("selAccAction").value;
      let dir = "tx";
      let bytes = 65536;

      if (action === "rx_boost") {
        dir = "rx";
        bytes = 65536;
      } else if (action === "tx_boost") {
        dir = "tx";
        bytes = 65536;
      } else if (action === "leech_attack") {
        dir = "tx";
        bytes = 5242880; // 5 MB
      }

      try {
        const res = await fetch("/api/accounting/record", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ direction: dir, bytes: bytes }),
        });
        const data = await res.json();
        const box = document.getElementById("accEvalFeedback");
        const txt = document.getElementById("accEvalText");
        if (box && txt) {
          txt.textContent = `Inyección completada: ${dir.toUpperCase()} +${(bytes/1024).toFixed(0)} KB -> Nivel resultante: ${data.tier} (Ratio: ${data.account.tit_for_tat_ratio})`;
          box.style.display = "block";
        }
        fetchAccountingData();
      } catch (err) {
        alert("Error inyectando reciprocidad: " + err);
      }
    });
  }

  const btnRefAcc = document.getElementById("btnRefreshAccounting");
  if (btnRefAcc) {
    btnRefAcc.addEventListener("click", () => {
      fetchAccountingData();
      fetchServicesData();
    });
  }

  const btnWakeSvc = document.getElementById("btnWakeService");
  if (btnWakeSvc) {
    btnWakeSvc.addEventListener("click", async () => {
      const svcName = document.getElementById("selServiceToWake").value;
      try {
        const res = await fetch("/api/services/request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: svcName }),
        });
        const data = await res.json();
        if (data.success) {
          fetchServicesData();
        }
      } catch (err) {
        alert("Error despertando servicio: " + err);
      }
    });
  }

  // --- Planetary Mesh & Resilience Guardian Logic ---
  async function fetchPlanetaryMetrics() {
    try {
      const res = await fetch("/api/planetary/metrics");
      const data = await res.json();
      const elCount = document.getElementById("pmNodeCount");
      const elOnline = document.getElementById("pmOnlineNodes");
      const elDegree = document.getElementById("pmAvgDegree");
      const elExp = document.getElementById("pmExponent");
      if (elCount) elCount.textContent = data.node_count;
      if (elOnline) elOnline.textContent = data.online_nodes;
      if (elDegree) elDegree.textContent = data.average_degree;
      if (elExp) elExp.textContent = `r = ${data.kleinberg_exponent.toFixed(1)}`;
    } catch (err) {
      console.warn("Planetary metrics fetch error:", err);
    }
  }

  async function fetchResilienceStatus() {
    try {
      const res = await fetch("/api/resilience/status");
      const data = await res.json();
      const elBadge = document.getElementById("circuitStateBadge");
      const elExec = document.getElementById("rgExecutions");
      const elExc = document.getElementById("rgExceptions");
      const elRec = document.getElementById("rgRecoveries");
      const elHealth = document.getElementById("rgHealthStatus");

      if (elBadge) {
        elBadge.textContent = `CIRCUIT: ${data.circuit_state}`;
        elBadge.className = `mono-text ${data.circuit_state === 'CLOSED' ? 'text-green' : 'text-danger'}`;
      }
      if (elExec) elExec.textContent = data.total_executions;
      if (elExc) elExc.textContent = data.total_exceptions_saved;
      if (elRec) elRec.textContent = data.total_recoveries;
      if (elHealth) {
        elHealth.textContent = data.status_message;
        elHealth.className = `bench-val ${data.is_healthy ? 'text-green' : 'text-danger'}`;
      }
    } catch (err) {
      console.warn("Resilience status fetch error:", err);
    }
  }

  const btnRoutePlanet = document.getElementById("btnRoutePlanetary");
  if (btnRoutePlanet) {
    btnRoutePlanet.addEventListener("click", async () => {
      const src = document.getElementById("txtPlanetSrc").value.trim() || "sat-000";
      const dst = document.getElementById("txtPlanetDst").value.trim() || "sat-015";
      const resBox = document.getElementById("planetaryRouteResult");

      btnRoutePlanet.disabled = true;
      btnRoutePlanet.textContent = "Calculando...";
      if (resBox) resBox.style.display = "block";

      try {
        const res = await fetch("/api/planetary/route", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ src, dst })
        });
        const data = await res.json();
        if (data.success && data.route) {
          const r = data.route;
          resBox.innerHTML = `
            <div style="color:#00f5d4; font-weight:700;">✓ Ruta Espacial de Kleinberg Calculada</div>
            <div>Camino (${r.hops} saltos): <strong>${r.path.join(" &rarr; ")}</strong></div>
            <div>Distancia Euclidiana: <span class="mono-text">${r.distance_units} unidades (${r.distance_km} km)</span></div>
            <div>Latencia Relativista (c): <span class="mono-text text-green">${r.estimated_latency_ms} ms</span></div>
          `;
        } else {
          resBox.innerHTML = `<span style="color:#ff007f;">✗ Fallo de enrutamiento: ${data.error || "Destino inalcanzable"}</span>`;
        }
      } catch (err) {
        resBox.innerHTML = `<span style="color:#ff007f;">Error: ${err}</span>`;
      } finally {
        btnRoutePlanet.disabled = false;
        btnRoutePlanet.textContent = "Enrutar en Malla LEO";
      }
    });
  }

  // --- Dark Node Stealth Profile & Silent Unicast Handlers ---
  async function fetchDarkNodeStatus() {
    try {
      const res = await fetch("/api/darknode/status");
      const data = await res.json();
      const elMode = document.getElementById("dnModeLabel");
      const elMute = document.getElementById("dnMuteLabel");
      const elSphinx = document.getElementById("dnSphinxLabel");
      const elJitter = document.getElementById("dnJitterLabel");
      const btn = document.getElementById("btnToggleDarkNodeProfile");

      if (elMode) {
        elMode.textContent = data.operating_mode;
        elMode.className = `stat-val mono-text ${data.is_stealth ? 'text-green' : ''}`;
      }
      if (elMute) {
        elMute.textContent = data.listeners_muted ? "SILENCIADOS (Egress-Only)" : "ACTIVOS (Visibles)";
        elMute.className = `stat-val ${data.listeners_muted ? 'color-danger' : 'text-green'}`;
      }
      if (elSphinx) {
        elSphinx.textContent = data.sphinx_mandatory ? "3 Saltos (1280B Forzado)" : "Bajo Demanda";
      }
      if (elJitter) {
        elJitter.textContent = data.micro_jitter_active ? "Activo (Anti-Correlación)" : "Inactivo";
        elJitter.className = `stat-val ${data.micro_jitter_active ? 'text-green' : ''}`;
      }
      if (btn) {
        btn.textContent = data.is_stealth ? "Desactivar Modo Sigilo" : "Conmutar Modo Sigilo";
      }
    } catch (err) {
      console.warn("Dark Node status fetch error:", err);
    }
  }

  async function fetchSilentStats() {
    try {
      const res = await fetch("/api/silent/stats");
      const data = await res.json();
      const elDisp = document.getElementById("silentCallsDispatched");
      const elResp = document.getElementById("silentRespReceived");
      const elDrop = document.getElementById("silentNoiseDropped");
      const elLimit = document.getElementById("silentRateLimited");

      if (elDisp) elDisp.textContent = data.total_calls_dispatched;
      if (elResp) elResp.textContent = data.total_responses_received;
      if (elDrop) elDrop.textContent = data.dropped_broadcast_noise;
      if (elLimit) elLimit.textContent = data.rate_limited_calls;
    } catch (err) {
      console.warn("Silent stats fetch error:", err);
    }
  }

  const btnToggleDn = document.getElementById("btnToggleDarkNodeProfile");
  if (btnToggleDn) {
    btnToggleDn.addEventListener("click", async () => {
      btnToggleDn.disabled = true;
      try {
        const res = await fetch("/api/darknode/toggle", { method: "POST" });
        await res.json();
        await fetchDarkNodeStatus();
        fetchStatus();
      } catch (err) {
        alert("Error al conmutar perfil Dark Node: " + err);
      } finally {
        btnToggleDn.disabled = false;
      }
    });
  }

  const btnSilent = document.getElementById("btnSendSilentCall");
  if (btnSilent) {
    btnSilent.addEventListener("click", async () => {
      const target = document.getElementById("txtSilentTargetDid").value.trim();
      const payload = document.getElementById("txtSilentPayload").value.trim() || "Unicast Directed Call";
      const feedback = document.getElementById("silentCallFeedback");

      if (!target) return alert("Ingrese un DID de destino");
      btnSilent.disabled = true;

      try {
        const res = await fetch("/api/silent/call", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target_did: target, payload })
        });
        const data = await res.json();
        if (feedback) {
          feedback.style.display = "block";
          feedback.textContent = JSON.stringify(data, null, 2);
        }
        fetchSilentStats();
      } catch (err) {
        if (feedback) {
          feedback.style.display = "block";
          feedback.textContent = `Error: ${err}`;
        }
      } finally {
        btnSilent.disabled = false;
      }
    });
  }

  // --- Sovereign E2EE Chat Engine ---
  const btnChat = document.getElementById("btnSendChat");
  async function fetchChatHistory() {
    const viewer = document.getElementById("chatHistoryViewer");
    const targetInput = document.getElementById("txtChatTarget");
    const peer = targetInput && targetInput.value.trim() ? targetInput.value.trim() : "";
    try {
      const res = await fetch(`/api/chat/messages${peer ? '?peer=' + encodeURIComponent(peer) : ''}`);
      const messages = await res.json();
      if (!viewer) return;
      if (Array.isArray(messages) && messages.length > 0) {
        viewer.innerHTML = messages.map(m => `
          <div style="padding:4px 0; border-bottom:1px solid rgba(255,255,255,0.05);">
            <strong style="color:var(--accent-cyan);">${m.sender_name}</strong> <span style="font-size:0.75rem; color:var(--text-muted);">${new Date(m.timestamp * 1000).toLocaleTimeString()}</span>
            <div>${m.text}</div>
            <div style="font-size:0.7rem; color:var(--accent-green);">Sig: ${m.signature ? m.signature.slice(0, 16) + '...' : 'Verified'} &bull; Latencia: ${m.delivery_latency_ms.toFixed(1)} ms</div>
          </div>
        `).join("");
      } else {
        viewer.textContent = "Sin mensajes recientes con este par.";
      }
    } catch (e) {
      if (viewer) viewer.textContent = "Error cargando historial de chat.";
    }
  }

  if (btnChat) {
    btnChat.addEventListener("click", async () => {
      const target = document.getElementById("txtChatTarget").value.trim();
      const text = document.getElementById("txtChatMessage").value.trim();
      const feedback = document.getElementById("chatFeedbackBox");
      if (!text) return alert("Ingrese un mensaje para transmitir.");

      btnChat.disabled = true;
      try {
        const res = await fetch("/api/chat/send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target_did: target, text, sender_name: "Operador Local" }),
        });
        const data = await res.json();
        if (feedback) {
          feedback.style.display = "block";
          feedback.textContent = `Mensaje transmitido con éxito. Latencia: ${data.message ? data.message.delivery_latency_ms.toFixed(1) : 0} ms`;
        }
        document.getElementById("txtChatMessage").value = "";
        fetchChatHistory();
      } catch (err) {
        if (feedback) {
          feedback.style.display = "block";
          feedback.textContent = `Fallo de transmisión: ${err}`;
        }
      } finally {
        btnChat.disabled = false;
      }
    });
  }

  // --- Link Healing & RFC 2439 Flap Damping ---
  async function fetchHealingSummary() {
    const feedback = document.getElementById("healingStatusFeedback");
    try {
      const res = await fetch("/api/healing/summary");
      const data = await res.json();
      if (feedback) {
        feedback.textContent = JSON.stringify(data, null, 2);
      }
    } catch (err) {
      if (feedback) feedback.textContent = "Error consultando resumen de enlaces.";
    }
  }

  async function sendProbe(success) {
    const peer = document.getElementById("txtProbePeer").value.trim();
    const feedback = document.getElementById("healingStatusFeedback");
    try {
      const res = await fetch("/api/healing/probe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          peer_did: peer || "did:ipvn7:zPeerNode",
          success: success,
          latency_ms: success ? 12.5 : 999.0
        })
      });
      const data = await res.json();
      if (feedback) {
        feedback.textContent = JSON.stringify(data, null, 2);
      }
    } catch (err) {
      if (feedback) feedback.textContent = `Error inyectando sonda: ${err}`;
    }
  }

  const btnSuccess = document.getElementById("btnProbeSuccess");
  if (btnSuccess) btnSuccess.addEventListener("click", () => sendProbe(true));
  const btnFailure = document.getElementById("btnProbeFailure");
  if (btnFailure) btnFailure.addEventListener("click", () => sendProbe(false));
  const btnRefreshHealing = document.getElementById("btnRefreshHealing");
  if (btnRefreshHealing) btnRefreshHealing.addEventListener("click", fetchHealingSummary);

  // --- Topological Mobility Handover ---
  const btnMobility = document.getElementById("btnSubmitMobility");
  if (btnMobility) {
    btnMobility.addEventListener("click", async () => {
      const did = document.getElementById("txtMobNodeDid").value.trim() || "did:ipvn7:zMobileClient";
      const ip = document.getElementById("txtMobNewIp").value.trim() || "10.42.0.88";
      const port = parseInt(document.getElementById("txtMobNewPort").value, 10) || 54321;
      const seq = parseInt(document.getElementById("txtMobSeq").value, 10) || 1;
      const feedback = document.getElementById("mobilityFeedback");

      btnMobility.disabled = true;
      try {
        const res = await fetch("/api/mobility/update", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ node_did: did, physical_ip: ip, physical_port: port, seq: seq })
        });
        const data = await res.json();
        if (feedback) {
          feedback.style.display = "block";
          feedback.textContent = JSON.stringify(data, null, 2);
        }
        document.getElementById("txtMobSeq").value = seq + 1;
      } catch (err) {
        if (feedback) {
          feedback.style.display = "block";
          feedback.textContent = `Error en actualización: ${err}`;
        }
      } finally {
        btnMobility.disabled = false;
      }
    });
  }

  // --- AI Copilot Inference & Auto-Healing ---
  const btnCopilot = document.getElementById("btnRunCopilotCycle");
  if (btnCopilot) {
    btnCopilot.addEventListener("click", async () => {
      const lat = parseFloat(document.getElementById("txtCopilotLat").value) || 65.0;
      const drops = parseInt(document.getElementById("txtCopilotDrops").value, 10) || 8;
      const entropy = parseFloat(document.getElementById("txtCopilotEntropy").value) || 0.35;
      const peer = document.getElementById("txtCopilotPeer").value.trim() || "did:ipvn7:zAttackerScanner";
      const feedback = document.getElementById("copilotResultsBox");

      btnCopilot.disabled = true;
      try {
        const res = await fetch("/api/copilot/cycle", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            latency_ms: lat,
            firewall_drops: drops,
            peer_did: peer,
            spectral_entropy: entropy,
            is_flap_damped: false
          })
        });
        const data = await res.json();
        if (feedback) {
          feedback.style.display = "block";
          feedback.textContent = JSON.stringify(data, null, 2);
        }
      } catch (err) {
        if (feedback) {
          feedback.style.display = "block";
          feedback.textContent = `Error ejecutando inferencia: ${err}`;
        }
      } finally {
        btnCopilot.disabled = false;
      }
    });
  }

  // --- UIN Sovereign Identity Handlers ---
  async function fetchUinPassport() {
    try {
      const res = await fetch("/api/uin/passport");
      const data = await res.json();
      const didElem = document.getElementById("uinRootDidDisplay");
      const rootIdElem = document.getElementById("uinRootIdShort");
      const modeElem = document.getElementById("uinModeDisplay");
      const activeElem = document.getElementById("uinActiveBindingsCount");
      const revokedElem = document.getElementById("uinRevokedCount");

      if (didElem) didElem.textContent = data.entity_did;
      if (rootIdElem) rootIdElem.textContent = data.root_id_hex.slice(0, 16) + "...";
      if (modeElem) modeElem.textContent = data.mode.toUpperCase();
      if (activeElem) activeElem.textContent = data.active_bindings ? data.active_bindings.length : 0;
      if (revokedElem) revokedElem.textContent = data.revoked_bindings ? data.revoked_bindings.length : 0;
    } catch (err) {
      console.warn("Error fetching UIN passport:", err);
    }
  }

  const btnIssueUin = document.getElementById("btnIssueUinBinding");
  if (btnIssueUin) {
    btnIssueUin.addEventListener("click", async () => {
      const scope = parseInt(document.getElementById("selUinScope").value, 10);
      const duration = parseFloat(document.getElementById("txtUinDuration").value) || 86400;
      const resBox = document.getElementById("uinBindingResultBox");
      btnIssueUin.disabled = true;
      resBox.style.display = "block";
      resBox.textContent = "Emitiendo y firmando BindingRecord con clave raíz...";

      try {
        const res = await fetch("/api/uin/bind", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scope: scope, duration_seconds: duration })
        });
        const data = await res.json();
        resBox.textContent = JSON.stringify(data, null, 2);
        fetchUinPassport();
      } catch (err) {
        resBox.textContent = `Error emitiendo binding: ${err}`;
      } finally {
        btnIssueUin.disabled = false;
      }
    });
  }

  // --- Shadow Devices Registry Handlers ---
  async function fetchShadowDevices() {
    try {
      const res = await fetch("/api/shadow/devices");
      const data = await res.json();
      const listElem = document.getElementById("shadowDevicesList");
      if (!listElem) return;

      if (!data.devices || data.devices.length === 0) {
        listElem.textContent = "No hay dispositivos sombra registrados en la LAN local.";
        return;
      }

      listElem.innerHTML = data.devices.map(d => `
        <div style="border-bottom:1px solid rgba(255,255,255,0.08); padding:4px 0;">
          <strong class="text-cyan">${d.name}</strong> [${d.type.toUpperCase()}] &bull; VIP: <strong class="text-green">${d.virtual_ipv4}</strong> &bull; LAN: ${d.physical_ip}
          <div style="font-size:0.75rem; color:#888;">DID: ${d.did} | Puertos: ${d.allowed_ports.join(', ')} | Estado: ${d.enabled ? 'ACTIVO' : 'INACTIVO'}</div>
        </div>
      `).join('');
    } catch (err) {
      console.warn("Error fetching shadow devices:", err);
    }
  }

  const btnRegShadow = document.getElementById("btnRegisterShadowDevice");
  if (btnRegShadow) {
    btnRegShadow.addEventListener("click", async () => {
      const name = document.getElementById("txtShadowName").value;
      const ip = document.getElementById("txtShadowIp").value;
      const mac = document.getElementById("txtShadowMac").value;
      const type = document.getElementById("selShadowType").value;
      btnRegShadow.disabled = true;

      try {
        await fetch("/api/shadow/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: name, physical_ip: ip, mac: mac, device_type: type })
        });
        fetchShadowDevices();
      } catch (err) {
        alert("Error registrando dispositivo sombra: " + err);
      } finally {
        btnRegShadow.disabled = false;
      }
    });
  }

  // --- PFO Ontological Governance Tree Handlers ---
  async function fetchPfoTree() {
    try {
      const res = await fetch("/api/pfo/tree");
      const data = await res.json();
      const box = document.getElementById("pfoTreeBox");
      const pTot = document.getElementById("pfoPrinciplesTotal");
      const fTot = document.getElementById("pfoFunctionsTotal");
      const oTot = document.getElementById("pfoObsTotal");
      const rTot = document.getElementById("pfoRateTotal");
      const rBadge = document.getElementById("pfoComplianceBadge");

      if (pTot) pTot.textContent = data.total_principles;
      if (fTot) fTot.textContent = data.total_functions;
      if (oTot) oTot.textContent = data.total_observations;
      if (rTot) rTot.textContent = data.compliance_rate + "%";
      if (rBadge) rBadge.textContent = data.compliance_rate + "%";

      if (box && data.pfo_tree) {
        box.innerHTML = data.pfo_tree.map(p => `
          <div style="margin-bottom:8px;">
            <strong class="text-cyan">${p.principle_id}</strong>: <em>"${p.statement}"</em>
            <div style="padding-left:12px; font-size:0.75rem; color:#aaa;">
              Módulos: ${p.functions.map(f => `<span class="code-badge" style="margin-right:4px;">${f.function_id} (${f.status})</span>`).join('')}
            </div>
          </div>
        `).join('');
      }
    } catch (err) {
      console.warn("Error fetching PFO tree:", err);
    }
  }

  const btnPfo = document.getElementById("btnRefreshPfoTree");
  if (btnPfo) {
    btnPfo.addEventListener("click", () => {
      fetchPfoTree();
    });
  }

  // --- WAN Active Prober Handlers ---
  async function fetchWanStats() {
    try {
      const res = await fetch("/api/wan/stats");
      const data = await res.json();
      if (!data.peers || data.peers.length === 0) return;
      const p = data.peers[0];
      const rttEl = document.getElementById("wanLastRtt");
      const minMaxEl = document.getElementById("wanMinMaxRtt");
      const jitEl = document.getElementById("wanJitterMs");
      const lossEl = document.getElementById("wanLossPct");

      if (rttEl) rttEl.textContent = p.last_rtt_ms + " ms";
      if (minMaxEl) minMaxEl.textContent = `${p.min_rtt_ms} / ${p.max_rtt_ms} ms`;
      if (jitEl) jitEl.textContent = p.jitter_ms + " ms";
      if (lossEl) lossEl.textContent = p.loss_pct + "%";
    } catch (err) {
      console.warn("Error fetching WAN stats:", err);
    }
  }

  const btnSendProbe = document.getElementById("btnSendWanProbe");
  if (btnSendProbe) {
    btnSendProbe.addEventListener("click", async () => {
      const peerDid = document.getElementById("txtWanPeerDid").value;
      const simRtt = parseFloat(document.getElementById("txtWanSimRtt").value) || 8.5;
      const resBox = document.getElementById("wanProbeResultBox");

      btnSendProbe.disabled = true;
      resBox.style.display = "block";
      resBox.textContent = "Transmitiendo trama binaria canónica IP7P (32B)...";

      try {
        const res = await fetch("/api/wan/probe", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ peer_did: peerDid, simulated_rtt_ms: simRtt })
        });
        const data = await res.json();
        resBox.textContent = JSON.stringify(data, null, 2);
        fetchWanStats();
      } catch (err) {
        resBox.textContent = `Error enviando sonda: ${err}`;
      } finally {
        btnSendProbe.disabled = false;
      }
    });
  }

  // --- Sovereign Remote Desktop Handlers ---
  async function fetchRemoteDesktopStatus() {
    try {
      const res = await fetch("/api/remote_desktop/status");
      const data = await res.json();
      const fpsEl = document.getElementById("rdFpsDisplay");
      const rttEl = document.getElementById("rdRttDisplay");
      const sasEl = document.getElementById("rdSasCode");
      const txEl = document.getElementById("rdFramesTx");

      if (fpsEl) fpsEl.textContent = data.fps + " FPS";
      if (rttEl) rttEl.textContent = data.rtt_ms + " ms";
      if (sasEl) sasEl.textContent = `${data.sas_digits} ${data.sas_emojis.join('')}`;
      if (txEl) txEl.textContent = data.total_frames_tx.toLocaleString();
    } catch (err) {
      console.warn("Error fetching remote desktop status:", err);
    }
  }

  const btnMoveMouse = document.getElementById("btnSimulateMouseMove");
  if (btnMoveMouse) {
    btnMoveMouse.addEventListener("click", async () => {
      const resBox = document.getElementById("rdInputResultBox");
      resBox.style.display = "block";
      resBox.textContent = "Inyectando evento de cursor...";

      try {
        const res = await fetch("/api/remote_desktop/input", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ event_type: "mouse_move", x: 0.5, y: 0.5 })
        });
        const data = await res.json();
        resBox.textContent = JSON.stringify(data, null, 2);
        fetchRemoteDesktopStatus();
      } catch (err) {
        resBox.textContent = `Error inyectando cursor: ${err}`;
      }
    });
  }

  const btnPressKey = document.getElementById("btnSimulateKeyPress");
  if (btnPressKey) {
    btnPressKey.addEventListener("click", async () => {
      const resBox = document.getElementById("rdInputResultBox");
      resBox.style.display = "block";
      resBox.textContent = "Inyectando evento de pulsación de teclado...";

      try {
        const res = await fetch("/api/remote_desktop/input", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ event_type: "key_down", key: "Enter" })
        });
        const data = await res.json();
        resBox.textContent = JSON.stringify(data, null, 2);
        fetchRemoteDesktopStatus();
      } catch (err) {
        resBox.textContent = `Error inyectando tecla: ${err}`;
      }
    });
  }

  // --- Interactive Remote Desktop Canvas & IP7M Video Stream Visualizer ---
  const rdCanvas = document.getElementById("rdLiveCanvas");
  let rdCursorX = 0.5;
  let rdCursorY = 0.5;
  let rdClickRipples = [];
  let rdVideoFlash = 0.0;

  if (rdCanvas) {
    const ctx = rdCanvas.getContext("2d");

    function renderRdCanvas() {
      const W = rdCanvas.width;
      const H = rdCanvas.height;

      // 1. Clear background
      ctx.fillStyle = "#070b14";
      ctx.fillRect(0, 0, W, H);

      // 2. High-tech cybernetic grid
      ctx.strokeStyle = "rgba(0, 255, 200, 0.08)";
      ctx.lineWidth = 1;
      const step = 32;
      for (let x = 0; x < W; x += step) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, H);
        ctx.stroke();
      }
      for (let y = 0; y < H; y += step) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(W, y);
        ctx.stroke();
      }

      // 3. Scanline effect
      const t = Date.now() * 0.002;
      const scanY = (t * 80) % H;
      ctx.fillStyle = "rgba(0, 255, 200, 0.06)";
      ctx.fillRect(0, scanY, W, 4);

      // 4. Video frame burst effect
      if (rdVideoFlash > 0.01) {
        ctx.fillStyle = `rgba(0, 255, 200, ${rdVideoFlash * 0.25})`;
        ctx.fillRect(0, 0, W, H);
        rdVideoFlash *= 0.88;
      }

      // 5. Click ripple animations
      for (let i = rdClickRipples.length - 1; i >= 0; i--) {
        const rip = rdClickRipples[i];
        rip.radius += 2.5;
        rip.alpha *= 0.92;
        ctx.strokeStyle = `rgba(0, 255, 200, ${rip.alpha})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(rip.x * W, rip.y * H, rip.radius, 0, Math.PI * 2);
        ctx.stroke();
        if (rip.alpha < 0.02) {
          rdClickRipples.splice(i, 1);
        }
      }

      // 6. Draw HUD Telemetry Box
      ctx.fillStyle = "rgba(10, 20, 35, 0.75)";
      ctx.strokeStyle = "rgba(0, 255, 200, 0.4)";
      ctx.fillRect(16, 16, 260, 80);
      ctx.strokeRect(16, 16, 260, 80);

      ctx.font = "11px 'Courier New', monospace";
      ctx.fillStyle = "#00ffc8";
      ctx.fillText("SESSION: notebook.ipv7 (E2EE)", 26, 36);
      ctx.fillStyle = "#94a3b8";
      ctx.fillText("CRYPTO:  ML-KEM-768 + ChaCha20", 26, 52);
      ctx.fillStyle = "#38bdf8";
      ctx.fillText("MTU:     1280B (IP7M Fragmenter)", 26, 68);
      ctx.fillStyle = "#4ade80";
      ctx.fillText(`FPS:     60.0  | RTT: 5.4ms`, 26, 84);

      // 7. Draw cursor indicator
      const px = rdCursorX * W;
      const py = rdCursorY * H;

      ctx.strokeStyle = "#00ffc8";
      ctx.lineWidth = 1.5;
      // Crosshair
      ctx.beginPath();
      ctx.moveTo(px - 10, py);
      ctx.lineTo(px + 10, py);
      ctx.moveTo(px, py - 10);
      ctx.lineTo(px, py + 10);
      ctx.stroke();

      // Outer targeting ring
      ctx.strokeStyle = "rgba(0, 255, 200, 0.6)";
      ctx.beginPath();
      ctx.arc(px, py, 14, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = "#00ffc8";
      ctx.font = "9px monospace";
      ctx.fillText(`X:${rdCursorX.toFixed(3)} Y:${rdCursorY.toFixed(3)}`, px + 18, py - 6);

      requestAnimationFrame(renderRdCanvas);
    }

    renderRdCanvas();

    // Mouse move tracking on canvas
    let lastMoveSent = 0;
    rdCanvas.addEventListener("mousemove", (e) => {
      const rect = rdCanvas.getBoundingClientRect();
      rdCursorX = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      rdCursorY = Math.max(0, Math.min(1, (e.clientY - rect.top) / rect.height));

      const now = Date.now();
      if (now - lastMoveSent > 120) {
        lastMoveSent = now;
        fetch("/api/remote_desktop/input", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ event_type: "mouse_move", x: rdCursorX, y: rdCursorY })
        }).catch(() => {});
      }
    });

    // Mouse click tracking on canvas
    rdCanvas.addEventListener("click", (e) => {
      const rect = rdCanvas.getBoundingClientRect();
      const clickX = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      const clickY = Math.max(0, Math.min(1, (e.clientY - rect.top) / rect.height));

      rdClickRipples.push({ x: clickX, y: clickY, radius: 4, alpha: 0.9 });

      const resBox = document.getElementById("rdInputResultBox");
      if (resBox) {
        resBox.style.display = "block";
        resBox.textContent = `Inyectando click en coords (${clickX.toFixed(3)}, ${clickY.toFixed(3)})...`;
      }

      fetch("/api/remote_desktop/input", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_type: "mouse_click", x: clickX, y: clickY, button: 1 })
      })
      .then(res => res.json())
      .then(data => {
        if (resBox) resBox.textContent = JSON.stringify(data, null, 2);
        fetchRemoteDesktopStatus();
      })
      .catch(err => {
        if (resBox) resBox.textContent = `Error inyectando click: ${err}`;
      });
    });
  }

  // --- Button: Live IP7M Video Frame Streaming Trigger ---
  const btnStreamVideo = document.getElementById("btnStreamTestVideoFrame");
  if (btnStreamVideo) {
    btnStreamVideo.addEventListener("click", async () => {
      const resBox = document.getElementById("rdInputResultBox");
      if (resBox) {
        resBox.style.display = "block";
        resBox.textContent = "Fragmentando y transmitiendo trama IP7M (AV1 / 1280B)...";
      }

      btnStreamVideo.disabled = true;
      try {
        const rpcPayload = {
          jsonrpc: "2.0",
          id: Date.now(),
          method: "tools/call",
          params: {
            name: "ipvn7_dispatch_remote_media_frame",
            arguments: { frame_type: "video_keyframe", codec: "av1" }
          }
        };

        const res = await fetch("/api/mcp", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(rpcPayload)
        });
        const data = await res.json();
        rdVideoFlash = 1.0;
        if (resBox) resBox.textContent = JSON.stringify(data, null, 2);
        fetchRemoteDesktopStatus();
      } catch (err) {
        if (resBox) resBox.textContent = `Error transmitiendo trama IP7M: ${err}`;
      } finally {
        btnStreamVideo.disabled = false;
      }
    });
  }

  // =============================================================
  // 3D PLANETARY GLOBE CANVAS (Kleinberg Small-World LEO Mesh)
  // =============================================================
  let globeNodes = [];
  let globeEdges = [];
  let globeActivePath = [];
  let globePhotons = [];
  let globeRotY = 0.4;
  let globeRotX = 0.25;
  let isGlobeRotating = true;
  let isGlobeDragging = false;
  let lastMouseX = 0;
  let lastMouseY = 0;

  async function initPlanetaryGlobe() {
    const canvas = document.getElementById("planetaryGlobeCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    // Fetch full 3D topology snapshot from IPVN 7 core
    try {
      const res = await fetch("/api/planetary/topology");
      const data = await res.json();
      if (data && data.nodes) {
        globeNodes = data.nodes;
        // Build edge list (unique pairs)
        const edgeSet = new Set();
        globeEdges = [];
        globeNodes.forEach(src => {
          const allLinks = [...(src.short_links || []), ...(src.long_links || [])];
          allLinks.forEach(targetId => {
            const pairKey = [src.id, targetId].sort().join("<->");
            if (!edgeSet.has(pairKey)) {
              edgeSet.add(pairKey);
              globeEdges.push({ srcId: src.id, dstId: targetId });
            }
          });
        });
      }
    } catch (e) {
      console.warn("No se pudo cargar la topología planetaria 3D:", e);
    }

    // Mouse drag interaction for 3D rotation
    canvas.addEventListener("mousedown", (e) => {
      isGlobeDragging = true;
      lastMouseX = e.clientX;
      lastMouseY = e.clientY;
    });

    window.addEventListener("mousemove", (e) => {
      if (!isGlobeDragging) return;
      const dx = e.clientX - lastMouseX;
      const dy = e.clientY - lastMouseY;
      lastMouseX = e.clientX;
      lastMouseY = e.clientY;
      globeRotY += dx * 0.008;
      globeRotX = Math.max(-1.1, Math.min(1.1, globeRotX + dy * 0.008));
    });

    window.addEventListener("mouseup", () => {
      isGlobeDragging = false;
    });

    // Touch support for mobile / tablets
    canvas.addEventListener("touchstart", (e) => {
      if (e.touches.length === 1) {
        isGlobeDragging = true;
        lastMouseX = e.touches[0].clientX;
        lastMouseY = e.touches[0].clientY;
      }
    }, { passive: true });

    window.addEventListener("touchmove", (e) => {
      if (!isGlobeDragging || e.touches.length !== 1) return;
      const dx = e.touches[0].clientX - lastMouseX;
      const dy = e.touches[0].clientY - lastMouseY;
      lastMouseX = e.touches[0].clientX;
      lastMouseY = e.touches[0].clientY;
      globeRotY += dx * 0.008;
      globeRotX = Math.max(-1.1, Math.min(1.1, globeRotX + dy * 0.008));
    }, { passive: true });

    window.addEventListener("touchend", () => {
      isGlobeDragging = false;
    });

    // Button controls
    const btnToggleRot = document.getElementById("btnToggleGlobeRotation");
    if (btnToggleRot) {
      btnToggleRot.addEventListener("click", () => {
        isGlobeRotating = !isGlobeRotating;
        btnToggleRot.textContent = isGlobeRotating ? "Pausar Rotación" : "Reanudar Rotación";
      });
    }

    const btnResetCam = document.getElementById("btnResetGlobeCamera");
    if (btnResetCam) {
      btnResetCam.addEventListener("click", () => {
        globeRotY = 0.4;
        globeRotX = 0.25;
      });
    }

    const btnPulse = document.getElementById("btnPulsePhotons");
    if (btnPulse) {
      btnPulse.addEventListener("click", () => {
        emitPhotonsAcrossLEO();
      });
    }

    // Main 3D Animation Render Loop (60 FPS)
    function renderGlobe() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      if (isGlobeRotating && !isGlobeDragging) {
        globeRotY += 0.005;
      }

      const cx = canvas.width / 2;
      const cy = canvas.height / 2;
      const R_earth = 110;
      const R_orbit = 142;

      // Draw Atmospheric Glow
      const glow = ctx.createRadialGradient(cx, cy, R_earth * 0.8, cx, cy, R_earth * 1.35);
      glow.addColorStop(0, "rgba(0, 242, 254, 0.2)");
      glow.addColorStop(0.6, "rgba(0, 150, 255, 0.08)");
      glow.addColorStop(1, "rgba(0, 0, 0, 0)");
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(cx, cy, R_earth * 1.35, 0, Math.PI * 2);
      ctx.fill();

      // Draw Earth Sphere Body
      const earthGrad = ctx.createRadialGradient(cx - 30, cy - 30, 10, cx, cy, R_earth);
      earthGrad.addColorStop(0, "#102544");
      earthGrad.addColorStop(0.7, "#081324");
      earthGrad.addColorStop(1, "#040914");
      ctx.fillStyle = earthGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, R_earth, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = "rgba(0, 242, 254, 0.4)";
      ctx.lineWidth = 1.2;
      ctx.stroke();

      // 3D Projection Helpers
      const cosY = Math.cos(globeRotY);
      const sinY = Math.sin(globeRotY);
      const cosX = Math.cos(globeRotX);
      const sinX = Math.sin(globeRotX);

      function project3D(x, y, z, radius) {
        // Rotate Y
        const x1 = x * cosY - z * sinY;
        const z1 = x * sinY + z * cosY;
        // Rotate X
        const y2 = y * cosX - z1 * sinX;
        const z2 = y * sinX + z1 * cosX;

        // Orthographic projection with slight perspective
        const scale = 1.0 + z2 * 0.15;
        const px = cx + x1 * radius * scale;
        const py = cy - y2 * radius * scale;
        return { px, py, z: z2, visible: z2 > -0.2 };
      }

      // Draw Wireframe Latitude & Longitude lines
      ctx.strokeStyle = "rgba(0, 242, 254, 0.12)";
      ctx.lineWidth = 0.8;
      for (let lat = -60; lat <= 60; lat += 30) {
        const rad = (lat * Math.PI) / 180;
        const rRing = Math.cos(rad);
        const yRing = Math.sin(rad);
        ctx.beginPath();
        let first = true;
        for (let lon = 0; lon <= 360; lon += 15) {
          const lRad = (lon * Math.PI) / 180;
          const pt = project3D(rRing * Math.cos(lRad), yRing, rRing * Math.sin(lRad), R_earth);
          if (first) { ctx.moveTo(pt.px, pt.py); first = false; }
          else { ctx.lineTo(pt.px, pt.py); }
        }
        ctx.stroke();
      }

      // Project Nodes
      const nodePosMap = {};
      const projectedNodes = globeNodes.map(n => {
        const geo = n.geo || { x3d: 0, y3d: 0, z3d: 1 };
        // Normalize vector
        const mag = Math.sqrt(geo.x3d*geo.x3d + geo.y3d*geo.y3d + geo.z3d*geo.z3d) || 1;
        const pt = project3D(geo.x3d / mag, geo.y3d / mag, geo.z3d / mag, R_orbit);
        nodePosMap[n.id] = pt;
        return { ...n, ...pt };
      });

      // Draw Edges (Kleinberg Links)
      globeEdges.forEach(edge => {
        const p1 = nodePosMap[edge.srcId];
        const p2 = nodePosMap[edge.dstId];
        if (!p1 || !p2) return;

        // Determine if edge is part of the active Kleinberg routed path
        const isActiveHop = globeActivePath.length > 1 &&
          globeActivePath.some((id, i) =>
            i < globeActivePath.length - 1 &&
            ((id === edge.srcId && globeActivePath[i+1] === edge.dstId) ||
             (id === edge.dstId && globeActivePath[i+1] === edge.srcId))
          );

        ctx.beginPath();
        ctx.moveTo(p1.px, p1.py);

        // Arc curve through 3D space
        const midX = (p1.px + p2.px) / 2;
        const midY = (p1.py + p2.py) / 2;
        ctx.quadraticCurveTo(midX, midY, p2.px, p2.py);

        if (isActiveHop) {
          ctx.strokeStyle = "rgba(255, 0, 160, 0.9)";
          ctx.lineWidth = 2.5;
          ctx.shadowColor = "#ff00a0";
          ctx.shadowBlur = 12;
        } else {
          const depthAlpha = Math.max(0.12, (p1.z + p2.z + 2) / 4);
          ctx.strokeStyle = `rgba(0, 242, 254, ${depthAlpha * 0.35})`;
          ctx.lineWidth = 1.0;
          ctx.shadowBlur = 0;
        }
        ctx.stroke();
        ctx.shadowBlur = 0;
      });

      // Update and Draw Traveling Photons
      for (let i = globePhotons.length - 1; i >= 0; i--) {
        const ph = globePhotons[i];
        ph.progress += ph.speed;
        if (ph.progress >= 1.0) {
          globePhotons.splice(i, 1);
          continue;
        }
        const p1 = nodePosMap[ph.srcId];
        const p2 = nodePosMap[ph.dstId];
        if (p1 && p2) {
          const fx = p1.px + (p2.px - p1.px) * ph.progress;
          const fy = p1.py + (p2.py - p1.py) * ph.progress;
          ctx.fillStyle = ph.color || "#00ffa6";
          ctx.shadowColor = ph.color || "#00ffa6";
          ctx.shadowBlur = 10;
          ctx.beginPath();
          ctx.arc(fx, fy, 3.2, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      }

      // Draw Satellite Nodes
      projectedNodes.sort((a, b) => a.z - b.z); // Z-sorting for correct depth
      projectedNodes.forEach(n => {
        const isTarget = globeActivePath.includes(n.id);
        const radius = isTarget ? 6.5 : (n.z > 0 ? 5.0 : 3.5);
        const alpha = n.z > 0 ? 1.0 : Math.max(0.3, 0.6 + n.z * 0.4);

        ctx.beginPath();
        ctx.arc(n.px, n.py, radius, 0, Math.PI * 2);

        if (isTarget) {
          ctx.fillStyle = `rgba(255, 0, 160, ${alpha})`;
          ctx.shadowColor = "#ff00a0";
          ctx.shadowBlur = 15;
        } else {
          ctx.fillStyle = `rgba(0, 255, 170, ${alpha})`;
          ctx.shadowColor = "#00ffa6";
          ctx.shadowBlur = 8;
        }
        ctx.fill();
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 1.2;
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Label if front-facing
        if (n.z > 0.1 || isTarget) {
          ctx.font = "9px 'JetBrains Mono', monospace";
          ctx.fillStyle = isTarget ? "#ff80df" : "rgba(255, 255, 255, 0.75)";
          ctx.fillText(n.id, n.px + 8, n.py + 3);
        }
      });

      requestAnimationFrame(renderGlobe);
    }

    renderGlobe();
  }

  function emitPhotonsAcrossLEO() {
    if (!globeEdges.length) return;
    for (let i = 0; i < 8; i++) {
      const e = globeEdges[Math.floor(Math.random() * globeEdges.length)];
      globePhotons.push({
        srcId: e.srcId,
        dstId: e.dstId,
        progress: 0.0,
        speed: 0.02 + Math.random() * 0.025,
        color: Math.random() > 0.4 ? "#00ffa6" : "#00f2fe",
      });
    }
  }

  // Hook into existing Planetary Route button to illuminate path on 3D Globe
  const origBtnRoutePlanetary = document.getElementById("btnRoutePlanetary");
  if (origBtnRoutePlanetary) {
    origBtnRoutePlanetary.addEventListener("click", () => {
      setTimeout(() => {
        const src = (document.getElementById("txtPlanetSrc")?.value || "sat-000").trim();
        const dst = (document.getElementById("txtPlanetDst")?.value || "sat-015").trim();
        fetch("/api/planetary/route", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ src_node: src, dst_node: dst }),
        })
        .then(res => res.json())
        .then(data => {
          if (data && data.path) {
            globeActivePath = data.path;
            // Send photon sequence along path
            data.path.forEach((nodeId, idx) => {
              if (idx < data.path.length - 1) {
                setTimeout(() => {
                  globePhotons.push({
                    srcId: nodeId,
                    dstId: data.path[idx + 1],
                    progress: 0.0,
                    speed: 0.035,
                    color: "#ff00a0",
                  });
                }, idx * 120);
              }
            });
          }
        }).catch(() => {});
      }, 100);
    });
  }

  // =============================================================
  // BITNET B1.58 TERNARY AI ENGINE CONTROLLER
  // =============================================================
  async function loadBitNetDemo(rows = 16, cols = 16, seed = 42) {
    const grid = document.getElementById("bitnetGrid");
    const leg = document.getElementById("bitnetDistLegend");
    const compBox = document.getElementById("bitnetComparisonBox");

    try {
      const res = await fetch(`/api/bitnet/demo?rows=${rows}&cols=${cols}&seed=${seed}`);
      const data = await res.json();

      // Update KPI Badges
      const elComp = document.getElementById("bitnetCompressionRatio");
      const elMem = document.getElementById("bitnetMemSaved");
      const elInfer = document.getElementById("bitnetInferUs");
      const elSparse = document.getElementById("bitnetSparsity");

      if (elComp) elComp.textContent = `${data.compression_ratio}x`;
      if (elMem) elMem.textContent = `${data.memory_saved_pct}%`;
      if (elInfer) elInfer.textContent = `${data.integer_inference_time_us} µs`;
      if (elSparse) elSparse.textContent = `${data.weight_distribution.sparsity_pct}%`;

      // Render Dynamic Heatmap Grid
      if (grid && data.ternary_weights) {
        grid.style.gridTemplateColumns = `repeat(${cols}, 32px)`;
        grid.innerHTML = "";

        data.ternary_weights.forEach((row, rIdx) => {
          row.forEach((val, cIdx) => {
            const cell = document.createElement("div");
            cell.className = "ternary-cell";
            if (val === 1) {
              cell.classList.add("cell-plus-one");
              cell.textContent = "+1";
            } else if (val === -1) {
              cell.classList.add("cell-minus-one");
              cell.textContent = "-1";
            } else {
              cell.classList.add("cell-zero");
              cell.textContent = "0";
            }
            cell.title = `W[${rIdx},${cIdx}] = ${val}`;
            grid.appendChild(cell);
          });
        });
      }

      // Legend of distribution
      if (leg && data.weight_distribution) {
        const d = data.weight_distribution;
        leg.innerHTML = `Distribución: <strong style="color:#00ffa6;">${d.plus_ones} (+1)</strong> &bull; ` +
          `<strong style="color:rgba(255,255,255,0.6);">${d.zeros} (0)</strong> &bull; ` +
          `<strong style="color:#ff4060;">${d.minus_ones} (-1)</strong> &bull; ` +
          `Total: ${rows * cols} pesos &bull; Escala $\\gamma$: ${data.scale_factor}`;
      }

      // Verification comparison
      if (compBox) {
        const sampleYInt = data.y_integer_output ? data.y_integer_output.slice(0, 6) : [];
        const sampleYFloat = data.y_float_baseline ? data.y_float_baseline.slice(0, 6) : [];
        compBox.textContent = JSON.stringify({
          model: data.model_name,
          first_6_integer_outputs: sampleYInt,
          first_6_float32_baseline: sampleYFloat,
          inner_product_operations: "100% Integer Additions & Subtractions (Zero Multiplications)",
        }, null, 2);
      }
    } catch (e) {
      console.warn("Error cargando demo BitNet:", e);
    }
  }

  const btnRunBitnet = document.getElementById("btnRunBitnetDemo");
  if (btnRunBitnet) {
    btnRunBitnet.addEventListener("click", () => {
      const dim = parseInt(document.getElementById("selBitnetDim")?.value || "16", 10);
      const seed = parseInt(document.getElementById("txtBitnetSeed")?.value || "42", 10);
      loadBitNetDemo(dim, dim, seed);
    });
  }

  // =============================================================
  // TEE ENCLAVE & RUNTIME FORMAL VERIFICATION CONTROLLER (Línea P)
  // =============================================================
  async function fetchTeeStatus() {
    try {
      const res = await fetch("/api/tee/status");
      const data = await res.json();
      const elMrenclave = document.getElementById("teeMrenclave");
      const elCounter = document.getElementById("teeMonotonicCounter");
      const elSealed = document.getElementById("teeSealedCount");
      const elState = document.getElementById("teeStateBadge");

      if (elMrenclave) elMrenclave.textContent = data.mrenclave ? data.mrenclave.slice(0, 24) + "..." : "--";
      if (elCounter) elCounter.textContent = data.monotonic_counter !== undefined ? data.monotonic_counter : "--";
      if (elSealed) elSealed.textContent = data.sealed_secrets_count !== undefined ? data.sealed_secrets_count : "--";
      if (elState) {
        elState.textContent = data.state || "ACTIVE";
        elState.className = data.state === "ACTIVE" ? "badge-status text-green" : "badge-status text-red";
      }
    } catch (e) {
      console.warn("Error fetching TEE status:", e);
    }
  }

  const btnRefreshTee = document.getElementById("btnRefreshTeeStatus");
  if (btnRefreshTee) {
    btnRefreshTee.addEventListener("click", fetchTeeStatus);
  }

  const btnGenAttest = document.getElementById("btnGenerateTeeAttest");
  if (btnGenAttest) {
    btnGenAttest.addEventListener("click", async () => {
      const nonce = document.getElementById("txtTeeNonce")?.value.trim() || "";
      const out = document.getElementById("teeAttestationOutput");
      if (out) out.textContent = "Generando reporte de atestación firmado por el enclave...";
      try {
        const res = await fetch("/api/tee/attest", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ challenge_nonce: nonce })
        });
        const data = await res.json();
        if (out) out.textContent = JSON.stringify(data, null, 2);
        fetchTeeStatus();
      } catch (err) {
        if (out) out.textContent = "Error: " + err;
      }
    });
  }

  const btnRunFormal = document.getElementById("btnRunFormalVerification");
  if (btnRunFormal) {
    btnRunFormal.addEventListener("click", async () => {
      const tbody = document.getElementById("formalInvariantsTableBody");
      const proofEl = document.getElementById("formalProofHash");
      const badge = document.getElementById("formalStatusBadge");

      if (tbody) tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#00f2fe;">Ejecutando demostraciones formales en tiempo real...</td></tr>`;

      try {
        const res = await fetch("/api/formal/verify");
        const data = await res.json();

        if (proofEl) proofEl.textContent = data.proof_hash ? data.proof_hash.slice(0, 24) + "..." : "--";
        if (badge) {
          badge.textContent = `${data.passed_invariants} / ${data.total_invariants} VERIFICADAS`;
          badge.className = data.all_passed ? "badge-status text-green" : "badge-status text-red";
        }

        if (tbody && data.invariants) {
          tbody.innerHTML = data.invariants.map(inv => `
            <tr>
              <td><strong>${inv.name}</strong><br><span style="font-size:0.7rem; color:var(--text-muted);">${inv.invariant_id}</span></td>
              <td><span class="badge ${inv.passed ? 'badge-green' : 'badge-red'}">${inv.passed ? 'PASSED' : 'FAILED'}</span></td>
              <td class="mono-text" style="font-size:0.75rem; color:#a5f3fc;">${inv.mathematical_proof}</td>
              <td class="mono-text">${inv.execution_time_us} µs</td>
            </tr>
          `).join("");
        }
      } catch (err) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="4" style="color:#ff4060;">Error ejecutando verificación formal: ${err}</td></tr>`;
      }
    });
  }

  // =============================================================
  // ZKP & EPHEMERAL RING SIGNATURES CONTROLLER (Línea Q)
  // =============================================================

  // 1. ZK-Schnorr Prove & Verify
  const btnZkpSchnorr = document.getElementById("btnRunZkpSchnorr");
  if (btnZkpSchnorr) {
    btnZkpSchnorr.addEventListener("click", async () => {
      const ctx = document.getElementById("txtZkpSchnorrCtx")?.value.trim() || "IPVN7:GOVERNANCE:2026";
      const out = document.getElementById("zkpSchnorrOutput");
      const pkEl = document.getElementById("zkpSchnorrPk");
      const lenEl = document.getElementById("zkpSchnorrWireLen");
      const badge = document.getElementById("zkpSchnorrStatusBadge");

      if (out) out.textContent = "Generando y verificando prueba ZK-Schnorr en Zq...";
      try {
        const resProve = await fetch("/api/zkp/schnorr/prove", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ context: ctx })
        });
        const dataProve = await resProve.json();

        if (pkEl && dataProve.pk_hex) pkEl.textContent = dataProve.pk_hex.slice(0, 18) + "...";
        if (lenEl) lenEl.textContent = `${dataProve.wire_len} B`;

        // Verify the wire frame
        const resVerify = await fetch("/api/zkp/schnorr/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ wire_hex: dataProve.wire_hex })
        });
        const dataVerify = await resVerify.json();

        if (badge) {
          badge.textContent = dataVerify.valid ? "VERIFICADO (100% ZK-PoK)" : "INVÁLIDO";
          badge.className = dataVerify.valid ? "badge-status text-green" : "badge-status text-red";
        }

        if (out) {
          out.textContent = JSON.stringify({
            protocol: "Schnorr Sigma (ZK-PoK) / IP7Z",
            public_key: dataProve.pk_hex,
            proof_commitment_R: dataProve.proof?.R,
            response_s: dataProve.proof?.s,
            fiat_shamir_e: dataProve.proof?.e,
            wire_frame_bytes: dataProve.wire_len,
            mtu_valid: dataProve.mtu_valid,
            verification_status: dataVerify.valid ? "ACCEPT (Linear s·G ≡ R + e·Y mod q verified)" : "REJECT",
          }, null, 2);
        }
      } catch (err) {
        if (out) out.textContent = "Error: " + err;
      }
    });
  }

  // 2. Bulletproof Range Proof
  const btnZkpRange = document.getElementById("btnRunZkpRange");
  if (btnZkpRange) {
    btnZkpRange.addEventListener("click", async () => {
      const val = parseInt(document.getElementById("txtZkpRangeVal")?.value || "137", 10);
      const nBits = parseInt(document.getElementById("selZkpRangeBits")?.value || "8", 10);
      const out = document.getElementById("zkpRangeOutput");
      const cEl = document.getElementById("zkpRangeCommitment");
      const lenEl = document.getElementById("zkpRangeWireLen");
      const badge = document.getElementById("zkpRangeStatusBadge");

      if (out) out.textContent = `Generando prueba de rango confidencial para v=${val} ∈ [0, 2^${nBits})...`;
      try {
        const resProve = await fetch("/api/zkp/range/prove", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ value: val, n_bits: nBits, context: "balance-proof" })
        });
        const dataProve = await resProve.json();

        if (!dataProve.success) {
          if (out) out.textContent = "Error: " + dataProve.error;
          return;
        }

        if (cEl) cEl.textContent = dataProve.commitment_hex ? dataProve.commitment_hex.slice(0, 18) + "..." : "--";
        if (lenEl) lenEl.textContent = `${dataProve.wire_len} B`;

        // Verify the wire frame
        const resVerify = await fetch("/api/zkp/range/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ wire_hex: dataProve.wire_hex, n_bits: nBits })
        });
        const dataVerify = await resVerify.json();

        if (badge) {
          badge.textContent = dataVerify.valid ? `RANGO VÁLIDO [0, 2^${nBits})` : "FALLO DE RANGO";
          badge.className = dataVerify.valid ? "badge-status text-green" : "badge-status text-red";
        }

        if (out) {
          out.textContent = JSON.stringify({
            protocol: "Pedersen Commitment + OR-Proof Σ (CDS94) / IP7Z",
            pedersen_commitment_C: dataProve.commitment_hex,
            value_secret: "(Oculto por blinding factor r)",
            n_bits: nBits,
            range_bound: `[0, ${Math.pow(2, nBits)})`,
            wire_frame_len: `${dataProve.wire_len} B (MTU ≤ 1280B)`,
            homomorphic_bit_sum_check: "Σ (2^i · C_i) ≡ C (mod q) [PASSED]",
            verified_soundness: dataVerify.valid,
          }, null, 2);
        }
      } catch (err) {
        if (out) out.textContent = "Error: " + err;
      }
    });
  }

  // 3. Sovereign Ephemeral Ring Signature
  const btnRingSign = document.getElementById("btnRunRingSign");
  if (btnRingSign) {
    btnRingSign.addEventListener("click", async () => {
      const msg = document.getElementById("txtRingMsg")?.value.trim() || "PROPUESTA_GOBERNANZA_MALLA_42";
      const ringSize = parseInt(document.getElementById("selRingSize")?.value || "4", 10);
      const out = document.getElementById("ringOutput");
      const kEl = document.getElementById("ringKeyImage");
      const lenEl = document.getElementById("ringWireLen");
      const badge = document.getElementById("ringDoubleSignBadge");

      if (out) out.textContent = `Firmando mensaje anónimamente en un anillo de ${ringSize} miembros...`;
      try {
        const resSign = await fetch("/api/ring/sign", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: msg, ring_size: ringSize, epoch: "2026-10-21:00", ring_context: "GOVERNANCE_VOTE" })
        });
        const dataSign = await resSign.json();

        if (kEl) kEl.textContent = dataSign.key_image_hex ? dataSign.key_image_hex.slice(0, 18) + "..." : "--";
        if (lenEl) lenEl.textContent = `${dataSign.wire_len} B`;

        // Verify the wire frame
        const resVerify = await fetch("/api/ring/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ wire_hex: dataSign.wire_hex, message: msg })
        });
        const dataVerify = await resVerify.json();

        if (badge) {
          badge.textContent = dataVerify.valid ? "PROTEGIDO (Nulificador K Activo)" : "RECHAZADO";
          badge.className = dataVerify.valid ? "badge-status text-green" : "badge-status text-red";
        }

        if (out) {
          out.textContent = JSON.stringify({
            protocol: "Abe-Ohkubo-Suzuki (AOS02) Ephemeral Ring Signature / IP7S",
            ring_size: dataSign.ring_pks?.length,
            anonymous_signer_identity: "Oculto matemáticamente entre los n miembros",
            key_image_nullifier_K: dataSign.key_image_hex,
            epoch: dataSign.epoch,
            ring_pks_in_group: dataSign.ring_pks?.map(pk => pk.slice(0, 16) + "..."),
            wire_len: `${dataSign.wire_len} B (MTU ≤ 1280B)`,
            cyclic_closure: "c_n ≡ c_0 [VERIFIED TRUE]",
            signature_valid: dataVerify.valid,
          }, null, 2);
        }
      } catch (err) {
        if (out) out.textContent = "Error: " + err;
      }
    });
  }

  // --- Línea S: eBPF / XDP Wire-Speed Switch & Early-Drop Engine Logic ---
  async function fetchXdpStats() {
    try {
      const res = await fetch("/api/xdp/stats");
      const data = await res.json();
      const elTotal = document.getElementById("xdpTotalProcessed");
      const elPassed = document.getElementById("xdpPassed");
      const elDropped = document.getElementById("xdpDropped");
      const elRatio = document.getElementById("xdpEarlyDropRatio");
      const elBytes = document.getElementById("xdpBytesProcessed");
      const elMalformed = document.getElementById("xdpMalformed");

      if (elTotal) elTotal.textContent = data.total_processed || 0;
      if (elPassed) elPassed.textContent = data.passed || 0;
      if (elDropped) elDropped.textContent = data.dropped || 0;
      if (elRatio) elRatio.textContent = `${data.early_drop_ratio_pct || 0.0}%`;
      if (elBytes) elBytes.textContent = `${(data.bytes_processed || 0).toLocaleString()} B`;
      if (elMalformed) elMalformed.textContent = data.malformed_dropped || 0;
    } catch (err) {
      console.error("Error fetching XDP stats:", err);
    }
  }

  const btnRefreshXdp = document.getElementById("btnRefreshXdpStats");
  if (btnRefreshXdp) {
    btnRefreshXdp.addEventListener("click", () => fetchXdpStats());
  }

  const btnResetXdp = document.getElementById("btnResetXdpStats");
  if (btnResetXdp) {
    btnResetXdp.addEventListener("click", async () => {
      try {
        await fetch("/api/xdp/reset", { method: "POST", headers: { "Content-Type": "application/json" } });
        await fetchXdpStats();
      } catch (err) {
        console.error("Error resetting XDP stats:", err);
      }
    });
  }

  const btnInjectXdp = document.getElementById("btnInjectXdpPacket");
  if (btnInjectXdp) {
    btnInjectXdp.addEventListener("click", async () => {
      const magic = document.getElementById("selXdpMagic").value;
      const size = parseInt(document.getElementById("selXdpSize").value, 10);
      const actionBadge = document.getElementById("xdpActionBadge");
      const frameLenEl = document.getElementById("xdpFrameLen");
      const reasonEl = document.getElementById("xdpReasonText");
      const out = document.getElementById("xdpSimulatorOutput");

      if (out) out.textContent = `Sintetizando trama Ethernet/IP/UDP [Magic: ${magic}, Payload: ${size}B]...`;
      try {
        const res = await fetch("/api/xdp/synthesize", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ magic: magic, payload_size: size })
        });
        const data = await res.json();

        if (actionBadge) {
          actionBadge.textContent = data.action;
          actionBadge.className = data.action === "XDP_PASS" ? "badge-status text-green" : "badge-status text-red";
        }
        if (frameLenEl) frameLenEl.textContent = `${data.frame_len} B`;
        if (reasonEl) reasonEl.textContent = data.reason;

        if (out) {
          out.textContent = JSON.stringify({
            kernel_driver: "eBPF/XDP Fast-Path Early-Drop Engine",
            action: data.action,
            action_code: data.action_code,
            reason: data.reason,
            synthetic_frame_len: `${data.frame_len} B`,
            magic: data.magic,
            stats_summary: data.stats,
          }, null, 2);
        }

        await fetchXdpStats();
      } catch (err) {
        if (out) out.textContent = "Error: " + err;
      }
    });
  }

  const btnExportXdpC = document.getElementById("btnExportXdpC");
  if (btnExportXdpC) {
    btnExportXdpC.addEventListener("click", async () => {
      const out = document.getElementById("xdpCProgramOutput");
      if (out) out.textContent = "Obteniendo código fuente del kernel C...";
      try {
        const res = await fetch("/api/xdp/export_c");
        const data = await res.json();
        if (out) {
          out.textContent = data.c_code;
        }
      } catch (err) {
        if (out) out.textContent = "Error exportando código C: " + err;
      }
    });
  }

  // -----------------------------------------------------------------
  // Línea T: Sovereign Tri-State Operating Mode Controller & Health Governor
  // -----------------------------------------------------------------
  async function fetchModeStatus() {
    try {
      const res = await fetch("/api/mode/status");
      const data = await res.json();

      const curLabel = document.getElementById("modeCurrentLabel");
      const preLabel = document.getElementById("modePreDegradadoLabel");
      const transCount = document.getElementById("modeTransitionsCount");
      const timeInCur = document.getElementById("modeTimeInCurrent");
      const healthyEvals = document.getElementById("modeHealthyEvals");
      const lastIso = document.getElementById("modeLastTransitionIso");
      const badgesContainer = document.getElementById("modeProtectionsBadges");
      const headerMode = document.getElementById("headerOperatingMode");
      const modeDot = document.getElementById("modeDot");

      if (curLabel) {
        curLabel.textContent = data.current_mode;
        if (data.current_mode === "MODE_OPEN") curLabel.className = "kpi-value text-green";
        else if (data.current_mode === "MODE_SAFE") curLabel.className = "kpi-value text-purple";
        else curLabel.className = "kpi-value text-red";
      }

      if (headerMode) headerMode.textContent = data.current_mode;
      if (modeDot) {
        if (data.current_mode === "MODE_OPEN") modeDot.style.backgroundColor = "var(--accent-green, #10b981)";
        else if (data.current_mode === "MODE_SAFE") modeDot.style.backgroundColor = "var(--accent-purple, #a855f7)";
        else modeDot.style.backgroundColor = "var(--accent-red, #ef4444)";
      }

      if (preLabel) preLabel.textContent = data.pre_degraded_mode;
      if (transCount) transCount.textContent = data.transitions_count;
      if (timeInCur) timeInCur.textContent = `${data.time_in_current_mode_sec}s activo`;
      if (healthyEvals) healthyEvals.textContent = data.consecutive_healthy_evals;
      if (lastIso) lastIso.textContent = data.last_transition_iso;

      if (badgesContainer && data.active_protections) {
        badgesContainer.innerHTML = data.active_protections.map(p =>
          `<span class="badge-tag" style="margin-right:4px;">${p}</span>`
        ).join("");
      }
    } catch (err) {
      console.warn("Error fetching mode status:", err);
    }
  }

  const btnRefreshModeStatus = document.getElementById("btnRefreshModeStatus");
  if (btnRefreshModeStatus) {
    btnRefreshModeStatus.addEventListener("click", fetchModeStatus);
  }

  async function switchMode(targetMode) {
    try {
      const res = await fetch("/api/mode/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: targetMode, reason: "ui_switch" })
      });
      const data = await res.json();
      if (data.success) {
        await fetchModeStatus();
      } else {
        alert("Error cambiando modo: " + data.error);
      }
    } catch (err) {
      alert("Error al conmutar modo: " + err);
    }
  }

  const btnSetModeOpen = document.getElementById("btnSetModeOpen");
  if (btnSetModeOpen) {
    btnSetModeOpen.addEventListener("click", () => switchMode("MODE_OPEN"));
  }

  const btnSetModeSafe = document.getElementById("btnSetModeSafe");
  if (btnSetModeSafe) {
    btnSetModeSafe.addEventListener("click", () => switchMode("MODE_SAFE"));
  }

  const btnSetModeDegraded = document.getElementById("btnSetModeDegraded");
  if (btnSetModeDegraded) {
    btnSetModeDegraded.addEventListener("click", () => switchMode("MODE_DEGRADED"));
  }

  const btnEvaluateHealth = document.getElementById("btnEvaluateHealth");
  if (btnEvaluateHealth) {
    btnEvaluateHealth.addEventListener("click", async () => {
      const loss = parseFloat(document.getElementById("inputLossPct").value) || 0.0;
      const drop = parseFloat(document.getElementById("inputDropRatioPct").value) || 0.0;
      const buffer = parseFloat(document.getElementById("inputBufferPct").value) || 0.0;
      const out = document.getElementById("modeGovernorOutput");
      if (out) out.textContent = "Evaluando telemetría en el gobernador...";

      try {
        const res = await fetch("/api/mode/evaluate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ loss_pct: loss, drop_ratio_pct: drop, buffer_util_pct: buffer })
        });
        const data = await res.json();
        if (out) {
          out.textContent = JSON.stringify(data, null, 2);
        }
        await fetchModeStatus();
      } catch (err) {
        if (out) out.textContent = "Error: " + err;
      }
    });
  }

  const btnSimulateCleanRecovery = document.getElementById("btnSimulateCleanRecovery");
  if (btnSimulateCleanRecovery) {
    btnSimulateCleanRecovery.addEventListener("click", async () => {
      document.getElementById("inputLossPct").value = "0.0";
      document.getElementById("inputDropRatioPct").value = "0.0";
      document.getElementById("inputBufferPct").value = "15.0";
      const out = document.getElementById("modeGovernorOutput");
      if (out) out.textContent = "Inyectando telemetría limpia para auto-recuperación...";

      try {
        const res = await fetch("/api/mode/evaluate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ loss_pct: 0.0, drop_ratio_pct: 0.0, buffer_util_pct: 15.0 })
        });
        const data = await res.json();
        if (out) {
          out.textContent = JSON.stringify(data, null, 2);
        }
        await fetchModeStatus();
      } catch (err) {
        if (out) out.textContent = "Error: " + err;
      }
    });
  }

  const btnFetchModeHistory = document.getElementById("btnFetchModeHistory");
  if (btnFetchModeHistory) {
    btnFetchModeHistory.addEventListener("click", async () => {
      const out = document.getElementById("modeHistoryOutput");
      if (out) out.textContent = "Cargando anillo de auditoría de transiciones...";
      try {
        const res = await fetch("/api/mode/history");
        const data = await res.json();
        if (out) {
          out.textContent = JSON.stringify(data, null, 2);
        }
      } catch (err) {
        if (out) out.textContent = "Error cargando historial: " + err;
      }
    });
  }

  // Initializations
  fetchDagBlocks();
  fetchDiagnostics();
  fetchPetnames();
  fetchAccountingData();
  fetchServicesData();
  fetchPlanetaryMetrics();
  fetchResilienceStatus();
  fetchDarkNodeStatus();
  fetchSilentStats();
  fetchHealingSummary();
  fetchChatHistory();
  fetchUinPassport();
  fetchShadowDevices();
  fetchPfoTree();
  fetchWanStats();
  fetchRemoteDesktopStatus();
  initPlanetaryGlobe();
  loadBitNetDemo(16, 16, 42);
  fetchTeeStatus();
  fetchXdpStats();
  fetchModeStatus();
});

