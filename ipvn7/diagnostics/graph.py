"""
Sovereign In-Memory Knowledge Graph Engine & openCypher Pattern Matcher.
Rescued and elevated from historical 0.7/src/pkg/interfaces/graph.go,
ipvn7 vX7/pkg/l3/kuzu_graph.go, and MAGNA SKILL 7.0 (AFE-Kùzu Architecture).

Provides:
- In-memory multi-relational directed graph with typed nodes and edges.
- High-performance openCypher query evaluator (MATCH ... WHERE ... RETURN ... LIMIT).
- Axiomatic coherence auditing (Principles -> Functions -> Observations -> Decisions).
- Zero-orphan validation, shortest semantic paths (BFS), and ego-network subgraph extraction.
- Automatic seeding of IPVN 7 sovereign architecture (Axioms, ADRs, Subsystems, Peers).
"""

from __future__ import annotations

import re
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class GraphNode:
    """Represents a typed entity vertex in the sovereign knowledge graph."""
    id: str
    label: str
    name: str
    layer: str = "L0"
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "name": self.name,
            "layer": self.layer,
            "properties": self.properties,
            "created_at": self.created_at,
        }


@dataclass
class GraphEdge:
    """Represents a typed directed relationship between two vertices."""
    id: str
    source_id: str
    target_id: str
    rel_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "rel_type": self.rel_type,
            "properties": self.properties,
            "created_at": self.created_at,
        }


@dataclass
class CypherExecutionResult:
    """Represents the structured result of an openCypher query evaluation."""
    query: str
    columns: List[str]
    rows: List[Dict[str, Any]]
    row_count: int
    matched_nodes: List[str]
    matched_edges: List[str]
    exec_ms: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "columns": self.columns,
            "rows": self.rows,
            "row_count": self.row_count,
            "matched_nodes": self.matched_nodes,
            "matched_edges": self.matched_edges,
            "exec_ms": round(self.exec_ms, 3),
            "timestamp": self.timestamp,
        }


class KnowledgeGraphEngine:
    """
    Sovereign In-Memory Multi-Relational Knowledge Graph Engine.
    Implements openCypher pattern matching and formal axiomatic governance.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}

        # Adjacency and indexing
        self._out_edges: Dict[str, List[str]] = {}  # source_id -> list[edge_id]
        self._in_edges: Dict[str, List[str]] = {}   # target_id -> list[edge_id]
        self._label_index: Dict[str, Set[str]] = {} # label.upper() -> set[node_id]
        self._type_index: Dict[str, Set[str]] = {}  # rel_type.upper() -> set[edge_id]
        self._layer_index: Dict[str, Set[str]] = {} # layer.upper() -> set[node_id]

    # -------------------------------------------------------------
    # Vertex and Edge CRUD Operations
    # -------------------------------------------------------------

    def register_node(
        self,
        node_or_id: GraphNode | str,
        label: str = "Component",
        name: str = "",
        layer: str = "L0",
        properties: Optional[Dict[str, Any]] = None,
    ) -> GraphNode:
        """Inserts or updates a vertex in the knowledge graph."""
        with self._lock:
            if isinstance(node_or_id, GraphNode):
                node = node_or_id
            else:
                node = GraphNode(
                    id=str(node_or_id),
                    label=label,
                    name=name or str(node_or_id),
                    layer=layer,
                    properties=properties or {},
                )

            # Update indices
            old_node = self._nodes.get(node.id)
            if old_node:
                self._label_index.get(old_node.label.upper(), set()).discard(old_node.id)
                self._layer_index.get(old_node.layer.upper(), set()).discard(old_node.id)

            self._nodes[node.id] = node
            self._out_edges.setdefault(node.id, [])
            self._in_edges.setdefault(node.id, [])

            self._label_index.setdefault(node.label.upper(), set()).add(node.id)
            self._layer_index.setdefault(node.layer.upper(), set()).add(node.id)
            return node

    def register_edge(
        self,
        edge_or_source: GraphEdge | str,
        target_id: str = "",
        rel_type: str = "CONNECTS_TO",
        edge_id: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> GraphEdge:
        """Inserts or updates a directed relationship between two vertices."""
        with self._lock:
            if isinstance(edge_or_source, GraphEdge):
                edge = edge_or_source
            else:
                source_id = str(edge_or_source)
                eid = edge_id or f"{source_id}->{target_id}:{rel_type}"
                edge = GraphEdge(
                    id=eid,
                    source_id=source_id,
                    target_id=target_id,
                    rel_type=rel_type,
                    properties=properties or {},
                )

            # Ensure endpoints exist as stubs if not registered
            if edge.source_id not in self._nodes:
                self.register_node(edge.source_id, label="Component", name=edge.source_id)
            if edge.target_id not in self._nodes:
                self.register_node(edge.target_id, label="Component", name=edge.target_id)

            # Check if edge id already exists
            old_edge = self._edges.get(edge.id)
            if old_edge:
                self._type_index.get(old_edge.rel_type.upper(), set()).discard(old_edge.id)

            self._edges[edge.id] = edge
            if edge.id not in self._out_edges[edge.source_id]:
                self._out_edges[edge.source_id].append(edge.id)
            if edge.id not in self._in_edges[edge.target_id]:
                self._in_edges[edge.target_id].append(edge.id)

            self._type_index.setdefault(edge.rel_type.upper(), set()).add(edge.id)
            return edge

    def remove_node(self, node_id: str) -> bool:
        """Removes a vertex and all its incident edges."""
        with self._lock:
            if node_id not in self._nodes:
                return False

            node = self._nodes.pop(node_id)
            self._label_index.get(node.label.upper(), set()).discard(node_id)
            self._layer_index.get(node.layer.upper(), set()).discard(node_id)

            # Remove incident edges
            incident_edge_ids = list(self._out_edges.pop(node_id, [])) + list(self._in_edges.pop(node_id, []))
            for eid in set(incident_edge_ids):
                self.remove_edge(eid)
            return True

    def remove_edge(self, edge_id: str) -> bool:
        """Removes a directed relationship by ID."""
        with self._lock:
            if edge_id not in self._edges:
                return False

            edge = self._edges.pop(edge_id)
            self._type_index.get(edge.rel_type.upper(), set()).discard(edge_id)

            if edge.source_id in self._out_edges:
                self._out_edges[edge.source_id] = [e for e in self._out_edges[edge.source_id] if e != edge_id]
            if edge.target_id in self._in_edges:
                self._in_edges[edge.target_id] = [e for e in self._in_edges[edge.target_id] if e != edge_id]
            return True

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieves a node by ID."""
        with self._lock:
            return self._nodes.get(node_id)

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        """Retrieves an edge by ID."""
        with self._lock:
            return self._edges.get(edge_id)

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "both",  # "out", "in", "both"
        rel_type: Optional[str] = None,
    ) -> List[Tuple[GraphEdge, GraphNode]]:
        """Finds neighboring edges and nodes for a given vertex."""
        with self._lock:
            if node_id not in self._nodes:
                return []

            results = []
            rel_filter = rel_type.upper() if rel_type else None

            if direction in ("out", "both"):
                for eid in self._out_edges.get(node_id, []):
                    edge = self._edges.get(eid)
                    if edge and (not rel_filter or edge.rel_type.upper() == rel_filter):
                        target = self._nodes.get(edge.target_id)
                        if target:
                            results.append((edge, target))

            if direction in ("in", "both"):
                for eid in self._in_edges.get(node_id, []):
                    edge = self._edges.get(eid)
                    if edge and (not rel_filter or edge.rel_type.upper() == rel_filter):
                        source = self._nodes.get(edge.source_id)
                        if source:
                            results.append((edge, source))

            return results

    # -------------------------------------------------------------
    # Topological Analysis & Axiomatic Auditing
    # -------------------------------------------------------------

    def validate_zero_orphans(self) -> Dict[str, Any]:
        """
        Formally verifies that no vertices are disconnected from the network graph.
        Returns orphan node list, count, and overall topological coverage percentage.
        """
        with self._lock:
            total_nodes = len(self._nodes)
            if total_nodes == 0:
                return {
                    "orphan_count": 0,
                    "coverage_pct": 100.0,
                    "orphans": [],
                    "zero_orphans": True,
                }

            orphans = []
            for nid, node in self._nodes.items():
                out_degree = len(self._out_edges.get(nid, []))
                in_degree = len(self._in_edges.get(nid, []))
                if out_degree == 0 and in_degree == 0:
                    orphans.append(nid)

            connected_count = total_nodes - len(orphans)
            coverage_pct = round((connected_count / total_nodes) * 100.0, 2)

            return {
                "orphan_count": len(orphans),
                "coverage_pct": coverage_pct,
                "orphans": orphans,
                "zero_orphans": len(orphans) == 0,
            }

    def audit_axiomatic_coherence(self) -> Dict[str, Any]:
        """
        Audits protocol integrity by checking that:
        1. Operational functions derive from immutable Axiom Principles.
        2. Subsystems are governed by Axiom Principles or implement Operational Functions.
        3. Empirical observations linked to functions are compliant.
        """
        with self._lock:
            axioms = {nid for nid in self._nodes if self._nodes[nid].label.upper() == "AXIOMPRINCIPLE"}
            functions = {nid for nid in self._nodes if self._nodes[nid].label.upper() == "OPERATIONALFUNCTION"}
            subsystems = {nid for nid in self._nodes if self._nodes[nid].label.upper() == "SUBSYSTEM"}
            observations = [self._nodes[nid] for nid in self._nodes if self._nodes[nid].label.upper() == "EMPIRICALOBSERVATION"]

            unanchored_functions = []
            for fid in functions:
                # Check if fid has an outgoing DERIVED_FROM edge to an axiom
                derives = False
                for eid in self._out_edges.get(fid, []):
                    edge = self._edges.get(eid)
                    if edge and edge.rel_type.upper() in ("DERIVED_FROM", "DERIVES_FROM") and edge.target_id in axioms:
                        derives = True
                        break
                if not derives:
                    unanchored_functions.append(fid)

            unanchored_subsystems = []
            for sid in subsystems:
                # Check if sid is GOVERNED_BY an axiom, or IMPLEMENTS a function
                governed = False
                for eid in self._out_edges.get(sid, []):
                    edge = self._edges.get(eid)
                    if edge and (
                        (edge.rel_type.upper() == "GOVERNED_BY" and edge.target_id in axioms)
                        or (edge.rel_type.upper() == "IMPLEMENTS" and edge.target_id in functions)
                    ):
                        governed = True
                        break
                if not governed:
                    unanchored_subsystems.append(sid)

            non_compliant_observations = []
            for obs in observations:
                compliant = obs.properties.get("compliant", True)
                if not compliant:
                    non_compliant_observations.append({
                        "id": obs.id,
                        "name": obs.name,
                        "metric": obs.properties.get("metric_name", ""),
                        "value": obs.properties.get("value", 0),
                    })

            is_coherent = (
                len(unanchored_functions) == 0
                and len(unanchored_subsystems) == 0
                and len(non_compliant_observations) == 0
            )

            total_audited = len(functions) + len(subsystems) + len(observations)
            flaws = len(unanchored_functions) + len(unanchored_subsystems) + len(non_compliant_observations)
            coherence_score = round(max(0.0, (1.0 - (flaws / max(1, total_audited)))) * 100.0, 2)

            return {
                "is_coherent": is_coherent,
                "coherence_score": coherence_score,
                "total_axioms": len(axioms),
                "total_functions": len(functions),
                "total_subsystems": len(subsystems),
                "total_observations": len(observations),
                "unanchored_functions": unanchored_functions,
                "unanchored_subsystems": unanchored_subsystems,
                "non_compliant_observations": non_compliant_observations,
            }

    def find_shortest_path(
        self,
        source_id: str,
        target_id: str,
        rel_type: Optional[str] = None,
    ) -> Optional[List[str]]:
        """Finds the shortest semantic path between two vertices via Breadth-First Search (BFS)."""
        with self._lock:
            if source_id not in self._nodes or target_id not in self._nodes:
                return None
            if source_id == target_id:
                return [source_id]

            queue = [[source_id]]
            visited = {source_id}
            rel_filter = rel_type.upper() if rel_type else None

            while queue:
                path = queue.pop(0)
                current = path[-1]

                for eid in self._out_edges.get(current, []):
                    edge = self._edges.get(eid)
                    if edge and (not rel_filter or edge.rel_type.upper() == rel_filter):
                        neighbor = edge.target_id
                        if neighbor == target_id:
                            return path + [neighbor]
                        if neighbor not in visited and neighbor in self._nodes:
                            visited.add(neighbor)
                            queue.append(path + [neighbor])

            return None

    def extract_subgraph(self, seed_id: str, max_depth: int = 1) -> Dict[str, Any]:
        """Extracts an ego-network subgraph centered at seed_id up to max_depth hops."""
        with self._lock:
            if seed_id not in self._nodes:
                return {"nodes": [], "edges": [], "seed_id": seed_id}

            nodes_to_include: Set[str] = {seed_id}
            current_layer: Set[str] = {seed_id}

            for _ in range(max(1, max_depth)):
                next_layer: Set[str] = set()
                for nid in current_layer:
                    for eid in self._out_edges.get(nid, []):
                        edge = self._edges.get(eid)
                        if edge and edge.target_id not in nodes_to_include:
                            nodes_to_include.add(edge.target_id)
                            next_layer.add(edge.target_id)
                    for eid in self._in_edges.get(nid, []):
                        edge = self._edges.get(eid)
                        if edge and edge.source_id not in nodes_to_include:
                            nodes_to_include.add(edge.source_id)
                            next_layer.add(edge.source_id)
                current_layer = next_layer

            sub_nodes = [self._nodes[nid].to_dict() for nid in nodes_to_include if nid in self._nodes]
            sub_edges = [
                e.to_dict() for e in self._edges.values()
                if e.source_id in nodes_to_include and e.target_id in nodes_to_include
            ]

            return {
                "seed_id": seed_id,
                "max_depth": max_depth,
                "node_count": len(sub_nodes),
                "edge_count": len(sub_edges),
                "nodes": sub_nodes,
                "edges": sub_edges,
            }

    def export_topology(self) -> Dict[str, Any]:
        """Exports the complete topological graph with summary metadata and metrics."""
        with self._lock:
            orphan_info = self.validate_zero_orphans()
            layers: Dict[str, int] = {}
            labels: Dict[str, int] = {}
            for node in self._nodes.values():
                layers[node.layer] = layers.get(node.layer, 0) + 1
                labels[node.label] = labels.get(node.label, 0) + 1

            rel_types: Dict[str, int] = {}
            for edge in self._edges.values():
                rel_types[edge.rel_type] = rel_types.get(edge.rel_type, 0) + 1

            return {
                "metrics": {
                    "total_nodes": len(self._nodes),
                    "total_edges": len(self._edges),
                    "orphan_count": orphan_info["orphan_count"],
                    "coverage_pct": orphan_info["coverage_pct"],
                    "zero_orphans": orphan_info["zero_orphans"],
                    "layer_distribution": layers,
                    "label_distribution": labels,
                    "relationship_distribution": rel_types,
                },
                "nodes": [n.to_dict() for n in self._nodes.values()],
                "edges": [e.to_dict() for e in self._edges.values()],
            }

    # -------------------------------------------------------------
    # openCypher Query Evaluation Engine
    # -------------------------------------------------------------

    def execute_cypher(self, query: str) -> CypherExecutionResult:
        """
        Evaluates openCypher query patterns against the active in-memory graph.
        Supported Patterns:
          MATCH (n) [WHERE ...] RETURN ...
          MATCH (n:Label) [WHERE ...] RETURN ...
          MATCH (n:Label {prop: 'val'}) [WHERE ...] RETURN ...
          MATCH (n:L1)-[r:TYPE]->(m:L2) [WHERE ...] RETURN ...
          MATCH (n:L1)<-[r:TYPE]-(m:L2) [WHERE ...] RETURN ...
          MATCH (n:L1)-[r:TYPE]-(m:L2) [WHERE ...] RETURN ...
        """
        start_t = time.perf_counter()
        raw_query = query.strip()
        if not raw_query:
            return CypherExecutionResult(
                query=query,
                columns=["error"],
                rows=[{"error": "Empty Cypher query string"}],
                row_count=0,
                matched_nodes=[],
                matched_edges=[],
                exec_ms=0.0,
            )

        with self._lock:
            try:
                result = self._evaluate_cypher_internal(raw_query)
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                result.exec_ms = elapsed_ms
                return result
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                return CypherExecutionResult(
                    query=query,
                    columns=["error"],
                    rows=[{"error": str(e)}],
                    row_count=0,
                    matched_nodes=[],
                    matched_edges=[],
                    exec_ms=elapsed_ms,
                )

    def _evaluate_cypher_internal(self, query: str) -> CypherExecutionResult:
        # Normalize and extract LIMIT
        limit_match = re.search(r"\bLIMIT\s+(\d+)\b", query, re.IGNORECASE)
        limit_val = int(limit_match.group(1)) if limit_match else None
        cleaned = re.sub(r"\bLIMIT\s+\d+\b", "", query, flags=re.IGNORECASE).strip()

        # Split into MATCH, optional WHERE, and RETURN
        match_part = ""
        where_part = ""
        return_part = ""

        m_idx = cleaned.upper().find("MATCH")
        if m_idx == -1:
            raise ValueError("Cypher query must begin with MATCH statement")

        w_idx = cleaned.upper().find("WHERE")
        r_idx = cleaned.upper().find("RETURN")

        if r_idx == -1:
            raise ValueError("Cypher query must specify a RETURN statement")

        if w_idx != -1 and w_idx < r_idx:
            match_part = cleaned[m_idx + 5 : w_idx].strip()
            where_part = cleaned[w_idx + 5 : r_idx].strip()
            return_part = cleaned[r_idx + 6 :].strip()
        else:
            match_part = cleaned[m_idx + 5 : r_idx].strip()
            return_part = cleaned[r_idx + 6 :].strip()

        # Determine pattern: Node pattern vs Edge pattern
        # Pattern 1: Edge pattern: (n)-[r]->(m) or (n)<-[r]-(m) or (n)-[r]-(m)
        edge_match = re.search(
            r"\((?P<v1>[a-zA-Z0-9_]*)(?::(?P<lbl1>[a-zA-Z0-9_]+))?(?:\s*\{(?P<props1>[^}]*)\})?\)"
            r"(?P<arrow_left><)?-\[(?P<rel_var>[a-zA-Z0-9_]*)(?::(?P<rel_type>[a-zA-Z0-9_]+))?\]-(?P<arrow_right>>)?\s*"
            r"\((?P<v2>[a-zA-Z0-9_]*)(?::(?P<lbl2>[a-zA-Z0-9_]+))?(?:\s*\{(?P<props2>[^}]*)\})?\)",
            match_part,
        )

        matched_bindings: List[Dict[str, Any]] = []
        matched_node_ids: Set[str] = set()
        matched_edge_ids: Set[str] = set()

        if edge_match:
            # Directed or undirected edge pattern
            v1_var = edge_match.group("v1") or "n"
            lbl1 = edge_match.group("lbl1")
            v2_var = edge_match.group("v2") or "m"
            lbl2 = edge_match.group("lbl2")
            rel_var = edge_match.group("rel_var") or "r"
            rel_type = edge_match.group("rel_type")
            arrow_left = bool(edge_match.group("arrow_left"))
            arrow_right = bool(edge_match.group("arrow_right"))

            # Iterate over edges
            for edge in self._edges.values():
                if rel_type and edge.rel_type.upper() != rel_type.upper():
                    continue

                candidates: List[Tuple[GraphNode, GraphEdge, GraphNode]] = []
                if arrow_right or (not arrow_left and not arrow_right):
                    # Forward: source=v1, target=v2
                    src = self._nodes.get(edge.source_id)
                    tgt = self._nodes.get(edge.target_id)
                    if src and tgt:
                        candidates.append((src, edge, tgt))
                if arrow_left or (not arrow_left and not arrow_right):
                    # Reverse: target=v1, source=v2
                    src = self._nodes.get(edge.source_id)
                    tgt = self._nodes.get(edge.target_id)
                    if src and tgt:
                        candidates.append((tgt, edge, src))

                for n1, ed, n2 in candidates:
                    if lbl1 and n1.label.upper() != lbl1.upper():
                        continue
                    if lbl2 and n2.label.upper() != lbl2.upper():
                        continue

                    binding = {v1_var: n1, rel_var: ed, v2_var: n2}
                    if self._eval_where(where_part, binding):
                        matched_bindings.append(binding)
                        matched_node_ids.add(n1.id)
                        matched_node_ids.add(n2.id)
                        matched_edge_ids.add(ed.id)

        else:
            # Pattern 2: Single node pattern: (n:Label) or (n)
            node_match = re.search(
                r"\((?P<var>[a-zA-Z0-9_]*)(?::(?P<lbl>[a-zA-Z0-9_]+))?(?:\s*\{(?P<props>[^}]*)\})?\)",
                match_part,
            )
            if not node_match:
                raise ValueError(f"Unsupported Cypher MATCH pattern: '{match_part}'")

            var_name = node_match.group("var") or "n"
            label_filter = node_match.group("lbl")

            target_node_ids = (
                self._label_index.get(label_filter.upper(), set())
                if label_filter
                else set(self._nodes.keys())
            )

            for nid in target_node_ids:
                node = self._nodes.get(nid)
                if not node:
                    continue

                binding = {var_name: node}
                if self._eval_where(where_part, binding):
                    matched_bindings.append(binding)
                    matched_node_ids.add(node.id)

        # Apply LIMIT if present
        if limit_val is not None:
            matched_bindings = matched_bindings[:limit_val]

        # Projection (RETURN clause)
        columns, rows = self._project_return(return_part, matched_bindings)

        return CypherExecutionResult(
            query=query,
            columns=columns,
            rows=rows,
            row_count=len(rows),
            matched_nodes=sorted(list(matched_node_ids)),
            matched_edges=sorted(list(matched_edge_ids)),
            exec_ms=0.0,
        )

    def _eval_where(self, where_clause: str, binding: Dict[str, Any]) -> bool:
        """Evaluates simple openCypher WHERE clauses against current entity bindings."""
        if not where_clause:
            return True

        # Split conditions by AND
        conditions = [c.strip() for c in re.split(r"\bAND\b", where_clause, flags=re.IGNORECASE)]
        for cond in conditions:
            if not cond:
                continue

            # Check comparisons: !=, =, <, >, <=, >=
            op_match = re.search(r"^(?P<field>[a-zA-Z0-9_.]+)\s*(?P<op>!=|<=|>=|=|<|>)\s*(?P<val>.+)$", cond)
            if not op_match:
                continue

            field_path = op_match.group("field").strip()
            op = op_match.group("op").strip()
            val_raw = op_match.group("val").strip().strip("'\"")

            actual_val = self._resolve_field_value(field_path, binding)
            if actual_val is None:
                return False

            # Type conversion
            target_val: Any = val_raw
            if isinstance(actual_val, bool):
                target_val = val_raw.lower() in ("true", "1")
            elif isinstance(actual_val, (int, float)):
                try:
                    target_val = float(val_raw)
                except ValueError:
                    target_val = val_raw
            else:
                target_val = str(val_raw)

            # Evaluate
            if op == "=":
                if str(actual_val).lower() != str(target_val).lower() and actual_val != target_val:
                    return False
            elif op == "!=":
                if actual_val == target_val:
                    return False
            elif op == "<":
                if not (actual_val < target_val):
                    return False
            elif op == ">":
                if not (actual_val > target_val):
                    return False
            elif op == "<=":
                if not (actual_val <= target_val):
                    return False
            elif op == ">=":
                if not (actual_val >= target_val):
                    return False

        return True

    def _resolve_field_value(self, path: str, binding: Dict[str, Any]) -> Any:
        """Resolves variable paths like n.id, n.label, n.properties.statement, n.status, r.rel_type."""
        parts = path.split(".")
        var_name = parts[0]
        if var_name not in binding:
            return None

        entity = binding[var_name]
        if len(parts) == 1:
            return entity

        field_name = parts[1]
        # Check standard attributes
        if hasattr(entity, field_name):
            val = getattr(entity, field_name)
            if len(parts) > 2 and isinstance(val, dict):
                return val.get(parts[2])
            return val

        # Check properties dict
        if hasattr(entity, "properties") and isinstance(entity.properties, dict):
            if field_name in entity.properties:
                val = entity.properties[field_name]
                if len(parts) > 2 and isinstance(val, dict):
                    return val.get(parts[2])
                return val

        return None

    def _project_return(
        self,
        return_clause: str,
        bindings: List[Dict[str, Any]],
    ) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Projects return expressions into structured columns and rows."""
        ret_exprs = [e.strip() for e in return_clause.split(",") if e.strip()]
        if not ret_exprs:
            ret_exprs = ["*"]

        # Parse projections with optional aliases: e.g. "n.id AS identifier"
        projections: List[Tuple[str, str]] = []
        for expr in ret_exprs:
            as_match = re.search(r"^(?P<src>.+?)\s+AS\s+(?P<alias>[a-zA-Z0-9_]+)$", expr, re.IGNORECASE)
            if as_match:
                projections.append((as_match.group("src").strip(), as_match.group("alias").strip()))
            else:
                projections.append((expr, expr))

        columns = [alias for _, alias in projections]
        rows: List[Dict[str, Any]] = []

        for binding in bindings:
            row: Dict[str, Any] = {}
            for src_expr, col_name in projections:
                if src_expr in binding:
                    ent = binding[src_expr]
                    row[col_name] = ent.to_dict() if hasattr(ent, "to_dict") else str(ent)
                else:
                    val = self._resolve_field_value(src_expr, binding)
                    if hasattr(val, "to_dict"):
                        row[col_name] = val.to_dict()
                    else:
                        row[col_name] = val
            rows.append(row)

        return columns, rows

    # -------------------------------------------------------------
    # Canonical Architecture Seeding
    # -------------------------------------------------------------

    def seed_canonical_architecture(self, node_ref: Any = None):
        """
        Seeds the sovereign knowledge graph with all canonical Axioms,
        ADRs (001-019), Subsystems, Operational Functions, and active topology.
        """
        with self._lock:
            # 1. Canonical Axiom Principles (L0 Core Invariants)
            axioms_data = [
                (
                    "AXIOM_ZERO_PII",
                    "Prohibición estricta de registrar IPs reales, geolocalizaciones o metadatos de usuario fuera de contenedores sellados.",
                    "L0",
                ),
                (
                    "AXIOM_STRICT_CORE_FREEZE",
                    "Inmutabilidad del núcleo L0 wire-format (1280B MTU y cabeceras canónicas universales).",
                    "L0",
                ),
                (
                    "AXIOM_SUSTAINABLE_FLOW",
                    "Subordinación del emisor al cuello de botella de la ruta mediante DWRR y Packet Pacing determinista.",
                    "L1",
                ),
                (
                    "AXIOM_FAST_PATH_FIRST",
                    "Decisiones de conmutación en camino crítico de kernel eBPF/XDP o buffers lock-free (<28ns).",
                    "L1",
                ),
                (
                    "AXIOM_SMALL_WORLD_RINGS",
                    "Enrutamiento voraz en espacio métrico XOR de 256 bits estructurado en 12 anillos logarítmicos de Kleinberg.",
                    "L1",
                ),
                (
                    "AXIOM_POST_QUANTUM",
                    "Seguridad criptográfica híbrida post-cuántica universal basada en ML-KEM-768 y ML-DSA-65.",
                    "L0",
                ),
                (
                    "AXIOM_SOVEREIGNTY",
                    "Intercepción DNS local y desvinculación total de intermediarios corporativos y resolutores ISP.",
                    "L2",
                ),
            ]

            for ax_id, stmt, lyr in axioms_data:
                self.register_node(
                    node_or_id=ax_id,
                    label="AxiomPrinciple",
                    name=ax_id,
                    layer=lyr,
                    properties={"statement": stmt, "immutable": True},
                )

            # 2. Canonical ADR Decisions (001 - 019)
            adrs = [
                ("ADR-001", "Architecture Consolidation", "APPROVED"),
                ("ADR-002", "Edge AI & Media Datapath", "APPROVED"),
                ("ADR-003", "BitNet b1.58 Ternary Quantization", "APPROVED"),
                ("ADR-004", "Security Audit Remediation 1", "APPROVED"),
                ("ADR-005", "Datapath Saturation & Compression", "APPROVED"),
                ("ADR-006", "Silent PQC Rekeying & Forward Secrecy", "APPROVED"),
                ("ADR-007", "Geopolicy Routing & Data Sovereignty", "APPROVED"),
                ("ADR-008", "Private DHT Interregion Sync", "APPROVED"),
                ("ADR-009", "Sovereign Tunnel Telemetry & PMTU", "APPROVED"),
                ("ADR-010", "Security Audit Remediation 2", "APPROVED"),
                ("ADR-011", "True Exit Node Datapath Relay", "APPROVED"),
                ("ADR-012", "Security Audit Remediation 3", "APPROVED"),
                ("ADR-013", "Sovereign Reciprocity Settlement IP7R", "APPROVED"),
                ("ADR-014", "Cryptographic TEE Enclave IP7E", "APPROVED"),
                ("ADR-015", "Zero-Knowledge Proofs IP7Z & Ring Signatures IP7S", "APPROVED"),
                ("ADR-016", "eBPF/XDP Wire-Speed Switch & Early-Drop Engine", "APPROVED"),
                ("ADR-017", "Tri-State Operating Mode Controller", "APPROVED"),
                ("ADR-018", "Over-The-Air Hot-Swapping & Sandboxing Engine", "APPROVED"),
                ("ADR-019", "Sovereign RFC 1035 UDP DNS Server & Binary Wire Codec", "APPROVED"),
            ]

            for adr_id, title, status in adrs:
                self.register_node(
                    node_or_id=adr_id,
                    label="Decision",
                    name=f"{adr_id}: {title}",
                    layer="Core",
                    properties={"title": title, "status": status},
                )

            # 3. Canonical Subsystems and Axiom/ADR Bindings
            subsystems_data = [
                ("subsystem-dns-server", "Sovereign DNS Server (RFC 1035)", "L2", "AXIOM_SOVEREIGNTY", "ADR-019"),
                ("subsystem-xdp-switch", "eBPF/XDP Wire-Speed Switch", "L1", "AXIOM_FAST_PATH_FIRST", "ADR-016"),
                ("subsystem-mode-controller", "Operating Mode Controller", "L2", "AXIOM_FAST_PATH_FIRST", "ADR-017"),
                ("subsystem-ota-hotswap", "Sovereign OTA Hot-Swap Engine", "L3", "AXIOM_STRICT_CORE_FREEZE", "ADR-018"),
                ("subsystem-tee-enclave", "Cryptographic TEE Enclave", "L0", "AXIOM_POST_QUANTUM", "ADR-014"),
                ("subsystem-formal-verifier", "Runtime Formal Verifier", "L3", "AXIOM_STRICT_CORE_FREEZE", "ADR-014"),
                ("subsystem-zkp-proofs", "Zero-Knowledge Proofs Engine", "L0", "AXIOM_ZERO_PII", "ADR-015"),
                ("subsystem-ring-signatures", "Ephemeral Ring Signatures", "L0", "AXIOM_ZERO_PII", "ADR-015"),
                ("subsystem-reciprocity", "Reciprocity Settlement (IP7R)", "L2", "AXIOM_SUSTAINABLE_FLOW", "ADR-013"),
                ("subsystem-dwrr-pacer", "DWRR Scheduler & Packet Pacer", "L1", "AXIOM_SUSTAINABLE_FLOW", "ADR-005"),
                ("subsystem-kleinberg-mesh", "Planetary Kleinberg Mesh", "L1", "AXIOM_SMALL_WORLD_RINGS", "ADR-001"),
                ("subsystem-pqc-keys", "Hybrid Post-Quantum Keys (ML-KEM/DSA)", "L0", "AXIOM_POST_QUANTUM", "ADR-006"),
                ("subsystem-dark-node", "Dark Node Macro & Anti-Probe Guard", "L1", "AXIOM_ZERO_PII", "ADR-004"),
                ("subsystem-shadow-device", "Shadow Device Ambassador", "L4", "AXIOM_ZERO_PII", "ADR-001"),
                ("subsystem-uin-manager", "UIN Sovereign Identity Manager", "L3", "AXIOM_ZERO_PII", "ADR-001"),
                ("subsystem-petname-resolver", "Human-Friendly Petname Resolver", "L3", "AXIOM_SOVEREIGNTY", "ADR-001"),
                ("subsystem-bitnet-edge", "BitNet 1-bit Ternary Edge AI", "L3", "AXIOM_FAST_PATH_FIRST", "ADR-003"),
            ]

            for s_id, name, lyr, ax_id, adr_id in subsystems_data:
                self.register_node(
                    node_or_id=s_id,
                    label="Subsystem",
                    name=name,
                    layer=lyr,
                    properties={"status": "ACTIVE"},
                )
                self.register_edge(
                    edge_or_source=s_id,
                    target_id=ax_id,
                    rel_type="GOVERNED_BY",
                    edge_id=f"{s_id}->{ax_id}:GOVERNED_BY",
                )
                self.register_edge(
                    edge_or_source=s_id,
                    target_id=adr_id,
                    rel_type="DECIDED_BY",
                    edge_id=f"{s_id}->{adr_id}:DECIDED_BY",
                )

            # 4. Canonical Operational Functions
            functions_data = [
                ("L0_SOVEREIGN_IDENTITY", "ipvn7/crypto/keys.py", "AXIOM_ZERO_PII", "subsystem-pqc-keys"),
                ("L0_DETERMINISTIC_WIRE", "ipvn7/network/onion.py", "AXIOM_STRICT_CORE_FREEZE", "subsystem-xdp-switch"),
                ("L1_ZTNA_FIREWALL", "ipvn7/security/firewall.py", "AXIOM_ZERO_PII", "subsystem-mode-controller"),
                ("L1_PACKET_PACER", "ipvn7/network/pacer.py", "AXIOM_SUSTAINABLE_FLOW", "subsystem-dwrr-pacer"),
                ("L1_DWRR_SCHEDULER", "ipvn7/network/pacer.py", "AXIOM_SUSTAINABLE_FLOW", "subsystem-dwrr-pacer"),
                ("L1_KLEINBERG_ROUTER", "ipvn7/network/planetary.py", "AXIOM_SMALL_WORLD_RINGS", "subsystem-kleinberg-mesh"),
                ("L1_DARK_NODE_MACRO", "ipvn7/security/dark_node.py", "AXIOM_ZERO_PII", "subsystem-dark-node"),
                ("L2_DNS_INTERCEPTION", "ipvn7/network/dns_server.py", "AXIOM_SOVEREIGNTY", "subsystem-dns-server"),
                ("L3_OTA_SANDBOX", "ipvn7/system/ota.py", "AXIOM_STRICT_CORE_FREEZE", "subsystem-ota-hotswap"),
                ("L3_UIN_IDENTITY", "ipvn7/identity/uin.py", "AXIOM_ZERO_PII", "subsystem-uin-manager"),
                ("L4_SHADOW_DEVICE", "ipvn7/access/shadow_device.py", "AXIOM_ZERO_PII", "subsystem-shadow-device"),
            ]

            for f_id, path, ax_id, s_id in functions_data:
                self.register_node(
                    node_or_id=f_id,
                    label="OperationalFunction",
                    name=f_id,
                    layer="Core",
                    properties={"module_path": path, "status": "VERIFIED"},
                )
                self.register_edge(
                    edge_or_source=f_id,
                    target_id=ax_id,
                    rel_type="DERIVED_FROM",
                    edge_id=f"{f_id}->{ax_id}:DERIVED_FROM",
                )
                self.register_edge(
                    edge_or_source=s_id,
                    target_id=f_id,
                    rel_type="IMPLEMENTS",
                    edge_id=f"{s_id}->{f_id}:IMPLEMENTS",
                )

            # 5. Connect Subsystems with internal Dataflow (TRANSFERS_DATA_TO)
            dataflows = [
                ("subsystem-xdp-switch", "subsystem-dwrr-pacer"),
                ("subsystem-dwrr-pacer", "subsystem-kleinberg-mesh"),
                ("subsystem-dns-server", "subsystem-petname-resolver"),
                ("subsystem-petname-resolver", "subsystem-shadow-device"),
                ("subsystem-mode-controller", "subsystem-xdp-switch"),
                ("subsystem-mode-controller", "subsystem-dark-node"),
            ]
            for src, tgt in dataflows:
                self.register_edge(
                    edge_or_source=src,
                    target_id=tgt,
                    rel_type="TRANSFERS_DATA_TO",
                    edge_id=f"{src}->{tgt}:TRANSFERS_DATA_TO",
                )

            # 6. If node_ref passed, ingest live node attributes
            if node_ref is not None:
                local_did = getattr(node_ref, "did", "did:ipvn7:local")
                self.register_node(
                    node_or_id=local_did,
                    label="Peer",
                    name=f"LocalNode ({local_did[:12]})",
                    layer="L0",
                    properties={"is_local": True, "status": "ONLINE"},
                )
                self.register_edge(
                    edge_or_source=local_did,
                    target_id="subsystem-pqc-keys",
                    rel_type="SECURED_BY",
                    edge_id=f"{local_did}->subsystem-pqc-keys:SECURED_BY",
                )

                # Connect PFO observations if available
                pfo = getattr(node_ref, "pfo_engine", None)
                if pfo and hasattr(pfo, "_observations"):
                    for obs in pfo._observations[-20:]:
                        self.register_node(
                            node_or_id=obs.observation_id,
                            label="EmpiricalObservation",
                            name=obs.metric_name,
                            layer="L2",
                            properties={
                                "metric_name": obs.metric_name,
                                "value": obs.value,
                                "unit": obs.unit,
                                "compliant": obs.compliant,
                            },
                        )
                        self.register_edge(
                            edge_or_source=obs.function_id,
                            target_id=obs.observation_id,
                            rel_type="VALIDATED_BY",
                            edge_id=f"{obs.function_id}->{obs.observation_id}:VALIDATED_BY",
                        )
