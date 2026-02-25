"""
graph_state.py — Thread-safe in-memory attack surface graph.

Stores GraphNode and GraphEdge objects. Fires a broadcast callback
on every mutation so ui_server.py can push SSE events to the browser.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class GraphNode:
    id: str          # e.g. "host:10.10.10.5", "service:80/tcp:10.10.10.5"
    type: str        # host | service | vulnerability | credential | access
    label: str       # display label
    data: dict       # arbitrary metadata
    timestamp: float = field(default_factory=time.time)


@dataclass
class GraphEdge:
    id: str          # f"{src}->{tgt}:{type}"
    source: str
    target: str
    type: str        # has_service | exposes_vuln | yields_cred | grants_access | lateral_movement
    label: str
    timestamp: float = field(default_factory=time.time)


class GraphState:
    """Thread-safe in-memory graph store."""

    def __init__(self) -> None:
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._lock = threading.Lock()
        self._version: int = 0
        self._broadcast_cb: Optional[Callable[[dict], None]] = None

    # ------------------------------------------------------------------ #
    # Mutations                                                            #
    # ------------------------------------------------------------------ #

    def add_node(self, id: str, type: str, label: str, data: dict) -> bool:
        """Add or update a node. Returns True if new, False if updated."""
        with self._lock:
            is_new = id not in self._nodes
            if is_new:
                node = GraphNode(id=id, type=type, label=label, data=data)
                self._nodes[id] = node
                self._version += 1
                cy_node = self._node_to_cy(node)
                event = {"type": "node_added", "node": cy_node}
            else:
                # Merge data fields into existing node
                existing = self._nodes[id]
                existing.data.update(data)
                existing.label = label
                self._version += 1
                cy_node = self._node_to_cy(existing)
                event = {"type": "node_updated", "node": cy_node}

        self._fire(event)
        return is_new

    def add_edge(self, source: str, target: str, type: str, label: str) -> bool:
        """Add an edge. Returns True if new, False if already exists."""
        edge_id = f"{source}->{target}:{type}"
        with self._lock:
            if edge_id in self._edges:
                return False
            edge = GraphEdge(id=edge_id, source=source, target=target, type=type, label=label)
            self._edges[edge_id] = edge
            self._version += 1
            cy_edge = self._edge_to_cy(edge)
            event = {"type": "edge_added", "edge": cy_edge}

        self._fire(event)
        return True

    def has_node(self, id: str) -> bool:
        with self._lock:
            return id in self._nodes

    def get_node(self, id: str) -> Optional[GraphNode]:
        with self._lock:
            return self._nodes.get(id)

    # ------------------------------------------------------------------ #
    # Broadcast callback                                                   #
    # ------------------------------------------------------------------ #

    def set_broadcast_callback(self, cb: Callable[[dict], None]) -> None:
        with self._lock:
            self._broadcast_cb = cb

    def _fire(self, event: dict) -> None:
        with self._lock:
            cb = self._broadcast_cb
        if cb:
            try:
                cb(event)
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Serialization                                                        #
    # ------------------------------------------------------------------ #

    def to_cytoscape_dict(self) -> dict:
        """Return full graph snapshot in Cytoscape.js element format."""
        with self._lock:
            nodes = [self._node_to_cy(n) for n in self._nodes.values()]
            edges = [self._edge_to_cy(e) for e in self._edges.values()]
            version = self._version
        return {"nodes": nodes, "edges": edges, "version": version}

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _node_to_cy(node: GraphNode) -> dict:
        return {
            "id": node.id,
            "type": node.type,
            "label": node.label,
            "timestamp": node.timestamp,
            **node.data,
        }

    @staticmethod
    def _edge_to_cy(edge: GraphEdge) -> dict:
        return {
            "id": edge.id,
            "source": edge.source,
            "target": edge.target,
            "type": edge.type,
            "label": edge.label,
            "timestamp": edge.timestamp,
        }

    def node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    def edge_count(self) -> int:
        with self._lock:
            return len(self._edges)
