"""
ui_server.py — Flask web server for the real-time attack surface graph UI.

Runs in a background daemon thread. Exposes:
  GET /              -> index.html (Cytoscape.js graph)
  GET /api/graph     -> full graph snapshot (JSON)
  GET /api/events    -> SSE stream of graph mutations
  GET /api/status    -> current agent status (JSON)
"""
from __future__ import annotations

import json
import queue
import threading
from typing import List

from graph_state import GraphState

# Lazy Flask import so that importing ui_server doesn't fail if Flask is absent
try:
    from flask import Flask, Response, jsonify, send_from_directory
    _FLASK_AVAILABLE = True
except ImportError:
    _FLASK_AVAILABLE = False

# ------------------------------------------------------------------ #
# Module-level globals                                                #
# ------------------------------------------------------------------ #

_app: "Flask" = None
_graph_state: GraphState = None
_subscribers: List[queue.Queue] = []
_subscribers_lock = threading.Lock()
_status: dict = {
    "iteration": 0,
    "tool": None,
    "phase": "Initializing",
    "target": "",
}


# ------------------------------------------------------------------ #
# Public API                                                          #
# ------------------------------------------------------------------ #

def start_server(graph_state: GraphState, host: str = "0.0.0.0", port: int = 5000) -> None:
    """Start the Flask server in a background daemon thread."""
    if not _FLASK_AVAILABLE:
        print("[UI] Flask not installed — run: pip install flask>=3.0.0")
        return

    global _app, _graph_state
    _graph_state = graph_state
    _graph_state.set_broadcast_callback(broadcast_event)

    _app = Flask(__name__, static_folder=None)
    _app.logger.disabled = True

    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)

    _register_routes(_app)

    thread = threading.Thread(
        target=lambda: _app.run(host=host, port=port, threaded=True, use_reloader=False),
        daemon=True,
        name="ui-server",
    )
    thread.start()


def broadcast_event(event: dict) -> None:
    """Push an event to all connected SSE subscribers."""
    with _subscribers_lock:
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)


def update_status(iteration: int, tool_name: str, phase: str = None) -> None:
    """Update the agent status and broadcast a status event."""
    global _status
    _status["iteration"] = iteration
    _status["tool"] = tool_name
    if phase:
        _status["phase"] = phase
    if _graph_state:
        _status["nodes"] = _graph_state.node_count()
        _status["edges"] = _graph_state.edge_count()
    broadcast_event({"type": "status", **_status})


# ------------------------------------------------------------------ #
# Routes                                                              #
# ------------------------------------------------------------------ #

def _register_routes(app: "Flask") -> None:
    import os

    @app.route("/")
    def index():
        ui_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
        return send_from_directory(ui_dir, "index.html")

    @app.route("/api/graph")
    def api_graph():
        if _graph_state is None:
            return jsonify({"nodes": [], "edges": [], "version": 0})
        return jsonify(_graph_state.to_cytoscape_dict())

    @app.route("/api/status")
    def api_status():
        status = dict(_status)
        if _graph_state:
            status["nodes"] = _graph_state.node_count()
            status["edges"] = _graph_state.edge_count()
        return jsonify(status)

    @app.route("/api/events")
    def api_events():
        local_q: queue.Queue = queue.Queue(maxsize=200)
        with _subscribers_lock:
            _subscribers.append(local_q)

        # Send a graph snapshot immediately on connect
        if _graph_state:
            snapshot = _graph_state.to_cytoscape_dict()
            cy_nodes = [{"data": n} for n in snapshot["nodes"]]
            cy_edges = [{"data": e} for e in snapshot["edges"]]
            init_event = {
                "type": "graph_snapshot",
                "elements": cy_nodes + cy_edges,
                "version": snapshot["version"],
            }
            local_q.put_nowait(init_event)

        def generate():
            try:
                while True:
                    try:
                        event = local_q.get(timeout=30)
                        yield f"data: {json.dumps(event)}\n\n"
                    except queue.Empty:
                        # Send keepalive ping
                        yield 'data: {"type":"ping"}\n\n'
            except GeneratorExit:
                pass
            finally:
                with _subscribers_lock:
                    if local_q in _subscribers:
                        _subscribers.remove(local_q)

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )
