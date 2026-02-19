"""
sky-shield/dashboard/app.py

Real-Time Flask Dashboard
==========================
Serves the Sky-Shield monitoring dashboard via Flask + Socket.IO.
Pushes live events to the browser using WebSockets.

Routes:
  GET  /           → Main dashboard UI
  GET  /api/stats  → JSON stats snapshot
  GET  /api/bots   → Detected bots list
  GET  /api/blocks → Currently blocked IPs
  GET  /api/log    → Event log
  POST /api/block  → Manually block an IP
  POST /api/unblock→ Manually unblock an IP
"""

import logging
import time
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

logger = logging.getLogger("skyshield.dashboard")

# These will be set by main.py when the app is initialized
_sniffer = None
_blocker = None
_trust_manager = None
_bot_detector = None
_event_log = []
_MAX_EVENTS = 200

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "skyshield-secret-2024"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


def init_dashboard(sniffer, blocker, trust_manager, bot_detector):
    """Connect dashboard to the core Sky-Shield components."""
    global _sniffer, _blocker, _trust_manager, _bot_detector
    _sniffer = sniffer
    _blocker = blocker
    _trust_manager = trust_manager
    _bot_detector = bot_detector

    # Connect event bus
    sniffer.event_bus = push_event


def push_event(event_type: str, data: dict):
    """Push a real-time event to all connected dashboard clients."""
    global _event_log

    event = {
        "type": event_type,
        "data": data,
        "timestamp": time.strftime("%H:%M:%S"),
    }
    _event_log.append(event)
    if len(_event_log) > _MAX_EVENTS:
        _event_log = _event_log[-_MAX_EVENTS:]

    # Auto-block if attack event
    if event_type == "attack" and _blocker and data.get("ip"):
        _blocker.block(data["ip"], reason="SkyShield Auto-Block")

    try:
        socketio.emit(event_type, data)
        socketio.emit("log_entry", event)
    except Exception as e:
        logger.error(f"SocketIO emit error: {e}")


# ─────────────────────────────────────────────
#  HTML Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─────────────────────────────────────────────
#  REST API Routes
# ─────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    if not _sniffer:
        return jsonify({"error": "Not initialized"}), 503
    stats = _sniffer.get_stats()
    stats.update(_blocker.get_stats() if _blocker else {})
    stats.update(_trust_manager.get_stats() if _trust_manager else {})
    return jsonify(stats)


@app.route("/api/bots")
def api_bots():
    if not _bot_detector:
        return jsonify([])
    return jsonify(_bot_detector.get_detected_bots())


@app.route("/api/blocks")
def api_blocks():
    if not _blocker:
        return jsonify([])
    return jsonify(_blocker.get_blocked_list())


@app.route("/api/log")
def api_log():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(_event_log[-limit:][::-1])


@app.route("/api/flagged")
def api_flagged():
    if not _trust_manager:
        return jsonify([])
    return jsonify(_trust_manager.get_all_flagged())


@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json()
    ip = data.get("ip")
    duration = data.get("duration", 300)
    if not ip:
        return jsonify({"error": "IP required"}), 400
    _blocker.block(ip, duration=duration, reason="Manual Block")
    _trust_manager.manual_block(ip, duration=duration)
    push_event("manual_block", {"ip": ip, "duration": duration})
    return jsonify({"status": "blocked", "ip": ip})


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    _blocker.unblock(ip)
    _trust_manager.manual_unblock(ip)
    push_event("manual_unblock", {"ip": ip})
    return jsonify({"status": "unblocked", "ip": ip})


@app.route("/api/block_log")
def api_block_log():
    if not _blocker:
        return jsonify([])
    return jsonify(_blocker.get_block_log())


# ─────────────────────────────────────────────
#  WebSocket Events
# ─────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    logger.info("Dashboard client connected")
    if _sniffer:
        emit("stats", _sniffer.get_stats())


@socketio.on("disconnect")
def on_disconnect():
    logger.info("Dashboard client disconnected")


@socketio.on("request_stats")
def on_request_stats():
    if _sniffer:
        emit("stats", _sniffer.get_stats())


def run_dashboard(host="0.0.0.0", port=5000, debug=False):
    """Start the Flask-SocketIO dashboard server."""
    logger.info(f"Starting dashboard at http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)
