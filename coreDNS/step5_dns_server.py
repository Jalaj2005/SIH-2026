"""
STEP 5: The complete Module 1 — Core DNS Resolver

Flow (Updated for Orchestrator Pattern):
  1. Listen on UDP port 53 for incoming raw DNS packets
  2. Extract the domain name, query type, and client IP
  3. Call the Risk Aggregator (Step 3) with the domain and IP
  4. If verdict == BLOCK -> return 0.0.0.0 (sinkhole)
     If verdict == ALLOW -> forward to real upstream DNS and relay real IP
"""

import socket
import threading

# --- NEW: Import Step 2 ---
from step2_packet_parser import extract_domain_from_packet
from step3_scoring_client import get_verdict
from step4_response_builder import build_sinkhole_response, resolve_upstream

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5053   # use 5053 for local testing (53 needs root/admin privileges)


def handle_query(data: bytes, addr, sock: socket.socket):
    try:
        # --- NEW: Use Step 2 to parse the packet ---
        domain, qtype_code, request = extract_domain_from_packet(data)
        
        # --- NEW: Extract the Client IP for Module 4's burst tracking ---
        client_ip = addr[0]

        # --- NEW: Pass the client_ip into Step 3 ---
        verdict = get_verdict(domain, qtype_code, client_ip)
        
        print(f"[QUERY] {client_ip} asked for {domain} -> {verdict['verdict']} ({verdict['reason']})")

        if verdict["verdict"] == "BLOCK":
            response_bytes = build_sinkhole_response(request)
        else:
            response_bytes = resolve_upstream(request, data)

        sock.sendto(response_bytes, addr)

    except Exception as e:
        print(f"[ERROR] Failed to handle query from {addr}: {e}")


def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"Core DNS Resolver listening on {LISTEN_IP}:{LISTEN_PORT} (UDP)")

    while True:
        data, addr = sock.recvfrom(512)
        # handle each query in its own thread so one slow upstream lookup
        # doesn't block other clients
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()


if __name__ == "__main__":
    start_server()