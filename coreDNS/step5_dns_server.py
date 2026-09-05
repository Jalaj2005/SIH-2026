import socket
import threading
import time
import requests
from step2_packet_parser import extract_domain_from_packet
from step3_scoring_client import get_verdict, QTYPE_NAMES
from step4_response_builder import build_sinkhole_response, resolve_upstream

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5053   # Port 5053 avoids requiring root/admin privileges
DASHBOARD_INGEST_URL = "http://localhost:4000/api/ingest"

def notify_dashboard(client_ip, domain, qtype_name, verdict, duration_ms):
    """Sends telemetry asynchronously to Module 6."""
    payload = {
        "client_ip": client_ip,
        "domain": domain,
        "query_type": qtype_name,
        "verdict": verdict["verdict"],
        "reason": verdict["reason"],
        "composite_risk": verdict.get("composite_risk", 0.0),
        "is_blacklisted": "Intel Match" in verdict["reason"],
        "response_time_ms": round(duration_ms, 2)
    }
    try:
        requests.post(DASHBOARD_INGEST_URL, json=payload, timeout=0.2)
    except Exception:
        pass  # Do not block DNS resolution if dashboard gateway is offline

def handle_query(data: bytes, addr, sock: socket.socket):
    start_time = time.time()
    try:
        domain, qtype_code, request = extract_domain_from_packet(data)
        client_ip = addr[0]
        qtype_name = QTYPE_NAMES.get(qtype_code, "A")

        verdict = get_verdict(domain, qtype_code, client_ip)
        duration_ms = (time.time() - start_time) * 1000

        print(f"[QUERY] {client_ip} asked for {domain} -> {verdict['verdict']} ({verdict['reason']})")

        # Emit telemetry to Module 6
        threading.Thread(
            target=notify_dashboard, 
            args=(client_ip, domain, qtype_name, verdict, duration_ms), 
            daemon=True
        ).start()

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
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()

if __name__ == "__main__":
    start_server()