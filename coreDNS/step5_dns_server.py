"""
STEP 5: The complete Module 1 — Core DNS Resolver

Flow (matches the doc's contract exactly):
  1. Listen on UDP port 53 for incoming raw DNS packets
  2. Extract the domain name
  3. Call the scoring engine (Module 4) with the domain
  4. If verdict == BLOCK -> return 0.0.0.0 (sinkhole)
     If verdict == ALLOW -> forward to real upstream DNS and relay real IP
"""

import socket
import threading
from dnslib import DNSRecord

from step3_scoring_client import get_verdict
from step4_response_builder import build_sinkhole_response, resolve_upstream

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5053   # use 5053 for local testing (53 needs root/admin privileges)


def handle_query(data: bytes, addr, sock: socket.socket):
    try:
        request = DNSRecord.parse(data)
        domain = str(request.q.qname).rstrip(".")
        qtype_code = request.q.qtype

        verdict = get_verdict(domain, qtype_code)
        print(f"[QUERY] {addr[0]} asked for {domain} -> {verdict['verdict']} ({verdict['reason']})")

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