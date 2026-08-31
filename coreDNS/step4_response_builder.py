"""
STEP 4: Build the actual DNS response packet.

Contract: Output = real IP address OR 0.0.0.0 (sinkhole) back to the client.

If verdict == BLOCK -> reply with 0.0.0.0 (sinkhole)
If verdict == ALLOW -> forward the query upstream (e.g. 8.8.8.8) and relay the real answer
"""

from dnslib import DNSRecord, RR, QTYPE, A
import socket

UPSTREAM_DNS = "8.8.8.8"   # real resolver we forward clean queries to
SINKHOLE_IP = "0.0.0.0"


def build_sinkhole_response(request: DNSRecord) -> bytes:
    """Return a forged A record pointing to 0.0.0.0."""
    reply = request.reply()
    reply.add_answer(RR(
        rname=request.q.qname,
        rtype=QTYPE.A,
        rdata=A(SINKHOLE_IP),
        ttl=60
    ))
    return reply.pack()


def resolve_upstream(request: DNSRecord, raw_query: bytes) -> bytes:
    """Forward the query to a real upstream DNS server and return its raw answer."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        s.sendto(raw_query, (UPSTREAM_DNS, 53))
        response_bytes, _ = s.recvfrom(512)
    return response_bytes


if __name__ == "__main__":
    q = DNSRecord.question("x89vf2qlmn3.top")
    sink = build_sinkhole_response(DNSRecord.parse(q.pack()))
    print("Sinkhole response:")
    print(DNSRecord.parse(sink))