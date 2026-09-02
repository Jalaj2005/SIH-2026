"""
STEP 4: DNS Response Builder

Responsibilities:
- Build sinkhole responses for blocked domains
- Forward allowed queries to upstream DNS
- Return raw DNS response bytes
"""

import socket

from dnslib import (
    DNSRecord,
    RR,
    QTYPE,
    A
)


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_PORT = 53

SINKHOLE_IP = "0.0.0.0"


# ---------------------------------------------------------
# Sinkhole response
# ---------------------------------------------------------

def build_sinkhole_response(request: DNSRecord) -> bytes:
    """
    Create a DNS response pointing the queried domain
    to 0.0.0.0.

    Used when the security engine returns BLOCK.
    """

    reply = request.reply()

    reply.add_answer(
        RR(
            rname=request.q.qname,
            rtype=QTYPE.A,
            rdata=A(SINKHOLE_IP),
            ttl=60
        )
    )

    return reply.pack()


# ---------------------------------------------------------
# Upstream DNS resolution
# ---------------------------------------------------------

def resolve_upstream(
    request: DNSRecord,
    raw_query: bytes
) -> bytes:
    """
    Forward the original DNS request to the upstream
    resolver and return the raw DNS response.
    """

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    ) as sock:

        sock.settimeout(2)

        sock.sendto(
            raw_query,
            (
                UPSTREAM_DNS,
                UPSTREAM_PORT
            )
        )

        response_bytes, _ = sock.recvfrom(4096)

    return response_bytes


if __name__ == "__main__":

    query = DNSRecord.question(
        "example.com"
    )

    response = resolve_upstream(
        query,
        query.pack()
    )

    print(
        DNSRecord.parse(response)
    )