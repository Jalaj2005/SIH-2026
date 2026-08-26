"""
STEP 2: Understand & parse an incoming raw DNS packet.
This is the foundation — before we can build a server, we need to
know how to pull the domain name out of the bytes a client sends us.
"""

from dnslib import DNSRecord

def extract_domain_from_packet(data: bytes) -> str:
    """
    Input:  raw DNS packet bytes (what arrives on UDP port 53)
    Output: the domain name being queried, e.g. "example.com"
    """
    request = DNSRecord.parse(data)
    qname = str(request.q.qname)          # e.g. "example.com."
    domain = qname.rstrip(".")            # strip trailing dot
    qtype = request.q.qtype               # 1=A, 16=TXT, etc.
    return domain, qtype, request


if __name__ == "__main__":
    # quick self-test: build a fake query and parse it back
    test_query = DNSRecord.question("x89vf2qlmn3.top")
    domain, qtype, parsed = extract_domain_from_packet(test_query.pack())
    print("Extracted domain:", domain)
    print("Query type code:", qtype)