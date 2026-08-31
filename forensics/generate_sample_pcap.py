"""
Run once to generate sample_data/sample.pcap for local testing.
    python generate_sample_pcap.py
"""

from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

domains = [
    "google.com",
    "malicious-c2.com",
    "qxz78m4vplo9.top",
    "mail.yahoo.com",
]

packets = []
for i, d in enumerate(domains):
    pkt = (
        Ether()
        / IP(src=f"192.168.1.{10 + i}", dst="8.8.8.8")
        / UDP(sport=50000 + i, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=d))
    )
    packets.append(pkt)

wrpcap("sample_data/sample.pcap", packets)
print(f"Wrote {len(packets)} packets to sample_data/sample.pcap")
