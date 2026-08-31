"""
Module 5 - Passive Forensics Engine
Parses .pcap files and Zeek dns.log (TSV) files into a normalized
list of DNS query records.

Each record has the shape:
{
    "src_ip": str,
    "domain": str,
    "timestamp": str,   # "YYYY-MM-DD HH:MM:SS" UTC
    "query_type": str,  # e.g. "A", "TXT", "AAAA"
}
"""

import csv
from datetime import datetime, timezone
from pathlib import Path


def parse_zeek_log(file_path: str) -> list[dict]:
    """Parses a Zeek dns.log (tab-separated, with #fields header)."""
    records = []
    with open(file_path, "r", newline="") as f:
        fields = []
        reader = csv.reader(f, delimiter="\t")
        for row in reader:
            if not row:
                continue
            if row[0].startswith("#fields"):
                fields = row[1:]
                continue
            if row[0].startswith("#"):
                continue  # skip other Zeek header/comment lines

            if not fields:
                # Fallback: standard Zeek dns.log column order
                fields = [
                    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
                    "id.resp_p", "proto", "trans_id", "rtt", "query",
                    "qclass", "qclass_name", "qtype", "qtype_name",
                    "rcode", "rcode_name", "AA", "TC", "RD", "RA", "Z",
                    "answers", "TTLs", "rejected",
                ]

            row_dict = dict(zip(fields, row))

            ts_raw = row_dict.get("ts", "")
            try:
                ts = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            domain = row_dict.get("query", "").strip()
            src_ip = row_dict.get("id.orig_h", "").strip()
            qtype = row_dict.get("qtype_name", "A").strip()

            if not domain or domain == "-":
                continue

            records.append({
                "src_ip": src_ip or "0.0.0.0",
                "domain": domain,
                "timestamp": ts,
                "query_type": qtype,
            })
    return records


def parse_pcap(file_path: str) -> list[dict]:
    """Parses a raw .pcap/.pcapng capture and extracts DNS query packets."""
    from scapy.all import rdpcap, DNS, DNSQR, IP

    records = []
    packets = rdpcap(file_path)
    qtype_map = {1: "A", 28: "AAAA", 16: "TXT", 5: "CNAME", 15: "MX", 2: "NS"}

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            try:
                domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except AttributeError:
                domain = str(pkt[DNSQR].qname).rstrip(".")

            src_ip = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
            qtype = qtype_map.get(pkt[DNSQR].qtype, str(pkt[DNSQR].qtype))
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            if domain:
                records.append({
                    "src_ip": src_ip,
                    "domain": domain,
                    "timestamp": ts,
                    "query_type": qtype,
                })
    return records


def parse_file(file_path: str) -> list[dict]:
    """Auto-detects file type by extension and parses accordingly."""
    suffix = Path(file_path).suffix.lower()
    if suffix in (".pcap", ".pcapng"):
        return parse_pcap(file_path)
    elif suffix in (".log", ".tsv", ".txt"):
        return parse_zeek_log(file_path)
    else:
        raise ValueError(f"Unsupported file type: {suffix}. Use .pcap/.pcapng or .log/.tsv")
