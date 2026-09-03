# Module 1: Core DNS Resolver

A lightweight, multi-threaded DNS resolver that serves as the entry point for DNS traffic. It inspects incoming raw DNS queries over UDP, coordinates with external scoring/threat-intelligence engines, sinkholes malicious domains to `0.0.0.0`, and forwards clean queries to an upstream resolver.

---

## Architecture & Data Flow

```
Client (UDP Query)
        │
        ▼
[step5_dns_server.py]
        │
        ├──> [step2_packet_parser.py] (Parses packet -> domain, qtype, client_ip)
        │
        ├──> [step3_scoring_client.py] (Calls microservices or mock)
        │       ├── Module 3 (Threat Intel Blacklist)
        │       ├── Module 2 (DGA Probability)
        │       ├── Module 4 (Tunneling Score)
        │       └── Composite Risk Aggregator
        │
        └──> [step4_response_builder.py]
                ├── BLOCK ──> Craft Sinkhole Response (0.0.0.0)
                └── ALLOW ──> Forward to Upstream (8.8.8.8)
                        │
                        ▼
                Client (DNS Response)
```

---

## File Structure

| File | Description |
| :--- | :--- |
| `step2_packet_parser.py` | Extracts query information (domain, query type code, and raw parsed object) from incoming wire-format DNS packets. |
| `step3_scoring_client.py` | Risk aggregator that coordinates calls to Modules 2, 3, and 4, computes composite risk, or runs a local mock test. |
| `step4_response_builder.py` | Constructs sinkhole responses (`0.0.0.0`) for blocked domains or resolves queries against an upstream DNS server. |
| `step5_dns_server.py` | Core server executable that binds to a UDP port, listens for queries, and assigns incoming packets to worker threads. |
| `cache.py` | Standalone thread-safe in-memory cache supporting TTL expiry, LRU eviction, and hit/miss metrics for DNS responses. |

---

## Requirements & Installation

Install dependencies:

```bash
pip install dnslib requests
```

---

## Configuration

All key configurations are located directly within their respective step files:

### Server Settings (`step5_dns_server.py`)

- `LISTEN_IP`: Default `0.0.0.0`
- `LISTEN_PORT`: Default `5053` for non-root testing (`53` requires root/admin privileges).

### Upstream & Sinkhole Settings (`step4_response_builder.py`)

- `UPSTREAM_DNS`: Default `8.8.8.8`
- `UPSTREAM_PORT`: Default `53`
- `SINKHOLE_IP`: Default `0.0.0.0` (returned for blocked queries)

### Risk Engine Integration (`step3_scoring_client.py`)

- `USE_MOCK`: Set to `True` for standalone testing without external microservices.
- `BLOCK_THRESHOLD`: Default `0.70`
- `WEIGHT_DGA`: Default `0.5`
- `WEIGHT_TUNNELING`: Default `0.5`
- Microservice URLs:
  - Intel API: `http://localhost:8003/check`
  - DGA API: `http://localhost:8000/predict`
  - Tunneling API: `http://localhost:8004/score`

---

## Running the Server

Start the core resolver:

```bash
python3 step5_dns_server.py
```

---

## Testing

Run the following script in a separate terminal or Python shell to send a DNS query:

```python
import socket
from dnslib import DNSRecord

# 1. Create a query
query = DNSRecord.question("x89vf2qlmn3.top")

# 2. Send over UDP to port 5053
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(query.pack(), ("127.0.0.1", 5053))

# 3. Receive and parse response
data, _ = sock.recvfrom(4096)
print(DNSRecord.parse(data))
```
