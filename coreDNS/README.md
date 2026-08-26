# Module 1: Core DNS Resolver (Person 1)

## Files (build/read in this order)
1. `step2_packet_parser.py` — parses raw DNS packet bytes, extracts the domain name
2. `step3_scoring_client.py` — calls Module 4 (scoring engine); includes a MOCK
   so you can develop without waiting on Person 4 to finish
3. `step4_response_builder.py` — builds the sinkhole (0.0.0.0) response, or
   forwards clean queries to a real upstream DNS server (8.8.8.8)
4. `step5_dns_server.py` — the actual server: listens on UDP, ties steps 2-4 together

## Run it
```bash
pip install dnslib requests
python3 step5_dns_server.py
```
Runs on port 5053 by default (use port 53 + sudo/admin for production, since ports <1024 need root).

## Test it
```python
from dnslib import DNSRecord
import socket

q = DNSRecord.question("x89vf2qlmn3.top")   # DGA-looking name -> gets sinkholed
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(q.pack(), ("127.0.0.1", 5053))
print(DNSRecord.parse(s.recvfrom(512)[0]))
```

## Wiring to the real Module 4
In `step3_scoring_client.py`:
- Set `USE_MOCK = False`
- Set `SCORING_ENGINE_URL` to Person 4's real endpoint

That's the only change needed — everything else stays the same, because of the
input/output contract defined in the spec.

## Contract this module fulfills
- **Input:** raw DNS packet on UDP port 53
- **Calls:** sends extracted domain to the scoring engine
- **Output:** real IP (ALLOW) or 0.0.0.0 sinkhole (BLOCK)

## Next steps for production
- Add a DoH (DNS-over-HTTPS) listener on port 443 (mentioned in the spec)
- Add a caching layer for repeated queries
- Add logging so results feed into Module 6 (SOC dashboard)
