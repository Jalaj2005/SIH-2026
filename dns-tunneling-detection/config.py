"""
Module 4 - Configuration
=========================
All tunables live here so the team can adjust thresholds/weights without
touching scoring logic. Values are placeholders — tune against real
train/test data once Person 2 (DGA) and Person 3 (Intel) are wired in.
"""


# ---- Tunneling sub-score weights (these four combine into Tunneling_Score) ----
TUNNEL_ENTROPY_WEIGHT = 0.40
TUNNEL_LENGTH_WEIGHT = 0.25
TUNNEL_QTYPE_WEIGHT = 0.15
TUNNEL_BURST_WEIGHT = 0.20

# Subdomain length (chars) considered fully suspicious (score saturates at 1.0)
TUNNEL_LENGTH_SATURATION = 50
# Length below which a subdomain is considered totally normal (score 0.0)
TUNNEL_LENGTH_FLOOR = 15

# Query types attackers favor for tunneling payload exfil/return channels
SUSPICIOUS_QUERY_TYPES = {"TXT": 0.6, "NULL": 1.0, "CNAME": 0.2}

# Burst detection: N unique subdomains from the same client+root domain
# within WINDOW_SECONDS triggers max burst score
BURST_WINDOW_SECONDS = 30
BURST_UNIQUE_SUBDOMAIN_THRESHOLD = 15

# Simple TLD risk table for the placeholder reputation score.
# Real reputation (domain age, WHOIS, historical patterns) is out of scope
# for Module 4 unless the team assigns it here explicitly.
HIGH_RISK_TLDS = {"top", "xyz", "click", "gq", "tk", "ml", "cf", "info"}
REPUTATION_HIGH_RISK_SCORE = 0.6
REPUTATION_DEFAULT_SCORE = 0.1
