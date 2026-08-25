"""
Module 4 - Configuration
=========================
All tunables live here so the team can adjust thresholds/weights without
touching scoring logic. Values are placeholders — tune against real
train/test data once Person 2 (DGA) and Person 3 (Intel) are wired in.
"""

# ---- Composite risk weights (must sum to 1.0) ----
WEIGHT_DGA = 0.5          # w1 - from Person 2's ML classifier
WEIGHT_TUNNELING = 0.4    # w2 - computed locally in this module
WEIGHT_REPUTATION = 0.1   # w3 - lightweight heuristic, computed locally

# ---- Verdict threshold ----
# NOTE: this must be calibrated against the weights above. With
# WEIGHT_DGA=0.5, a domain the DGA model is 100% sure about only
# contributes 0.5 to composite_risk on its own — so a threshold above
# 0.5 means DGA alone can never trigger BLOCK, no matter how confident
# the classifier is. Re-tune this (and the weights) once you have real
# train/test data; 0.45 is a placeholder that lets a single strong
# signal dominate while still allowing weaker combined signals to add up.
BLOCK_THRESHOLD = 0.30

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
