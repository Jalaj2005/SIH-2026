"""
Quick local test - no server needed.
    python test_local.py
"""

import json

from parser import parse_file
from detector import analyze

TEST_FILES = ["sample_data/sample_dns.log", "sample_data/sample.pcap"]

for path in TEST_FILES:
    print(f"\n=== Testing {path} ===")
    try:
        records = parse_file(path)
        print(f"Parsed {len(records)} DNS queries")
        compromises = analyze(records)
        print(f"Found {len(compromises)} compromises:")
        print(json.dumps(compromises, indent=2))
    except FileNotFoundError:
        print(f"File not found - run generate_sample_pcap.py first if testing the .pcap file")
    except Exception as e:
        print(f"Error: {e}")
