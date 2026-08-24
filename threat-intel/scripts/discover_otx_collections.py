"""
Helper script to discover MITRE ATT&CK TAXII 2.1 collection IDs.
"""
from taxii2client.v21 import Server

def main() -> None:
    # The modern MITRE TAXII 2.1 discovery URL
    taxii_url = "https://attack-taxii.mitre.org/taxii2/"
    
    print(f"Connecting to {taxii_url}...\n")
    
    # No auth required for MITRE!
    server = Server(taxii_url)

    print("--- Available Collections ---")
    for api_root in server.api_roots:
        for collection in api_root.collections:
            print(f"id:    {collection.id}")
            print(f"title: {collection.title}")
            print("-" * 40)

if __name__ == "__main__":
    main()