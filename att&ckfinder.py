import stix2
import requests

# MITRE ATT&CK Enterprise STIX

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Def - MITRE data

def load_attack_data():
    print("Fetching ATT&CK dataset...")
    response = requests.get(MITRE_URL)
    response.raise_for_status()
    data = stix2.MemoryStore(stix_data=response.json()["objects"])
    return data

def search_techniques(data, keyword):
    keyword = keyword.lower()
    results = []

    for obj in data.query([stix2.Filter("type", "=", "attack-pattern")]):
        name = obj.get("name", "")
        desc = obj.get("description", "")

        if keyword in name.lower() or keyword in desc.lower():
            results.append({
                "id": obj.external_references[0]["external_id"],
                "name": name,
                "description": desc.split("\n")[0] if desc else ""
            })
    return results

# Search

if __name__ == "__main__":
    attack_data = load_attack_data()
    while True:
        keyword = input("\nEnter a behavior/tool to map (or 'exit'): ").strip()
        if keyword.lower() == "exit":
            break

        matches = search_techniques(attack_data, keyword)
        if not matches:
            print("No matches found.")
        else:
            for match in matches:
                print(f"\n• [{match['id']}] {match['name']}\n  ↳ {match['description']}")

