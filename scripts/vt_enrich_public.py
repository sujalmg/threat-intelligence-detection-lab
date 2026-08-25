#!/usr/bin/env python3
import os
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================================
# CONFIG
# ================================
VT_API_KEY = os.environ["VT_API_KEY"]
FILE_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

MISP_URL = "https://localhost"
MISP_API_KEY = os.environ["MISP_API_KEY"]

def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    print("VirusTotal lookup:", r.status_code)
    if r.status_code != 200:
        print(r.text[:300])
        return None
    data = r.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    return stats

def find_test_event():
    headers = {"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"}
    payload = {"value": "Threat Detection Lab - Suspicious File Test", "searchall": True}
    r = requests.post(f"{MISP_URL}/events/restSearch", headers=headers, json=payload, verify=False)
    print("MISP event search:", r.status_code)
    if r.status_code != 200:
        return None
    results = r.json().get("response", [])
    if not results:
        return None
    return results[0]["Event"]["id"]

def add_enrichment_attribute(event_id, stats):
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    headers = {"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"}

    # Add the hash itself as an attribute
    payload_hash = {"Attribute": {
        "event_id": event_id, "category": "Payload delivery", "type": "sha256",
        "value": FILE_HASH, "comment": "EICAR test-file SHA256 - VirusTotal verified",
        "to_ids": True, "distribution": "0",
    }}
    r1 = requests.post(f"{MISP_URL}/attributes/add/{event_id}", headers=headers, json=payload_hash, verify=False)
    print("Hash attribute added:", r1.status_code)

    # Add the VirusTotal verdict as a comment attribute
    payload_comment = {"Attribute": {
        "event_id": event_id, "category": "External analysis", "type": "text",
        "value": f"VirusTotal: {malicious}/{total} vendors flagged this file as malicious",
        "comment": "Automated VirusTotal enrichment",
        "to_ids": False, "distribution": "0",
    }}
    r2 = requests.post(f"{MISP_URL}/attributes/add/{event_id}", headers=headers, json=payload_comment, verify=False)
    print("VT verdict attribute added:", r2.status_code)

def main():
    print("Starting VirusTotal enrichment...")
    stats = check_virustotal(FILE_HASH)
    if not stats:
        print("Could not retrieve VirusTotal results.")
        return
    print("VirusTotal stats:", stats)

    event_id = find_test_event()
    if not event_id:
        print("Could not find the Threat Detection Lab test even in MISP.")
        return
    print(f"Found event ID: {event_id}")

    add_enrichment_attribute(event_id, stats)
    print("Enrichment completed.")

if __name__ == "__main__":
    main()
