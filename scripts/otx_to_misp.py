#!/usr/bin/env python3
import os
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================================
# CONFIG
# ================================
OTX_API_KEY = os.environ["OTX_API_KEY"]
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

MISP_URL = "https://localhost"
MISP_API_KEY = os.environ["MISP_API_KEY"]

# Map OTX indicator types -> MISP attribute types
TYPE_MAP = {
    "IPv4": "ip-dst",
    "IPv6": "ip-dst",
    "domain": "domain",
    "hostname": "hostname",
    "URL": "url",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
    "email": "email-src",
    "CVE": "vulnerability",
}

def get_otx_pulses(limit=5):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(OTX_URL, headers=headers, params={"limit": limit}, verify=False)
    print("OTX pulses fetch:", r.status_code)
    if r.status_code != 200:
        return []
    return r.json().get("results", [])

def create_misp_event(pulse):
    headers = {"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"}
    payload = {"Event": {
        "info": f"OTX Pulse - {pulse.get('name', 'Unnamed')}",
        "distribution": "0", "threat_level_id": "2", "analysis": "1",
    }}
    r = requests.post(f"{MISP_URL}/events/add", headers=headers, json=payload, verify=False)
    print("MISP event created:", r.status_code, r.text[:200])
    if r.status_code not in [200, 201]:
        return None
    return r.json()["Event"]["id"]

def add_misp_attribute(event_id, attr_type, value, comment):
    headers = {"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"}
    payload = {"Attribute": {
        "event_id": event_id, "category": "External analysis", "type": attr_type,
        "value": value, "comment": comment, "to_ids": True, "distribution": "0",
    }}
    r = requests.post(f"{MISP_URL}/attributes/add/{event_id}", headers=headers, json=payload, verify=False)
    print(f"MISP attribute {value}:", r.status_code)

def main():
    print("Starting OTX -> MISP sync...")
    pulses = get_otx_pulses(limit=5)
    print(f"Fetched {len(pulses)} pulses")
    for pulse in pulses:
        event_id = create_misp_event(pulse)
        if not event_id:
            continue
        for ind in pulse.get("indicators", []):
            misp_type = TYPE_MAP.get(ind.get("type"))
            if not misp_type:
                continue
            add_misp_attribute(event_id, misp_type, ind.get("indicator"), f"OTX indicator type: {ind.get('type')}")
    print("OTX -> MISP sync completed.")

if __name__ == "__main__":
    main()
