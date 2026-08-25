#!/usr/bin/python3

import requests
import urllib3
from datetime import date
import datetime
import logging
import argparse
import ipaddress
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =========================
# LOGGING
# =========================

LOG_FILE = "/opt/splunk/var/log/splunk/cti_response.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


def log_info(message):
    print(message)
    logging.info(message)


def log_error(message):
    print(message)
    logging.error(message)


# =========================
# SECRET MANAGEMENT
# =========================

def load_secrets(path):
    secrets = {}

    with open(path, "r", encoding="utf-8") as secret_file:
        for raw_line in secret_file:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            key, separator, value = line.partition("=")

            if not separator or not key.strip() or not value.strip():
                raise RuntimeError("Invalid entry in CTI secrets file")

            secrets[key.strip()] = value.strip()

    required_keys = {
        "MISP_API_KEY",
        "THEHIVE_API_KEY"
    }

    missing_keys = required_keys - secrets.keys()

    if missing_keys:
        raise RuntimeError(
            f"Missing required secrets: {', '.join(sorted(missing_keys))}"
        )

    return secrets


SECRETS = load_secrets("/opt/splunk/etc/cti_secrets.conf")


# =========================
# CONFIG
# =========================

MISP_URL = "https://misp.local"
MISP_API_KEY = SECRETS["MISP_API_KEY"]

THEHIVE_URL = "https://192.168.95.132"
THEHIVE_CA_CERT = "/opt/splunk/etc/certs/thehive.crt"
THEHIVE_API_KEY = SECRETS["THEHIVE_API_KEY"]

# Neutral defaults used for manual testing.
# Splunk supplies these values dynamically during automated execution.
ALERT_NAME = "Threat Detection Lab - Suspicious File Activity"
SOURCE_IP = "192.168.95.134"
DESTINATION_IP = "192.168.95.135"
DETECTED_URL = "http://192.168.95.135:8080/test-file.txt"
FILENAME = "test-file.txt"
PORT = "8080"


# =========================
# ARGUMENTS
# =========================

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Threat Detection Lab automated CTI response workflow"
    )

    parser.add_argument(
        "--alert-name",
        default=ALERT_NAME
    )

    parser.add_argument(
        "--source-ip",
        default=SOURCE_IP
    )

    parser.add_argument(
        "--destination-ip",
        default=DESTINATION_IP
    )

    parser.add_argument(
        "--port",
        default=PORT
    )

    parser.add_argument(
        "--url",
        default=DETECTED_URL
    )

    parser.add_argument(
        "--filename",
        default=FILENAME
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs without contacting MISP or TheHive"
    )

    return parser.parse_args()


# =========================
# INPUT VALIDATION
# =========================

def validate_inputs():
    errors = []

    for label, value in (
        ("source IP", SOURCE_IP),
        ("destination IP", DESTINATION_IP),
    ):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            errors.append(f"Invalid {label}: {value}")

    try:
        port_number = int(PORT)

        if not 1 <= port_number <= 65535:
            raise ValueError

    except ValueError:
        errors.append(f"Invalid port: {PORT}")

    parsed_url = urlparse(DETECTED_URL)

    if (
        parsed_url.scheme not in ("http", "https")
        or not parsed_url.hostname
    ):
        errors.append(f"Invalid URL: {DETECTED_URL}")

    if not ALERT_NAME.strip():
        errors.append("Alert name cannot be empty")

    if (
        not FILENAME.strip()
        or "/" in FILENAME
        or "\\" in FILENAME
    ):
        errors.append(f"Invalid filename: {FILENAME}")

    if errors:
        raise ValueError("; ".join(errors))


# =========================
# MISP
# =========================

def find_existing_event():
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "value": f"{ALERT_NAME} - Automated Splunk Detection",
        "searchall": True
    }

    response = requests.post(
        f"{MISP_URL}/events/restSearch",
        headers=headers,
        json=payload,
        verify=False,
        timeout=30
    )

    print(
        "MISP existing-event search:",
        response.status_code
    )

    if response.status_code != 200:
        return None

    results = response.json().get("response", [])

    if not results:
        return None

    return results[0]["Event"]["id"]


def create_misp_event():
    existing_id = find_existing_event()

    if existing_id:
        print(
            f"Existing event found, reusing ID {existing_id}"
        )

        add_misp_attribute(
            existing_id,
            "Other",
            "text",
            f"Re-detected at {datetime.datetime.now().isoformat()}",
            "Additional automated detection occurrence"
        )

        return existing_id

    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "Event": {
            "info": (
                f"{ALERT_NAME} - Automated Splunk Detection"
            ),
            "date": str(date.today()),
            "threat_level_id": "2",
            "analysis": "1",
            "distribution": "0"
        }
    }

    response = requests.post(
        f"{MISP_URL}/events/add",
        headers=headers,
        json=payload,
        verify=False,
        timeout=30
    )

    print(
        "MISP event:",
        response.status_code,
        response.text
    )

    if response.status_code not in [200, 201]:
        return None

    return response.json()["Event"]["id"]


def add_misp_attribute(
    event_id,
    category,
    attr_type,
    value,
    comment
):
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "Attribute": {
            "event_id": event_id,
            "category": category,
            "type": attr_type,
            "value": value,
            "comment": comment,
            "to_ids": False,
            "distribution": "0"
        }
    }

    response = requests.post(
        f"{MISP_URL}/attributes/add/{event_id}",
        headers=headers,
        json=payload,
        verify=False,
        timeout=30
    )

    print(
        f"MISP attribute {value}:",
        response.status_code,
        response.text
    )


# =========================
# THEHIVE
# =========================

def create_thehive_case():
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "title": (
            f"{ALERT_NAME} - Automated Splunk Alert"
        ),
        "description": (
            f"Splunk detected activity associated with "
            f"{ALERT_NAME}. "
            f"Source {SOURCE_IP} communicated with "
            f"destination {DESTINATION_IP} on port {PORT}. "
            f"The detected URL was {DETECTED_URL}, and the "
            f"associated filename was {FILENAME}. "
            f"Indicators were sent to MISP, and this case "
            f"was created for analyst investigation."
        ),
        "severity": 2,
        "tlp": 2,
        "pap": 2,
        "tags": [
            "splunk",
            "misp",
            "cti",
            "automated-alert",
            "threat-detection-lab"
        ]
    }

    response = requests.post(
        f"{THEHIVE_URL}/api/case",
        headers=headers,
        json=payload,
        verify=THEHIVE_CA_CERT,
        timeout=30
    )

    print(
        "TheHive case:",
        response.status_code,
        response.text
    )

    if response.status_code not in [200, 201]:
        return None

    return response.json()["_id"]


def add_thehive_observable(
    case_id,
    data_type,
    data,
    message
):
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "dataType": data_type,
        "data": data,
        "message": message,
        "tlp": 2,
        "pap": 2,
        "tags": [
            "automated-from-splunk"
        ]
    }

    response = requests.post(
        f"{THEHIVE_URL}/api/case/{case_id}/artifact",
        headers=headers,
        json=payload,
        verify=THEHIVE_CA_CERT,
        timeout=30
    )

    print(
        f"TheHive observable {data}:",
        response.status_code,
        response.text
    )


# =========================
# MAIN WORKFLOW
# =========================

def main():
    global ALERT_NAME
    global SOURCE_IP
    global DESTINATION_IP
    global PORT
    global DETECTED_URL
    global FILENAME

    args = parse_arguments()

    ALERT_NAME = args.alert_name
    SOURCE_IP = args.source_ip
    DESTINATION_IP = args.destination_ip
    PORT = str(args.port)
    DETECTED_URL = args.url
    FILENAME = args.filename

    try:
        validate_inputs()

    except ValueError as error:
        log_error(
            f"Input validation failed: {error}"
        )
        return 2

    log_info(
        f"CTI workflow started: alert={ALERT_NAME}"
    )

    log_info(
        f"Indicators received: "
        f"source={SOURCE_IP}, "
        f"destination={DESTINATION_IP}, "
        f"port={PORT}, "
        f"url={DETECTED_URL}, "
        f"filename={FILENAME}"
    )

    if args.dry_run:
        log_info(
            "Dry-run validation completed; "
            "no MISP or TheHive API calls were made"
        )
        return 0

    # -------------------------
    # MISP RESPONSE
    # -------------------------

    event_id = create_misp_event()

    if event_id:
        add_misp_attribute(
            event_id,
            "Network activity",
            "ip-src",
            SOURCE_IP,
            "Source IP detected by Splunk"
        )

        add_misp_attribute(
            event_id,
            "Network activity",
            "ip-dst",
            DESTINATION_IP,
            "Destination IP detected by Splunk"
        )

        add_misp_attribute(
            event_id,
            "Network activity",
            "url",
            DETECTED_URL,
            f"URL associated with {ALERT_NAME}"
        )

        add_misp_attribute(
            event_id,
            "Payload delivery",
            "filename",
            FILENAME,
            f"Filename associated with {ALERT_NAME}"
        )

        add_misp_attribute(
            event_id,
            "Network activity",
            "port",
            PORT,
            "Destination port detected by Splunk"
        )

    # -------------------------
    # THEHIVE RESPONSE
    # -------------------------

    case_id = create_thehive_case()

    if case_id:
        add_thehive_observable(
            case_id,
            "ip",
            SOURCE_IP,
            "Detected source IP"
        )

        add_thehive_observable(
            case_id,
            "ip",
            DESTINATION_IP,
            "Detected destination IP"
        )

        add_thehive_observable(
            case_id,
            "url",
            DETECTED_URL,
            f"URL associated with {ALERT_NAME}"
        )

        add_thehive_observable(
            case_id,
            "filename",
            FILENAME,
            f"Filename associated with {ALERT_NAME}"
        )

        add_thehive_observable(
            case_id,
            "other",
            f"TCP/{PORT}",
            "Detected network port"
        )

    log_info(
        "CTI workflow completed successfully"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
