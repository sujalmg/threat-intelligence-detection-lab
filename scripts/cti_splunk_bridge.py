#!/usr/bin/python3

import csv
import gzip
import os
import subprocess
import sys
from datetime import datetime

RESULT_SCRIPT = "/opt/splunk/bin/scripts/cti_response.py"
LOG_FILE = "/opt/splunk/var/log/splunk/cti_bridge.log"


def write_log(level, message):
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(f"{datetime.now().isoformat()} | {level} | {message}\n")

def main():
    results_file = os.environ.get("SPLUNK_ARG_8")

    if not results_file:
        for argument in reversed(sys.argv[1:]):
            if argument.endswith("results.csv.gz"):
                results_file = argument
                break

    if not results_file:
        write_log("ERROR", "No Splunk results file was received")
        return 2

    try:

        with gzip.open(
            results_file,
            "rt",
            encoding="utf-8-sig",
            newline=""
        ) as handle:
            reader = csv.DictReader(handle)
            row = next(reader, None)
    except Exception as error:
        write_log(
            "ERROR",
            f"Could not read results file: {type(error).__name__}: {error}"
        )
        return 1

    if not row:
        write_log("ERROR", "Splunk results file contained no rows")
        return 2

    required_fields = [
        "alert_name",
        "source_ip",
        "destination_ip",
        "destination_port",
        "url",
        "filename",
    ]

    missing = [
        field for field in required_fields
        if not row.get(field, "").strip()
    ]

    if missing:
        write_log(
            "ERROR",
            "Missing required fields: " + ", ".join(missing)
        )
        return 2

    command = [
        "/usr/bin/python3",
        RESULT_SCRIPT,
        "--alert-name", row["alert_name"],
        "--source-ip", row["source_ip"],
        "--destination-ip", row["destination_ip"],
        "--port", row["destination_port"],
        "--url", row["url"],
        "--filename", row["filename"],
    ]

    write_log(
        "INFO",
        (
            f"Launching CTI response: alert={row['alert_name']}, "
            f"source={row['source_ip']}, "
            f"destination={row['destination_ip']}, "
            f"port={row['destination_port']}, "
            f"filename={row['filename']}"
        )
    )

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )
    except Exception as error:
        write_log(
            "ERROR",
            f"CTI response launch failed: {type(error).__name__}: {error}"
        )
        return 1

    write_log(
        "INFO" if result.returncode == 0 else "ERROR",
        f"CTI response completed with exit code {result.returncode}"
    )

    if result.stderr.strip():
        write_log("ERROR", result.stderr.strip()[-500:])

    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
