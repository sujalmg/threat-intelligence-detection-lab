# Automation Scripts

This directory contains the sanitized automation components used in the Threat-Intelligence-Driven Detection Lab.

## `cti_splunk_bridge.py`

Acts as the bridge between Splunk alert results and the CTI response workflow.

It:

- Reads Splunk `results.csv.gz` output
- Extracts required alert fields
- Validates that the required fields are present
- Launches `cti_response.py`
- Passes alert context such as source IP, destination IP, port, URL, and filename

## `cti_response.py`

Runs the main automated response workflow after receiving alert context from Splunk.

It:

- Validates incoming observables
- Searches MISP for an existing event
- Creates or updates a MISP event
- Adds relevant observables to MISP
- Creates an investigation case in TheHive
- Adds observables to the TheHive case
- Supports dry-run validation

API credentials are not hard-coded in the script.

## `otx_to_misp.py`

Imports threat-intelligence indicators from subscribed AlienVault OTX pulses into MISP.

Supported indicator types include:

- IPv4 / IPv6
- Domains
- Hostnames
- URLs
- MD5
- SHA-1
- SHA-256
- Email addresses
- CVEs

The OTX and MISP API keys are loaded from environment variables.

## `vt_enrich_public.py`

Performs VirusTotal enrichment for a file hash and adds the resulting context to a MISP event.

The public example uses the EICAR SHA-256 hash as a safe validation artifact.

VirusTotal and MISP API keys are loaded from environment variables.

## Secrets

Do not store real API keys, passwords, or tokens in this repository.

The scripts expect credentials to be provided through environment variables or a separate local secrets configuration.

Example:

```bash
export MISP_API_KEY="your_key"
export THEHIVE_API_KEY="your_key"
export OTX_API_KEY="your_key"
export VT_API_KEY="your_key"
