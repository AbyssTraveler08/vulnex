# Vulnex 2.0 — Phase 1

Phase 1 changes Vulnex from a single-target scanner into a network asset discovery workflow.

## Current flow

1. Detect the active local IPv4 network.
2. Discover live devices using Nmap host discovery.
3. Show IP, MAC, hostname, vendor and device type in Streamlit.
4. Select a device.
5. Run a per-device Nmap assessment.
6. Reuse the existing CVE/risk/remediation pipeline.
7. Generate one PDF per device.
8. Download that PDF from Streamlit.

## Run

`app.py` checks `requirements.txt` **before importing the application**. If a
Python dependency is missing, it installs the requirements automatically using
the same Python interpreter that launched Vulnex.

Recommended:

```bash
python3 app.py
```

Vulnex will check/install the Python dependencies and then launch Streamlit.

You can also launch it directly with:

```bash
python3 -m streamlit run app.py
```

**Nmap is a system program, not a Python package**, so it must be installed
separately and available in `PATH`. Vulnex reports a clear error if Nmap is
missing.

The bootstrap checks imports first, so it does not run `pip install` on every
Streamlit rerun once the dependencies are present.

On Linux/macOS, Nmap may require elevated privileges for some discovery/fingerprinting operations.

## Scope

The Phase 1 discovery path intentionally restricts automatic discovery to private,
loopback or link-local networks. Only assess networks/devices you own or have
explicit authorization to test.

## Next phases

- Hardware collector
- OS/package/software inventory
- Endpoint agent for deep host inventory
- Security configuration checks
- Persistent database
- Historical scan/change detection
- Network topology
- Per-device risk scoring
- Compliance checks


## Nmap Assessment Scope

The per-device assessment scans the complete TCP port range **1-65535** (`-p-`) rather than Nmap's default top 1000 ports. It also runs Nmap's `vuln` NSE script category and full service/version probing. Extended mode adds OS fingerprinting when the required privileges are available.

Because a full-port NSE assessment is substantially more expensive than a top-port scan, Vulnex allows a longer per-device timeout. Use this only against systems you are authorized to assess.

## Phase 6 Dashboard

The Streamlit interface is organized as a landing page with four primary areas:

1. **Network Discovery** — start discovery, select a device, scan all TCP ports, review services/NSE findings, CVEs and remediation guidance.
2. **Endpoint Agents** — generate direct-run Windows/macOS/Linux agents, list registered endpoints, inspect full endpoint inventory and download full device reports.
3. **Local Endpoint Inventory** — collect and review the local machine's hardware, OS, software, network, users and services.
4. **Developer Details** — project/developer information for Amar Kant Yadav and Team VORTEX.

The authorization warning and assessment guidance remain inside the sections where they are relevant.
