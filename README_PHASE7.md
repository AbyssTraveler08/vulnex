# Vulnex Phase 7 — Risk & Vulnerability Management

This release keeps the existing Vulnex network discovery, 1–65,535 TCP-port Nmap assessment,
NSE vulnerability checks, CVE/KEV correlation, endpoint agents, local inventory and PDF reporting.

## Added
- Explainable 0–100 vulnerability risk score using CVSS, exploitability, CISA KEV,
  exposed-service context and configurable asset criticality.
- Critical/High/Medium/Low risk levels.
- Global vulnerability dashboard and asset risk view.
- Remediation lifecycle: Open, Acknowledged, In Progress, Resolved, Accepted Risk.
- Persistent scan history with new/resolved CVE comparison and before/after risk changes.
- Executive risk report PDF.
- Endpoint posture and available-update visibility when supported by the OS.
- API request validation, expiring enrollment tokens and audit logging.
- Safer bounded telemetry payload handling.

## Risk model
The score is an explainable prioritization aid, not a guarantee of exploitability.
CVSS contributes up to 55 points, exploitability up to 15, KEV 20, exposed-service
context 5, and asset criticality 5. Asset-level risk additionally considers open-port
exposure and incomplete endpoint inventory.

## Run
```bash
python3 -m streamlit run app.py
```

Use only against systems and networks you own or are authorized to administer.
