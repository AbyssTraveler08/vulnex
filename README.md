# VULNEX — Vulnerability Assessment & Reporting

VULNEX is a Python-based vulnerability assessment and reporting project. This repository snapshot includes the Phase 9 Windows agent/detection fixes and the project modules supplied in the accompanying ZIP.

## Repository contents

- `app.py` — application entry point / interface
- `scanner.py`, `nmap_locator.py` — scanning workflow and Nmap discovery
- `agent/` — endpoint agent and collector
- `agent_server.py` — agent communication/server component
- `collectors/` — host/system data collection
- `discovery/` — network discovery
- `auth_manager.py`, `security_store.py` — authentication and security storage
- `cve_fetcher.py`, `risk_engine.py`, `remediation_engine.py` — vulnerability context, risk scoring, and remediation logic
- `report_generator.py` — report generation
- `models/`, `storage/` — data models and persistence helpers
- `tests/` — automated tests
- `docs/` — complete project documentation PDF

## Requirements

- Python 3.10+ recommended (use the version supported by your dependencies)
- Nmap installed and available on `PATH` for network scanning
- Windows or another supported host for the agent, depending on the specific collector features

## Setup

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

If the agent has separate dependencies, install them from its directory:

```bash
pip install -r agent/requirements.txt
```

Use the exact launch mode described in the relevant phase README if the application or agent is intended to run as a separate service. The appropriate launch command can vary by platform and configuration.

## Testing

Run the available tests from the repository root:

```bash
python -m pytest -q
```

## Security and responsible use

- Scan only systems and networks for which you have explicit authorization.
- Never commit API keys, passwords, tokens, private certificates, or real scan output containing sensitive data.
- Review configuration and access controls before exposing any service to a network.
- Run agents with the least privileges necessary; elevate privileges only when a documented scan feature requires them.
- Treat generated reports and collected endpoint data as potentially sensitive.

## Documentation

See [`docs/Vulnex_Complete_Project_Documentation.pdf`](docs/Vulnex_Complete_Project_Documentation.pdf) for the full project documentation. Additional phase-specific notes are included as `README_*.md` files.

## Disclaimer

This project is provided for authorized security assessment, defensive testing, and educational use. The operator is responsible for obtaining permission and complying with applicable laws and policies.
