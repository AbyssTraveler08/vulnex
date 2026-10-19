# VULNEX
### Vulnerability Assessment, Endpoint Inventory & Security Reporting

VULNEX is a Python-based security assessment platform for authorized network discovery, endpoint inventory, vulnerability context, risk prioritization, remediation tracking, and report generation. The repository includes the Phase 9 Windows-agent/Python-detection fixes alongside the existing cross-platform agent and assessment workflows.

> **Authorized use only:** Run assessments only against systems and networks you own or have explicit permission to test.

## What VULNEX does

- **Network discovery and assessment** — integrates with Nmap to discover and assess reachable hosts.
- **Cross-platform endpoint inventory** — agent launchers support macOS, Linux, and Windows PowerShell.
- **Hardware and software inventory** — collects system identity, CPU/memory/disk information, network configuration, installed software, services, and local account metadata where supported.
- **Agent management** — registers endpoints, reports heartbeats, and supports persistent background operation and restart after reboot when installed using the platform's service/task mechanism.
- **Vulnerability context and risk** — combines CVE information and CISA Known Exploited Vulnerabilities (KEV) context with project risk-scoring logic.
- **Remediation tracking** — records remediation status and related assessment history.
- **Authentication and role-based access control** — user approval flow and separate administrator/user capabilities.
- **Reporting** — generates PDF assessment and device reports.
- **Local persistence and tests** — keeps application state under the local project data directories and includes automated tests.

## Project layout

| Path | Purpose |
| --- | --- |
| `app.py` | Application entry point and dashboard |
| `scanner.py`, `nmap_locator.py` | Scanning workflow and Nmap discovery |
| `discovery/` | Network discovery helpers |
| `agent/` | Endpoint agent and collector |
| `agent_server.py` | Agent communication/API component |
| `collectors/` | Host and system data collectors |
| `auth_manager.py`, `security_store.py` | Authentication and security-related persistence |
| `cve_fetcher.py`, `risk_engine.py` | Vulnerability context and risk scoring |
| `remediation_engine.py` | Remediation workflow |
| `report_generator.py` | PDF/report generation |
| `models/`, `storage/` | Data models and persistence helpers |
| `tests/` | Automated tests |
| `docs/` | Complete project documentation |
| `scans/` | Local scan data and reports (runtime data should not be committed) |

Phase-specific implementation notes are available in the `README_*.md` files, including `README_AGENT.md`, `README_PHASE8_AUTH_RBAC.md`, and `README_VENV_SETUP.md`.

## Requirements

- Python 3.10 or newer is recommended; use a version compatible with the installed dependencies.
- Nmap is required for network scanning and must be installed separately.
- Internet access is needed on first setup to install Python packages and when using features that retrieve external vulnerability information.

### Install Nmap

- **macOS (Homebrew):** `brew install nmap`
- **Debian/Ubuntu:** `sudo apt install nmap`
- **Windows:** install Nmap from [nmap.org/download.html](https://nmap.org/download.html) and ensure its installation directory is available on `PATH`.

## Quick start

Run these commands from the repository root.

### macOS / Linux

```bash
python3 app.py
```

### Windows PowerShell

```powershell
py -3 app.py
```

VULNEX's bootstrap is designed to create a project-local `.venv` when needed, install dependencies into it, and reuse it on subsequent launches. The first launch requires an internet connection. If automatic bootstrap is unavailable in your checkout, create and activate the environment manually:

**macOS / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

**Windows PowerShell**
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

The endpoint agent has a separate requirements file for workflows that need it:

```bash
python -m pip install -r agent/requirements.txt
```

## Endpoint agent

The project documents direct-run agent launchers for the supported platforms:

| Platform | Launcher | Shell |
| --- | --- | --- |
| macOS | `.sh` | Terminal / Bash |
| Linux | `.sh` | Terminal / Bash |
| Windows | `.ps1` | PowerShell |

The generated launcher embeds the one-time enrollment token and starts the agent in an isolated Python environment. For persistent background operation, automatic startup after reboot, and agent registration, follow the instructions in [README_AGENT.md](README_AGENT.md). The installer may require administrator/root privileges to register the platform's background service or scheduled task.

The agent is intended to collect read-only inventory data and send endpoint profiles to the configured VULNEX server. Review the data collected and server configuration before deploying it to real endpoints.

## Authentication and access control

VULNEX includes account approval and role-based access controls. New accounts may require administrator approval before login. Administrator and standard-user permissions differ; see [README_PHASE8_AUTH_RBAC.md](README_PHASE8_AUTH_RBAC.md) for the role matrix and authentication details.

Do not expose the dashboard or agent API to untrusted networks without reviewing authentication, network binding, TLS/reverse-proxy configuration, and secret handling.

## Tests

From the repository root, run:

```bash
python -m pytest -q
```

This runs the tests available in the checkout. A successful test run does not by itself confirm that Nmap scans, platform-specific service installation, Windows endpoint collection, or external CVE lookups work on every target system; validate those workflows on the platforms where you intend to deploy VULNEX.

## Security and data hygiene

- Assess only systems for which you have explicit authorization.
- Do not commit passwords, API keys, enrollment tokens, session files, private keys, or other secrets.
- Keep local authentication/session data, logs, endpoint inventories, scan results, and reports private; they may contain sensitive information.
- Use least privilege. Do not run the entire dashboard as root/Administrator unless a documented operation specifically requires it.
- On macOS/Linux, follow the phase-specific Nmap privilege guidance rather than running the whole dashboard with `sudo`.
- Review agent enrollment, server URL, firewall rules, and permissions before deployment.
- Use a trusted reverse proxy if forwarded client-IP headers are relied upon; do not trust arbitrary forwarded headers from untrusted clients.

## Documentation

- [Complete VULNEX project documentation (PDF)](docs/Vulnex_Complete_Project_Documentation.pdf)
- [Endpoint agent guide](README_AGENT.md)
- [Authentication and RBAC](README_PHASE8_AUTH_RBAC.md)
- [Automatic virtual environment setup](README_VENV_SETUP.md)

## Disclaimer

VULNEX is provided for authorized security assessment, defensive testing, and educational use. You are responsible for obtaining the required permissions and complying with applicable laws, policies, and third-party terms.
