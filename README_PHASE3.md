# Vulnex 2.0 — Phase 3.1: Dashboard-Managed Endpoint Agents

Phase 3.1 adds an authorized endpoint-agent enrollment workflow without changing the existing Phase 1/2 network discovery and local inventory flow.

## What is new

- **Agent Management in the Streamlit dashboard**
  - Create an endpoint label.
  - Generate a one-time enrollment token.
  - Generate and download a self-contained agent ZIP directly from the dashboard.
- **Vulnex Agent API** on port `8765`.
  - One-time enrollment token is required for first registration.
  - Successful registration consumes the enrollment token.
  - Server issues a unique agent ID and persistent agent secret.
  - The agent stores its secret locally and clears the enrollment token.
  - Subsequent heartbeats authenticate with the agent secret.
- **Agent inventory**
  - Uses the same best-effort cross-platform system inventory collector introduced in Phase 2.
  - Sends identity, hardware, software, network, users, and running-service information.
- **Dashboard status**
  - Registered agents are listed with hostname, IP, OS, status, and last-seen time.
  - Agents older than 10 minutes are shown as stale.

## Dashboard-only enrollment model

The endpoint cannot self-enroll with an arbitrary identifier. A valid one-time token must first be generated from the Vulnex dashboard. This makes the dashboard the administrative entry point for adding agents.

The agent package contains a generated configuration with the Vulnex server address and one-time token. After registration, the token is cleared and replaced by a unique persistent secret.

## Network requirement

The endpoint running the agent must be able to reach the Vulnex machine on TCP port `8765`. The generated package defaults to the local LAN address detected by Vulnex, and the dashboard allows the server URL to be changed before generating a package.

## Security scope

Run Vulnex and its agents only on systems and networks you own or have explicit authorization to assess. This phase is intentionally limited to inventory collection and authenticated reporting; it does not implement remote command execution.

## Next phase

Phase 3.2 will improve the agent lifecycle and endpoint profile integration, including richer device detail views and merging agent inventory with Nmap assessment data.
