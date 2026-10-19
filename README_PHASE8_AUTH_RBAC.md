# Vulnex Phase 8 — Authentication & RBAC

## Overview

Phase 8 adds account-based access control without removing the existing Phase 7 network assessment, endpoint agent, risk, remediation, history, and reporting workflows.

## Roles

### Administrator

Full access to Vulnex, including:

- Network discovery and assessment
- Endpoint agent configuration
- Agent deletion
- Local endpoint inventory
- Vulnerability/risk views
- Remediation state management
- User approval/rejection
- Developer profile editing from the web interface
- Reports and executive reporting

### User

Limited operational access:

- Network/device discovery and assessment
- View assessment and vulnerability results
- Download assessment/full-device/executive reports
- Generate/configure endpoint agents
- View endpoint inventory

User accounts cannot:

- Delete endpoint agents
- Approve/reject accounts
- Edit developer details
- Change asset criticality
- Change remediation status
- Access administrator-only local endpoint/developer administration pages

## Account Lifecycle

1. A new user selects **Sign Up** on the Vulnex landing page.
2. The account is stored with `pending` status.
3. An administrator signs in through the **Admin Login** section on the homepage.
4. The administrator approves or rejects pending users.
5. Only approved users can log in.

## First Administrator Setup

On a fresh Vulnex installation, the Admin Login section provides a one-time administrator creation form. The administrator password is stored as a salted PBKDF2-SHA256 hash, not plaintext.

## Storage

Authentication data is stored under:

```text
scans/auth/users.json
scans/auth/developer.json
scans/auth/auth_audit.log
```

These files are ignored by Git because they can contain account metadata and audit information.

## Homepage

The public landing page now includes:

- Vulnex security logo
- One-line platform caption
- User Login
- User Sign Up
- Admin Login below the user authentication area
- Explanation of approval workflow

The generated logo asset is stored at:

```text
assets/vulnex_logo.png
```

## Security Notes

- Passwords use PBKDF2-HMAC-SHA256 with a unique random salt and 210,000 iterations.
- Password hashes are never displayed through the dashboard.
- User approval is enforced during authentication, not only in the UI.
- Role checks are enforced in the application before privileged operations.
- Administrator-only actions remain protected even if a user manually navigates to a restricted page.
- Production deployments should add TLS, secure secret management, session timeout, CSRF-aware deployment controls and stronger centralized identity management if the platform becomes multi-tenant.

## Phase 9 — Persistent Login Session & Login Rate Limiting

This update addresses two authentication hardening requirements:

### Persistent login
- Authentication is no longer held only in `st.session_state`.
- A random server-side session token is created after successful login.
- Only a SHA-256 digest of the token is persisted in `scans/auth/sessions.json`.
- The browser receives a persistent `vulnex_session` cookie.
- Refreshing the page restores the authenticated user from the server-side session.
- The session remains valid until the user explicitly logs out; logout revokes the server-side token and deletes the cookie.
- If an account is no longer approved/active, its persistent session is invalidated on the next restore attempt.

### Login rate limiting
- Failed password attempts are tracked by client IP.
- Maximum allowed wrong password attempts: **5**.
- On the 5th wrong password attempt, that IP is blocked for **1 hour**.
- The block is persisted in `scans/auth/login_rate_limits.json`, so a Streamlit refresh or application rerun does not reset it.
- A successful login clears the failed-attempt counter for that IP.
- While blocked, the login form refuses authentication before checking the supplied password.
- The application uses `X-Forwarded-For` / `X-Real-IP` when present behind a trusted reverse proxy and falls back to Streamlit session metadata for direct deployments.

### Important deployment note
If Vulnex is placed behind a reverse proxy, only trust forwarded IP headers from that controlled proxy. Do not expose the Streamlit service directly to untrusted networks while accepting arbitrary client-supplied `X-Forwarded-For` values.


### macOS/Linux privileged Nmap access
Launch Vulnex from a terminal with `python3 app.py`. The automatic bootstrap creates/uses `.venv`, installs dependencies there, then requests `sudo` authorization before starting Streamlit. Vulnex itself runs as the normal user; only the Nmap command uses the cached sudo authorization (`sudo -n`) for privileged probes. If you decline the password prompt, scans still run but raw-packet discovery/OS fingerprinting may be limited. Do not launch the entire dashboard with `sudo`, because that can create root-owned files in the project virtual environment.
