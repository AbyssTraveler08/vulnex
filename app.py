from __future__ import annotations

# ============================================================
# Vulnex dependency bootstrap
# Must run before importing third-party/application modules.
# ============================================================

import importlib.util
import re
import os
import subprocess
import sys
import io
import base64
import json
import zipfile
import shutil
import html
from datetime import datetime
from pathlib import Path

# Always run Vulnex in a project-local virtual environment. If the user launches
# `python app.py` with system/Homebrew Python, create `.venv`, install requirements
# there, and relaunch Streamlit using that interpreter. This avoids PEP 668 errors.
PROJECT_DIR = Path(__file__).resolve().parent
VENV_DIR = PROJECT_DIR / ".venv"
BOOTSTRAP_FLAG = "VULNEX_VENV_BOOTSTRAPPED"


def _venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _inside_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix) or bool(os.environ.get("VIRTUAL_ENV"))


def _bootstrap_virtualenv_and_relaunch() -> None:
    # The flag prevents relaunch loops when Streamlit executes this file.
    if os.environ.get(BOOTSTRAP_FLAG) == "1" or _inside_virtualenv():
        return

    requirements = PROJECT_DIR / "requirements.txt"
    if not requirements.is_file():
        raise FileNotFoundError("Vulnex requirements.txt is missing: {}".format(requirements))

    interpreter = _venv_python()
    if not interpreter.is_file():
        print("[VULNEX] Creating project virtual environment at {}".format(VENV_DIR))
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])

    # Install/update dependencies only when requirements change. The marker is
    # stored inside .venv, never in the system Python environment.
    import hashlib
    requirements_hash = hashlib.sha256(requirements.read_bytes()).hexdigest()
    marker = VENV_DIR / ".vulnex_requirements_hash"
    installed_hash = marker.read_text(encoding="utf-8").strip() if marker.exists() else ""
    if installed_hash != requirements_hash:
        print("[VULNEX] Installing project dependencies inside .venv (first run or requirements changed)...")
        subprocess.check_call([str(interpreter), "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([str(interpreter), "-m", "pip", "install", "-r", str(requirements)])
        marker.write_text(requirements_hash, encoding="utf-8")

    # Cache sudo authorization BEFORE launching Streamlit. The scanner runs
    # only Nmap with `sudo -n`; the dashboard itself must never run as root.
    # This is important on macOS/Linux because the bootstrap/relaunch path
    # otherwise skipped the normal __main__ sudo warm-up below.
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo = shutil.which("sudo") or "/usr/bin/sudo"
        try:
            print("[VULNEX] Requesting permission for privileged Nmap probes...")
            subprocess.run([sudo, "-v"], check=True)
            print("[VULNEX] Privileged Nmap access is ready for this login session.")
        except (OSError, subprocess.CalledProcessError):
            print("[VULNEX] Warning: sudo authorization was not granted. Vulnex will run without privileged Nmap probes; some discovery/OS-detection results may be limited.")

    env = os.environ.copy()
    env[BOOTSTRAP_FLAG] = "1"
    env["VULNEX_STREAMLIT_PROCESS"] = "1"
    print("[VULNEX] Starting Vulnex using its virtual environment...")
    subprocess.check_call([str(interpreter), "-m", "streamlit", "run", str(PROJECT_DIR / "app.py")], env=env, cwd=str(PROJECT_DIR))
    raise SystemExit(0)


_bootstrap_virtualenv_and_relaunch()

from nmap_locator import find_nmap, nmap_install_message


def _requirement_import_name(package_name: str) -> str:
    """Map common PyPI distribution names to Python import names."""
    return {
        "streamlit": "streamlit",
        "reportlab": "reportlab",
        "netifaces": "netifaces",
        "matplotlib": "matplotlib",
        "requests": "requests",
        "psutil": "psutil",
        "extra-streamlit-components": "extra_streamlit_components",
    }.get(package_name.lower().replace("_", "-"), package_name.split("==")[0].split(">=")[0].strip().replace("-", "_"))


def ensure_dependencies() -> None:
    requirements = Path(__file__).resolve().parent / "requirements.txt"
    if not requirements.exists():
        raise FileNotFoundError(f"Missing requirements.txt: {requirements}")

    packages = []
    missing = []

    for raw in requirements.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(("-", "--")):
            continue

        # Ignore version operators when checking the import.
        package = re.split(r"[<>=!~]", line, maxsplit=1)[0].strip()
        if not package:
            continue

        packages.append(line)
        module = _requirement_import_name(package)
        if importlib.util.find_spec(module) is None:
            missing.append(package)

    if not missing:
        return

    print("[VULNEX] Missing Python dependencies detected:")
    for package in missing:
        print("  - {}".format(package))
    if not _inside_virtualenv():
        raise RuntimeError(
            "Vulnex must run inside its project virtual environment. "
            "Launch it with `python app.py` so the automatic bootstrap can prepare .venv."
        )

    print("[VULNEX] Installing dependencies inside the active virtual environment...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(requirements)])
    print("[VULNEX] Dependency installation completed.")


ensure_dependencies()

# Nmap is a system executable, so pip cannot install it from requirements.txt.
# Resolve it early so the UI can give a precise installation message.
NMAP_PATH = find_nmap()

# If launched directly with `python app.py`, warm the macOS/Linux sudo
# credential cache once in the terminal, then start Streamlit normally.
# Streamlit itself does NOT need to run as root: the discovery engine uses
# `sudo -n nmap` after this one-time credential check. This avoids trying to
# capture a sudo password inside the Streamlit browser UI.
if __name__ == "__main__" and os.environ.get("VULNEX_STREAMLIT_PROCESS") != "1":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo = shutil.which("sudo") or "/usr/bin/sudo"
        try:
            print("[VULNEX] Checking privileged network-discovery access...")
            subprocess.run([sudo, "-v"], check=True)
            print("[VULNEX] Privileged discovery access is ready.")
        except (OSError, subprocess.CalledProcessError):
            print("[VULNEX] Warning: sudo authorization was not granted. Network discovery may be limited.")

    env = os.environ.copy()
    env["VULNEX_STREAMLIT_PROCESS"] = "1"
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(Path(__file__).resolve())],
        env=env,
        check=True,
    )
    raise SystemExit

import streamlit as st
import extra_streamlit_components as stx

from discovery.network_discovery import discover_devices, get_local_network, get_discovery_status
from scanner import run_nmap
from report_generator import generate_device_pdf, generate_full_device_pdf, generate_executive_risk_pdf
from collectors.system_info import collect_local_profile
from models.device_profile import DeviceProfile
from storage.profile_store import ProfileStore
from agent_server import REGISTRY, start_agent_server


from cve_fetcher import fetch_cves
from risk_engine import rank_vulnerabilities, enrich_vulnerabilities, summarize, asset_risk
from security_store import SecurityStore
from remediation_engine import get_remediation
from auth_manager import AuthStore, APPROVED, PENDING, REJECTED
LEGACY_ANALYSIS_AVAILABLE = True


st.set_page_config(page_title="Vulnex — Security Console", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background: radial-gradient(circle at 15% 0%, rgba(34,197,94,.07), transparent 25%), radial-gradient(circle at 95% 5%, rgba(59,130,246,.10), transparent 30%), #080c12; }
[data-testid="stHeader"] { background: transparent; }
.block-container { max-width: 1500px; padding-top: 1.2rem; padding-bottom: 3rem; }
.vx-topbar { display:flex; align-items:center; justify-content:space-between; gap:18px; padding: 18px 22px; margin-bottom: 18px; border:1px solid rgba(148,163,184,.16); border-radius:20px; background:linear-gradient(135deg, rgba(15,23,42,.96), rgba(10,15,24,.92)); box-shadow:0 18px 50px rgba(0,0,0,.25); }
.vx-brand { font-size:1.8rem; font-weight:800; letter-spacing:-.03em; }
.vx-sub { color:#94a3b8; margin-top:3px; font-size:.92rem; }
.vx-card { min-height:235px; padding:24px; border:1px solid rgba(148,163,184,.16); border-radius:20px; background:linear-gradient(145deg, rgba(20,29,44,.96), rgba(12,18,29,.96)); box-shadow:0 14px 35px rgba(0,0,0,.18); transition:transform .2s ease, border-color .2s ease; }
.vx-card:hover { transform:translateY(-3px); border-color:rgba(96,165,250,.40); }
.vx-icon { font-size:2.25rem; margin-bottom:12px; }
.vx-card-title { font-size:1.25rem; font-weight:800; margin-bottom:8px; }
.vx-card-text { color:#94a3b8; line-height:1.55; min-height:75px; }
.vx-card-stat { color:#cbd5e1; font-size:.86rem; margin-top:14px; }
.vx-section { margin:22px 0 12px; font-size:1.15rem; font-weight:800; }
.vx-page-title { font-size:1.85rem; font-weight:850; letter-spacing:-.03em; margin-bottom:4px; }
.vx-page-sub { color:#94a3b8; margin-bottom:18px; }
.vx-footer { margin-top:35px; padding:18px; border-top:1px solid rgba(148,163,184,.12); color:#64748b; text-align:center; font-size:.82rem; }
.vx-login-card { padding:26px; border:1px solid rgba(56,189,248,.18); border-radius:22px; background:linear-gradient(145deg, rgba(15,23,42,.96), rgba(8,15,25,.96)); box-shadow:0 20px 55px rgba(0,0,0,.28); }
div[data-testid="stMetric"] { background:rgba(15,23,42,.60); border:1px solid rgba(148,163,184,.13); padding:12px 14px; border-radius:14px; }
div.stButton > button, div.stDownloadButton > button { border-radius:11px; font-weight:650; }
.stTabs [data-baseweb="tab"] { border-radius:9px; padding:8px 14px; }
</style>
<div class="vx-topbar"><div><div class="vx-brand">🛡️ VULNEX</div><div class="vx-sub">Network discovery • Endpoint visibility • Vulnerability assessment</div></div></div>
""", unsafe_allow_html=True)

# -------------------------
# Session state / navigation
# -------------------------
if "page" not in st.session_state:
    st.session_state.page = "home"
if "devices" not in st.session_state:
    st.session_state.devices = []
if "selected_ip" not in st.session_state:
    st.session_state.selected_ip = None
if "assessments" not in st.session_state:
    st.session_state.assessments = {}

profile_store = ProfileStore()
security_store = SecurityStore()
auth_store = AuthStore()

# Persistent browser session: the signed-in state survives Streamlit reruns/page refreshes
# and is explicitly revoked only when the user logs out (or the server session is revoked).
cookie_manager = stx.CookieManager(key="vulnex_auth_cookie_manager")

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "auth_user" not in st.session_state:
    st.session_state.auth_user = None
if "auth_session_token" not in st.session_state:
    st.session_state.auth_session_token = None
if "auth_restore_checked" not in st.session_state:
    st.session_state.auth_restore_checked = False

def _client_ip() -> str:
    """Best-effort client IP for login throttling.

    X-Forwarded-For/X-Real-IP are used when Vulnex is behind a trusted reverse proxy.
    Streamlit's internal session metadata is used as a fallback for direct deployments.
    """
    try:
        headers = st.context.headers
        forwarded = headers.get("X-Forwarded-For") or headers.get("X-Real-IP")
        if forwarded:
            return str(forwarded).split(",")[0].strip() or "unknown"
    except Exception:
        pass
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        from streamlit.runtime import get_instance
        ctx = get_script_run_ctx()
        if ctx is not None:
            server = get_instance()
            info = server._session_mgr.get_active_session_info(ctx.session_id)
            client = getattr(info, "client", None)
            address = getattr(client, "address", None)
            if address:
                return str(address)
    except Exception:
        pass
    return "unknown"

def _restore_persistent_session():
    """Restore login from the browser cookie after a Streamlit refresh.

    Streamlit session_state is reset when the browser WebSocket is recreated.
    The browser cookie is therefore the source of truth for persistence.  Use
    st.context.cookies first because it is populated from the HTTP request on
    a real page refresh; the extra-streamlit-components getter can be
    asynchronous on its first render and may otherwise return None too early.
    """
    if st.session_state.auth_restore_checked:
        return

    token = None
    try:
        token = st.context.cookies.get("vulnex_session")
    except Exception:
        token = None

    # Fallback for environments where st.context.cookies is unavailable.
    if not token:
        try:
            token = cookie_manager.get("vulnex_session")
        except Exception:
            token = None

    if token:
        user = auth_store.get_session(str(token))
        if user:
            st.session_state.auth_session_token = str(token)
            st.session_state.authenticated = True
            st.session_state.auth_user = user

    # Mark checked only after both cookie sources have been attempted.
    # A page refresh creates a new Session State, so this does not prevent
    # restoration on future refreshes.
    st.session_state.auth_restore_checked = True

_restore_persistent_session()

def _logged_in():
    return bool(st.session_state.get("authenticated") and st.session_state.get("auth_user"))

def _is_admin():
    return _logged_in() and st.session_state.auth_user.get("role") == "admin"

def _is_user():
    return _logged_in() and st.session_state.auth_user.get("role") == "user"

def _logout():
    username = (st.session_state.get("auth_user") or {}).get("username", "")
    token = st.session_state.get("auth_session_token")
    auth_store.revoke_session(token, username)
    auth_store._audit("LOGOUT", username)
    try:
        cookie_manager.delete("vulnex_session")
    except Exception:
        pass
    st.session_state.authenticated = False
    st.session_state.auth_user = None
    st.session_state.auth_session_token = None
    st.session_state.auth_restore_checked = True
    st.session_state.page = "home"
    st.rerun()

def _login(role: str, username: str, password: str):
    client_ip = _client_ip()
    allowed, retry_after = auth_store.login_allowed(client_ip)
    if not allowed:
        minutes = max(1, (retry_after + 59) // 60)
        st.error(f"Too many failed login attempts from this IP. Login is blocked for approximately {minutes} minute(s).")
        return

    ok, result = auth_store.authenticate(username, password, role)
    if ok:
        auth_store.clear_login_failures(client_ip)
        token = auth_store.create_session(result.get("username", username), result.get("role", role))
        # Persistent cookie: refreshes and browser restarts do not log the user out.
        # Explicit Logout revokes the server-side token and deletes this cookie.
        try:
            from datetime import timedelta
            cookie_manager.set(
                "vulnex_session", token,
                expires_at=datetime.now() + timedelta(days=3650),
            )
            # Give the browser-side component time to commit the cookie before
            # Streamlit interrupts the run with st.rerun().
            import time
            time.sleep(0.6)
        except Exception as exc:
            st.warning(f"Login succeeded, but persistent session storage could not be set: {exc}")
        st.session_state.auth_session_token = token
        st.session_state.authenticated = True
        st.session_state.auth_user = result
        st.session_state.auth_restore_checked = True
        st.session_state.page = "home"
        st.success("Login successful.")
        st.rerun()
    else:
        message = str(result)
        if message == "Invalid credentials.":
            _, remaining = auth_store.record_login_failure(client_ip, username.strip())
            if remaining == 3600:
                st.error("Maximum of 5 wrong password attempts reached. This IP is blocked for 1 hour.")
            else:
                st.error(f"Invalid credentials. {remaining} attempt(s) remaining before this IP is blocked for 1 hour.")
        else:
            st.error(message)


@st.cache_resource
def _start_vulnex_agent_api():
    """Start the local agent API once per Streamlit process."""
    try:
        return start_agent_server("0.0.0.0", 8765)
    except OSError:
        return None


AGENT_API_SERVER = _start_vulnex_agent_api()

if _logged_in():
    u = st.session_state.auth_user
    st.markdown(
        f'<div style="display:flex;justify-content:flex-end;gap:10px;align-items:center;margin:-8px 0 12px 0;">'
        f'<span style="color:#94a3b8;font-size:.88rem;">Signed in as <b style="color:#e2e8f0;">{html.escape(str(u.get("username","")))}</b> · {html.escape(str(u.get("role","user").title()))}</span>'
        f'</div>', unsafe_allow_html=True)
    if st.button("↪ Logout", key="logout_top", use_container_width=False):
        _logout()


def _agent_server_url() -> str:
    # Agents on the LAN need a reachable address, not localhost.
    try:
        from discovery.network_discovery import get_local_ip
        host = get_local_ip()
    except Exception:
        host = "127.0.0.1"
    return f"http://{host}:8765"


def _agent_payload_files(server_url: str, token: str, token_id: str) -> dict[str, bytes]:
    """Build the common self-contained agent payload used by every OS launcher."""
    project = Path(__file__).resolve().parent
    agent_dir = project / "agent"
    config = {
        "server_url": server_url.rstrip("/"),
        "enrollment_token": token,
        "enrollment_id": token_id,
        "heartbeat_seconds": 60,
        "collection_seconds": 300,
    }
    return {
        "agent.py": (agent_dir / "agent.py").read_bytes(),
        "collector.py": (agent_dir / "collector.py").read_bytes(),
        "requirements.txt": (agent_dir / "requirements.txt").read_bytes(),
        "agent_config.json": json.dumps(config, indent=2).encode("utf-8"),
    }


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _build_unix_agent_script(server_url: str, token: str, token_id: str, os_name: str) -> bytes:
    """Generate a self-contained installer that registers the agent as a boot service."""
    files = _agent_payload_files(server_url, token, token_id)
    encoded = {name: _b64(data) for name, data in files.items()}
    if os_name == "macos":
        install_dir = '/Library/Application Support/Vulnex/Agent'
        b64decode = 'base64 -D'
        service_block = r'''PLIST_PATH="/Library/LaunchDaemons/com.vulnex.endpoint-agent.plist"
cat > "$PLIST_PATH" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.vulnex.endpoint-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Application Support/Vulnex/Agent/.venv/bin/python</string>
        <string>/Library/Application Support/Vulnex/Agent/agent.py</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>WorkingDirectory</key><string>/Library/Application Support/Vulnex/Agent</string>
    <key>StandardOutPath</key><string>/Library/Application Support/Vulnex/Agent/agent.log</string>
    <key>StandardErrorPath</key><string>/Library/Application Support/Vulnex/Agent/agent.error.log</string>
</dict>
</plist>
PLIST
chmod 644 "$PLIST_PATH"
chown root:wheel "$PLIST_PATH"
launchctl bootout system/com.vulnex.endpoint-agent >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST_PATH"
launchctl enable system/com.vulnex.endpoint-agent
launchctl kickstart -k system/com.vulnex.endpoint-agent
'''
    else:
        install_dir = '/opt/vulnex-agent'
        b64decode = 'base64 --decode'
        service_block = r'''SERVICE_FILE="/etc/systemd/system/vulnex-agent.service"
cat > "$SERVICE_FILE" <<'UNIT'
[Unit]
Description=Vulnex Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/vulnex-agent
Environment=VULNEX_AGENT_DATA_DIR=/var/lib/vulnex-agent
ExecStart=/opt/vulnex-agent/.venv/bin/python /opt/vulnex-agent/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /var/lib/vulnex-agent
chmod 700 /var/lib/vulnex-agent
systemctl daemon-reload
systemctl enable --now vulnex-agent.service
systemctl restart vulnex-agent.service
'''
    script = f'''#!/bin/bash
set -euo pipefail
# Vulnex authorized endpoint agent installer - {os_name.title()}
# Installs the agent as a background service that starts automatically after reboot.
if [ "$(id -u)" -ne 0 ]; then
    exec sudo bash "$0" "$@"
fi
INSTALL_DIR="{install_dir}"
mkdir -p "$INSTALL_DIR"
log() {{ printf '[VULNEX] %s\n' "$1"; }}
fail() {{ printf '[VULNEX] ERROR: %s\n' "$1" >&2; exit 1; }}

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
elif command -v brew >/dev/null 2>&1; then
    log "Python 3 not found; installing it with Homebrew..."
    brew install python
    PYTHON_BIN="$(command -v python3 || true)"
else
    fail "Python 3 is required. Install Python 3 and run this script again."
fi
[ -n "$PYTHON_BIN" ] || fail "Could not locate Python 3."

write_file() {{
    local name="$1"; local encoded="$2"
    printf '%s' "$encoded" | {b64decode} > "$INSTALL_DIR/$name"
}}
write_file agent.py '{encoded["agent.py"]}'
write_file collector.py '{encoded["collector.py"]}'
write_file requirements.txt '{encoded["requirements.txt"]}'
write_file agent_config.json '{encoded["agent_config.json"]}'
export VULNEX_AGENT_DATA_DIR="{install_dir}"
chmod 600 "$INSTALL_DIR/agent_config.json"

if [ ! -x "$INSTALL_DIR/.venv/bin/python" ]; then
    log "Creating isolated Python environment..."
    "$PYTHON_BIN" -m venv "$INSTALL_DIR/.venv"
fi
"$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip >/dev/null 2>&1 || true
if [ -s "$INSTALL_DIR/requirements.txt" ]; then
    "$INSTALL_DIR/.venv/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"
fi

{service_block}
log "Vulnex endpoint agent installed as a background service."
log "It will continue running after logout/reboot and retry when the Vulnex server is temporarily unavailable."
'''
    return script.encode("utf-8")


def _build_windows_agent_script(server_url: str, token: str, token_id: str) -> bytes:
    """Generate a self-contained PowerShell installer registered as a startup task."""
    files = _agent_payload_files(server_url, token, token_id)
    encoded = {name: _b64(data) for name, data in files.items()}
    script = f'''$ErrorActionPreference = "Stop"
# Vulnex authorized endpoint agent installer - Windows
# Installs the agent as a background Scheduled Task that starts at boot.
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    throw "Run this PowerShell script as Administrator so Vulnex can install the persistent background task."
}}
$InstallDir = if ($env:VULNEX_AGENT_DATA_DIR) {{ $env:VULNEX_AGENT_DATA_DIR }} else {{ Join-Path $env:ProgramData "Vulnex\\Agent" }}
$VenvDir = Join-Path $InstallDir ".venv"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

function Write-B64File([string]$Name, [string]$Encoded) {{
    [IO.File]::WriteAllBytes((Join-Path $InstallDir $Name), [Convert]::FromBase64String($Encoded))
}}
Write-B64File "agent.py" "{encoded["agent.py"]}"
Write-B64File "collector.py" "{encoded["collector.py"]}"
Write-B64File "requirements.txt" "{encoded["requirements.txt"]}"
Write-B64File "agent_config.json" "{encoded["agent_config.json"]}"

$env:VULNEX_AGENT_DATA_DIR = $InstallDir

# Find a real Python interpreter, avoiding the Microsoft Store execution-alias stub.
$PythonExe = $null
$pyLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($pyLauncher) {{
    try {{
        & $pyLauncher.Source -3 --version *> $null
        if ($LASTEXITCODE -eq 0) {{
            $PythonExe = (& $pyLauncher.Source -3 -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1).Trim()
        }}
    }} catch {{ $PythonExe = $null }}
}}
if (-not $PythonExe) {{
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd) {{
        try {{
            $candidate = (& $pythonCmd.Source -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
            if ($LASTEXITCODE -eq 0 -and $candidate -and (Test-Path $candidate.Trim())) {{ $PythonExe = $candidate.Trim() }}
        }} catch {{ $PythonExe = $null }}
    }}
}}
if (-not $PythonExe) {{
    $knownPaths = @(
        "$env:LocalAppData\\Programs\\Python\\Python313\\python.exe",
        "$env:LocalAppData\\Programs\\Python\\Python312\\python.exe",
        "$env:LocalAppData\\Programs\\Python\\Python311\\python.exe",
        "$env:ProgramFiles\\Python313\\python.exe",
        "$env:ProgramFiles\\Python312\\python.exe",
        "$env:ProgramFiles\\Python311\\python.exe"
    )
    $PythonExe = $knownPaths | Where-Object {{ Test-Path $_ }} | Select-Object -First 1
}}
if (-not $PythonExe) {{
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {{
        Write-Host "[VULNEX] Python was not found. Attempting to install Python 3.12 with winget..."
        & $winget.Source install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -eq 0) {{
            $knownPaths = @(
                "$env:LocalAppData\\Programs\\Python\\Python312\\python.exe",
                "$env:ProgramFiles\\Python312\\python.exe"
            )
            $PythonExe = $knownPaths | Where-Object {{ Test-Path $_ }} | Select-Object -First 1
        }}
    }}
}}
if (-not $PythonExe) {{
    throw "Python 3 was not found. Install Python 3.12 from https://www.python.org/downloads/windows/ (enable Add Python to PATH), then close and reopen PowerShell and run this installer again."
}}
if (-not (Test-Path (Join-Path $VenvDir "Scripts\\python.exe"))) {{
    & $PythonExe -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {{ throw "Failed to create the Vulnex Python environment using $PythonExe." }}
}}
$VenvPython = Join-Path $VenvDir "Scripts\\python.exe"
if (-not (Test-Path $VenvPython)) {{ throw "Failed to create the Vulnex Python environment." }}
& $VenvPython -m pip install --upgrade pip | Out-Null
$Req = Join-Path $InstallDir "requirements.txt"
if ((Get-Item $Req).Length -gt 0) {{ & $VenvPython -m pip install -r $Req }}

$TaskName = "Vulnex Endpoint Agent"
$AgentPy = Join-Path $InstallDir "agent.py"
$action = New-ScheduledTaskAction -Execute $VenvPython -Argument "`"$AgentPy`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "[VULNEX] Endpoint agent installed as a background service."
Write-Host "[VULNEX] It will continue running after logout/reboot and retry when the Vulnex server is temporarily unavailable."
'''
    return script.encode("utf-8")


def _build_agent_scripts(server_url: str, token: str, token_id: str) -> dict[str, bytes]:
    return {
        "macOS": _build_unix_agent_script(server_url, token, token_id, "macos"),
        "Linux": _build_unix_agent_script(server_url, token, token_id, "linux"),
        "Windows": _build_windows_agent_script(server_url, token, token_id),
    }

def _agent_for_device(device: dict, agents: list[dict]):
    dip = str(device.get("ip", "")).strip()
    dhost = str(device.get("hostname", "")).strip().lower()
    dmac = str(device.get("mac", "")).strip().lower()
    for agent in agents:
        profile = agent.get("profile") or {}
        identity = profile.get("identity") or {}
        network = profile.get("network") or {}
        if dip and dip in [str(x) for x in network.get("ipv4_addresses", []) or []]:
            return agent
        if dhost and dhost != "unknown" and dhost == str(identity.get("hostname", "")).strip().lower():
            return agent
        if dmac and dmac != "unknown":
            for interface in network.get("interfaces", []) or []:
                if dmac == str(interface.get("mac", "")).strip().lower():
                    return agent
    return None


def _render_full_report_button(device: dict, agent: dict | None, scan_data: dict | None, vulnerabilities: list[dict] | None, key_suffix: str):
    if not agent or not agent.get("profile"):
        return
    if st.button("📘 Prepare Full Device Report", key=f"full_report_{key_suffix}", use_container_width=True):
        try:
            path = generate_full_device_pdf(device, scan_data or {}, vulnerabilities or [], agent.get("profile") or {}, label=agent.get("label") or agent.get("agent_id") or device.get("ip", "endpoint"))
            with open(path, "rb") as fh:
                data = fh.read()
            st.download_button("⬇️ Download Full Device Report", data=data, file_name=Path(path).name, mime="application/pdf", key=f"full_report_download_{key_suffix}", use_container_width=True)
        except Exception as exc:
            st.error(f"Full report generation failed: {exc}")


def _go(page: str):
    st.session_state.page = page
    st.rerun()


def _back_button():
    if st.button("← Back to Vulnex Home", key=f"back_{st.session_state.page}", use_container_width=False):
        _go("home")


def _page_header(title: str, subtitle: str, icon: str):
    st.markdown(f'<div class="vx-page-title">{icon} {title}</div><div class="vx-page-sub">{subtitle}</div>', unsafe_allow_html=True)



# -------------------------
# Risk / vulnerability-management helpers
# -------------------------
def _all_findings():
    """Return persistent current findings as (asset_ip, vulnerability)."""
    findings=[]
    latest_by_ip={}
    for snap in security_store.history:
        latest_by_ip[snap.get("ip")] = snap
    for ip,snap in latest_by_ip.items():
        for v in snap.get("vulnerabilities",[]) or []:
            item=dict(v); item["status"]=security_store.get_status(ip,item); findings.append((ip,item))
    for ip,a in st.session_state.assessments.items():
        # Current in-memory result is authoritative for this run.
        existing={v.get("cve") for x,v in findings if x==ip}
        for v in a.get("vulnerabilities",[]) or []:
            if v.get("cve") not in existing:
                item=dict(v); item["status"]=security_store.get_status(ip,item); findings.append((ip,item))
    return findings

def _risk_metrics():
    findings=_all_findings()
    summary=summarize([v for _,v in findings])
    assets=[]
    latest_by_ip={}
    for ip,snap in ((x.get("ip"),x) for x in security_store.history):
        latest_by_ip[ip]=snap
    for ip,snap in latest_by_ip.items():
        rd=snap.get("asset_risk") or asset_risk(snap.get("vulnerabilities",[]),len((snap.get("scan_data") or {}).get("ports",[]) or []),None,security_store.criticality(ip))
        agent=next((a for a in REGISTRY.list_agents() if ip in ((a.get("profile") or {}).get("network") or {}).get("ipv4_addresses",[])),None)
        prof=(agent or {}).get("profile") or {}
        updates=prof.get("updates") or {}
        posture="Complete" if all(prof.get(k) for k in ("hardware","network","software","services","users")) else ("Partial" if prof else "Network-only")
        assets.append({"ip":ip,**rd,"outdated_software":updates.get("count","Unknown") if updates.get("supported") else "Unknown","endpoint_posture":posture})
    # Include live session assessments not yet represented in persisted history.
    for ip,a in st.session_state.assessments.items():
        if not any(x.get("ip")==ip for x in assets):
            assets.append({"ip":ip,**(a.get("risk") or {}),"outdated_software":"Unknown","endpoint_posture":"Network-only"})
    return summary, assets, findings

def _render_risk_strip():
    summary,assets,findings=_risk_metrics()
    cols=st.columns(6)
    cols[0].metric("Vulnerabilities",summary["total"])
    cols[1].metric("Critical",summary["critical"])
    cols[2].metric("High",summary["high"])
    cols[3].metric("KEV",summary["kev"])
    cols[4].metric("Affected Assets",len(assets))
    cols[5].metric("Avg Risk",summary["avg_risk"])
    return summary,assets,findings

def _render_remediation_controls(findings, key_prefix="rm"):
    if not findings:
        st.info("No tracked vulnerability findings.")
        return
    rows=[]
    for ip,v in findings:
        rows.append({"Asset":ip,"CVE":v.get("cve"),"Risk":v.get("risk_score"),"Severity":v.get("risk_level",v.get("severity")),
                     "KEV":"Yes" if v.get("known_exploited") else "No","Service":v.get("service"),"Status":security_store.get_status(ip,v)})
    st.dataframe(rows,use_container_width=True,hide_index=True)
    if not _is_admin():
        st.caption("Read-only for user accounts. Only administrators can change remediation status.")
        return
    choices=["Open","Acknowledged","In Progress","Resolved","Accepted Risk"]
    idx=st.selectbox("Finding",list(range(len(findings))),format_func=lambda i:f"{findings[i][0]} — {findings[i][1].get('cve')} — {findings[i][1].get('service','')}",key=f"{key_prefix}_finding")
    ip,v=findings[idx]
    status=st.selectbox("Remediation status",choices,index=choices.index(security_store.get_status(ip,v)),key=f"{key_prefix}_status")
    note=st.text_input("Remediation note",value=security_store.status.get(security_store.finding_key(ip,v),{}).get("note",""),key=f"{key_prefix}_note")
    if st.button("Update remediation status",key=f"{key_prefix}_update",type="primary"):
        security_store.set_status(ip,v,status,note); st.success(f"{v.get('cve')} marked {status}."); st.rerun()

def _render_history(ip=None):
    history=security_store.for_ip(ip) if ip else security_store.history
    if not history:
        st.info("No historical scans have been stored yet.")
        return
    rows=[]
    for snap in reversed(history):
        s=summarize(snap.get("vulnerabilities",[]))
        rows.append({"Scan ID":snap.get("scan_id"),"Time":snap.get("timestamp"),"IP":snap.get("ip"),
                     "Risk":(snap.get("asset_risk") or {}).get("asset_risk_score",0),
                     "CVEs":s["total"],"Critical":s["critical"],"High":s["high"],"KEV":s["kev"]})
    st.dataframe(rows,use_container_width=True,hide_index=True)
    if ip and len(history)>=2:
        prev,current=history[-2],history[-1]
        old={v.get("cve") for v in prev.get("vulnerabilities",[]) if v.get("cve")}
        new={v.get("cve") for v in current.get("vulnerabilities",[]) if v.get("cve")}
        c1,c2,c3=st.columns(3); c1.metric("New vulnerabilities",len(new-old)); c2.metric("Resolved vulnerabilities",len(old-new))
        c3.metric("Risk change",round((current.get("asset_risk") or {}).get("asset_risk_score",0)-(prev.get("asset_risk") or {}).get("asset_risk_score",0),1))
        if new-old: st.write("**New:**",", ".join(sorted(new-old)))
        if old-new: st.write("**Resolved:**",", ".join(sorted(old-new)))

def _render_vulnerability_dashboard():
    st.markdown('<div class="vx-section">📊 Vulnerability Dashboard</div>',unsafe_allow_html=True)
    summary,assets,findings=_render_risk_strip()
    c1,c2=st.columns(2)
    with c1:
        st.markdown("**Severity distribution**")
        st.dataframe([{"Severity":"Critical","Count":summary["critical"]},{"Severity":"High","Count":summary["high"]},{"Severity":"Medium","Count":summary["medium"]},{"Severity":"Low","Count":summary["low"]},{"Severity":"Unknown","Count":summary["unknown"]}],use_container_width=True,hide_index=True)
    with c2:
        st.markdown("**Remediation status**")
        rc=security_store.remediation_counts(findings)
        st.dataframe([{"Status":k,"Count":v} for k,v in rc.items()],use_container_width=True,hide_index=True)
    st.markdown("**Asset Risk View**")
    if assets: st.dataframe([{"Asset":a.get("ip"),"Risk":a.get("asset_risk_score",0),"Level":a.get("asset_risk_level","UNKNOWN"),"CVEs":a.get("total",0),"Open Ports":a.get("open_ports",0),"Criticality":a.get("asset_criticality",3),"Outdated/Updates":a.get("outdated_software","Unknown"),"Endpoint Posture":a.get("endpoint_posture","Network-only")} for a in assets],use_container_width=True,hide_index=True)
    else: st.info("Assess a device to populate asset risk.")
    with st.expander("Remediation Tracking"):
        _render_remediation_controls(findings,"home_rm")
    with st.expander("Historical Scanning & Change Detection"):
        _render_history()
    _render_executive_report_button()

# -------------------------
# Network section
# -------------------------
def render_network():
    _back_button()
    _page_header("Network Discovery", "Discover live devices first, then perform a full-port security assessment on any selected device.", "🌐")

    status = get_discovery_status()
    if status["nmap"]:
        st.caption(f"Nmap detected: `{status['nmap']}`")
        if status["privileged"]:
            st.success(f"Nmap discovery privileges: {status['privilege_reason']}")
        else:
            st.warning("Nmap is installed, but Vulnex is not running with privileged discovery access. ARP-cache discovery will still be attempted. For full macOS Nmap ARP discovery, start Vulnex with: sudo -E python3 -m streamlit run app.py")
    else:
        st.error(nmap_install_message())

    st.info("Network assessment is available without an endpoint agent: Vulnex scans all 65,535 TCP ports, performs service/version detection, and runs Nmap vulnerability NSE scripts. CVE matching uses NVD data; CISA KEV status is shown when available. Deep hardware/software/user inventory still requires an authorized Vulnex Agent.")
    st.warning("Authorized use only: scan networks and devices you own or have explicit permission to assess.")

    iface, network = get_local_network()
    c1, c2, c3 = st.columns(3)
    c1.metric("Network", network)
    c2.metric("Interface", iface)
    c3.metric("Discovered Devices", len(st.session_state.devices))

    if st.button("🔎 Start Network Discovery", type="primary", use_container_width=True):
        with st.spinner(f"Discovering live hosts on {network}..."):
            try:
                st.session_state.devices = discover_devices(network, iface)
                st.session_state.selected_ip = None
                st.session_state.assessments = {}
                if st.session_state.devices:
                    st.success(f"Discovered {len(st.session_state.devices)} device(s). Select a device below to assess it.")
                else:
                    st.info("No live devices were returned.")
            except Exception as exc:
                st.error(str(exc))

    devices = st.session_state.devices
    st.markdown('<div class="vx-section">Discovered Devices</div>', unsafe_allow_html=True)
    if not devices:
        st.info("Start network discovery to populate the device inventory.")
        return

    for idx, device in enumerate(devices):
        cols = st.columns([1.5, 2, 2, 1.6, 1.1])
        cols[0].markdown(f"**{device.get('ip', 'Unknown')}**")
        cols[1].write(device.get("hostname", "Unknown"))
        cols[2].write(device.get("vendor", "Unknown"))
        cols[3].write(device.get("device_type", "Unknown"))
        if cols[4].button("Assess", key=f"network_view_{device.get('ip')}_{idx}", use_container_width=True):
            st.session_state.selected_ip = device.get("ip")
            st.rerun()

    selected_ip = st.session_state.selected_ip
    if not selected_ip:
        st.caption("Click **Assess** on a device to scan all TCP ports, identify services, correlate CVEs and show remediation guidance.")
        return

    device = next((d for d in devices if d.get("ip") == selected_ip), None)
    if not device:
        return

    st.divider()
    st.markdown(f'<div class="vx-section">🖥️ Device Assessment — {selected_ip}</div>', unsafe_allow_html=True)
    info = st.columns(4)
    info[0].metric("IP", device.get("ip", "Unknown"))
    info[1].metric("Hostname", device.get("hostname", "Unknown"))
    info[2].metric("Vendor", device.get("vendor", "Unknown"))
    info[3].metric("Type", device.get("device_type", "Unknown"))
    st.write(f"**MAC:** {device.get('mac', 'Unknown')}  •  **Discovered:** {device.get('discovered_at', 'Unknown')}")

    if device.get("hostname") == "Unknown":
        st.caption("Hostname is not published by this device. Run an assessment or install the authorized Vulnex Agent for deeper inventory.")
    if device.get("vendor") == "Unknown":
        st.caption("Vendor could not be derived from the device MAC/OUI. This is common with randomized/private MAC addresses.")

    mode = st.radio(
        "Assessment depth", ["Quick", "Extended"], horizontal=True,
        key=f"mode_{selected_ip}",
        help="Both modes scan all 65,535 TCP ports and run Nmap vulnerability NSE scripts. Extended additionally enables OS fingerprinting and version probing. Full-port vulnerability scans can take several minutes; endpoint hardware/software/users still come from the authorized Vulnex Agent.",
    )
    mode_value = "1" if mode == "Quick" else "2"

    if st.button("🚀 Scan All 65,535 Ports + Deep Vulnerability Assessment", key=f"assess_{selected_ip}", type="primary", use_container_width=True):
        with st.spinner(f"Assessing {selected_ip} across all TCP ports and vulnerability NSE checks..."):
            try:
                scan_data = run_nmap(selected_ip, mode_value)
                vulns = fetch_cves(scan_data.get("ports", []), scan_data.get("cpe", []))
                criticality = security_store.criticality(selected_ip)
                exposed_services = {str(p.get("service") or "").lower() for p in scan_data.get("ports", []) or []}
                ranked = enrich_vulnerabilities(vulns, criticality, exposed_services)
                for vuln in ranked:
                    vuln["fix"] = get_remediation(vuln.get("service", ""))
                    vuln["status"] = security_store.get_status(selected_ip, vuln)
                risk = asset_risk(ranked, len(scan_data.get("ports", []) or []), None, criticality)
                comparison = security_store.compare_previous(selected_ip, ranked)
                report = generate_device_pdf(device, scan_data, ranked)
                security_store.record_scan(selected_ip, scan_data, ranked, risk)
                st.session_state.assessments[selected_ip] = {
                    "scan_data": scan_data,
                    "vulnerabilities": ranked,
                    "report": report,
                    "completed_at": datetime.now().isoformat(timespec="seconds"),
                    "risk": risk,
                    "comparison": comparison,
                }
                st.success("Device assessment completed.")
            except Exception as exc:
                st.error(f"Assessment failed: {exc}")

    assessment = st.session_state.assessments.get(selected_ip)
    if not assessment:
        return

    scan_data = assessment["scan_data"]
    vulns = assessment["vulnerabilities"]
    metrics = st.columns(4)
    metrics[0].metric("Open Ports", len(scan_data.get("ports", []) or []))
    metrics[1].metric("NSE Findings", len(scan_data.get("scripts", []) or []))
    metrics[2].metric("CVE Findings", len(vulns))
    metrics[3].metric("OS", scan_data.get("os", "Unknown"))

    st.markdown('<div class="vx-section">Risk & Severity</div>', unsafe_allow_html=True)
    risk_now = assessment.get("risk") or asset_risk(vulns, len(scan_data.get("ports",[]) or []), None, security_store.criticality(selected_ip))
    r1,r2,r3,r4,r5=st.columns(5)
    r1.metric("Asset Risk", risk_now.get("asset_risk_score",0))
    r2.metric("Risk Level", risk_now.get("asset_risk_level","UNKNOWN"))
    r3.metric("Criticality", risk_now.get("asset_criticality",3))
    r4.metric("KEV", summarize(vulns)["kev"])
    r5.metric("Avg Finding Risk", summarize(vulns)["avg_risk"])
    if _is_admin():
        crit=st.select_slider("Asset criticality",options=[1,2,3,4,5],value=security_store.criticality(selected_ip),key=f"crit_{selected_ip}",help="1=Low, 5=Critical")
        if crit != security_store.criticality(selected_ip):
            security_store.set_criticality(selected_ip,crit); st.info("Criticality saved. Re-run the assessment to recalculate vulnerability risk.")
    else:
        st.caption(f"Asset criticality: {security_store.criticality(selected_ip)} · managed by administrators.")
    st.markdown('<div class="vx-section">System & Network</div>', unsafe_allow_html=True)
    st.json({
        "Operating System": scan_data.get("os", "Unknown"),
        "IP Address": scan_data.get("ip") or device.get("ip"),
        "MAC Address": scan_data.get("mac") or device.get("mac"),
        "Hostname": scan_data.get("hostname") or device.get("hostname"),
        "Vendor": scan_data.get("vendor") or device.get("vendor"),
        "OS fingerprint accuracy": scan_data.get("os_accuracy", "Unknown"),
    })

    st.markdown('<div class="vx-section">Open Ports & Services</div>', unsafe_allow_html=True)
    if scan_data.get("ports"):
        st.dataframe(scan_data["ports"], use_container_width=True, hide_index=True)
    else:
        st.success("No open TCP ports were reported in this assessment.")

    st.markdown('<div class="vx-section">Nmap Vulnerability Script Findings</div>', unsafe_allow_html=True)
    nse_findings = scan_data.get("scripts", [])
    if nse_findings:
        st.dataframe(nse_findings, use_container_width=True, hide_index=True)
        st.caption("These are Nmap NSE observations from the full 1–65,535 TCP-port assessment. Validate findings on the authorized target before remediation.")
    else:
        st.info("No Nmap NSE vulnerability-script findings were returned.")

    st.markdown('<div class="vx-section">Vulnerability Findings & Remediation</div>', unsafe_allow_html=True)
    if vulns:
        display_vulns = [{
            "CVE": v.get("cve"), "Severity": v.get("severity"), "CVSS": v.get("score"),
            "Known exploited (CISA KEV)": "Yes" if v.get("known_exploited") else "No",
            "Exploitability score": v.get("exploitability_score"),
            "Affected service": v.get("service"), "Remediation": v.get("fix"),
        } for v in vulns]
        st.dataframe(display_vulns, use_container_width=True, hide_index=True)
        st.caption("CVE findings indicate potentially affected software/versions; confirm applicability on the endpoint before taking action. CISA KEV marks vulnerabilities that CISA lists as known exploited in the wild.")
        st.markdown("#### Remediation Tracking")
        _render_remediation_controls([(selected_ip,v) for v in vulns],f"net_rm_{selected_ip.replace('.','_')}")
    else:
        st.success("No CVE matches were returned for the detected service/version data.")

    matched_agent = _agent_for_device(device, REGISTRY.list_agents())
    if matched_agent and matched_agent.get("profile"):
        st.markdown('<div class="vx-section">📦 Full Device Report</div>', unsafe_allow_html=True)
        st.caption("Combines Nmap results with authorized endpoint hardware, OS, network, software, services and user inventory.")
        _render_full_report_button(device, matched_agent, scan_data, vulns, f"device_{selected_ip.replace('.', '_')}")

    report_path = Path(assessment["report"])
    if report_path.exists():
        st.markdown('<div class="vx-section">📄 Assessment Report</div>', unsafe_allow_html=True)
        with report_path.open("rb") as pdf:
            st.download_button(
                "⬇️ Download Network Assessment PDF",
                data=pdf.read(),
                file_name=report_path.name,
                mime="application/pdf",
                key=f"download_{selected_ip}",
                use_container_width=True,
            )

    with st.expander("Historical Scan Comparison"):
        _render_history(selected_ip)
    with st.expander("Raw assessment data"):
        st.json(scan_data)


# -------------------------
# Endpoint agent section
# -------------------------
def render_agents():
    _back_button()
    _page_header("Endpoint Agents", "Manage authorized endpoint agents and inspect the full hardware, OS, network, software, service and user inventory they report.", "🤖")

    st.info("Generate a direct-run endpoint agent for an authorized Windows, macOS, or Linux device. The generated launcher is executed directly on the endpoint; no .exe/.pkg/native build step is required.")

    if AGENT_API_SERVER is None:
        st.error("The Vulnex Agent API could not start on port 8765. Stop any process using that port and restart Vulnex.")
    else:
        with st.expander("➕ Add / Generate Endpoint Agent", expanded=not bool(REGISTRY.list_agents())):
            server_url = st.text_input("Vulnex Agent Server URL", value=st.session_state.get("agent_server_url", _agent_server_url()))
            st.session_state.agent_server_url = server_url.strip().rstrip("/")
            left, right = st.columns([1, 2])
            with left:
                agent_label = st.text_input("Endpoint label", value="Authorized Endpoint")
                agent_platform = st.selectbox("Endpoint OS", ["Windows", "macOS", "Linux"], index=0)
                create_agent = st.button("➕ Generate Endpoint Agent", type="primary", use_container_width=True)
            with right:
                st.caption("macOS/Linux → .sh  •  Windows → .ps1")
                st.caption("The launcher embeds its one-time enrollment token and the complete endpoint collector.")

            if create_agent:
                try:
                    token_id, token = REGISTRY.create_enrollment(agent_label.strip() or "Authorized Endpoint")
                    scripts = _build_agent_scripts(st.session_state.agent_server_url, token, token_id)
                    st.session_state.pending_agent_scripts = scripts
                    st.session_state.pending_agent_name = agent_label.strip() or "authorized_endpoint"
                    st.session_state.pending_agent_token_id = token_id
                    st.session_state.pending_agent_token = token
                    st.session_state.pending_agent_platform = agent_platform
                    st.success(f"{agent_platform} direct-run agent generated successfully.")
                except Exception as exc:
                    st.error(f"Agent generation failed: {exc}")

        if st.session_state.get("pending_agent_scripts"):
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", st.session_state.get("pending_agent_name", "vulnex_agent"))
            platform_name = st.session_state.get("pending_agent_platform", "Windows")
            script_ext = ".ps1" if platform_name == "Windows" else ".sh"
            script = st.session_state.pending_agent_scripts[platform_name]
            filename = f"vulnex_agent_{safe_name}_{platform_name.lower().replace(' ', '_')}{script_ext}"
            st.markdown('<div class="vx-section">Generated Agent</div>', unsafe_allow_html=True)
            st.download_button(f"⬇️ Download {platform_name} Agent {script_ext}", data=script, file_name=filename, mime="text/plain", use_container_width=True)
            if platform_name == "Windows":
                st.code(f"Set-ExecutionPolicy -Scope Process Bypass\n.\\{filename}", language="powershell")
            else:
                st.code(f"chmod +x {filename}\n./{filename}", language="bash")
            st.caption("Run only on the authorized endpoint. No native installer build command is required.")

    agents = REGISTRY.list_agents()
    st.markdown('<div class="vx-section">Registered Endpoint Devices</div>', unsafe_allow_html=True)
    if not agents:
        st.info("No endpoint agents have registered yet. Use **Add / Generate Endpoint Agent** above.")
        return

    rows = []
    now = datetime.now()
    for agent in agents:
        last_seen = agent.get("last_seen", "Unknown")
        status = agent.get("status", "unknown")
        try:
            age = (now - datetime.fromisoformat(last_seen)).total_seconds()
            status = "🟢 Online" if age <= 600 else "🟠 Stale"
        except (TypeError, ValueError):
            pass
        profile = agent.get("profile", {}) or {}
        identity = profile.get("identity", {}) if isinstance(profile, dict) else {}
        network_data = profile.get("network", {}) if isinstance(profile, dict) else {}
        ips = network_data.get("ipv4_addresses", []) if isinstance(network_data, dict) else []
        rows.append({
            "Agent ID": agent.get("agent_id"), "Label": agent.get("label"),
            "Hostname": identity.get("hostname", "Unknown"), "IP": ", ".join(ips) if ips else "Unknown",
            "OS": identity.get("os", "Unknown"), "Software": len(profile.get("software", []) or []),
            "Services": len(profile.get("services", []) or []), "Users": len(profile.get("users", []) or []),
            "Status": status, "Last Seen": last_seen,
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)

    agent_options = {f"{a.get('label', 'Endpoint')} — {a.get('agent_id')}": a.get("agent_id") for a in agents}
    selected_agent_label = st.selectbox("Open endpoint device", ["Select an endpoint"] + list(agent_options))
    if selected_agent_label == "Select an endpoint":
        return

    selected_agent_id = agent_options[selected_agent_label]
    selected_agent = next((a for a in agents if a.get("agent_id") == selected_agent_id), None)
    if not selected_agent:
        return

    profile = selected_agent.get("profile", {}) or {}
    identity = profile.get("identity", {}) or {}
    hardware = profile.get("hardware", {}) or {}
    network_profile = profile.get("network", {}) or {}
    software = profile.get("software", []) or []
    services = profile.get("services", []) or []
    users = profile.get("users", []) or []
    collection = profile.get("collection", {}) or {}
    updates = profile.get("updates", {}) or {}

    st.divider()
    st.markdown(f'<div class="vx-section">🖥️ {selected_agent.get("label", "Endpoint")} — Full Inventory</div>', unsafe_allow_html=True)

    # Queue a fresh read-only inventory collection on the endpoint. The agent
    # receives this command on its next authenticated heartbeat and immediately
    # posts a fresh profile back to Vulnex.
    c_collect, c_status = st.columns([1, 2])
    with c_collect:
        if st.button("🔄 Collect Data Again", key=f"collect_agent_{selected_agent_id}", type="primary", use_container_width=True):
            if REGISTRY.request_collection(selected_agent_id):
                st.success("Collection request queued. The endpoint will refresh its inventory on the next heartbeat.")
                st.rerun()
            else:
                st.error("Endpoint is no longer registered.")
    with c_status:
        last_collection = selected_agent.get("last_collection", "Not recorded")
        requested = selected_agent.get("collection_requested_at")
        st.caption(f"Last inventory collection: {last_collection}" + (f" · Refresh requested: {requested}" if requested else ""))
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Hardware", "Collected" if hardware else "Missing")
    m2.metric("Network Interfaces", len(network_profile.get("interfaces", []) or []))
    m3.metric("Software", len(software))
    m4.metric("Services", len(services))
    m5.metric("Users", len(users))
    if collection.get("schema_version", 1) < 2 or not network_profile.get("interfaces"):
        st.warning("This endpoint appears to be using an older agent profile. Generate a fresh agent and run it on the endpoint to refresh the full inventory schema.")

    t_over, t_hw, t_net, t_sw, t_sv, t_us = st.tabs(["Overview", "Hardware", "Network", "Software", "Services", "Users"])
    with t_over:
        st.json({"Agent ID": selected_agent.get("agent_id"), "Label": selected_agent.get("label"), "Registered": selected_agent.get("registered_at"), "Last Seen": selected_agent.get("last_seen"), "Status": selected_agent.get("status"), "Identity": identity, "Collection": collection, "Updates": updates})
    with t_hw:
        if hardware:
            st.json(hardware)
        else:
            st.info("No hardware inventory has been received yet.")
    with t_net:
        if network_profile:
            st.json(network_profile)
        else:
            st.info("No network inventory has been received yet.")
    with t_sw:
        if software:
            st.dataframe(software, use_container_width=True, hide_index=True)
        else:
            st.info("No software inventory has been received yet.")
        st.markdown("**Available software/OS updates**")
        if updates.get("supported"):
            if updates.get("items"):
                st.dataframe(updates.get("items"), use_container_width=True, hide_index=True)
            else:
                st.success("No updates were reported by the native update checker.")
        else:
            st.info("Update inventory is not available on this endpoint.")
    with t_sv:
        if services:
            st.dataframe(services, use_container_width=True, hide_index=True)
        else:
            st.info("No service inventory has been received yet.")
    with t_us:
        if users:
            st.dataframe(users, use_container_width=True, hide_index=True)
        else:
            st.info("No user inventory has been received yet.")

    # Endpoint security posture and risk context.
    st.markdown('<div class="vx-section">🛡️ Endpoint Security Posture</div>', unsafe_allow_html=True)
    posture = {"Hardware":bool(hardware),"OS":bool(identity),"Network":bool(network_profile),"Software":bool(software),"Services":bool(services),"Users":bool(users)}
    pc=st.columns(6)
    for col,(label,present) in zip(pc,posture.items()): col.metric(label,"Ready" if present else "Missing")
    latest_assessment = None
    if network_profile.get("ipv4_addresses"):
        latest_assessment = st.session_state.assessments.get(network_profile["ipv4_addresses"][0]) or security_store.latest(network_profile["ipv4_addresses"][0])
    agent_ip = (network_profile.get("ipv4_addresses") or [None])[0]
    if agent_ip:
        if _is_admin():
            agent_crit=st.select_slider("Asset criticality",options=[1,2,3,4,5],value=security_store.criticality(agent_ip),key=f"agent_crit_{selected_agent_id}",help="1=Low, 5=Critical")
            if agent_crit != security_store.criticality(agent_ip):
                security_store.set_criticality(agent_ip,agent_crit); st.info("Criticality saved. Re-run the network assessment to recalculate finding and asset risk.")
        else:
            st.caption(f"Asset criticality: {security_store.criticality(agent_ip)} · managed by administrators.")
    st.caption(f"Software updates available: {updates.get('count', 0) if updates.get('supported') else 'Unknown'} (source: {updates.get('source','Unknown')})")
    if latest_assessment and isinstance(latest_assessment,dict):
        av=latest_assessment.get("vulnerabilities",[])
        ar=latest_assessment.get("risk") or latest_assessment.get("asset_risk") or {}
        st.write(f"**Network risk:** {ar.get('asset_risk_score',0)} ({ar.get('asset_risk_level','UNKNOWN')}) • **Vulnerabilities:** {len(av)}")
        if av:
            _render_remediation_controls([(network_profile["ipv4_addresses"][0],v) for v in av],f"agent_rm_{selected_agent_id}")
    # Full endpoint report without requiring an Nmap assessment.
    device = {
        "ip": (network_profile.get("ipv4_addresses") or [selected_agent.get("label", "endpoint")])[0],
        "hostname": identity.get("hostname", "Unknown"),
        "vendor": identity.get("vendor", "Unknown"),
        "device_type": identity.get("device_type", "Endpoint"),
        "mac": next((x.get("mac") for x in network_profile.get("interfaces", []) if x.get("mac")), "Unknown"),
    }
    st.markdown('<div class="vx-section">📦 Full Device Report</div>', unsafe_allow_html=True)
    st.caption("Download hardware, OS, network, software, services and user inventory for this endpoint. If a network assessment exists for the same device, it is included too.")
    latest_assessment = st.session_state.assessments.get(device["ip"]) if device.get("ip") else (security_store.latest(device["ip"]) if device.get("ip") else None)
    _render_full_report_button(device, selected_agent, (latest_assessment or {}).get("scan_data") if latest_assessment else None, (latest_assessment or {}).get("vulnerabilities") if latest_assessment else None, f"agent_{selected_agent_id}")
    with st.expander("Historical Scans & Before/After Risk"):
        _render_history(device.get("ip") if device.get("ip") else None)

    if _is_admin():
        confirm_key = f"delete_confirm_{selected_agent_id}"
        if st.button("🗑️ Delete Endpoint", key=f"delete_{selected_agent_id}", type="secondary"):
            st.session_state[confirm_key] = True
        if st.session_state.get(confirm_key):
            st.warning("This removes the endpoint from the Vulnex registry. The agent will no longer be accepted.")
            if st.button("Confirm Delete", key=f"confirm_delete_{selected_agent_id}", type="primary"):
                if REGISTRY.delete_agent(selected_agent_id):
                    st.session_state.pop(confirm_key, None)
                    st.success("Endpoint deleted from Vulnex.")
                    st.rerun()
                else:
                    st.error("Endpoint was not found.")
    else:
        st.caption("Agent deletion is restricted to administrators.")


# -------------------------
# Local endpoint section
# -------------------------
def render_local():
    _back_button()
    _page_header("Local Endpoint Inventory", "Collect deep inventory from the machine running Vulnex without installing a remote agent.", "💻")
    st.info("Collects hardware, OS, software, network, users and services from the local machine running Vulnex. Remote devices require an authorized Vulnex Agent for equivalent depth.")
    st.warning("Authorized use only: collect endpoint information from systems you own or are authorized to administer.")

    if st.button("📋 Collect This Machine's Details", type="primary", use_container_width=True):
        with st.spinner("Collecting local endpoint information..."):
            try:
                local = collect_local_profile()
                local_ips = local.get("network", {}).get("ipv4_addresses", [])
                matched = next((d for d in st.session_state.devices if d.get("ip") in local_ips), None)
                profile = DeviceProfile.from_discovered_device(matched) if matched else DeviceProfile(ip=local_ips[0] if local_ips else "local")
                profile.merge_local_profile(local)
                saved = profile_store.save(profile.to_dict())
                st.session_state.local_profile = profile.to_dict()
                st.success(f"Local device profile saved: {saved}")
            except Exception as exc:
                st.error(f"Local inventory collection failed: {exc}")

    local_profile = st.session_state.get("local_profile")
    if not local_profile:
        st.info("Click **Collect This Machine's Details** to populate the local inventory.")
        return

    p = local_profile
    updates = p.get("updates", {}) or {}
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("OS", ((p.get("os") or {}).get("os", "Unknown") if isinstance(p.get("os"), dict) else p.get("os", "Unknown")))
    m2.metric("Software", len(p.get("software", []) or []))
    m3.metric("Services", len(p.get("services", []) or []))
    m4.metric("Users", len(p.get("users", []) or []))

    tabs = st.tabs(["Overview", "Hardware", "Software", "Network", "Users", "Services"])
    with tabs[0]:
        st.json({"IP": p.get("ip"), "Hostname": p.get("hostname"), "Vendor": p.get("vendor"), "Device Type": p.get("device_type"), "OS": ((p.get("os") or {}).get("os", "Unknown") if isinstance(p.get("os"), dict) else p.get("os", "Unknown"))})
    with tabs[1]:
        st.json(p.get("hardware", {}))
    with tabs[2]:
        data = p.get("software", [])
        if data:
            st.dataframe(data, use_container_width=True, hide_index=True)
        else:
            st.info("No software inventory was returned by this collector.")
        st.markdown("**Available software/OS updates**")
        if updates.get("supported"):
            st.metric("Updates available", updates.get("count",0))
            if updates.get("items"): st.dataframe(updates.get("items"),use_container_width=True,hide_index=True)
        else:
            st.info("Update inventory is not available on this platform.")
    with tabs[3]:
        st.json(p.get("network", {}))
    with tabs[4]:
        data = p.get("users", [])
        if data:
            st.dataframe(data, use_container_width=True, hide_index=True)
        else:
            st.info("No local-user inventory was returned.")
    with tabs[5]:
        data = p.get("services", [])
        if data:
            st.dataframe(data, use_container_width=True, hide_index=True)
        else:
            st.info("No service inventory was returned.")

    st.markdown('<div class="vx-section">🔎 Local Machine Network Security Assessment</div>', unsafe_allow_html=True)
    local_ips = [str(x) for x in (p.get("network", {}).get("ipv4_addresses", []) or []) if str(x) and ":" not in str(x)]
    local_ip = p.get("ip") or (local_ips[0] if local_ips else "local")
    local_target = next((x for x in local_ips if not x.startswith("127.")), local_ip if local_ip != "local" else "127.0.0.1")
    st.caption("Vulnex can assess the local machine across the complete TCP port range (1–65,535), with service/version detection and Nmap vulnerability NSE checks. Use only on the local machine you are authorized to assess.")
    local_mode = st.radio(
        "Local assessment depth", ["Quick", "Extended"], horizontal=True, key="local_assessment_mode",
        help="Both modes scan all 65,535 TCP ports and run Nmap vulnerability NSE scripts. Extended additionally enables OS fingerprinting when privileges allow it."
    )
    local_mode_value = "1" if local_mode == "Quick" else "2"
    if st.button("🚀 Scan Local Machine — All 65,535 TCP Ports + Deep Vulnerability Assessment", key="local_full_assess", type="primary", use_container_width=True):
        with st.spinner(f"Assessing local machine ({local_target}) across all 65,535 TCP ports and vulnerability NSE checks..."):
            try:
                scan_data = run_nmap(local_target, local_mode_value)
                vulns = fetch_cves(scan_data.get("ports", []), scan_data.get("cpe", []))
                criticality = security_store.criticality(local_target)
                exposed_services = {str(x.get("service") or "").lower() for x in scan_data.get("ports", []) or []}
                ranked = enrich_vulnerabilities(vulns, criticality, exposed_services)
                for vuln in ranked:
                    vuln["fix"] = get_remediation(vuln.get("service", ""))
                    vuln["status"] = security_store.get_status(local_target, vuln)
                risk = asset_risk(ranked, len(scan_data.get("ports", []) or []), None, criticality)
                comparison = security_store.compare_previous(local_target, ranked)
                report = generate_device_pdf({
                    "ip": local_target,
                    "hostname": p.get("hostname", scan_data.get("hostname", "Unknown")),
                    "vendor": p.get("vendor", scan_data.get("vendor", "Unknown")),
                    "device_type": p.get("device_type", "Local Endpoint"),
                    "mac": p.get("mac", scan_data.get("mac", "Unknown")),
                }, scan_data, ranked)
                security_store.record_scan(local_target, scan_data, ranked, risk)
                st.session_state.assessments[local_target] = {
                    "scan_data": scan_data, "vulnerabilities": ranked, "report": report,
                    "completed_at": datetime.now().isoformat(timespec="seconds"),
                    "risk": risk, "comparison": comparison,
                }
                st.success(f"Local machine assessment completed across all 65,535 TCP ports ({local_target}).")
                local_ip = local_target
            except Exception as exc:
                st.error(f"Local machine assessment failed: {exc}")

    st.markdown('<div class="vx-section">🛡️ Local Endpoint Security Posture</div>', unsafe_allow_html=True)
    local_findings = []
    local_scan = st.session_state.assessments.get(local_ip) or security_store.latest(local_ip)
    if local_scan:
        local_findings=[(local_ip,v) for v in local_scan.get("vulnerabilities",[])]
        ar=local_scan.get("risk") or local_scan.get("asset_risk") or {}
        a,b,c,d=st.columns(4); a.metric("Asset Risk",ar.get("asset_risk_score",0)); b.metric("Risk Level",ar.get("asset_risk_level","UNKNOWN")); c.metric("Vulnerabilities",len(local_findings)); d.metric("Open Ports",len((local_scan.get("scan_data") or {}).get("ports",[]) or []))
        if local_findings: _render_remediation_controls(local_findings,"local_rm")
    else:
        st.info("No network vulnerability assessment is linked to this local endpoint yet. Endpoint inventory is available now; run a network assessment to calculate CVE/risk context.")
    if local_ip and local_ip != "local":
        local_crit=st.select_slider("Asset criticality",options=[1,2,3,4,5],value=security_store.criticality(local_ip),key="local_criticality",help="1=Low, 5=Critical")
        if local_crit != security_store.criticality(local_ip):
            security_store.set_criticality(local_ip,local_crit); st.info("Criticality saved. Re-run the assessment to recalculate risk.")
    with st.expander("Historical Local Scans"): _render_history(local_ip)

    st.markdown('<div class="vx-section">📦 Full Local Device Report</div>', unsafe_allow_html=True)
    device = {"ip": p.get("ip", "local"), "hostname": p.get("hostname", "Unknown"), "vendor": p.get("vendor", "Unknown"), "device_type": p.get("device_type", "Local Endpoint"), "mac": "Unknown"}
    local_agent_like = {"agent_id": "local", "label": p.get("hostname", "Local Endpoint"), "profile": p}
    _render_full_report_button(
        device,
        local_agent_like,
        (local_scan or {}).get("scan_data") if local_scan else None,
        (local_scan or {}).get("vulnerabilities") if local_scan else None,
        "local",
    )


# -------------------------
# Developer section
# -------------------------
def render_developer():
    _back_button()
    profile = auth_store.developer
    _page_header("Developer Details", "Project ownership, author profile and selected portfolio details.", "👨‍💻")
    d_name = html.escape(str(profile.get("name", "Vulnex Team")))
    d_desc = html.escape(str(profile.get("project_description", "Vulnex vulnerability assessment and security visibility platform.")))
    d_bio = html.escape(str(profile.get("bio", "")))
    st.markdown(f"""
    <div class="vx-card" style="min-height:unset; margin-bottom:18px;">
      <div class="vx-icon">🛡️</div>
      <div class="vx-card-title">Vulnex — Developed by {d_name}</div>
      <div class="vx-card-text">{d_desc}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### About the Developer")
    st.markdown(f"""
    <div class="vx-card" style="min-height:unset; margin-bottom:18px;">
      <div class="vx-card-text">{d_bio}</div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("### Profile")
        st.write(f"**Name:** {profile.get('name','')}")
        st.write(f"**Location:** {profile.get('location','')}")
        st.write(f"**Current role:** {profile.get('role','')}")
        st.write(f"**Vulnex role:** {profile.get('vulnex_role','')}")
        if profile.get('linkedin'):
            st.link_button("🔗 Open LinkedIn Profile", profile.get('linkedin'), use_container_width=True)
    with c2:
        st.markdown("### Vulnex")
        st.write(profile.get('project_description',''))
        st.write("Network reconnaissance with Nmap, vulnerability identification, risk analysis and structured reporting.")

    st.markdown("### Selected Certifications")
    for cert in profile.get("certifications", []):
        st.markdown(f"- {cert}")

    st.markdown("### Selected Projects")
    for project in profile.get("projects", []):
        st.markdown(f"- {project}")

    if _is_admin():
        st.markdown('<div class="vx-section">✏️ Administrator — Edit Developer Details</div>', unsafe_allow_html=True)
        with st.form("developer_edit_form"):
            name = st.text_input("Name", value=profile.get("name", ""))
            location = st.text_input("Location", value=profile.get("location", ""))
            role = st.text_input("Current role", value=profile.get("role", ""))
            vulnex_role = st.text_input("Vulnex role", value=profile.get("vulnex_role", ""))
            linkedin = st.text_input("LinkedIn URL", value=profile.get("linkedin", ""))
            bio = st.text_area("About the developer", value=profile.get("bio", ""), height=130)
            project_description = st.text_area("Vulnex project description", value=profile.get("project_description", ""), height=90)
            certifications = st.text_area("Certifications — one per line", value="\n".join(profile.get("certifications", [])), height=130)
            projects = st.text_area("Selected projects — one per line", value="\n".join(profile.get("projects", [])), height=130)
            save = st.form_submit_button("💾 Save Developer Details", type="primary", use_container_width=True)
            if save:
                auth_store.save_developer({
                    "name": name.strip(), "location": location.strip(), "role": role.strip(),
                    "vulnex_role": vulnex_role.strip(), "linkedin": linkedin.strip(), "bio": bio.strip(),
                    "project_description": project_description.strip(),
                    "certifications": certifications.splitlines(), "projects": projects.splitlines(),
                }, st.session_state.auth_user.get("username", "admin"))
                st.success("Developer details updated.")
                st.rerun()
    else:
        st.caption("Developer details are managed by administrators.")

    st.caption("Developer profile details are managed inside Vulnex and can be edited by an administrator.")


def render_account_profile():
    _back_button()
    user = dict(st.session_state.get("auth_user") or {})
    username = str(user.get("username", ""))
    live_user = auth_store.users.get(username, user)
    current_email = str(live_user.get("email", ""))

    _page_header("My Account", "Manage your Vulnex account email and password.", "👤")

    st.markdown(f"""
    <div class="vx-card" style="min-height:unset; margin-bottom:18px;">
      <div class="vx-icon">👤</div>
      <div class="vx-card-title">Account Profile</div>
      <div class="vx-card-text"><b>Username:</b> {html.escape(username)}<br>
      <b>Role:</b> {html.escape(str(live_user.get("role", "user")).title())}<br>
      <b>Email:</b> {html.escape(current_email or "Not configured")}</div>
      <div class="vx-card-stat">Change email or password securely</div>
    </div>
    """, unsafe_allow_html=True)

    with st.form("account_profile_form"):
        st.markdown("### Account details")
        email = st.text_input("Email address", value=current_email, key="account_email")
        st.markdown("### Change password")
        st.caption("Leave the password fields empty if you only want to change your email. New passwords require at least 8 characters, one uppercase letter, one number and one symbol.")
        current_password = st.text_input("Current password", type="password", key="account_current_password")
        new_password = st.text_input("New password", type="password", key="account_new_password")
        confirm_password = st.text_input("Confirm new password", type="password", key="account_confirm_password")
        save = st.form_submit_button("💾 Save Account Changes", type="primary", use_container_width=True)

    if save:
        if bool(new_password) != bool(confirm_password):
            st.error("Enter and confirm the new password together.")
        elif new_password and new_password != confirm_password:
            st.error("New password and confirmation do not match.")
        else:
            ok, message = auth_store.update_account(
                username, email, current_password if new_password else "", new_password
            )
            if ok:
                refreshed = dict(auth_store.users.get(username, {}))
                refreshed.pop("password_hash", None)
                st.session_state.auth_user = refreshed
                st.success(message)
                st.rerun()
            else:
                st.error(message)


def _render_executive_report_button():
    summary,assets,findings=_risk_metrics()
    if st.button("📑 Prepare Executive Risk Report",key="exec_risk_report",use_container_width=True):
        try:
            path=generate_executive_risk_pdf(summary,assets,findings,security_store.history)
            with open(path,"rb") as fh: data=fh.read()
            st.download_button("⬇️ Download Executive Risk Report",data=data,file_name=Path(path).name,mime="application/pdf",key="exec_risk_download",use_container_width=True)
        except Exception as exc: st.error(f"Executive report generation failed: {exc}")

# -------------------------
# Authentication / public landing page
# -------------------------
def _render_auth_landing():
    logo = Path(__file__).resolve().parent / "assets" / "vulnex_logo.png"
    left, right = st.columns([1.05, 1], gap="large")
    with left:
        if logo.exists():
            st.image(str(logo), use_container_width=True)
        else:
            st.markdown("<div class='vx-brand'>🛡️ VULNEX</div>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:1.1rem;color:#cbd5e1;font-weight:700;margin-top:-18px;'>Discover. Assess. Prioritize. Secure.</div>", unsafe_allow_html=True)
        st.markdown("<div style='color:#94a3b8;margin-top:8px;line-height:1.6;'>A unified vulnerability assessment and security visibility platform for authorized environments.</div>", unsafe_allow_html=True)
        st.markdown("<div class='vx-section'>Platform capabilities</div>", unsafe_allow_html=True)
        add_cols = st.columns(4)
        for col, icon, title in zip(add_cols, ["🌐","🤖","📊","📄"], ["Network Discovery","Endpoint Visibility","Risk Prioritization","Actionable Reports"]):
            with col:
                st.markdown(f"<div style='text-align:center;color:#cbd5e1;'><div style='font-size:1.7rem'>{icon}</div><b>{title}</b></div>", unsafe_allow_html=True)
    with right:
        st.markdown("<div class='vx-login-card'>", unsafe_allow_html=True)
        st.markdown("<h2 style='margin-bottom:4px;'>Welcome to <span style='color:#38bdf8;'>VULNEX</span></h2><div style='color:#94a3b8;margin-bottom:18px;'>Sign in to access the vulnerability assessment platform.</div>", unsafe_allow_html=True)
        login_tab, signup_tab = st.tabs(["🔐 User Login", "➕ Sign Up"])
        with login_tab:
            with st.form("user_login_form"):
                username = st.text_input("Username", key="user_login_username")
                password = st.text_input("Password", type="password", key="user_login_password")
                submit = st.form_submit_button("Login as User", type="primary", use_container_width=True)
                if submit:
                    _login("user", username, password)
        with signup_tab:
            st.caption("New accounts remain pending until an administrator approves them.")
            with st.form("user_signup_form"):
                new_username = st.text_input("Username", key="signup_username")
                email = st.text_input("Email", key="signup_email")
                new_password = st.text_input("Password", type="password", key="signup_password")
                confirm = st.text_input("Confirm password", type="password", key="signup_confirm")
                signup = st.form_submit_button("Create User Account", use_container_width=True)
                if signup:
                    if new_password != confirm:
                        st.error("Passwords do not match.")
                    else:
                        ok, msg = auth_store.signup(new_username, email, new_password)
                        (st.success if ok else st.error)(msg)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="vx-section">🔐 Admin Login</div>', unsafe_allow_html=True)
    st.caption("Administrators have full platform access, including user approval, agent deletion and developer-profile editing.")
    with st.expander("Open Administrator Login", expanded=False):
        if not auth_store.admin_exists():
            st.info("First run: create the initial administrator account. This form is shown only until an administrator exists.")
            with st.form("first_admin_setup"):
                admin_username = st.text_input("Admin username", value="admin")
                admin_password = st.text_input("Admin password", type="password")
                admin_confirm = st.text_input("Confirm admin password", type="password")
                create = st.form_submit_button("Create Administrator", type="primary", use_container_width=True)
                if create:
                    if admin_password != admin_confirm:
                        st.error("Passwords do not match.")
                    else:
                        ok, msg = auth_store.create_admin(admin_username, admin_password)
                        (st.success if ok else st.error)(msg)
                        if ok:
                            st.info("Administrator created. Use the Admin Login form below to sign in.")
        else:
            with st.form("admin_login_form"):
                admin_username = st.text_input("Admin username", key="admin_login_username")
                admin_password = st.text_input("Admin password", type="password", key="admin_login_password")
                submit = st.form_submit_button("🛡️ Login as Admin", type="primary", use_container_width=True)
                if submit:
                    _login("admin", admin_username, admin_password)

    st.markdown("<div class='vx-footer'>Vulnex • Authorized security assessment platform • Visibility | Security | Resilience</div>", unsafe_allow_html=True)


def _render_admin_controls():
    if not _is_admin():
        return
    st.markdown('<div class="vx-section">🛡️ Administrator Controls</div>', unsafe_allow_html=True)
    pending = auth_store.pending_users()
    if pending:
        st.markdown("**Pending User Approvals**")
        for user in pending:
            c1, c2, c3 = st.columns([3, 1, 1])
            with c1:
                st.write(f"**{user.get('username')}** · {user.get('email','')} · {user.get('created_at','')}")
            with c2:
                if st.button("Approve", key=f"approve_{user.get('username')}", use_container_width=True):
                    ok, msg = auth_store.set_user_status(user.get('username'), APPROVED, st.session_state.auth_user.get('username','admin'))
                    (st.success if ok else st.error)(msg)
                    st.rerun()
            with c3:
                if st.button("Reject", key=f"reject_{user.get('username')}", use_container_width=True):
                    ok, msg = auth_store.set_user_status(user.get('username'), REJECTED, st.session_state.auth_user.get('username','admin'))
                    (st.success if ok else st.error)(msg)
                    st.rerun()
    else:
        st.info("No user accounts are awaiting approval.")
    users = auth_store.all_users()
    if users:
        st.markdown("**Account Status & User Management**")
        st.dataframe([
            {"Username": u.get("username"), "Role": u.get("role"), "Status": u.get("status"), "Created": u.get("created_at"), "Last Login": u.get("last_login", "Never")}
            for u in users
        ], use_container_width=True, hide_index=True)

        deletable_users = [u for u in users if u.get("role") == "user"]
        if deletable_users:
            st.markdown("**Delete User Account**")
            st.caption("Administrator-only action. Deleting a user also revokes all active sessions for that account.")
            delete_username = st.selectbox(
                "Select user to delete",
                [u.get("username") for u in deletable_users],
                key="admin_delete_user_select",
            )
            confirm_delete_user = st.checkbox(
                "I understand that deleting this user permanently removes the account and cannot be undone from the dashboard.",
                key="admin_confirm_delete_user",
            )
            if st.button("🗑️ Delete Selected User", key="admin_delete_user_button", type="secondary", disabled=not confirm_delete_user, use_container_width=True):
                admin_username = st.session_state.auth_user.get("username", "admin")
                ok, msg = auth_store.delete_user(delete_username, admin_username)
                (st.success if ok else st.error)(msg)
                if ok:
                    st.session_state.pop("admin_confirm_delete_user", None)
                    st.rerun()


# -------------------------
# Landing page
# -------------------------
def render_home():
    if not _logged_in():
        _render_auth_landing()
        return

    _render_admin_controls()

    st.info("Network assessment is available without an endpoint agent: Vulnex scans all 65,535 TCP ports, performs service/version detection, and runs Nmap vulnerability NSE scripts. CVE matching uses NVD data; CISA KEV status is shown when available. Deep hardware/software/user inventory requires an authorized Vulnex Agent.")
    st.caption(f"Signed in as **{st.session_state.auth_user.get('username')}** · Role: **{st.session_state.auth_user.get('role','user').title()}**")
    st.warning("Authorized use only: scan networks and devices you own or have explicit permission to assess.")

    agents = REGISTRY.list_agents()
    iface, network = get_local_network()
    vuln_count = sum(len(a.get("vulnerabilities", []) or []) for a in st.session_state.assessments.values())
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Discovered Devices", len(st.session_state.devices))
    c2.metric("Endpoint Agents", len(agents))
    c3.metric("Assessed Devices", len(st.session_state.assessments))
    c4.metric("CVE Findings", vuln_count)
    st.caption(f"Active network: `{network}`  •  Interface: `{iface}`")

    st.markdown('<div class="vx-section">Security Operations</div>', unsafe_allow_html=True)
    cards = [
        ("🌐", "Network Discovery", "Discover live devices, inspect their identity and assess selected devices across all 65,535 TCP ports with service, NSE, CVE and remediation analysis.", f"{len(st.session_state.devices)} device(s) discovered", "network"),
        ("🤖", "Endpoint Agents", "Manage authorized Windows, macOS and Linux agents and inspect complete endpoint inventory: hardware, OS, network, software, services and users.", f"{len(agents)} registered agent(s)", "agents"),
    ]
    if _is_admin():
        cards.append(
            ("💻", "Local Endpoint", "Collect a deep inventory of the machine running Vulnex without installing a remote agent, including hardware, software, network, users and services.", "Local collection on demand", "local")
        )
    cols = st.columns(len(cards), gap="large")
    for col, (icon, title, desc, stat, page) in zip(cols, cards):
        with col:
            st.markdown(f'<div class="vx-card"><div class="vx-icon">{icon}</div><div class="vx-card-title">{title}</div><div class="vx-card-text">{desc}</div><div class="vx-card-stat">{stat}</div></div>', unsafe_allow_html=True)
            if st.button(f"Open {title}", key=f"home_{page}", use_container_width=True):
                _go(page)

    _render_vulnerability_dashboard()

    if _is_user():
        st.caption("User access: device discovery/assessment, report downloads and endpoint-agent configuration. Agent deletion, developer editing, account approvals and other administrative actions are restricted to administrators.")

    if _is_admin():
        st.markdown('<div class="vx-section">🔐 Platform Security</div>', unsafe_allow_html=True)
        sec1,sec2,sec3,sec4,sec5=st.columns(5)
        sec1.metric("Agent Auth","Token + Secret")
        sec2.metric("Request Validation","Enabled")
        sec3.metric("Enrollment","30 min expiry")
        sec4.metric("Audit Trail","Enabled")
        sec5.metric("Config","One-time token")
        with st.expander("Recent audit events"):
            try:
                lines=security_store.audit_file.read_text(encoding="utf-8").splitlines()[-25:]
                st.code("\n".join(lines) if lines else "No audit events yet.")
            except OSError: st.info("Audit log is not available.")

    st.markdown('<div class="vx-section">Workflow</div>', unsafe_allow_html=True)
    st.caption("Network Discovery → Select Device → Full-Port Assessment → Services/NSE → CVE & Remediation  |  Endpoint Agents → Register → Collect → Inspect Full Inventory  |  Local Endpoint → Collect → Review → Report")

    # Keep both developer and account-management cards as the final homepage section for every authenticated role.
    st.markdown('<div class="vx-section">Developer & Account</div>', unsafe_allow_html=True)
    profile = auth_store.developer or {}
    profile_name = html.escape(str(profile.get("name", "Vulnex Team")))
    profile_role = html.escape(str(profile.get("role", "Cybersecurity Developer")))
    profile_desc = html.escape(str(profile.get("project_description", "Vulnex vulnerability assessment and security visibility platform.")))
    profile_stat = "Administrator can edit details" if _is_admin() else "Developer and project details"
    account = st.session_state.get("auth_user") or {}
    account_email = html.escape(str(account.get("email", "Not configured")))
    account_role = html.escape(str(account.get("role", "user")).title())

    dev_col, account_col = st.columns(2, gap="large")
    with dev_col:
        st.markdown(
            f"""<div class="vx-card">
              <div class="vx-icon">👨‍💻</div>
              <div class="vx-card-title">Developer Details</div>
              <div class="vx-card-text"><b>{profile_name}</b> · {profile_role}<br>{profile_desc}</div>
              <div class="vx-card-stat">{profile_stat}</div>
            </div>""",
            unsafe_allow_html=True,
        )
        if st.button("Open Developer Profile", key="home_developer_profile", use_container_width=True):
            _go("developer")

    with account_col:
        st.markdown(
            f"""<div class="vx-card">
              <div class="vx-icon">👤</div>
              <div class="vx-card-title">My Account Profile</div>
              <div class="vx-card-text"><b>Username:</b> {html.escape(str(account.get('username','')))}<br>
              <b>Email:</b> {account_email}<br>
              <b>Role:</b> {account_role}</div>
              <div class="vx-card-stat">Change email and password</div>
            </div>""",
            unsafe_allow_html=True,
        )
        if st.button("Manage My Account", key="home_account_profile", use_container_width=True):
            _go("account")

    st.markdown('<div class="vx-footer">Vulnex • Authorized security assessment platform • Developed by Amar Kant Yadav / Team VORTEX</div>', unsafe_allow_html=True)


# -------------------------
# Start the selected page
# -------------------------
if not _logged_in():
    st.session_state.page = "home"

page = st.session_state.page
if page == "network" and _logged_in():
    render_network()
elif page == "agents" and _logged_in():
    render_agents()
elif page == "local" and _is_admin():
    render_local()
elif page == "developer" and _logged_in():
    render_developer()
elif page == "account" and _logged_in():
    render_account_profile()
else:
    render_home()
