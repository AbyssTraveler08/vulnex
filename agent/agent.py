"""Vulnex Endpoint Agent runtime for direct-run OS launchers.

Run only on endpoints you own or are explicitly authorized to manage.
"""
from __future__ import annotations

import json
import os
import platform
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from collector import collect_local_profile


def _data_dir() -> Path:
    override = os.environ.get("VULNEX_AGENT_DATA_DIR")
    if override:
        return Path(override).expanduser()
    system = platform.system()
    if system == "Windows":
        root = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(root) / "Vulnex" / "Agent"
    if system == "Darwin":
        return Path("/Library/Application Support/Vulnex/Agent")
    return Path("/var/lib/vulnex-agent")


def _config_candidates() -> list[Path]:
    base = Path(__file__).resolve().parent
    candidates = [base / "agent_config.json", _data_dir() / "agent_config.json"]
    if platform.system() == "Darwin":
        candidates.append(Path("/Library/VulnexAgent/agent_config.json"))
    return candidates


DATA_DIR = _data_dir()
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_PATH = DATA_DIR / "agent_state.json"


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def load_config():
    for path in _config_candidates():
        data = load_json(path, {})
        if data:
            return data, path
    return {}, _config_candidates()[0]


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def post(url, payload):
    body = json.dumps(payload).encode("utf-8")
    request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    config, config_path = load_config()
    server = str(config.get("server_url", "")).rstrip("/")
    enrollment_token = str(config.get("enrollment_token", ""))
    heartbeat_interval = max(30, int(config.get("heartbeat_seconds", 60)))
    collection_interval = max(60, int(config.get("collection_seconds", 300)))
    if not server:
        raise SystemExit("Vulnex Agent is not configured. Generate a fresh direct-run agent script from the Vulnex dashboard.")

    state = load_json(STATE_PATH, {})

    if not state.get("agent_id") or not state.get("agent_secret"):
        if not enrollment_token:
            raise SystemExit("Vulnex Agent enrollment is missing. Generate a fresh endpoint agent from the dashboard.")
        profile = collect_local_profile()
        result = post(server + "/api/agent/register", {
            "enrollment_token": enrollment_token,
            "profile": profile,
        })
        state = {"agent_id": result["agent_id"], "agent_secret": result["agent_secret"]}
        save_json(STATE_PATH, state)
        config["enrollment_token"] = ""
        save_json(config_path, config)
        print("Vulnex agent registered successfully:", state["agent_id"])

    agent_id = state["agent_id"]
    agent_secret = state["agent_secret"]
    next_collection = 0.0

    while True:
        try:
            profile = None
            if time.time() >= next_collection:
                profile = collect_local_profile()
            result = post(server + "/api/agent/heartbeat", {
                "agent_id": agent_id,
                "agent_secret": agent_secret,
                "profile": profile,
            })
            if profile is not None:
                next_collection = time.time() + collection_interval
                print("Vulnex inventory collection accepted.")
            if result.get("collect_now"):
                refreshed = collect_local_profile()
                post(server + "/api/agent/heartbeat", {
                    "agent_id": agent_id,
                    "agent_secret": agent_secret,
                    "profile": refreshed,
                })
                next_collection = time.time() + collection_interval
                print("Vulnex requested inventory refresh accepted.")
            else:
                print("Vulnex agent heartbeat accepted.")
        except (HTTPError, URLError, OSError, ValueError, KeyError) as exc:
            print("Vulnex agent communication failed:", exc)
        time.sleep(heartbeat_interval)


if __name__ == "__main__":
    main()
