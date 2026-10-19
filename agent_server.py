"""Vulnex Agent API server.

The dashboard creates one-time enrollment tokens. An endpoint agent can only
register when it possesses a token created from the Vulnex dashboard.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


class AgentRegistry:
    def __init__(self, root: str = "scans/agents"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.pending_file = self.root / "pending_enrollments.json"
        self.agents_file = self.root / "agents.json"
        self.audit_file = self.root / "audit.log"
        self.lock = threading.Lock()
        self.pending = self._load(self.pending_file, {})
        self.agents = self._load(self.agents_file, {})

    @staticmethod
    def _load(path: Path, default):
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _audit(self, action, agent_id):
        try:
            with self.audit_file.open("a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat(timespec='seconds')} | {action} | {agent_id}\n")
        except OSError:
            pass

    def _save(self):
        self.pending_file.write_text(json.dumps(self.pending, indent=2), encoding="utf-8")
        self.agents_file.write_text(json.dumps(self.agents, indent=2, default=str), encoding="utf-8")

    @staticmethod
    def _valid_profile(profile):
        if not isinstance(profile, dict):
            return False
        # Keep telemetry bounded and JSON-like; never execute or interpret profile values.
        allowed={"identity","hardware","network","software","services","users","updates","collection"}
        if any(k not in allowed for k in profile.keys()):
            return False
        for key in ("software","services","users"):
            value=profile.get(key,[])
            if not isinstance(value,list) or len(value)>10000: return False
        return True

    def create_enrollment(self, label: str) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        token_id = secrets.token_hex(8)
        with self.lock:
            self.pending[token_id] = {
                "label": label or "Vulnex Endpoint",
                "token_hash": self._hash(token),
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "expires_at": (datetime.now() + timedelta(minutes=30)).isoformat(timespec="seconds"),
                "used": False,
            }
            self._save()
        return token_id, token

    def register(self, token: str, profile: dict):
        if not token or not self._valid_profile(profile):
            return None
        token_hash = self._hash(token)
        now_dt = datetime.now()
        with self.lock:
            match_id = next(
                (k for k, v in self.pending.items() if not v.get("used") and v.get("token_hash") == token_hash
                 and (not v.get("expires_at") or datetime.fromisoformat(v["expires_at"]) >= now_dt)),
                None,
            )
            if not match_id:
                return None

            pending = self.pending[match_id]
            agent_id = "agent-" + secrets.token_hex(10)
            agent_secret = secrets.token_urlsafe(40)
            now = datetime.now().isoformat(timespec="seconds")
            self.pending[match_id]["used"] = True
            self.pending[match_id]["used_at"] = now
            self.agents[agent_id] = {
                "agent_id": agent_id,
                "label": pending.get("label", "Vulnex Endpoint"),
                "secret_hash": self._hash(agent_secret),
                "registered_at": now,
                "last_seen": now,
                "status": "online",
                "profile": profile,
            }
            self._save()
            self._audit("AGENT_REGISTERED", agent_id)
            return {"agent_id": agent_id, "agent_secret": agent_secret}

    def heartbeat(self, agent_id: str, agent_secret: str, profile: dict | None = None) -> tuple[bool, bool]:
        if not agent_id or not agent_secret or (profile is not None and not self._valid_profile(profile)):
            return False, False
        with self.lock:
            agent = self.agents.get(agent_id)
            if not agent or not secrets.compare_digest(agent.get("secret_hash", ""), self._hash(agent_secret)):
                return False, False
            agent["last_seen"] = datetime.now().isoformat(timespec="seconds")
            agent["status"] = "online"
            if profile is not None:
                agent["profile"] = profile
                agent["last_collection"] = agent["last_seen"]
            collect_now = bool(agent.pop("collect_now", False))
            self._save()
            self._audit("AGENT_HEARTBEAT", agent_id)
            return True, collect_now

    def request_collection(self, agent_id: str) -> bool:
        with self.lock:
            agent = self.agents.get(agent_id)
            if not agent:
                return False
            agent["collect_now"] = True
            agent["collection_requested_at"] = datetime.now().isoformat(timespec="seconds")
            self._save()
            self._audit("AGENT_COLLECTION_REQUESTED", agent_id)
            return True

    def delete_agent(self, agent_id: str) -> bool:
        with self.lock:
            if agent_id not in self.agents:
                return False
            del self.agents[agent_id]
            self._save()
            self._audit("AGENT_DELETED", agent_id)
            return True

    def list_agents(self) -> list[dict]:
        with self.lock:
            result = []
            for agent in self.agents.values():
                item = dict(agent)
                item.pop("secret_hash", None)
                result.append(item)
            return sorted(result, key=lambda x: x.get("last_seen", ""), reverse=True)


REGISTRY = AgentRegistry()


class AgentRequestHandler(BaseHTTPRequestHandler):
    server_version = "VulnexAgentAPI/1.0"

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 5_000_000:
                return None
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None

    def do_GET(self):
        if urlparse(self.path).path == "/api/agent/health":
            self._json(200, {"service": "vulnex-agent-api", "status": "ok"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        data = self._read_json()
        if not isinstance(data, dict):
            self._json(400, {"error": "invalid JSON request"})
            return
        if self.headers.get("Content-Type","").split(";")[0].lower() != "application/json":
            self._json(415, {"error": "Content-Type must be application/json"})
            return

        if path == "/api/agent/register":
            token = str(data.get("enrollment_token", ""))
            profile = data.get("profile") or {}
            if not token:
                self._json(400, {"error": "enrollment_token is required"})
                return
            result = REGISTRY.register(token, profile)
            if not result:
                self._json(403, {"error": "invalid or already-used enrollment token"})
                return
            self._json(201, result)
            return

        if path == "/api/agent/heartbeat":
            ok, collect_now = REGISTRY.heartbeat(
                str(data.get("agent_id", "")),
                str(data.get("agent_secret", "")),
                data.get("profile"),
            )
            if ok:
                self._json(200, {"status": "accepted", "collect_now": collect_now})
            else:
                self._json(403, {"error": "agent authentication failed"})
            return

        if path == "/api/agent/collect":
            agent_id = str(data.get("agent_id", ""))
            agent_secret = str(data.get("agent_secret", ""))
            if not agent_id or not agent_secret:
                self._json(400, {"error": "agent_id and agent_secret are required"})
                return
            with REGISTRY.lock:
                agent = REGISTRY.agents.get(agent_id)
                valid = bool(agent and secrets.compare_digest(agent.get("secret_hash", ""), REGISTRY._hash(agent_secret)))
            if not valid:
                self._json(403, {"error": "agent authentication failed"})
                return
            if REGISTRY.request_collection(agent_id):
                self._json(202, {"status": "queued"})
            else:
                self._json(404, {"error": "agent not found"})
            return

        self._json(404, {"error": "not found"})

    def log_message(self, format, *args):
        return


def start_agent_server(host: str = "0.0.0.0", port: int = 8765):
    server = ThreadingHTTPServer((host, port), AgentRequestHandler)
    thread = threading.Thread(target=server.serve_forever, name="vulnex-agent-api", daemon=True)
    thread.start()
    return server
