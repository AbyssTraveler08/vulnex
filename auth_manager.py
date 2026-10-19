"""Vulnex local authentication and role-based access control.

Authentication is intentionally self-contained for the project deployment:
- passwords are stored as salted PBKDF2-SHA256 hashes, never plaintext
- new users start in a pending state and require admin approval
- the built-in administrator is created through a first-run setup form
- developer profile content is persisted separately so an admin can edit it
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROLES = {"admin", "user"}
PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"

DEFAULT_DEVELOPER = {
    "name": "Amar Kant Yadav",
    "location": "India",
    "role": "Tech Lead — Cyber Shield Centre",
    "vulnex_role": "Team Lead — Team VORTEX",
    "linkedin": "https://www.linkedin.com/in/amar-kant-yadav/",
    "bio": (
        "Amar Kant Yadav is a cybersecurity-focused developer and Tech Lead at Cyber Shield Centre. "
        "His work spans vulnerability assessment, network security, endpoint monitoring, Python-based "
        "security tooling and security analysis. Vulnex is presented as a Team VORTEX project focused "
        "on network vulnerability assessment, endpoint visibility, risk analysis and reporting."
    ),
    "project_description": (
        "Vulnex is a Python and Nmap-based vulnerability scanning and reporting platform with a Streamlit dashboard."
    ),
    "certifications": [
        "Cybersecurity Career Starter Certification (CCSC) — Hack & Fix",
        "Certified in Cybersecurity — ISC2",
        "Python for Cybersecurity Specialization — InfoSEC",
        "Ethical Hacking Specialization — LearnKartS",
        "Penetration Testing, Threat Hunting, and Cryptography — Coursera",
    ],
    "projects": [
        "VULNEX — Network vulnerability scanning, Nmap reconnaissance, risk analysis and security reporting.",
        "Secure File Transfer Monitoring System — Real-time file activity monitoring and integrity verification.",
        "Network Interface MAC Address Management Tool — Controlled Linux MAC-address management.",
        "Phishing-Detector — Python/Flask phishing-link detection using URL/domain heuristics.",
    ],
}


class AuthStore:
    def __init__(self, root: str = "scans/auth"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.users_file = self.root / "users.json"
        self.developer_file = self.root / "developer.json"
        self.audit_file = self.root / "auth_audit.log"
        self.sessions_file = self.root / "sessions.json"
        self.rate_limit_file = self.root / "login_rate_limits.json"
        self.users = self._load(self.users_file, {})
        self.sessions = self._load(self.sessions_file, {})
        self.rate_limits = self._load(self.rate_limit_file, {})
        self.developer = self._load(self.developer_file, DEFAULT_DEVELOPER.copy())
        self._ensure_developer_defaults()

    @staticmethod
    def _load(path: Path, default):
        if not path.exists():
            return default
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value
        except (OSError, json.JSONDecodeError):
            return default

    @staticmethod
    def _hash_password(password: str, salt: bytes | None = None) -> str:
        salt = salt or secrets.token_bytes(16)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
        return f"pbkdf2_sha256$210000${salt.hex()}${derived.hex()}"

    @staticmethod
    def _verify_password(password: str, encoded: str) -> bool:
        try:
            scheme, iterations, salt_hex, digest_hex = encoded.split("$", 3)
            if scheme != "pbkdf2_sha256":
                return False
            derived = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
            )
            return hmac.compare_digest(derived.hex(), digest_hex)
        except (ValueError, TypeError):
            return False

    def _save_sessions(self):
        self.sessions_file.write_text(json.dumps(self.sessions, indent=2), encoding="utf-8")

    def _save_rate_limits(self):
        self.rate_limit_file.write_text(json.dumps(self.rate_limits, indent=2), encoding="utf-8")

    @staticmethod
    def _utc_now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _parse_time(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _token_digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(self, username: str, role: str) -> str:
        token = secrets.token_urlsafe(48)
        digest = self._token_digest(token)
        now = self._utc_now().isoformat()
        self.sessions[digest] = {
            "username": username,
            "role": role,
            "created_at": now,
            "last_seen": now,
        }
        self._save_sessions()
        return token

    def get_session(self, token: str | None) -> dict | None:
        if not token:
            return None
        digest = self._token_digest(token)
        session = self.sessions.get(digest)
        if not session:
            return None
        username = str(session.get("username", ""))
        user = self.users.get(username)
        if not user or user.get("status") != APPROVED or user.get("role") != session.get("role"):
            self.sessions.pop(digest, None)
            self._save_sessions()
            return None
        session["last_seen"] = self._utc_now().isoformat()
        self._save_sessions()
        public = dict(user)
        public.pop("password_hash", None)
        return public

    def revoke_session(self, token: str | None, username: str = ""):
        if not token:
            return
        digest = self._token_digest(token)
        session = self.sessions.pop(digest, None)
        self._save_sessions()
        if session:
            self._audit("SESSION_REVOKED", username or session.get("username", ""))

    def revoke_user_sessions(self, username: str):
        changed = False
        for digest, session in list(self.sessions.items()):
            if session.get("username") == username:
                self.sessions.pop(digest, None)
                changed = True
        if changed:
            self._save_sessions()

    def login_allowed(self, ip: str) -> tuple[bool, int]:
        ip = ip or "unknown"
        entry = self.rate_limits.get(ip, {})
        blocked_until = self._parse_time(entry.get("blocked_until"))
        now = self._utc_now()
        if blocked_until and blocked_until > now:
            return False, max(1, int((blocked_until - now).total_seconds()))
        if blocked_until and blocked_until <= now:
            self.rate_limits.pop(ip, None)
            self._save_rate_limits()
        return True, 0

    def record_login_failure(self, ip: str, username: str = "") -> tuple[bool, int]:
        ip = ip or "unknown"
        allowed, remaining = self.login_allowed(ip)
        if not allowed:
            return False, remaining
        entry = self.rate_limits.setdefault(ip, {"failed_attempts": 0})
        entry["failed_attempts"] = int(entry.get("failed_attempts", 0)) + 1
        entry["last_failed_at"] = self._utc_now().isoformat()
        if entry["failed_attempts"] >= 5:
            blocked_until = self._utc_now() + timedelta(hours=1)
            entry["blocked_until"] = blocked_until.isoformat()
            self._save_rate_limits()
            self._audit("LOGIN_IP_BLOCKED", username, f"ip={ip}; blocked_for=1h")
            return False, 3600
        self._save_rate_limits()
        self._audit("LOGIN_FAILED", username, f"ip={ip}; attempt={entry['failed_attempts']}/5")
        return True, 5 - entry["failed_attempts"]

    def clear_login_failures(self, ip: str):
        ip = ip or "unknown"
        if ip in self.rate_limits:
            self.rate_limits.pop(ip, None)
            self._save_rate_limits()

    def _save_users(self):
        self.users_file.write_text(json.dumps(self.users, indent=2), encoding="utf-8")

    def _save_developer(self):
        self.developer_file.write_text(json.dumps(self.developer, indent=2, ensure_ascii=False), encoding="utf-8")

    def _audit(self, action: str, username: str = "", details: str = ""):
        with self.audit_file.open("a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now().isoformat(timespec='seconds')} | {action} | {username} | {details}\n")

    def _ensure_developer_defaults(self):
        changed = False
        for key, value in DEFAULT_DEVELOPER.items():
            if key not in self.developer:
                self.developer[key] = value
                changed = True
        if changed or not self.developer_file.exists():
            self._save_developer()

    def admin_exists(self) -> bool:
        return any(u.get("role") == "admin" for u in self.users.values())

    def create_admin(self, username: str, password: str) -> tuple[bool, str]:
        username = username.strip()
        if self.admin_exists():
            return False, "An administrator already exists."
        if not username or len(username) < 3:
            return False, "Admin username must contain at least 3 characters."
        if len(password) < 10:
            return False, "Admin password must contain at least 10 characters."
        if username.lower() in {k.lower() for k in self.users}:
            return False, "That username already exists."
        self.users[username] = {
            "username": username,
            "password_hash": self._hash_password(password),
            "role": "admin",
            "status": APPROVED,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "approved_at": datetime.now().isoformat(timespec="seconds"),
        }
        self._save_users()
        self._audit("ADMIN_CREATED", username)
        return True, "Administrator account created."

    def signup(self, username: str, email: str, password: str) -> tuple[bool, str]:
        username = username.strip()
        email = email.strip().lower()
        if not username or len(username) < 3:
            return False, "Username must contain at least 3 characters."
        if not email or "@" not in email:
            return False, "Enter a valid email address."
        if len(password) < 8:
            return False, "Password must contain at least 8 characters."
        if any(k.lower() == username.lower() for k in self.users):
            return False, "That username is already registered."
        if any(u.get("email", "").lower() == email for u in self.users.values()):
            return False, "That email is already registered."
        self.users[username] = {
            "username": username,
            "email": email,
            "password_hash": self._hash_password(password),
            "role": "user",
            "status": PENDING,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        self._save_users()
        self._audit("USER_SIGNUP", username, "pending approval")
        return True, "Account created. An administrator must approve it before you can log in."

    def authenticate(self, username: str, password: str, role: str) -> tuple[bool, dict | str]:
        user = self.users.get(username.strip())
        if not user:
            return False, "Invalid credentials."
        if user.get("role") != role:
            return False, "Use the correct login area for this account."
        if not self._verify_password(password, user.get("password_hash", "")):
            return False, "Invalid credentials."
        if role == "user" and user.get("status") != APPROVED:
            self._audit("LOGIN_BLOCKED", username, user.get("status", "pending"))
            if user.get("status") == REJECTED:
                return False, "Your account was not approved by an administrator."
            return False, "Your account is awaiting administrator approval."
        if role == "admin" and user.get("status") != APPROVED:
            return False, "Administrator account is not active."
        user["last_login"] = datetime.now().isoformat(timespec="seconds")
        self._save_users()
        self._audit("LOGIN_SUCCESS", username, role)
        public = dict(user)
        public.pop("password_hash", None)
        return True, public

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        if len(password) < 8:
            return False, "Password must contain at least 8 characters."
        if not any(ch.isupper() for ch in password):
            return False, "Password must contain at least one uppercase letter."
        if not any(ch.isdigit() for ch in password):
            return False, "Password must contain at least one number."
        if not any(not ch.isalnum() for ch in password):
            return False, "Password must contain at least one symbol."
        return True, ""

    def update_account(self, username: str, email: str, current_password: str = "", new_password: str = "") -> tuple[bool, str]:
        username = username.strip()
        user = self.users.get(username)
        if not user:
            return False, "Account not found."

        old_email = str(user.get("email", "")).lower()
        email = email.strip().lower()
        if not email or "@" not in email:
            return False, "Enter a valid email address."
        if any(
            key != username and str(other.get("email", "")).lower() == email
            for key, other in self.users.items()
        ):
            return False, "That email address is already in use."

        changing_password = bool(new_password)
        if changing_password:
            if not self._verify_password(current_password, user.get("password_hash", "")):
                return False, "Current password is incorrect."
            valid, message = self.validate_password_strength(new_password)
            if not valid:
                return False, message
            if self._verify_password(new_password, user.get("password_hash", "")):
                return False, "New password must be different from the current password."
            user["password_hash"] = self._hash_password(new_password)
            user["password_changed_at"] = datetime.now().isoformat(timespec="seconds")

        user["email"] = email
        self._save_users()
        self._audit(
            "ACCOUNT_UPDATED",
            username,
            f"email_changed={'yes' if email != old_email else 'no'}; password_changed={'yes' if changing_password else 'no'}",
        )
        return True, "Account details updated successfully."

    def pending_users(self) -> list[dict]:
        return [dict(u) for u in self.users.values() if u.get("role") == "user" and u.get("status") == PENDING]

    def all_users(self) -> list[dict]:
        return sorted(
            [dict(u) for u in self.users.values()],
            key=lambda x: (x.get("role") != "admin", x.get("created_at", "")),
        )

    def set_user_status(self, username: str, status: str, admin_username: str) -> tuple[bool, str]:
        if status not in {APPROVED, REJECTED, PENDING}:
            return False, "Invalid account status."
        user = self.users.get(username)
        if not user or user.get("role") != "user":
            return False, "User account not found."
        user["status"] = status
        user["approved_at"] = datetime.now().isoformat(timespec="seconds") if status == APPROVED else user.get("approved_at")
        self._save_users()
        self._audit("USER_STATUS_CHANGED", username, f"{status} by {admin_username}")
        return True, f"{username} is now {status}."

    def delete_user(self, username: str, admin_username: str) -> tuple[bool, str]:
        """Delete a non-admin user account and revoke all of its active sessions."""
        username = str(username or "").strip()
        admin_username = str(admin_username or "").strip()
        if not username:
            return False, "Username is required."
        if username == admin_username:
            return False, "You cannot delete your own administrator account."
        user = self.users.get(username)
        if not user:
            return False, "User account not found."
        if user.get("role") == "admin":
            return False, "Administrator accounts cannot be deleted from this control."

        self.users.pop(username, None)
        self.revoke_user_sessions(username)
        self._save_users()
        self._audit("USER_DELETED", username, f"deleted by {admin_username}")
        return True, f"User account '{username}' deleted successfully."

    def save_developer(self, profile: dict, admin_username: str):
        clean = dict(DEFAULT_DEVELOPER)
        clean.update(profile)
        for key in ("certifications", "projects"):
            value = clean.get(key, [])
            if isinstance(value, str):
                value = [x.strip() for x in value.splitlines() if x.strip()]
            clean[key] = value if isinstance(value, list) else []
        self.developer = clean
        self._save_developer()
        self._audit("DEVELOPER_PROFILE_UPDATED", admin_username)
