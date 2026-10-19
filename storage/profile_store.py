import json
import re
from pathlib import Path


class ProfileStore:
    def __init__(self, root="scans/profiles"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _safe(value):
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value))

    def save(self, profile):
        path = self.root / f"{self._safe(profile.get('ip', 'unknown'))}.json"
        path.write_text(json.dumps(profile, indent=2, default=str), encoding="utf-8")
        return str(path)

    def load(self, ip):
        path = self.root / f"{self._safe(ip)}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
