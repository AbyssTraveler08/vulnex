from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class DeviceProfile:
    ip: str
    mac: str = "Unknown"
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    device_type: str = "Unknown"
    os: dict = field(default_factory=dict)
    hardware: dict = field(default_factory=dict)
    software: list[dict] = field(default_factory=list)
    network: dict = field(default_factory=dict)
    users: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    updates: dict = field(default_factory=dict)
    ports: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    security: dict = field(default_factory=dict)
    scan_metadata: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_discovered_device(cls, device):
        return cls(
            ip=device.get("ip", "Unknown"),
            mac=device.get("mac", "Unknown"),
            hostname=device.get("hostname", "Unknown"),
            vendor=device.get("vendor", "Unknown"),
            device_type=device.get("device_type", "Unknown"),
            scan_metadata={
                "discovered_at": device.get("discovered_at"),
                "profile_created_at": datetime.now().isoformat(timespec="seconds"),
            },
        )

    def merge_local_profile(self, local):
        identity = local.get("identity", {})
        self.hostname = identity.get("hostname", self.hostname)
        self.os = identity
        self.hardware = local.get("hardware", {})
        self.network.update(local.get("network", {}))
        interfaces = self.network.get("interfaces", [])
        if interfaces:
            mac = next((i.get("mac") for i in interfaces if i.get("mac") and i.get("mac") != "Unknown"), None)
            if mac:
                self.mac = mac
        self.software = local.get("software", [])
        self.users = local.get("users", [])
        self.services = local.get("services", [])
        self.updates = local.get("updates", {})
        self.scan_metadata.update(local.get("collection", {}))
