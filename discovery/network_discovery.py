"""Network-wide asset discovery for Vulnex.

Discovery is intentionally limited to the local network/interface selected by the
operator. Use only on networks you own or are explicitly authorized to assess.

The discovery engine uses multiple local-network techniques because a single
Nmap host-discovery probe can miss clients that block ICMP/TCP probes or when
Nmap is running without raw-packet privileges on macOS/Linux.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import re
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime

from nmap_locator import find_nmap, nmap_install_message

try:
    import netifaces
except ImportError:
    netifaces = None


@dataclass
class Device:
    ip: str
    mac: str = "Unknown"
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    device_type: str = "Unknown"
    status: str = "up"
    discovered_at: str = ""


def get_local_ip() -> str:
    """Return the IPv4 address used for normal outbound traffic."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def get_local_network() -> tuple[str, str]:
    """Return (interface, CIDR) for the active IPv4 interface."""
    local_ip = get_local_ip()

    if netifaces:
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                ip = addr.get("addr")
                if ip != local_ip:
                    continue
                netmask = addr.get("netmask", "255.255.255.0")
                network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                return iface, str(network)

    octets = local_ip.split(".")
    if len(octets) == 4:
        return "auto", ".".join(octets[:3]) + ".0/24"
    return "unknown", "127.0.0.1/32"


def _resolve_hostname(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".") if name and name != ip else "Unknown"
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"


def _classify(device: Device) -> str:
    text = f"{device.hostname} {device.vendor}".lower()
    if any(x in text for x in ("router", "gateway", "mikrotik", "cisco", "tp-link", "netgear")):
        return "Network Device"
    if any(x in text for x in ("printer", "hp inc", "canon", "epson", "brother")):
        return "Printer"
    if any(x in text for x in ("apple", "iphone", "ipad", "android")):
        return "Mobile"
    return "Endpoint"


def _parse_nmap_xml(path: str) -> list[Device]:
    root = ET.parse(path).getroot()
    now = datetime.now().isoformat(timespec="seconds")
    devices = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = "Unknown"
        mac = "Unknown"
        vendor = "Unknown"

        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", ip)
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", mac)
                vendor = addr.get("vendor", vendor)

        hostname = "Unknown"
        hn = host.find("./hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", hostname)

        device = Device(ip=ip, mac=mac, hostname=hostname, vendor=vendor, discovered_at=now)
        device.device_type = _classify(device)
        if ip != "Unknown":
            devices.append(device)

    return devices


def _parse_arp_table(interface: str | None = None, network: ipaddress.IPv4Network | None = None) -> list[Device]:
    """Read the local macOS/Linux neighbor cache as a discovery source."""
    candidates = []
    found = shutil.which("arp")
    if found:
        candidates.append(found)
    candidates.extend(["/usr/sbin/arp", "/usr/bin/arp"])
    outputs = []
    for arp_path in dict.fromkeys(candidates):
        for args in (("-an",), ("-a",)):
            try:
                result = subprocess.run([arp_path, *args], capture_output=True, text=True, timeout=10, env=os.environ.copy())
            except (FileNotFoundError, subprocess.SubprocessError):
                continue
            if result.stdout:
                outputs.append(result.stdout)
            if result.returncode == 0 and result.stdout:
                break
    if not outputs:
        return []
    now = datetime.now().isoformat(timespec="seconds")
    devices, seen = [], set()
    patterns = [
        re.compile(r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(?P<mac>[0-9a-fA-F:.-]+)(?:\s+on\s+(?P<iface>\S+))?"),
        re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?:dev\s+(?P<iface>\S+)\s+)?(?:lladdr|at)\s+(?P<mac>[0-9a-fA-F:.-]+)", re.I),
    ]
    for output in outputs:
        for pattern in patterns:
            for match in pattern.finditer(output):
                ip, mac = match.group("ip"), match.group("mac")
                iface = match.groupdict().get("iface")
                if interface and interface not in {"auto", "unknown"} and iface and iface != interface:
                    continue
                if mac.lower() in {"incomplete", "ff:ff:ff:ff:ff:ff"} or ip in seen:
                    continue
                try:
                    parsed_ip = ipaddress.ip_address(ip)
                    if parsed_ip.version != 4 or parsed_ip.is_multicast or parsed_ip.is_unspecified or (network is not None and parsed_ip not in network):
                        continue
                except ValueError:
                    continue
                seen.add(ip)
                d = Device(ip=ip, mac=mac.upper(), discovered_at=now)
                d.device_type = _classify(d)
                devices.append(d)
    return devices


def _nmap_privilege_status() -> tuple[bool, str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True, "running as root"
    sudo = shutil.which("sudo") or "/usr/bin/sudo"
    try:
        r = subprocess.run([sudo, "-n", "true"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0: return True, "sudo credentials available"
    except (OSError, subprocess.SubprocessError): pass
    return False, "not privileged"

def _run_nmap_discovery(nmap_path: str, net: ipaddress.IPv4Network, interface: str) -> tuple[list[Device], str]:
    """Run Nmap discovery, using cached sudo credentials when available."""
    privileged, _ = _nmap_privilege_status()
    base_attempts = [["-sn", "-n", "-PR"], ["-sn", "-n", "-PE", "-PS22,80,443,445,3389", "-PA80,443,445,3389"]]
    last_error = ""
    for flags in base_attempts:
        cmd = [nmap_path, *flags]
        if privileged and hasattr(os, "geteuid") and os.geteuid() != 0:
            cmd = [shutil.which("sudo") or "/usr/bin/sudo", "-n", *cmd]
        with tempfile.NamedTemporaryFile(prefix="vulnex_discovery_", suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name
        cmd += ["-oX", xml_path]
        if interface and interface not in {"auto", "unknown"}: cmd += ["-e", interface]
        cmd.append(str(net))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                devices = _parse_nmap_xml(xml_path)
                if devices: return devices, "Nmap"
            last_error = (result.stderr or result.stdout).strip()
        except (FileNotFoundError, subprocess.SubprocessError) as exc:
            last_error = str(exc)
        finally:
            try: os.remove(xml_path)
            except OSError: pass
    return [], last_error

def _merge_devices(*device_lists: list[Device]) -> list[dict]:
    merged: dict[str, Device] = {}
    for devices in device_lists:
        for device in devices:
            if device.ip == "Unknown":
                continue
            existing = merged.get(device.ip)
            if existing is None:
                merged[device.ip] = device
                continue
            if existing.mac == "Unknown" and device.mac != "Unknown":
                existing.mac = device.mac
            if existing.hostname == "Unknown" and device.hostname != "Unknown":
                existing.hostname = device.hostname
            if existing.vendor == "Unknown" and device.vendor != "Unknown":
                existing.vendor = device.vendor
            existing.device_type = _classify(existing)

    # Reverse DNS is best-effort; many phones/IoT devices intentionally do not
    # publish a hostname. Never label those as identified when no name exists.
    for device in merged.values():
        if device.hostname == "Unknown":
            device.hostname = _resolve_hostname(device.ip)
        device.device_type = _classify(device)

    return [asdict(d) for d in sorted(merged.values(), key=lambda d: ipaddress.ip_address(d.ip))]


def get_discovery_status() -> dict:
    privileged, reason = _nmap_privilege_status()
    arp = shutil.which("arp") or ("/usr/sbin/arp" if os.path.exists("/usr/sbin/arp") else None)
    return {"nmap": find_nmap(), "privileged": privileged, "privilege_reason": reason, "arp": arp}


def discover_devices(network: str | None = None, interface: str | None = None) -> list[dict]:
    """Discover live hosts on the authorized local network.

    Nmap is the primary source. The local ARP cache is merged as a fallback and
    supplement. No arbitrary public-network discovery is permitted here.
    """
    detected_interface, detected_network = get_local_network()
    network = network or detected_network
    interface = interface or detected_interface

    net = ipaddress.ip_network(network, strict=False)
    if not (net.is_private or net.is_loopback or net.is_link_local):
        raise ValueError("Vulnex discovery only permits private/loopback/link-local networks in this phase.")

    nmap_path = find_nmap()
    if not nmap_path:
        raise RuntimeError(nmap_install_message())

    nmap_devices, nmap_error = _run_nmap_discovery(nmap_path, net, interface)
    arp_devices = _parse_arp_table(interface, net)
    merged = _merge_devices(nmap_devices, arp_devices)

    if not merged and nmap_error:
        # Keep the original actionable error if Nmap genuinely failed.
        raise RuntimeError(nmap_error or "Nmap host discovery failed.")

    return merged
