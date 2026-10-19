"""Vulnex authorized endpoint inventory collector.

The collector is intentionally read-only. It gathers hardware, network, software,
services, users, and OS information using Python stdlib plus native read-only
commands available on Windows, macOS, and Linux.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path


def _run(command: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            errors="replace"
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _json_output(command: list[str], timeout: int = 30) -> list[dict]:
    output = _run(command, timeout)
    if not output:
        return []
    try:
        value = json.loads(output)
        if isinstance(value, dict):
            return [value]
        return value if isinstance(value, list) else []
    except json.JSONDecodeError:
        return []


def collect_identity() -> dict:
    system = platform.system()
    return {
        "hostname": socket.gethostname(),
        "os": system,
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "Unknown",
        "python_version": platform.python_version(),
        "current_user": os.environ.get("USERNAME") or os.environ.get("USER") or "Unknown",
    }


def _ram_gb() -> float | str:
    system = platform.system()
    if system == "Linux":
        value = _run(["bash", "-lc", "awk '/MemTotal/ {print $2}' /proc/meminfo"])
    elif system == "Darwin":
        value = _run(["sysctl", "-n", "hw.memsize"])
    elif system == "Windows":
        value = _run(["powershell", "-NoProfile", "-Command",
                       "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"])
    else:
        return "Unknown"
    try:
        return round(int(value) / (1024 ** 3), 2)
    except (TypeError, ValueError):
        return "Unknown"


def collect_hardware() -> dict:
    system = platform.system()
    data = {
        "cpu": platform.processor() or "Unknown",
        "cpu_cores_logical": os.cpu_count() or "Unknown",
        "ram_gb": _ram_gb(),
        "machine": platform.machine(),
        "system": system,
    }

    if system == "Linux":
        cpu = _run(["bash", "-lc", "awk -F: '/model name|Hardware/ {gsub(/^ +/,\"\",$2); print $2; exit}' /proc/cpuinfo"])
        if cpu:
            data["cpu"] = cpu
        data["kernel"] = platform.release()
        data["disk_total_gb"] = round(shutil.disk_usage("/").total / 1024**3, 2)
        data["disks"] = _run(["lsblk", "-dn", "-o", "NAME,SIZE,TYPE,MODEL"], 20).splitlines()
    elif system == "Darwin":
        cpu = _run(["sysctl", "-n", "machdep.cpu.brand_string"]) or _run(["sysctl", "-n", "hw.model"])
        if cpu:
            data["cpu"] = cpu
        data["cpu_cores_physical"] = _run(["sysctl", "-n", "hw.physicalcpu"])
        data["model"] = _run(["sysctl", "-n", "hw.model"]) or "Unknown"
        data["disk_total_gb"] = round(shutil.disk_usage("/").total / 1024**3, 2)
        data["disks"] = _run(["diskutil", "list"], 20).splitlines()
    elif system == "Windows":
        rows = _json_output(["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory,NumberOfLogicalProcessors,NumberOfProcessors | ConvertTo-Json -Compress"])
        if rows:
            row = rows[0]
            data.update({
                "manufacturer": row.get("Manufacturer", "Unknown"),
                "model": row.get("Model", "Unknown"),
                "cpu_cores_physical": row.get("NumberOfProcessors", "Unknown"),
                "cpu_cores_logical": row.get("NumberOfLogicalProcessors", data["cpu_cores_logical"]),
            })
        disks = _json_output(["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_DiskDrive | Select-Object Model,InterfaceType,Size,SerialNumber,MediaType | ConvertTo-Json -Compress"])
        data["disks"] = disks
        logical = _json_output(["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object DeviceID,Size,FreeSpace,FileSystem | ConvertTo-Json -Compress"])
        data["logical_disks"] = logical
    return data


def _mac_from_sysfs(interface: str) -> str:
    p = Path("/sys/class/net") / interface / "address"
    return p.read_text().strip() if p.exists() else "Unknown"


def collect_network() -> dict:
    system = platform.system()
    interfaces = []
    ips = []

    if system == "Linux":
        output = _run(["ip", "-j", "addr", "show"], 20)
        if output:
            try:
                for item in json.loads(output):
                    name = item.get("ifname", "Unknown")
                    mac = item.get("address", "Unknown")
                    addrs = []
                    for a in item.get("addr_info", []):
                        if a.get("family") == "inet":
                            ip = a.get("local")
                            if ip:
                                addrs.append(ip)
                                if ip not in ips:
                                    ips.append(ip)
                    interfaces.append({"name": name, "mac": mac, "ipv4": addrs,
                                       "state": item.get("operstate", "Unknown")})
            except json.JSONDecodeError:
                pass
        gateway = "Unknown"
        parts = _run(["bash", "-lc", "ip route show default | head -n 1"]).split()
        if "via" in parts:
            gateway = parts[parts.index("via") + 1]
        dns = _run(["bash", "-lc", "awk '/^nameserver/ {print $2}' /etc/resolv.conf"]).splitlines()

    elif system == "Darwin":
        names = _run(["ifconfig", "-l"]).split()
        for name in names:
            block = _run(["ifconfig", name], 10)
            mac = "Unknown"
            ip_list = []
            for line in block.splitlines():
                stripped = line.strip()
                if stripped.startswith("ether "):
                    mac = stripped.split()[1]
                elif stripped.startswith("inet "):
                    value = stripped.split()[1]
                    if value != "127.0.0.1":
                        ip_list.append(value)
                        if value not in ips:
                            ips.append(value)
            interfaces.append({"name": name, "mac": mac, "ipv4": ip_list})
        gateway = "Unknown"
        for line in _run(["route", "-n", "get", "default"]).splitlines():
            if "gateway:" in line:
                gateway = line.split(":", 1)[1].strip()
        dns = _run(["scutil", "--dns"], 20).splitlines()

    elif system == "Windows":
        rows = _json_output(["powershell", "-NoProfile", "-Command",
            "Get-NetIPConfiguration | ForEach-Object { $a=$_.NetAdapter; [PSCustomObject]@{Name=$a.Name;Mac=$a.MacAddress;Status=$a.Status;IPv4=($_.IPv4Address.IPAddress -join ',');Gateway=($_.IPv4DefaultGateway.NextHop -join ',');Dns=($_.DNSServer.ServerAddresses -join ',')} } | ConvertTo-Json -Compress"], 30)
        gateway = "Unknown"
        dns = []
        for row in rows:
            ip_list = [x for x in str(row.get("IPv4", "")).split(",") if x]
            ips.extend(x for x in ip_list if x not in ips)
            gw = str(row.get("Gateway", "")).strip()
            if gw:
                gateway = gw
            d = str(row.get("Dns", "")).strip()
            if d:
                dns.extend(x for x in d.split(",") if x)
            interfaces.append({
                "name": row.get("Name", "Unknown"),
                "mac": row.get("Mac", "Unknown"),
                "ipv4": ip_list,
                "state": row.get("Status", "Unknown"),
            })
    else:
        gateway, dns = "Unknown", []

    return {
        "hostname": socket.gethostname(),
        "ipv4_addresses": list(dict.fromkeys(ips)),
        "interfaces": interfaces,
        "default_gateway": gateway,
        "dns_servers": list(dict.fromkeys(dns)),
    }


def collect_software() -> list[dict]:
    system = platform.system()
    result = []

    if system == "Darwin":
        for root in (Path("/Applications"), Path("/System/Applications")):
            if root.exists():
                for app in sorted(root.glob("*.app")):
                    version = _run(["mdls", "-raw", "-name", "CFBundleShortVersionString", str(app)], 10) or "Unknown"
                    result.append({"name": app.stem, "version": version,
                                   "source": str(root), "path": str(app)})
    elif system == "Linux":
        if shutil.which("dpkg-query"):
            output = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], 60)
            for line in output.splitlines():
                p = line.split("\t", 1)
                if len(p) == 2:
                    result.append({"name": p[0], "version": p[1], "source": "dpkg"})
        elif shutil.which("rpm"):
            output = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], 60)
            for line in output.splitlines():
                p = line.split("\t", 1)
                if len(p) == 2:
                    result.append({"name": p[0], "version": p[1], "source": "rpm"})
    elif system == "Windows":
        rows = _json_output(["powershell", "-NoProfile", "-Command",
            "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | ConvertTo-Json -Compress"], 60)
        for x in rows:
            result.append({"name": x.get("DisplayName", "Unknown"),
                           "version": x.get("DisplayVersion", "Unknown"),
                           "publisher": x.get("Publisher", "Unknown"),
                           "install_date": x.get("InstallDate", "Unknown"),
                           "source": "Windows Registry"})
    return result


def collect_services() -> list[dict]:
    system = platform.system()
    result = []
    if system == "Linux":
        if shutil.which("systemctl"):
            output = _run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"], 45)
            for line in output.splitlines():
                parts = line.split(None, 4)
                if parts:
                    result.append({"name": parts[0], "load": parts[1] if len(parts)>1 else "",
                                   "active": parts[2] if len(parts)>2 else "",
                                   "sub": parts[3] if len(parts)>3 else "",
                                   "description": parts[4] if len(parts)>4 else ""})
    elif system == "Darwin":
        output = _run(["launchctl", "list"], 45)
        for line in output.splitlines()[1:]:
            parts = line.split("\t")
            if parts:
                result.append({"name": parts[-1], "state": "loaded"})
    elif system == "Windows":
        rows = _json_output(["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | ConvertTo-Json -Compress"], 60)
        for x in rows:
            result.append({"name": x.get("Name", "Unknown"),
                           "display_name": x.get("DisplayName", "Unknown"),
                           "state": x.get("State", "Unknown"),
                           "start_mode": x.get("StartMode", "Unknown"),
                           "account": x.get("StartName", "Unknown"),
                           "path": x.get("PathName", "Unknown")})
    return result


def collect_users() -> list[dict]:
    system = platform.system()
    result = []
    if system in ("Linux", "Darwin"):
        passwd = Path("/etc/passwd")
        if passwd.exists():
            for line in passwd.read_text(errors="ignore").splitlines():
                parts = line.split(":")
                if len(parts) >= 7:
                    try:
                        uid = int(parts[2])
                    except ValueError:
                        continue
                    result.append({"username": parts[0], "uid": uid,
                                   "gid": parts[3], "home": parts[5], "shell": parts[6],
                                   "account_class": "system" if uid < 1000 else "user"})
    elif system == "Windows":
        rows = _json_output(["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_UserAccount -Filter \"LocalAccount=True\" | Select-Object Name,FullName,Disabled,Lockout,Status,Description,SID | ConvertTo-Json -Compress"], 45)
        for x in rows:
            result.append({"username": x.get("Name", "Unknown"),
                           "full_name": x.get("FullName", ""),
                           "disabled": x.get("Disabled", "Unknown"),
                           "locked": x.get("Lockout", "Unknown"),
                           "status": x.get("Status", "Unknown"),
                           "description": x.get("Description", ""),
                           "sid": x.get("SID", "Unknown")})
    return result


def collect_updates() -> dict:
    """Collect available OS/package updates when the platform exposes a native read-only command."""
    system = platform.system()
    result = {"supported": False, "count": 0, "items": [], "source": "Unknown"}
    try:
        if system == "Darwin":
            out = _run(["softwareupdate", "-l"], 60)
            items=[]
            for line in out.splitlines():
                line=line.strip()
                if line.startswith("*") and ":" in line:
                    items.append({"name": line.lstrip("* ").strip()})
            result.update({"supported": True, "count": len(items), "items": items, "source": "softwareupdate"})
        elif system == "Linux":
            commands=[
                (["apt-get","-s","upgrade"], "apt"),
                (["dnf","check-update"], "dnf"),
                (["yum","check-update"], "yum"),
                (["pacman","-Qu"], "pacman"),
            ]
            for cmd,source in commands:
                if shutil.which(cmd[0]):
                    out=_run(cmd,60)
                    lines=[x.strip() for x in out.splitlines() if x.strip()]
                    if source=="apt":
                        lines=[x for x in lines if re.match(r"^[A-Za-z0-9_.:+-]+\s",x) and "Inst " in x]
                    result.update({"supported": True,"count":len(lines),"items":[{"name":x} for x in lines[:500]],"source":source})
                    break
        elif system == "Windows":
            if shutil.which("winget"):
                out=_run(["winget","upgrade","--include-unknown","--accept-source-agreements"],60)
                lines=[x.strip() for x in out.splitlines() if x.strip()]
                # Winget table rows are conservatively counted only after the separator.
                sep=next((i for i,x in enumerate(lines) if set(x.replace(" ",""))=={"-"}),None)
                items=lines[sep+1:] if sep is not None else []
                result.update({"supported":True,"count":len(items),"items":[{"name":x} for x in items[:500]],"source":"winget"})
    except Exception:
        pass
    return result

def collect_local_profile() -> dict:
    identity = collect_identity()
    return {
        "identity": identity,
        "hardware": collect_hardware(),
        "network": collect_network(),
        "software": collect_software(),
        "services": collect_services(),
        "users": collect_users(),
        "updates": collect_updates(),
        "collection": {
            "scope": "local_endpoint",
            "collector": "Vulnex Endpoint Agent v3",
            "read_only": True,
        },
    }
