"""Privileged per-device Nmap assessment for Vulnex.

Nmap OS fingerprinting and several low-level probes require raw-packet privileges
on macOS/Linux. Vulnex reuses an already-authorized sudo credential when available;
it never asks for a password inside Streamlit.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from nmap_locator import find_nmap, nmap_install_message


def _sudo_path() -> str:
    return shutil.which("sudo") or "/usr/bin/sudo"


def _has_privilege() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    try:
        r = subprocess.run([_sudo_path(), "-n", "true"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _run_command(cmd: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
    # Do not run the whole Streamlit process as root. Reuse cached sudo credentials
    # from Vulnex startup for only the Nmap command that needs raw privileges.
    if not (hasattr(os, "geteuid") and os.geteuid() == 0) and _has_privilege():
        cmd = [_sudo_path(), "-n", *cmd]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _reverse_dns(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        if name and name != ip:
            return name.rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        pass
    return "Unknown"


def run_nmap(ip: str, mode: str = "1", output_path: str | None = None) -> dict:
    """Run a full TCP-port Nmap assessment for one authorized device.

    Vulnex deliberately scans ports 1-65535 instead of Nmap's default/top-port
    set. Quick mode performs full-port service/version detection plus the Nmap
    vulnerability NSE category. Extended mode additionally enables OS detection
    and all-version probing. Both modes therefore cover the complete TCP port
    range; Extended simply performs the more expensive fingerprinting pass.
    """
    nmap_path = find_nmap()
    if not nmap_path:
        raise RuntimeError(nmap_install_message())
    if not output_path:
        fd, output_path = tempfile.mkstemp(prefix=f"vulnex_{ip}_", suffix=".xml")
        os.close(fd)

    privileged = _has_privilege() or (hasattr(os, "geteuid") and os.geteuid() == 0)

    # -p- means every TCP port (1-65535). --script vuln runs Nmap's
    # vulnerability-detection NSE scripts. -sV is retained for product/version
    # discovery so Vulnex can continue its NVD/CISA KEV correlation afterwards.
    common = [
        nmap_path,
        "-Pn",
        "-p-",
        "-sV",
        "--version-all",
        "--script", "vuln",
        "--script-timeout", "120s",
        "-R",
        "-T4",
        "-oX", output_path,
        ip,
    ]

    if mode != "1" and privileged:
        # Extended mode adds OS fingerprinting while keeping the complete-port
        # and vulnerability scan identical.
        cmd = [
            nmap_path, "-Pn", "-p-", "-sV", "--version-all",
            "-O", "--osscan-guess",
            "--script", "vuln", "--script-timeout", "120s",
            "-R", "-T4", "-oX", output_path, ip,
        ]
    else:
        cmd = common

    # Full-port + NSE scans can legitimately take much longer than a top-1000
    # scan. Allow up to 45 minutes for one device while keeping the UI responsive.
    timeout = 2700 if mode != "1" else 1800

    try:
        result = _run_command(cmd, timeout=timeout)
        if result.returncode != 0:
            err = (result.stderr or result.stdout).strip()
            if ("requires root" in err.lower() or "requires privileged" in err.lower()
                    or "requires administrator" in err.lower()):
                # OS detection needs raw privileges, but the full TCP-port service
                # and vulnerability assessment does not. Retry without -O so the
                # user still gets the requested 1-65535 + vuln scan.
                retry = _run_command(common, timeout=1800)
                if retry.returncode == 0:
                    return parse_xml(output_path, ip)
                raise RuntimeError((retry.stderr or retry.stdout or err).strip())
            raise RuntimeError(err or f"Nmap failed for {ip}")
        return parse_xml(output_path, ip)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Nmap full-port vulnerability scan timed out after {timeout // 60} minutes. "
            "The target may expose many ports or slow vulnerability scripts."
        ) from exc
    except FileNotFoundError as exc:
        raise RuntimeError(nmap_install_message()) from exc


def parse_xml(path: str, requested_ip: str | None = None) -> dict:
    root = ET.parse(path).getroot()
    data = {
        "ip": requested_ip,
        "hostname": "Unknown",
        "mac": "Unknown",
        "vendor": "Unknown",
        "os": "Unknown",
        "os_accuracy": "Unknown",
        "ports": [],
        "scripts": [],
        "cpe": [],
    }

    host = root.find("host")
    if host is None:
        if requested_ip:
            data["hostname"] = _reverse_dns(requested_ip)
        return data

    for address in host.findall("address"):
        if address.get("addrtype") == "ipv4":
            data["ip"] = address.get("addr", data["ip"])
        elif address.get("addrtype") == "mac":
            data["mac"] = address.get("addr", "Unknown")
            data["vendor"] = address.get("vendor", "Unknown")

    hn = host.find("./hostnames/hostname")
    if hn is not None:
        data["hostname"] = hn.get("name", "Unknown")
    if data["hostname"] == "Unknown" and data.get("ip"):
        data["hostname"] = _reverse_dns(data["ip"])

    osmatch = host.find("./os/osmatch")
    if osmatch is not None:
        data["os"] = osmatch.get("name", "Unknown")
        data["os_accuracy"] = osmatch.get("accuracy", "Unknown")

    for port in host.findall("./ports/port"):
        service = port.find("service")
        state = port.find("state")
        if state is not None and state.get("state") != "open":
            continue
        cpes = [c.text.strip() for c in port.findall("./service/cpe") if c.text]
        data["cpe"].extend(cpes)
        data["ports"].append({
            "port": port.get("portid", ""),
            "protocol": port.get("protocol", ""),
            "service": service.get("name", "unknown") if service is not None else "unknown",
            "product": service.get("product", "") if service is not None else "",
            "version": service.get("version", "unknown") if service is not None else "unknown",
            "extrainfo": service.get("extrainfo", "") if service is not None else "",
        })

    for script in host.findall(".//script"):
        data["scripts"].append({"id": script.get("id", ""), "output": script.get("output", "")})

    return data
