import subprocess
import xml.etree.ElementTree as ET
from tqdm import tqdm
import time


def run_nmap(ip, mode):
    print("[+] Running Nmap scan...")

    if mode == "1":  # Quick scan
        cmd = [
            "nmap",
            "-sV",
            "--top-ports", "1000",
            "-oX", "scan.xml",
            ip
        ]
        est_time = 60   # seconds

    else:  # Deep scan
        cmd = [
            "nmap",
            "-A",
            "-O",
            "-sU",
            "-p-",
            "--script", "vuln",
            "-oX", "scan.xml",
            ip
        ]
        est_time = 900  # ~15 min

    # Start scan process
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Fake progress bar (realistic UX)
    with tqdm(total=est_time, desc="Scanning", unit="s") as bar:
        while process.poll() is None:
            time.sleep(1)
            bar.update(1)

    return parse_xml()


def parse_xml():
    tree = ET.parse("scan.xml")
    root = tree.getroot()

    data = {
        "os": "Unknown",
        "ports": [],
        "scripts": []
    }

    for osmatch in root.findall(".//osmatch"):
        data["os"] = osmatch.get("name")
        break

    for port in root.findall(".//port"):
        service = port.find("service")
        data["ports"].append({
            "port": port.get("portid"),
            "protocol": port.get("protocol"),
            "service": service.get("name") if service is not None else "unknown",
            "version": service.get("version") if service is not None else "unknown"
        })

    for script in root.findall(".//script"):
        data["scripts"].append({
            "id": script.get("id"),
            "output": script.get("output")
        })

    return data
