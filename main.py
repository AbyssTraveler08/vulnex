from utils import validate_ip, banner
from scanner import run_nmap
from cve_fetcher import fetch_cves
from risk_engine import rank_vulnerabilities
from graph_generator import generate_risk_chart
from report_generator import generate_pdf_report
from remediation_engine import get_remediation
from logger import log_event
import socket


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def choose_target():
    print("\n1. Scan this device")
    print("2. Scan another device")

    choice = input("Select option (1/2): ").strip()

    if choice == "1":
        ip = get_local_ip()
        print(f"\n[+] Local device IP detected: {ip}")
        return ip

    elif choice == "2":
        ip = input("Enter target IP: ").strip()
        if not validate_ip(ip):
            print("[!] Invalid IP format")
            exit()
        return ip

    else:
        print("[!] Invalid choice")
        exit()


def main():
    banner()

    print("\n⚠ DISCLAIMER")
    print("This tool is developed for educational purposes only.")
    print("Use it ONLY on devices you own or have permission to scan.\n")
    input("Press ENTER to continue...")

    target_ip = choose_target()

    log_event(f"Scan started on {target_ip}")

    print("\nScan Mode:")
    print("1. Quick Scan (Recommended)")
    print("2. Deep Scan (Very slow)")

    mode = input("Select mode (1/2): ")

    scan_data = run_nmap(target_ip, mode)

    print("\n[+] Detected OS:", scan_data["os"])

    vulns = fetch_cves(scan_data["ports"])
    ranked = rank_vulnerabilities(vulns)

    # Add remediation
    for v in ranked:
        v["fix"] = get_remediation(v["service"])

    chart = generate_risk_chart(ranked)

    report_file = generate_pdf_report(target_ip, scan_data, ranked)

    log_event("Scan completed")

    print(f"\n[+] Report saved to: {report_file}")


if __name__ == "__main__":
    main()
