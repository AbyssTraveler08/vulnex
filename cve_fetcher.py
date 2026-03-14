import requests
import time

# ------------------------------------
# NVD API Configuration
# ------------------------------------

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 🔑 Put your NVD API key here (optional but recommended)
API_KEY = None  # Example: "abcd1234-xxxx-xxxx"

# ------------------------------------
# Service Normalization
# ------------------------------------

SERVICE_MAP = {
    "http": "apache",
    "ssl/http": "apache",
    "ssh": "openssh",
    "ftp": "vsftpd",
    "mysql": "mysql",
    "smb": "samba",
    "microsoft-ds": "windows"
}


def normalize(service):
    if not service:
        return ""
    return SERVICE_MAP.get(service.lower(), service.lower())


# ------------------------------------
# Severity Mapping
# ------------------------------------

def get_severity(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "UNKNOWN"


# ------------------------------------
# CVE Fetcher
# ------------------------------------

def fetch_cves(services):
    print("\n[+] Fetching CVEs with smart matching...")

    vulnerabilities = []

    headers = {}
    if API_KEY:
        headers["apiKey"] = API_KEY

    for s in services:

        service = normalize(s.get("service", ""))
        version = s.get("version", "")

        # If version exists, include it; otherwise search only by service
        query = f"{service} {version}".strip()

        if not service:
            continue

        print(f"   ↳ Querying NVD for: {query}")

        try:
            response = requests.get(
                NVD_API,
                params={
                    "keywordSearch": query,
                    "resultsPerPage": 5
                },
                headers=headers,
                timeout=15
            )

            if response.status_code != 200:
                print(f"   ⚠ API Error: {response.status_code}")
                continue

            data = response.json()

            total_results = data.get("totalResults", 0)
            print(f"   → Found {total_results} results")

            for item in data.get("vulnerabilities", []):

                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")

                description = "No description available"
                if cve.get("descriptions"):
                    description = cve["descriptions"][0].get("value", description)

                score = 0
                metrics = cve.get("metrics", {})

                # Handle multiple CVSS formats safely
                try:
                    if "cvssMetricV31" in metrics:
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                except Exception:
                    score = 0

                vulnerabilities.append({
                    "service": service,
                    "cve": cve_id,
                    "description": description,
                    "score": score,
                    "severity": get_severity(score)
                })

            # Respect NVD rate limits
            time.sleep(1)

        except requests.exceptions.Timeout:
            print("   ⚠ Request timed out")
        except requests.exceptions.RequestException as e:
            print(f"   ⚠ Request failed: {e}")
        except Exception as e:
            print(f"   ⚠ Unexpected error: {e}")

    print(f"\n[+] Total vulnerabilities collected: {len(vulnerabilities)}\n")

    return vulnerabilities