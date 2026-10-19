"""Network-service CVE lookup using the NVD 2.0 API and CISA KEV catalog.

The module reports matches; it does not attempt exploitation. Version matching
is deliberately conservative: CPE matches are preferred, and keyword matching
is only used when Nmap did not provide a CPE.
"""
from __future__ import annotations

import time
from functools import lru_cache

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {"User-Agent": "Vulnex/2.0 vulnerability-assessment-tool"}


def _severity(metrics: dict) -> tuple[str, float | None, float | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        items = metrics.get(key) or []
        if items:
            cvss = items[0].get("cvssData", {})
            return str(cvss.get("baseSeverity", "UNKNOWN")), cvss.get("baseScore"), items[0].get("exploitabilityScore")
    return "UNKNOWN", None, None


def _description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _references(cve: dict) -> list[str]:
    return [r.get("url") for r in cve.get("references", []) if r.get("url")]

@lru_cache(maxsize=1)
def _kev_ids() -> set[str]:
    try:
        r = requests.get(KEV_URL, headers=HEADERS, timeout=12)
        r.raise_for_status()
        return {x.get("cveID") for x in r.json().get("vulnerabilities", []) if x.get("cveID")}
    except Exception:
        return set()


def _query(params: dict) -> list[dict]:
    try:
        r = requests.get(NVD_URL, params=params, headers=HEADERS, timeout=20)
        r.raise_for_status()
        return r.json().get("vulnerabilities", [])
    except Exception:
        return []


def fetch_cves(ports: list[dict], cpes: list[str] | None = None, max_per_service: int = 8) -> list[dict]:
    findings: list[dict] = []
    kev = _kev_ids()
    seen: set[str] = set()
    cpes = cpes or []

    for cpe in cpes:
        if not cpe or cpe in ("unknown", "Unknown"):
            continue
        for item in _query({"cpeName": cpe, "resultsPerPage": max_per_service}):
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid or cid in seen:
                continue
            seen.add(cid)
            severity, score, exploitability = _severity(cve.get("metrics", {}))
            findings.append({
                "cve": cid, "severity": severity, "score": score,
                "exploitability_score": exploitability,
                "known_exploited": cid in kev,
                "description": _description(cve),
                "references": _references(cve), "service": cpe,
            })
        time.sleep(0.15)

    # Conservative fallback for services where Nmap did not expose a CPE.
    for p in ports:
        product = (p.get("product") or "").strip()
        version = (p.get("version") or "").strip()
        service = (p.get("service") or "").strip()
        if not product and not service:
            continue
        query = " ".join(x for x in (product, version) if x)
        if not query:
            query = service
        for item in _query({"keywordSearch": query, "resultsPerPage": max_per_service}):
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid or cid in seen:
                continue
            # Avoid presenting a keyword hit as a confirmed product match unless
            # NVD's applicability data contains the observed product/version text.
            blob = str(cve.get("configurations", "")).lower()
            if product and product.lower() not in blob and version and version.lower() not in blob:
                continue
            seen.add(cid)
            severity, score, exploitability = _severity(cve.get("metrics", {}))
            findings.append({
                "cve": cid, "severity": severity, "score": score,
                "exploitability_score": exploitability,
                "known_exploited": cid in kev,
                "description": _description(cve),
                "references": _references(cve), "service": product or service,
            })
        time.sleep(0.15)
    return findings
