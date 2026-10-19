"""Transparent, explainable Vulnex risk scoring and vulnerability-management helpers."""
from __future__ import annotations
from typing import Iterable

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
DEFAULT_CRITICALITY = 3  # 1=low, 5=critical

def _num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default

def severity_base(severity: str) -> float:
    return {"CRITICAL": 85.0, "HIGH": 65.0, "MEDIUM": 40.0, "LOW": 20.0}.get(str(severity or "").upper(), 10.0)

def score_vulnerability(v: dict, asset_criticality: int = DEFAULT_CRITICALITY, exposed: bool = True) -> dict:
    cvss = max(0.0, min(10.0, _num(v.get("score"), 0.0)))
    exploit = max(0.0, min(10.0, _num(v.get("exploitability_score"), 0.0)))
    kev = bool(v.get("known_exploited"))
    sev = str(v.get("severity") or "UNKNOWN").upper()
    # Explainable 0-100 model. CVSS is dominant; KEV, exploitability,
    # externally exposed service, and asset criticality provide context.
    cvss_component = cvss * 5.5          # 55 max
    exploit_component = exploit * 1.5    # 15 max
    kev_component = 20.0 if kev else 0.0  # 20 max
    exposure_component = 5.0 if exposed else 0.0
    criticality = max(1, min(5, int(asset_criticality)))
    criticality_component = (criticality - 1) * 1.25  # 5 max
    score = round(min(100.0, cvss_component + exploit_component + kev_component +
                      exposure_component + criticality_component), 1)
    if score >= 85: risk_level = "CRITICAL"
    elif score >= 65: risk_level = "HIGH"
    elif score >= 40: risk_level = "MEDIUM"
    else: risk_level = "LOW"
    out = dict(v)
    out.update({
        "risk_score": score,
        "risk_level": risk_level,
        "asset_criticality": criticality,
        "exposed_service": bool(exposed),
        "risk_breakdown": {
            "cvss": round(cvss_component, 1),
            "exploitability": round(exploit_component, 1),
            "known_exploited": round(kev_component, 1),
            "exposed_service": round(exposure_component, 1),
            "asset_criticality": round(criticality_component, 1),
        },
    })
    return out

def enrich_vulnerabilities(vulns: Iterable[dict], asset_criticality: int = DEFAULT_CRITICALITY,
                           exposed_services: set[str] | None = None) -> list[dict]:
    exposed_services = {str(x).lower() for x in (exposed_services or set())}
    result = []
    for v in vulns or []:
        service = str(v.get("service") or "").lower()
        exposed = True if not exposed_services else any(x and x in service for x in exposed_services)
        result.append(score_vulnerability(v, asset_criticality, exposed))
    return sorted(result, key=lambda x: (x.get("risk_score", 0), bool(x.get("known_exploited"))), reverse=True)

def summarize(vulns: Iterable[dict]) -> dict:
    items=list(vulns or [])
    counts={s:0 for s in SEVERITIES}
    for v in items:
        level=str(v.get("risk_level") or v.get("severity") or "UNKNOWN").upper()
        counts[level if level in counts else "UNKNOWN"] += 1
    kev=sum(bool(v.get("known_exploited")) for v in items)
    scores=[_num(v.get("risk_score"),0) for v in items]
    return {
        "total": len(items),
        "critical": counts["CRITICAL"], "high": counts["HIGH"],
        "medium": counts["MEDIUM"], "low": counts["LOW"], "unknown": counts["UNKNOWN"],
        "kev": kev, "max_risk": max(scores, default=0), "avg_risk": round(sum(scores)/len(scores),1) if scores else 0,
    }

def asset_risk(vulns: Iterable[dict], open_ports: int = 0, agent_profile: dict | None = None,
               asset_criticality: int = DEFAULT_CRITICALITY) -> dict:
    s=summarize(vulns)
    exposure=min(10, open_ports) * 1.5
    posture=0
    if agent_profile:
        required=("hardware","network","software","services","users")
        present=sum(bool(agent_profile.get(k)) for k in required)
        posture = (5-present) * 2
    score=min(100.0, round(s["max_risk"] + exposure + posture, 1))
    if score >= 85: level="CRITICAL"
    elif score >= 65: level="HIGH"
    elif score >= 40: level="MEDIUM"
    else: level="LOW"
    return {**s, "asset_risk_score": score, "asset_risk_level": level,
            "open_ports": open_ports, "asset_criticality": asset_criticality,
            "posture_penalty": posture}

def rank_vulnerabilities(vulns: list[dict]) -> list[dict]:
    return sorted(vulns or [], key=lambda v: (
        bool(v.get("known_exploited")), _num(v.get("risk_score"),0),
        _num(v.get("score"),0), _num(v.get("exploitability_score"),0)), reverse=True)
