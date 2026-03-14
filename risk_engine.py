def get_severity(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"

def rank_vulnerabilities(vulns):
    for v in vulns:
        v["severity"] = get_severity(v["score"])

    return sorted(vulns, key=lambda x: x["score"], reverse=True)

