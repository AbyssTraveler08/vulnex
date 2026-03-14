import matplotlib.pyplot as plt
import os


def generate_risk_chart(vulns):
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for v in vulns:
        counts[v["severity"]] += 1

    labels = counts.keys()
    values = counts.values()

    plt.figure()
    plt.bar(labels, values)
    plt.title("Vulnerability Risk Distribution")
    plt.xlabel("Severity Level")
    plt.ylabel("Number of Vulnerabilities")

    # 🔥 Create reports folder automatically
    os.makedirs("reports", exist_ok=True)

    filename = "reports/risk_chart.png"
    plt.savefig(filename)
    plt.close()

    return filename
