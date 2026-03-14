"""
PDF Report Generator
Author: Amar Kant Yadav
Purpose: Generate professional vulnerability scan reports
"""

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image
)
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import os


# Footer on every page
def add_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.drawString(200, 20, "Developed by Amar Kant Yadav")
    canvas.restoreState()


def generate_pdf_report(ip, scan_data, vulns):
    if not os.path.exists("reports"):
        os.mkdir("reports")

    filename = f"reports/scan_{ip}_{datetime.now().strftime('%H%M%S')}.pdf"
    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(
        Paragraph("<b>Vulnerability Assessment Report</b>", styles["Title"])
    )
    elements.append(Spacer(1, 12))

    # Header
    elements.append(
        Paragraph(
            f"<b>Target IP:</b> {ip}<br/>"
            f"<b>Scan Time:</b> {datetime.now()}<br/>"
            f"<b>Detected OS:</b> {scan_data['os']}",
            styles["Normal"]
        )
    )
    elements.append(Spacer(1, 12))

    # Port details
    elements.append(
        Paragraph("<b>Open Ports & Services</b>", styles["Heading2"])
    )

    for p in scan_data["ports"]:
        elements.append(
            Paragraph(
                f"Port: {p['port']} | "
                f"Protocol: {p['protocol']} | "
                f"Service: {p['service']} | "
                f"Version: {p['version']}",
                styles["Normal"]
            )
        )

    elements.append(Spacer(1, 12))

    # NSE script results
    elements.append(
        Paragraph("<b>NSE Vulnerability Script Results</b>", styles["Heading2"])
    )

    for s in scan_data["scripts"]:
        elements.append(
            Paragraph(
                f"<b>Script:</b> {s['id']}<br/>"
                f"<b>Output:</b> {s['output']}",
                styles["Normal"]
            )
        )

    elements.append(Spacer(1, 12))

    # Risk Chart
    elements.append(
        Paragraph("<b>Risk Distribution Chart</b>", styles["Heading2"])
    )

    chart_path = "reports/risk_chart.png"
    if os.path.exists(chart_path):
        img = Image(chart_path, width=400, height=300)
        elements.append(img)
        elements.append(Spacer(1, 12))

    # Vulnerability details
    elements.append(
        Paragraph("<b>Detected Vulnerabilities</b>", styles["Heading2"])
    )

    for v in vulns:
        elements.append(
            Paragraph(
                f"""
<b>Service:</b> {v['service']}<br/>
<b>CVE:</b> {v['cve']}<br/>
<b>Severity:</b> {v['severity']}<br/>
<b>Score:</b> {v['score']}<br/>
<b>Description:</b> {v['description']}<br/>
<b>Recommended Fix:</b> {v['fix']}<br/>
---------------------------------------
""",
                styles["Normal"]
            )
        )

    # Build PDF with footer
    doc.build(
        elements,
        onFirstPage=add_footer,
        onLaterPages=add_footer
    )

    return filename
