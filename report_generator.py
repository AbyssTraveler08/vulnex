"""PDF report generation for Vulnex network and endpoint assessments."""
from __future__ import annotations

import html
import re
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

REPORT_ROOT = Path("reports")


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value))


def _p(value) -> str:
    return html.escape(str(value if value not in (None, "", []) else "Unknown"))


def _value(value):
    if isinstance(value, (dict, list)):
        return ", ".join(f"{k}: {v}" for k, v in value.items()) if isinstance(value, dict) else ", ".join(map(str, value))
    return value


def _section_title(story, title, styles):
    story.append(Spacer(1, 5))
    story.append(Paragraph(title, styles["Heading2"]))
    story.append(Spacer(1, 4))


def _kv_table(data: dict, styles):
    rows = [[Paragraph("Field", styles["Small"]), Paragraph("Value", styles["Small"])]]
    for key, value in data.items():
        rows.append([Paragraph(_p(key), styles["Small"]), Paragraph(_p(_value(value)), styles["Small"])])
    table = Table(rows, repeatRows=1, colWidths=[48 * mm, 132 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#182233")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    return table


def _list_table(items: list[dict], styles, preferred=None):
    if not items:
        return None
    keys = preferred or []
    seen = set(keys)
    for item in items:
        if isinstance(item, dict):
            for key in item:
                if key not in seen:
                    keys.append(key)
                    seen.add(key)
                if len(keys) >= 7:
                    break
        if len(keys) >= 7:
            break
    rows = [[Paragraph(_p(k), styles["Small"]) for k in keys]]
    for item in items:
        rows.append([Paragraph(_p(_value(item.get(k, ""))), styles["Tiny"]) for k in keys])
    width = 180 * mm / max(1, len(keys))
    table = Table(rows, repeatRows=1, colWidths=[width] * len(keys))
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#182233")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
    ]))
    return table


def add_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(15 * mm, 10 * mm, "Vulnex — Authorized Security Assessment")
    canvas.drawRightString(195 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()

def generate_executive_risk_pdf(summary: dict, assets: list[dict], findings: list[dict], history: list[dict]) -> str:
    """Generate a concise executive + technical vulnerability-management report."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from datetime import datetime
    outdir = Path("reports"); outdir.mkdir(exist_ok=True)
    filename = outdir / f"vulnex_risk_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    styles=getSampleStyleSheet()
    doc=SimpleDocTemplate(str(filename),pagesize=A4,rightMargin=12*mm,leftMargin=12*mm,topMargin=12*mm,bottomMargin=12*mm)
    story=[Paragraph("Vulnex — Vulnerability & Risk Management Report",styles["Title"]),
           Paragraph(f"Generated {datetime.now().isoformat(timespec='seconds')}",styles["Normal"]),Spacer(1,10)]
    story.append(Paragraph("Executive Summary",styles["Heading2"]))
    rows=[[str(k).replace("_"," ").title(),str(v)] for k,v in summary.items()]
    t=Table(rows,colWidths=[70*mm,100*mm]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.3,colors.grey),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#182233")),("TEXTCOLOR",(0,0),(0,-1),colors.white)])); story.append(t)
    story.append(Spacer(1,10)); story.append(Paragraph("Affected Assets & Risk",styles["Heading2"]))
    ar=[["Asset","Risk","Level","CVEs","Open Ports","Criticality"]]
    for a in assets: ar.append([str(a.get("ip")),str(a.get("asset_risk_score")),str(a.get("asset_risk_level")),str(a.get("total",0)),str(a.get("open_ports",0)),str(a.get("asset_criticality",3))])
    t=Table(ar,repeatRows=1,colWidths=[38*mm,22*mm,25*mm,22*mm,25*mm,25*mm]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.3,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#182233")),("TEXTCOLOR",(0,0),(-1,0),colors.white)])); story.append(t)
    story.append(PageBreak()); story.append(Paragraph("Technical Findings & Remediation",styles["Heading2"]))
    if findings:
        fr=[["CVE","Risk","CVSS","KEV","Status","Service","Remediation"]]
        for ip,v in findings[:250]:
            fr.append([str(v.get("cve")),str(v.get("risk_score")),str(v.get("score") or "—"),"Yes" if v.get("known_exploited") else "No",
                       str(v.get("status","Open")),str(v.get("service","")),str(v.get("fix",""))[:90]])
        t=Table(fr,repeatRows=1,colWidths=[25*mm,16*mm,16*mm,15*mm,25*mm,28*mm,55*mm]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.25,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#182233")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTSIZE",(0,0),(-1,-1),6.5),("VALIGN",(0,0),(-1,-1),"TOP")])); story.append(t)
    else: story.append(Paragraph("No vulnerability findings are currently stored.",styles["Normal"]))
    story.append(Spacer(1,10)); story.append(Paragraph("Historical Change & Before/After Risk",styles["Heading2"]))
    story.append(Paragraph(f"Stored scan snapshots: {len(history)}. Historical comparison is based on CVE identity per asset; validate applicability before remediation.",styles["Normal"]))
    latest={}
    previous={}
    for snap in history:
        ip=snap.get("ip")
        if ip in latest: previous[ip]=latest[ip]
        latest[ip]=snap
    if latest:
        hr=[["Asset","Previous Risk","Current Risk","Risk Δ","New CVEs","Resolved CVEs"]]
        for ip,current in latest.items():
            prev=previous.get(ip)
            old_ids={v.get("cve") for v in (prev or {}).get("vulnerabilities",[]) if v.get("cve")}
            new_ids={v.get("cve") for v in current.get("vulnerabilities",[]) if v.get("cve")}
            old_r=(prev or {}).get("asset_risk",{}).get("asset_risk_score",0)
            cur_r=current.get("asset_risk",{}).get("asset_risk_score",0)
            hr.append([str(ip),str(old_r),str(cur_r),str(round(cur_r-old_r,1)),str(len(new_ids-old_ids)),str(len(old_ids-new_ids))])
        ht=Table(hr,repeatRows=1,colWidths=[38*mm,28*mm,28*mm,24*mm,28*mm,28*mm])
        ht.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.3,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#182233")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTSIZE",(0,0),(-1,-1),7)]))
        story.append(ht)
    doc.build(story); return str(filename)


def generate_device_pdf(device: dict, scan_data: dict, vulnerabilities: list[dict]) -> str:
    """Generate the existing network/security assessment PDF."""
    return _generate_pdf(device, scan_data, vulnerabilities, None, full=False)


def generate_full_device_pdf(device: dict, scan_data: dict | None, vulnerabilities: list[dict], endpoint_profile: dict, label: str | None = None) -> str:
    """Generate a combined network + endpoint inventory PDF when an agent is configured."""
    return _generate_pdf(device, scan_data or {}, vulnerabilities or [], endpoint_profile or {}, full=True, label=label)


def _generate_pdf(device, scan_data, vulnerabilities, endpoint_profile, full=False, label=None):
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    endpoint_profile = endpoint_profile or {}
    # Agent profiles use nested identity/collection fields, while the local
    # DeviceProfile stores identity as ``os`` and collection metadata as
    # ``scan_metadata``. Normalize both shapes so local and remote full reports
    # use the same generator.
    if isinstance(endpoint_profile, dict):
        identity = endpoint_profile.get("identity") or endpoint_profile.get("os") or {}
        if not isinstance(identity, dict):
            identity = {"os": identity}
        hardware = endpoint_profile.get("hardware", {}) or {}
        network = endpoint_profile.get("network", {}) or {}
        software = endpoint_profile.get("software", []) or []
        services = endpoint_profile.get("services", []) or []
        users = endpoint_profile.get("users", []) or []
        collection = endpoint_profile.get("collection") or endpoint_profile.get("scan_metadata") or {}
        updates = endpoint_profile.get("updates", {}) or {}
    else:
        identity, hardware, network, software, services, users, collection, updates = {}, {}, {}, [], [], [], {}, {}

    ip = device.get("ip") or scan_data.get("ip") or (network.get("ipv4_addresses") or ["unknown"])[0]
    stem = "full_device" if full else "device"
    suffix = label or ip
    filename = REPORT_ROOT / f"{stem}_{_safe_filename(suffix)}.pdf"

    doc = SimpleDocTemplate(str(filename), pagesize=A4, rightMargin=15 * mm, leftMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8.2, leading=10.5))
    styles.add(ParagraphStyle(name="Tiny", parent=styles["Normal"], fontSize=6.7, leading=8.2))
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontSize=21, leading=25, textColor=colors.HexColor("#111827")))

    story = [
        Paragraph("VULNEX — FULL DEVICE REPORT" if full else "VULNEX — DEVICE SECURITY ASSESSMENT", styles["ReportTitle"]),
        Spacer(1, 5),
        Paragraph("Combined endpoint inventory and network security assessment" if full else "Network security assessment", styles["Normal"]),
        Spacer(1, 10),
    ]

    summary = {
        "Generated": datetime.now().isoformat(timespec="seconds"),
        "IP": ip,
        "Hostname": identity.get("hostname") or scan_data.get("hostname") or device.get("hostname"),
        "MAC": scan_data.get("mac") or device.get("mac") or "Unknown",
        "Vendor": scan_data.get("vendor") or device.get("vendor") or "Unknown",
        "Device Type": device.get("device_type", "Unknown"),
        "Operating System": identity.get("os") or scan_data.get("os") or "Unknown",
        "Agent Inventory": "Configured" if endpoint_profile else "Not configured",
    }
    story.append(_kv_table(summary, styles))

    if full:
        _section_title(story, "Endpoint Collection Summary", styles)
        story.append(_kv_table({
            "Collector": collection.get("collector", "Unknown"),
            "Schema Version": collection.get("schema_version", "Unknown"),
            "Scope": collection.get("scope", "Unknown"),
            "Read Only": collection.get("read_only", "Unknown"),
            "Software Records": len(software),
            "Service Records": len(services),
            "User Records": len(users),
            "Network Interfaces": len(network.get("interfaces", []) or []),
            "Updates Available": updates.get("count", "Unknown") if updates.get("supported") else "Unknown",
        }, styles))

        _section_title(story, "Hardware Inventory", styles)
        story.append(_kv_table(hardware or {"Status": "No hardware inventory received"}, styles))

        _section_title(story, "Operating System & Identity", styles)
        story.append(_kv_table(identity or {"Status": "No endpoint identity received"}, styles))

        _section_title(story, "Network Inventory", styles)
        story.append(_kv_table({
            "Hostname": network.get("hostname", identity.get("hostname", "Unknown")),
            "IPv4 Addresses": network.get("ipv4_addresses", []),
            "Default Gateway": network.get("default_gateway", "Unknown"),
            "DNS Servers": network.get("dns_servers", []),
        }, styles))
        interfaces = _list_table(network.get("interfaces", []) or [], styles, ["name", "mac", "ipv4", "state"])
        if interfaces:
            story.append(Spacer(1, 5)); story.append(interfaces)

        story.append(Paragraph("Software Update Status", styles["Heading2"]))
        story.append(_kv_table({"Supported": updates.get("supported","Unknown"), "Source": updates.get("source","Unknown"), "Updates Available": updates.get("count","Unknown")}, styles))
        for title, data, preferred in [
            ("Installed Software", software, ["name", "version", "publisher", "source"]),
            ("Services", services, ["name", "display_name", "state", "active", "start_mode", "account"]),
            ("Local Users", users, ["username", "full_name", "uid", "status", "disabled", "home", "shell"]),
        ]:
            story.append(PageBreak())
            _section_title(story, title, styles)
            table = _list_table(data, styles, preferred)
            story.append(table if table else Paragraph(f"No {title.lower()} were received.", styles["Normal"]))

    story.append(PageBreak())
    _section_title(story, "Open Ports & Services", styles)
    port_rows = [["Port", "Protocol", "Service", "Product", "Version"]]
    for port in scan_data.get("ports", []):
        port_rows.append([_p(port.get("port")), _p(port.get("protocol")), _p(port.get("service")), _p(port.get("product")), _p(port.get("version"))])
    if len(port_rows) == 1:
        port_rows.append(["—", "—", "No open ports reported", "—", "—"])
    table = Table(port_rows, repeatRows=1, colWidths=[18*mm, 20*mm, 32*mm, 55*mm, 45*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#182233")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0,0), (-1,-1), 7.5),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    story.extend([table, Spacer(1, 12)])

    _section_title(story, "Vulnerability Findings", styles)
    if vulnerabilities:
        for v in vulnerabilities:
            story.append(Paragraph(
                f"<b>{_p(v.get('cve'))}</b> — {_p(v.get('severity'))} (CVSS {_p(v.get('score'))})<br/>"
                f"<b>Risk:</b> {_p(v.get('risk_score','Unknown'))} / {_p(v.get('risk_level',v.get('severity','UNKNOWN')))} • "
                f"<b>KEV:</b> {'Yes' if v.get('known_exploited') else 'No'} • <b>Status:</b> {_p(v.get('status','Open'))}<br/>"
                f"<b>Service:</b> {_p(v.get('service'))}<br/>{_p(v.get('description'))}<br/>"
                f"<b>Remediation:</b> {_p(v.get('fix'))}", styles["Small"]))
            story.append(Spacer(1, 7))
    else:
        story.append(Paragraph("No CVE findings were returned by the current assessment pipeline.", styles["Normal"]))

    if scan_data.get("scripts"):
        story.append(PageBreak())
        _section_title(story, "Nmap Vulnerability Script Results", styles)
        for script in scan_data["scripts"]:
            story.append(Paragraph(f"<b>{_p(script.get('id'))}</b><br/>{_p(script.get('output'))}", styles["Small"]))
            story.append(Spacer(1, 6))

    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
    return str(filename)
