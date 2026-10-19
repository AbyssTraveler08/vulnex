"""Defensive remediation guidance for network findings."""
from __future__ import annotations

def get_remediation(service: str) -> str:
    s=(service or "").lower()
    if "ssh" in s:
        return "Upgrade OpenSSH to the vendor-supported patched release; disable unused SSH access and restrict management access to trusted networks."
    if "http" in s or "apache" in s or "nginx" in s or "iis" in s:
        return "Upgrade the detected web server/application to a vendor-supported patched release and restrict unnecessary exposure."
    if "smb" in s or "microsoft-ds" in s:
        return "Apply current Windows security updates and restrict SMB to trusted network segments; disable SMBv1 where applicable."
    if "rdp" in s or "ms-wbt-server" in s:
        return "Apply current Windows security updates and restrict RDP to trusted administrative networks or VPN access."
    if "ftp" in s:
        return "Disable FTP if unnecessary; otherwise upgrade and restrict access, preferably replacing it with SFTP/SSH."
    if "telnet" in s:
        return "Disable Telnet and use SSH or another encrypted management protocol."
    if "mysql" in s or "postgres" in s or "mssql" in s or "oracle" in s:
        return "Upgrade the database service, restrict network exposure, and enforce authenticated access from approved application hosts only."
    return "Verify the detected product/version against the vendor advisory, apply the latest security update, and restrict the service to required hosts only."
