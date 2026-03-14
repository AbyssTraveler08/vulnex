"""
Automated Remediation Suggestion Engine
Author: Amar Kant Yadav
Purpose: Provide security fix recommendations
"""

REMEDIATION_DB = {
    "apache": "Update Apache to latest stable version and disable directory listing",
    "ssh": "Disable root login, use key-based authentication, change default port",
    "ftp": "Use SFTP instead of FTP, disable anonymous login",
    "mysql": "Restrict remote root login, update to latest version",
    "smb": "Disable SMBv1, apply latest security patches",
    "rdp": "Enable NLA, restrict IP access, enforce strong passwords",
}

def get_remediation(service_name):
    service_name = service_name.lower()

    for key in REMEDIATION_DB:
        if key in service_name:
            return REMEDIATION_DB[key]

    return "Apply latest security patches and follow vendor hardening guidelines"
