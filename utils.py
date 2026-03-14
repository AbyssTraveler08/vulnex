import re

def banner():
    print("""
=================================
 Automated Vulnerability Scanner
 Developed by Amar Kant Yadav
=================================
""")

def validate_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip)

