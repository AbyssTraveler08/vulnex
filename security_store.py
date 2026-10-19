"""Persistent risk-management state for Vulnex."""
from __future__ import annotations
import json, hashlib, secrets
from datetime import datetime
from pathlib import Path

class SecurityStore:
    def __init__(self, root="scans/security"):
        self.root=Path(root); self.root.mkdir(parents=True,exist_ok=True)
        self.history_file=self.root/"scan_history.json"
        self.status_file=self.root/"remediation.json"
        self.assets_file=self.root/"assets.json"
        self.audit_file=self.root/"audit.log"
        self.history=self._load(self.history_file,[])
        self.status=self._load(self.status_file,{})
        self.assets=self._load(self.assets_file,{})
    def _load(self,p,default):
        try: return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
        except Exception: return default
    def _save(self):
        self.history_file.write_text(json.dumps(self.history,indent=2,default=str),encoding="utf-8")
        self.status_file.write_text(json.dumps(self.status,indent=2,default=str),encoding="utf-8")
        self.assets_file.write_text(json.dumps(self.assets,indent=2,default=str),encoding="utf-8")
    def audit(self, action, target="", details=""):
        line=f"{datetime.now().isoformat(timespec='seconds')} | {action} | {target} | {details}\n"
        with self.audit_file.open("a",encoding="utf-8") as f: f.write(line)
    def set_criticality(self, ip, value):
        value=max(1,min(5,int(value))); self.assets.setdefault(ip,{})["criticality"]=value; self._save()
        self.audit("SET_ASSET_CRITICALITY",ip,str(value))
    def criticality(self, ip): return int(self.assets.get(ip,{}).get("criticality",3))
    @staticmethod
    def finding_key(ip, vuln):
        raw=f"{ip}|{vuln.get('cve')}|{vuln.get('service')}".encode()
        return hashlib.sha256(raw).hexdigest()[:24]
    def get_status(self, ip, vuln):
        """Return the remediation status string for a finding.

        Older/newer remediation records may be stored either as a plain
        status string or as a metadata dictionary containing ``status``.
        Always normalize to a string so callers can safely use it as a
        dictionary key, selectbox value, or table value.
        """
        value = self.status.get(self.finding_key(ip, vuln), "Open")
        if isinstance(value, dict):
            value = value.get("status", "Open")
        if value not in {"Open", "Acknowledged", "In Progress", "Resolved", "Accepted Risk"}:
            return "Open"
        return value
    def set_status(self, ip, vuln, status, note=""):
        allowed={"Open","Acknowledged","In Progress","Resolved","Accepted Risk"}
        if status not in allowed: raise ValueError("Invalid remediation status")
        key=self.finding_key(ip,vuln)
        self.status[key]={"status":status,"updated_at":datetime.now().isoformat(timespec="seconds"),"note":note}
        self._save(); self.audit("REMEDIATION_STATUS",ip,f"{vuln.get('cve')} -> {status}")
    def record_scan(self, ip, scan_data, vulnerabilities, asset_score):
        snapshot={
            "scan_id":"scan-"+secrets.token_hex(8),"timestamp":datetime.now().isoformat(timespec="seconds"),
            "ip":ip,"scan_data":scan_data,"vulnerabilities":vulnerabilities,
            "asset_risk":asset_score,
        }
        self.history.append(snapshot); self.history=self.history[-500:]; self._save()
        self.audit("SCAN_COMPLETED",ip,f"{len(vulnerabilities)} vulnerabilities")
        return snapshot
    def for_ip(self,ip): return [x for x in self.history if x.get("ip")==ip]
    def latest(self,ip):
        xs=self.for_ip(ip); return xs[-1] if xs else None
    def compare_previous(self,ip,current):
        xs=self.for_ip(ip)
        prev=xs[-1] if xs else None
        cur={v.get("cve") for v in current or [] if v.get("cve")}
        old={v.get("cve") for v in (prev or {}).get("vulnerabilities",[]) if v.get("cve")}
        return {"new":sorted(cur-old),"resolved":sorted(old-cur),"previous_scan_id":(prev or {}).get("scan_id")}
    def remediation_counts(self, findings):
        counts={x:0 for x in ("Open","Acknowledged","In Progress","Resolved","Accepted Risk")}
        for ip,v in findings:
            counts[self.get_status(ip,v)]=counts.get(self.get_status(ip,v),0)+1
        return counts
