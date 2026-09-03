#!/usr/bin/env python3
"""
findings.py — Parse raw tool output into structured, risk-rated findings.

Each parser takes the raw stdout (and command) of a scan and returns a dict:

    {
        "tool": "nmap",
        "supported": True,            # False if we have no parser for this tool
        "ports": [                    # nmap only; [] for others
            {"port": "3306", "proto": "tcp", "state": "open",
             "service": "mysql", "version": "MySQL 5.7.33", "risk": "high"}
        ],
        "findings": [                 # highlighted, human-readable findings
            {"title": "...", "detail": "...", "severity": "high"}
        ],
        "summary": {"open_ports": 4, "high": 1, "medium": 2, "low": 1,
                    "info": 0, "total": 3}
    }

Severities: "high" | "medium" | "low" | "info"
"""

import re
from typing import Dict, Any, List

SEVERITIES = ("high", "medium", "low", "info")

# Services that are risky to expose directly to a network
HIGH_RISK_SERVICES = {
    "mysql", "mariadb", "postgresql", "postgres", "mssql", "ms-sql-s",
    "mongodb", "mongod", "redis", "memcached", "elasticsearch", "couchdb",
    "vnc", "rdp", "ms-wbt-server", "telnet", "rlogin", "rsh",
    "docker", "kubernetes",
}
# Legacy / cleartext / commonly-attacked services -> medium
MEDIUM_RISK_SERVICES = {
    "ftp", "http", "smb", "microsoft-ds", "netbios-ssn", "netbios-ns",
    "snmp", "tftp", "smtp", "pop3", "imap", "nfs", "rpcbind", "finger",
}
# Ports that map to a service even when nmap doesn't name it
PORT_HINTS = {
    "3306": ("mysql", "high"), "5432": ("postgresql", "high"),
    "1433": ("mssql", "high"), "27017": ("mongodb", "high"),
    "6379": ("redis", "high"), "11211": ("memcached", "high"),
    "9200": ("elasticsearch", "high"), "5900": ("vnc", "high"),
    "3389": ("rdp", "high"), "23": ("telnet", "high"),
    "21": ("ftp", "medium"), "445": ("smb", "medium"),
    "139": ("netbios", "medium"), "161": ("snmp", "medium"),
    "25": ("smtp", "medium"), "80": ("http", "medium"),
    "8080": ("http", "medium"), "22": ("ssh", "low"), "443": ("https", "low"),
}


def _service_risk(service: str, port: str) -> str:
    s = (service or "").lower()
    if s in HIGH_RISK_SERVICES:
        return "high"
    if s in MEDIUM_RISK_SERVICES:
        return "medium"
    if port in PORT_HINTS:
        return PORT_HINTS[port][1]
    if s in ("ssh", "https", "ssl", "domain", "dns"):
        return "low"
    return "info"


def _empty(tool: str, supported: bool = True) -> Dict[str, Any]:
    return {"tool": tool, "supported": supported, "ports": [], "findings": [],
            "summary": {"open_ports": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}}


def _finalize(result: Dict[str, Any]) -> Dict[str, Any]:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in result["findings"]:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    result["summary"] = {
        "open_ports": len(result["ports"]),
        "high": counts["high"], "medium": counts["medium"],
        "low": counts["low"], "info": counts["info"],
        "total": len(result["findings"]),
    }
    return result


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------
# Matches lines like:  22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu
_NMAP_PORT_RE = re.compile(
    r'^\s*(\d{1,5})/(tcp|udp)\s+(open|open\|filtered|filtered|closed)\s+([\w\-\/?]+)\s*(.*)$'
)

# Known outdated/vulnerable versions worth flagging: (regex, message, severity)
_OUTDATED_HINTS = [
    (re.compile(r'vsftpd 2\.3\.4', re.I), "vsftpd 2.3.4 — ünlü backdoor açığı (CVE-2011-2523)!", "high"),
    (re.compile(r'ProFTPD 1\.3\.[0-3]', re.I), "Eski ProFTPD sürümü — RCE açıkları olabilir.", "high"),
    (re.compile(r'Apache httpd? 2\.[0-2]\.', re.I), "Eski Apache sürümü — bilinen CVE'ler olabilir, güncelleyin.", "medium"),
    (re.compile(r'OpenSSH [1-6]\.', re.I), "Eski OpenSSH sürümü — güncel sürüme yükseltin.", "medium"),
    (re.compile(r'Microsoft-IIS/[1-6]\.', re.I), "Eski IIS sürümü — güncelleyin.", "medium"),
    (re.compile(r'nginx/1\.(?:[0-9]|1[0-2])\.', re.I), "Eski nginx sürümü — güncel sürüm önerilir.", "medium"),
]


def parse_nmap(stdout: str, command: str = "") -> Dict[str, Any]:
    result = _empty("nmap")
    ports = []
    for line in stdout.splitlines():
        m = _NMAP_PORT_RE.match(line)
        if not m:
            continue
        port, proto, state, service, version = m.groups()
        if "open" not in state:
            continue
        version = (version or "").strip()
        risk = _service_risk(service, port)
        ports.append({"port": port, "proto": proto, "state": "open",
                      "service": service, "version": version, "risk": risk})

    result["ports"] = ports

    # Build highlighted findings from the ports
    for p in ports:
        label = f"{p['service']} ({p['port']}/{p['proto']})"
        if p["risk"] == "high":
            result["findings"].append({
                "title": f"{label} dışarıya açık",
                "detail": (f"Hassas/uzaktan yönetim servisi erişilebilir durumda"
                           f"{' — ' + p['version'] if p['version'] else ''}. "
                           f"Firewall ile sınırlandırın veya kapatın."),
                "severity": "high",
            })
        # Version-based outdated/vulnerable checks
        for rx, msg, sev in _OUTDATED_HINTS:
            if p["version"] and rx.search(p["version"]):
                result["findings"].append({
                    "title": f"{label}: {p['version']}",
                    "detail": msg, "severity": sev,
                })
                break

    # Medium services that weren't already flagged as high
    flagged_ports = {f["title"].split("(")[-1].split("/")[0] for f in result["findings"]}
    for p in ports:
        if p["risk"] == "medium" and p["port"] not in flagged_ports:
            result["findings"].append({
                "title": f"{p['service']} ({p['port']}/{p['proto']}) açık",
                "detail": "Yaygın olarak hedef alınan/temiz-metin servis — erişimi ve yapılandırmayı gözden geçirin.",
                "severity": "medium",
            })

    if ports and not result["findings"]:
        result["findings"].append({
            "title": f"{len(ports)} açık port bulundu",
            "detail": "Belirgin bir yüksek risk tespit edilmedi; servis sürümlerini yine de gözden geçirin.",
            "severity": "info",
        })

    return _finalize(result)


# ---------------------------------------------------------------------------
# nikto  (+ lines are findings)
# ---------------------------------------------------------------------------
def parse_nikto(stdout: str, command: str = "") -> Dict[str, Any]:
    result = _empty("nikto")
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        text = line[2:].strip()
        # Skip pure informational header lines
        low = text.lower()
        if low.startswith(("target ip", "target host", "target port",
                           "start time", "end time", "server:", "ssl info",
                           "root page", "retrieved")):
            sev = "info"
        elif re.search(r'cve-|traversal|backdoor|remote code|\brce\b|shell upload|'
                       r'sql inject|command inject|default (account|cred)|arbitrary file', text, re.I):
            sev = "high"
        elif re.search(r'osvdb|outdated|deprecated|allowed http methods|\bput\b|\bdelete\b|'
                       r'\btrace\b|directory indexing|admin|phpinfo|backup|config', text, re.I):
            sev = "medium"
        elif re.search(r'header|cookie|x-|clickjack|autocomplete|charset', text, re.I):
            sev = "low"
        else:
            sev = "low"
        result["findings"].append({"title": text[:120], "detail": text if len(text) > 120 else "", "severity": sev})
    return _finalize(result)


# ---------------------------------------------------------------------------
# gobuster (dir mode) / dirb  -> discovered paths
# ---------------------------------------------------------------------------
_GOBUSTER_RE = re.compile(r'^(\/\S*)\s+\(Status:\s*(\d{3})\)(?:\s*\[Size:\s*(\d+)\])?', re.I)
_DIRB_URL_RE = re.compile(r'^\+\s+(\S+)\s+\(CODE:(\d{3})[^)]*\)', re.I)
_DIRB_DIR_RE = re.compile(r'^==>\s*DIRECTORY:\s*(\S+)', re.I)


def _status_severity(code: str) -> str:
    if code in ("200", "301", "302"):
        return "medium"   # reachable resource
    if code == "403":
        return "low"      # exists but forbidden
    if code in ("401",):
        return "medium"
    return "info"


def parse_gobuster(stdout: str, command: str = "") -> Dict[str, Any]:
    result = _empty("gobuster")
    for line in stdout.splitlines():
        m = _GOBUSTER_RE.match(line.strip())
        if not m:
            continue
        path, code, size = m.groups()
        result["findings"].append({
            "title": f"{path}  →  HTTP {code}",
            "detail": f"Boyut: {size} bayt" if size else "",
            "severity": _status_severity(code),
        })
    return _finalize(result)


def parse_dirb(stdout: str, command: str = "") -> Dict[str, Any]:
    result = _empty("dirb")
    for raw in stdout.splitlines():
        line = raw.strip()
        m = _DIRB_URL_RE.match(line)
        if m:
            url, code = m.groups()
            result["findings"].append({
                "title": f"{url}  →  HTTP {code}", "detail": "",
                "severity": _status_severity(code)})
            continue
        d = _DIRB_DIR_RE.match(line)
        if d:
            result["findings"].append({
                "title": f"Dizin bulundu: {d.group(1)}", "detail": "",
                "severity": "medium"})
    return _finalize(result)


# ---------------------------------------------------------------------------
# sqlmap
# ---------------------------------------------------------------------------
def parse_sqlmap(stdout: str, command: str = "") -> Dict[str, Any]:
    result = _empty("sqlmap")
    text = stdout
    if re.search(r'is vulnerable|appears to be .* injectable|parameter .* is .* injectable', text, re.I):
        result["findings"].append({
            "title": "SQL Injection açığı tespit edildi",
            "detail": "Hedef parametre SQL injection'a karşı savunmasız — kritik bulgu.",
            "severity": "high"})
    # Injection techniques
    for m in re.finditer(r'Type:\s*(.+)', text):
        result["findings"].append({"title": f"Injection tekniği: {m.group(1).strip()[:80]}",
                                   "detail": "", "severity": "medium"})
    # Parameter
    for m in re.finditer(r'Parameter:\s*(.+)', text):
        result["findings"].append({"title": f"Savunmasız parametre: {m.group(1).strip()[:80]}",
                                   "detail": "", "severity": "high"})
    # DBMS
    m = re.search(r'back-end DBMS:\s*(.+)', text, re.I)
    if m:
        result["findings"].append({"title": f"Veritabanı: {m.group(1).strip()[:80]}",
                                   "detail": "", "severity": "info"})
    # available databases
    dbs = re.findall(r'^\[\*\]\s+(\w+)\s*$', text, re.M)
    if dbs:
        result["findings"].append({
            "title": f"{len(dbs)} veritabanı listelendi",
            "detail": ", ".join(dbs[:15]), "severity": "medium"})
    return _finalize(result)


PARSERS = {
    "nmap": parse_nmap,
    "nikto": parse_nikto,
    "gobuster": parse_gobuster,
    "dirb": parse_dirb,
    "sqlmap": parse_sqlmap,
}


def parse_findings(tool_name: str, command: str, stdout: str, stderr: str = "") -> Dict[str, Any]:
    """Dispatch to the right parser. Returns a structured findings dict."""
    tool = (tool_name or "").lower().strip()
    if not tool and command:
        tool = command.strip().split(" ")[0].lower()
    parser = PARSERS.get(tool)
    if not parser:
        return _empty(tool or "unknown", supported=False)
    try:
        return parser(stdout or "", command or "")
    except Exception as e:  # never let a parser crash the request
        res = _empty(tool)
        res["findings"].append({"title": "Ayrıştırma hatası", "detail": str(e), "severity": "info"})
        return _finalize(res)
