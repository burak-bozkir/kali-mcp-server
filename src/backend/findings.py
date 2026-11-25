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

import json
import re
from typing import Any, Dict

SEVERITIES = ("high", "medium", "low", "info")
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}

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
    sevs = [f.get("severity", "info") for f in result["findings"]]
    result["summary"] = {"open_ports": len(result["ports"]),
                         **{sev: sevs.count(sev) for sev in SEVERITIES},
                         "total": len(sevs)}
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
                # keep the ports table consistent with the highlighted finding
                if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(p["risk"], 0):
                    p["risk"] = sev
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
        else:
            sev = "low"   # headers, cookies and everything else
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


# ---------------------------------------------------------------------------
# hydra  -> cracked credentials
# ---------------------------------------------------------------------------
# [22][ssh] host: 10.0.0.5   login: admin   password: admin123
_HYDRA_CRED_RE = re.compile(
    r'^\[(\d+)\]\[([\w\-]+)\]\s+host:\s*(\S+)(?:\s+login:\s*(\S*))?(?:\s+password:\s?(.*))?$')
_HYDRA_SUMMARY_RE = re.compile(r'(\d+)\s+valid passwords?\s+found', re.I)


def parse_hydra(stdout: str, command: str = "") -> Dict[str, Any]:
    result = _empty("hydra")
    seen = set()
    errors = []
    for raw in stdout.splitlines():
        line = raw.strip()
        m = _HYDRA_CRED_RE.match(line)
        if m:
            port, service, host, login, password = m.groups()
            login = login or ""
            password = (password or "").rstrip()
            key = (host, port, service, login, password)
            if key in seen:
                continue
            seen.add(key)
            if not password:
                note = "Boş parola ile giriş yapılabiliyor!"
            elif password == login:
                note = "Parola kullanıcı adıyla aynı."
            else:
                note = "Zayıf/tahmin edilebilir parola."
            result["findings"].append({
                "title": f"Geçerli kimlik bilgisi: {service} ({host}:{port})",
                "detail": (f"Kullanıcı: {login or '(boş)'} · Parola: {password or '(boş)'} — {note} "
                           f"Parolayı değiştirin, güçlü parola politikası ve hesap kilitleme uygulayın."),
                "severity": "high",
            })
            continue
        if line.startswith("[ERROR]") and len(errors) < 3:
            errors.append(line[7:].strip())

    if not result["findings"]:
        m = _HYDRA_SUMMARY_RE.search(stdout)
        if m or "successfully completed" in stdout:
            result["findings"].append({
                "title": "Geçerli kimlik bilgisi bulunamadı",
                "detail": "Denenen kullanıcı/parola listesiyle giriş başarılı olmadı.",
                "severity": "info"})
    for e in errors:
        result["findings"].append({"title": f"Hydra hatası: {e[:100]}", "detail": e if len(e) > 100 else "",
                                   "severity": "info"})
    return _finalize(result)


# ---------------------------------------------------------------------------
# wpscan  (CLI text output, or --format json)
# ---------------------------------------------------------------------------
_WP_HIGH_VULN_RE = re.compile(
    r'remote code|\brce\b|code execution|sql injection|sqli|authenticated? bypass|'
    r'unauthenticated|privilege escalation|arbitrary file|file upload|object injection|'
    r'command injection|takeover', re.I)


def _wp_vuln_severity(title: str) -> str:
    return "high" if _WP_HIGH_VULN_RE.search(title or "") else "medium"


# interesting finding text -> (title, detail, severity)
_WP_INTERESTING = [
    (re.compile(r'debug log found', re.I), "Debug log erişilebilir",
     "debug.log dosyası hassas bilgi (yol, hata, kimlik) sızdırabilir.", "high"),
    (re.compile(r'config backup|wp-config', re.I), "wp-config yedeği bulundu",
     "Veritabanı parolası içerebilir — hemen kaldırın.", "high"),
    (re.compile(r'db export|database export', re.I), "Veritabanı dışa aktarımı bulundu",
     "Tüm veritabanı içeriği indirilebilir olabilir.", "high"),
    (re.compile(r'upload directory has listing enabled|directory listing', re.I),
     "Dizin listeleme açık", "Yüklenen dosyalar listelenebiliyor — dizin listelemeyi kapatın.", "medium"),
    (re.compile(r'xml-rpc', re.I), "XML-RPC etkin",
     "xmlrpc.php kaba kuvvet (system.multicall) ve pingback saldırılarına açık olabilir.", "medium"),
    (re.compile(r'registration is enabled', re.I), "Kullanıcı kaydı açık",
     "Herkes hesap açabiliyor — gerekmiyorsa kapatın.", "medium"),
    (re.compile(r'full path disclosure', re.I), "Tam yol ifşası",
     "Sunucu dosya yolu sızıyor.", "low"),
    (re.compile(r'readme', re.I), "WordPress readme dosyası erişilebilir",
     "Sürüm bilgisini ifşa edebilir — kaldırın.", "low"),
    (re.compile(r'wp-cron', re.I), "Harici WP-Cron etkin",
     "DoS amaçlı kötüye kullanılabilir; genelde düşük risk.", "info"),
]


def _wp_interesting(text: str):
    for rx, title, detail, sev in _WP_INTERESTING:
        if rx.search(text):
            return title, detail, sev
    return None


def _parse_wpscan_json(data: Dict[str, Any], result: Dict[str, Any]) -> None:
    F = result["findings"]

    def add_vulns(component: str, vulns):
        for v in vulns or []:
            title = v.get("title", "?")
            fixed = v.get("fixed_in")
            refs = (v.get("references") or {}).get("cve") or []
            detail = []
            if fixed:
                detail.append(f"Düzeltildiği sürüm: {fixed}")
            if refs:
                detail.append("CVE: " + ", ".join("CVE-" + str(c) for c in refs[:5]))
            F.append({"title": f"{component}: {title}"[:160], "detail": " · ".join(detail),
                      "severity": _wp_vuln_severity(title)})

    for it in data.get("interesting_findings") or []:
        text = it.get("to_s") or it.get("type") or ""
        hit = _wp_interesting(text)
        if hit:
            title, detail, sev = hit
            F.append({"title": title, "detail": f"{detail} ({it.get('url', '')})".strip(), "severity": sev})

    ver = data.get("version") or {}
    if ver.get("number"):
        status = (ver.get("status") or "").lower()
        if status == "insecure":
            F.append({"title": f"WordPress {ver['number']} güvensiz sürüm",
                      "detail": "Bilinen açıkları olan sürüm — güncelleyin.", "severity": "medium"})
        else:
            F.append({"title": f"WordPress sürümü: {ver['number']}", "detail": status, "severity": "info"})
        add_vulns(f"WordPress {ver['number']}", ver.get("vulnerabilities"))

    themes = {}
    if data.get("main_theme"):
        themes[data["main_theme"].get("slug", "theme")] = data["main_theme"]
    themes.update(data.get("themes") or {})
    for kind, items in (("Tema", themes), ("Eklenti", data.get("plugins") or {})):
        for name, info in items.items():
            info = info or {}
            if info.get("outdated"):
                cur = (info.get("version") or {}).get("number") or "?"
                F.append({"title": f"{kind} güncel değil: {name} {cur}",
                          "detail": f"Son sürüm: {info.get('latest_version') or '?'}", "severity": "low"})
            add_vulns(f"{kind} {name}", info.get("vulnerabilities"))

    users = list((data.get("users") or {}).keys())
    if users:
        F.append({"title": f"{len(users)} WordPress kullanıcısı listelendi",
                  "detail": ", ".join(users[:20]) + " — kaba kuvvet saldırısında kullanılabilir.",
                  "severity": "low"})

    for user, info in (data.get("password_attack") or {}).items():
        pw = (info or {}).get("password", "")
        F.append({"title": f"Geçerli WordPress girişi: {user}",
                  "detail": f"Parola: {pw} — hemen değiştirin.", "severity": "high"})


_WP_VULN_TITLE_RE = re.compile(r'\[!\]\s*Title:\s*(.+)')
_WP_FIXED_RE = re.compile(r'Fixed in:\s*(\S+)', re.I)
_WP_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}|cvename\.cgi\?name=(CVE-\d{4}-\d{4,7})', re.I)
_WP_CRED_RE = re.compile(r'Username:\s*(\S+?),\s*Password:\s*(.*)$', re.I)


def parse_wpscan(stdout: str, command: str = "") -> Dict[str, Any]:
    result = _empty("wpscan")
    text = stdout.strip()
    if text.startswith("{"):
        try:
            _parse_wpscan_json(json.loads(text), result)
            return _finalize(result)
        except ValueError:
            pass

    F = result["findings"]
    component = "WordPress"
    section = None          # "plugins" | "themes" | "users" | "creds"
    users, plugins = [], []
    current_vuln = None

    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue

        # --- details of the vulnerability currently being read
        if current_vuln is not None and line.startswith("|"):
            fm = _WP_FIXED_RE.search(line)
            if fm:
                current_vuln["_fixed"] = fm.group(1)
            for cm in _WP_CVE_RE.finditer(line):
                cve = (cm.group(1) or cm.group(0)).upper()
                if cve not in current_vuln["_cves"]:
                    current_vuln["_cves"].append(cve)

        vm = _WP_VULN_TITLE_RE.search(line)
        if vm:
            title = vm.group(1).strip()
            current_vuln = {"title": f"{component}: {title}"[:160], "detail": "",
                            "severity": _wp_vuln_severity(title), "_fixed": None, "_cves": []}
            F.append(current_vuln)
            continue
        if not line.startswith("|"):
            current_vuln = None

        # --- section headers
        low = line.lower()
        if low.startswith("[i] plugin(s) identified"):
            section = "plugins"; continue
        if low.startswith("[i] theme(s) identified"):
            section = "themes"; continue
        if low.startswith("[i] user(s) identified"):
            section = "users"; continue
        if "valid combinations found" in low:
            section = "creds"; continue
        if low.startswith(("[+] enumerating", "[i] no ")):
            section = None

        # --- credentials found by the password attack
        cm = _WP_CRED_RE.search(line)
        if cm and section == "creds":
            F.append({"title": f"Geçerli WordPress girişi: {cm.group(1)}",
                      "detail": f"Parola: {cm.group(2).strip()} — hemen değiştirin.", "severity": "high"})
            continue

        if line.startswith("[+]"):
            body = line[3:].strip()
            vmatch = re.match(r'WordPress version\s+(\S+)\s+identified(.*)', body, re.I)
            if vmatch:
                ver, rest = vmatch.groups()
                component = f"WordPress {ver}"
                section = None
                if "insecure" in rest.lower():
                    F.append({"title": f"WordPress {ver} güvensiz sürüm",
                              "detail": "Bilinen açıkları olan sürüm — güncelleyin.", "severity": "medium"})
                else:
                    F.append({"title": f"WordPress sürümü: {ver}", "detail": rest.strip(" ()."),
                              "severity": "info"})
                continue
            tm = re.match(r'WordPress theme in use:\s*(\S+)', body, re.I)
            if tm:
                component = f"Tema {tm.group(1)}"
                section = None
                continue
            if section == "plugins" and re.fullmatch(r'[\w.\-]+', body):
                component = f"Eklenti {body}"
                plugins.append(body)
                continue
            if section == "themes" and re.fullmatch(r'[\w.\-]+', body):
                component = f"Tema {body}"
                continue
            if section == "users" and re.fullmatch(r'\S+', body):
                users.append(body)
                continue
            hit = _wp_interesting(body)
            if hit:
                title, detail, sev = hit
                url = re.search(r'https?://\S+', body)
                F.append({"title": title, "detail": detail + (f" ({url.group(0)})" if url else ""),
                          "severity": sev})
                continue

        # | [!] The version is out of date, the latest version is 2.1
        om = re.search(r'out of date, the latest version is\s*(\S+)', line, re.I)
        if om and not component.startswith("WordPress"):
            F.append({"title": f"{component} güncel değil", "detail": f"Son sürüm: {om.group(1)}",
                      "severity": "low"})

    for f in F:
        fixed, cves = f.pop("_fixed", None), f.pop("_cves", [])
        parts = []
        if fixed:
            parts.append(f"Düzeltildiği sürüm: {fixed}")
        if cves:
            parts.append("CVE: " + ", ".join(cves[:5]))
        if parts:
            f["detail"] = " · ".join(parts)

    if users:
        F.append({"title": f"{len(users)} WordPress kullanıcısı listelendi",
                  "detail": ", ".join(users[:20]) + " — kaba kuvvet saldırısında kullanılabilir.",
                  "severity": "low"})
    if plugins:
        F.append({"title": f"{len(plugins)} eklenti tespit edildi",
                  "detail": ", ".join(plugins[:30]), "severity": "info"})
    if re.search(r'No WPScan API Token given', stdout, re.I):
        F.append({"title": "WPScan API token verilmedi",
                  "detail": "Açık (vulnerability) verisi gösterilmedi. --api-token ile tekrar çalıştırın.",
                  "severity": "info"})
    return _finalize(result)


# ---------------------------------------------------------------------------
# enum4linux  -> SMB/Samba enumeration
# ---------------------------------------------------------------------------
_E4L_NULL_RE = re.compile(r"allows? sessions? using username '',\s*password ''", re.I)
_E4L_DOMAIN_RE = re.compile(r'Got domain/workgroup name:\s*(\S+)', re.I)
_E4L_SAMBA_RE = re.compile(r'Samba\s+(\d+\.\d+(?:\.\d+)?)[\w.\-]*', re.I)
_E4L_USER_RES = [
    re.compile(r'^user:\[([^\]]+)\]\s+rid:', re.I),
    re.compile(r'Account:\s*(\S+)\s+Name:', re.I),
    re.compile(r'^S-1-[\d-]+\s+.+?\\(\S+)\s+\((?:Local|Domain) User\)', re.I),
]
_E4L_SHARE_RE = re.compile(r'^\s*(\S+)\s+(Disk|IPC|Printer)\s*(.*)$')
_E4L_MAP_RE = re.compile(
    r'^//[^/]+/(\S+)\s+Mapping:\s*(\w+),?\s*Listing:\s*([\w/]+)(?:,?\s*Writing:\s*([\w/]+))?', re.I)
_E4L_MINLEN_RE = re.compile(r'Minimum password length:\s*(\d+)', re.I)
_E4L_LOCKOUT_RE = re.compile(r'Account Lockout Threshold:\s*(\S+)', re.I)
_E4L_COMPLEX_RE = re.compile(r'Password Complex(?:ity)?(?: Flags)?:?\s*(\S+)', re.I)


def _samba_version_risk(ver: str):
    parts = [int(x) for x in ver.split(".")]
    while len(parts) < 3:
        parts.append(0)
    if parts[:2] == [3, 0] and 20 <= parts[2] <= 25:
        return ("Samba 3.0.20–3.0.25 — usermap_script RCE açığı (CVE-2007-2447)!", "high")
    if parts[0] < 3 or (parts[0] == 3 and parts[1] <= 5):
        return ("Çok eski Samba sürümü — bilinen uzaktan açıkları var, güncelleyin.", "high")
    if parts[0] == 3 or (parts[0] == 4 and parts[1] < 6):
        return ("Eski Samba sürümü (ör. SambaCry CVE-2017-7494) — güncelleyin.", "medium")
    return None


def parse_enum4linux(stdout: str, command: str = "") -> Dict[str, Any]:
    result = _empty("enum4linux")
    F = result["findings"]

    if _E4L_NULL_RE.search(stdout):
        F.append({"title": "Null session (anonim SMB oturumu) açık",
                  "detail": "Kullanıcı adı ve parola olmadan oturum açılabiliyor; kullanıcı, paylaşım ve "
                            "politika bilgisi sızar. RestrictAnonymous / 'restrict anonymous = 2' ayarlayın.",
                  "severity": "high"})

    m = _E4L_DOMAIN_RE.search(stdout)
    if m:
        F.append({"title": f"Domain/Workgroup: {m.group(1)}", "detail": "", "severity": "info"})

    sm = _E4L_SAMBA_RE.search(stdout)
    if sm:
        ver = sm.group(1)
        risk = _samba_version_risk(ver)
        if risk:
            F.append({"title": f"Samba {ver}", "detail": risk[0], "severity": risk[1]})
        else:
            F.append({"title": f"Samba sürümü: {ver}", "detail": "", "severity": "info"})

    users, shares, groups = [], [], []
    for raw in stdout.splitlines():
        line = raw.rstrip()
        for rx in _E4L_USER_RES:
            um = rx.search(line.strip())
            if um:
                u = um.group(1)
                if u not in users:
                    users.append(u)
                break
        gm = re.match(r'^group:\[([^\]]+)\]', line.strip(), re.I)
        if gm and gm.group(1) not in groups:
            groups.append(gm.group(1))
        shm = _E4L_SHARE_RE.match(line)
        if shm and shm.group(1) not in ("Sharename", "---------") and shm.group(1) not in shares:
            shares.append(shm.group(1))
        mm = _E4L_MAP_RE.match(line.strip())
        if mm:
            share, mapping, listing, writing = mm.groups()
            if (writing or "").upper() == "OK":
                F.append({"title": f"Anonim yazılabilir paylaşım: {share}",
                          "detail": "Kimlik doğrulamasız dosya yazılabiliyor — zararlı dosya yükleme riski.",
                          "severity": "high"})
            elif mapping.upper() == "OK" and listing.upper() == "OK":
                F.append({"title": f"Anonim erişilebilir paylaşım: {share}",
                          "detail": "Kimlik doğrulamasız listelenebiliyor — içeriği ve izinleri gözden geçirin.",
                          "severity": "medium"})

    if users:
        F.append({"title": f"{len(users)} kullanıcı hesabı listelendi",
                  "detail": ", ".join(users[:25]) + " — parola saldırılarında hedef listesi olarak kullanılabilir.",
                  "severity": "medium"})
    if shares:
        F.append({"title": f"{len(shares)} SMB paylaşımı bulundu", "detail": ", ".join(shares[:25]),
                  "severity": "info"})
    if groups:
        F.append({"title": f"{len(groups)} grup listelendi", "detail": ", ".join(groups[:25]),
                  "severity": "info"})

    mm = _E4L_MINLEN_RE.search(stdout)
    if mm and int(mm.group(1)) < 8:
        F.append({"title": f"Zayıf parola politikası: minimum uzunluk {mm.group(1)}",
                  "detail": "En az 8 (tercihen 12+) karakter zorunlu tutun.", "severity": "medium"})
    lm = _E4L_LOCKOUT_RE.search(stdout)
    if lm and lm.group(1).lower() in ("none", "0"):
        F.append({"title": "Hesap kilitleme eşiği yok",
                  "detail": "Sınırsız parola denemesi yapılabilir — kaba kuvvete açık.", "severity": "medium"})
    cm = _E4L_COMPLEX_RE.search(stdout)
    if cm and cm.group(1) in ("0", "000000", "Disabled"):
        F.append({"title": "Parola karmaşıklığı zorunlu değil", "detail": "", "severity": "low"})
    return _finalize(result)


PARSERS = {
    "nmap": parse_nmap,
    "nikto": parse_nikto,
    "gobuster": parse_gobuster,
    "dirb": parse_dirb,
    "sqlmap": parse_sqlmap,
    "hydra": parse_hydra,
    "wpscan": parse_wpscan,
    "enum4linux": parse_enum4linux,
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
