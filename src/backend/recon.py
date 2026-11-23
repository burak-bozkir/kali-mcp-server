#!/usr/bin/env python3
"""
recon.py — Pure helpers for the chained recon workflow
(nmap → gobuster / nikto on every discovered web port).

Nothing here runs a process or touches the database, so it can be unit-tested
without Kali. The runner that actually executes the steps lives in
kali_server.py (ReconRunner).
"""

import re
from typing import Dict, Any, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Defaults & limits
# ---------------------------------------------------------------------------
DEFAULT_NMAP_SCAN_TYPE = "-sV"
DEFAULT_NMAP_ARGS = "-T4 -Pn"
DEFAULT_GOBUSTER_ARGS = "-t 30"
DEFAULT_NIKTO_ARGS = ""
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
DEFAULT_MAX_WEB_TARGETS = 5     # don't fan out to dozens of ports by accident
HARD_MAX_WEB_TARGETS = 20
MIN_STEP_TIMEOUT = 10
MAX_STEP_TIMEOUT = 14400

# Ports that are almost always HTTP(S) even when nmap can't name the service
COMMON_WEB_PORTS = {"80", "81", "443", "591", "3000", "5000", "8000", "8008",
                    "8080", "8081", "8443", "8888", "9000", "9443"}
HTTPS_PORTS = {"443", "8443", "9443"}
# Services that contain "http" in the name but are NOT web servers
NON_WEB_HTTP_SERVICES = {"ncacn_http"}   # Windows RPC over HTTP (port 593)

STEP_STATUSES = ("pending", "running", "done", "failed", "skipped", "cancelled")
WORKFLOW_STATUSES = ("running", "completed", "failed", "cancelled")

# ---------------------------------------------------------------------------
# Input validation (stricter than the single-tool endpoints, because a
# workflow runs several commands unattended from one request)
# ---------------------------------------------------------------------------
# A single host: IPv4, IPv6 in brackets or bare, or a hostname. No CIDR,
# no scheme, no path — the web URLs are built from this value.
_HOST_RE = re.compile(r'^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)*'
                      r'[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$')
_IPV6_RE = re.compile(r'^\[?[0-9A-Fa-f:]+\]?$')
# Extra CLI args: letters, digits, spaces and a few safe punctuation marks.
# Blocks ; | & > < ` $ ( ) quotes and newlines → no shell tricks.
_ARGS_RE = re.compile(r'^[A-Za-z0-9 \-_=.,:/+]*$')
_PATH_RE = re.compile(r'^[A-Za-z0-9_\-./]+$')
_PORTS_RE = re.compile(r'^[0-9,\-TU:]*$')


def validate_host(target: str) -> Optional[str]:
    """Return an error message, or None if `target` is a single valid host."""
    t = (target or "").strip()
    if not t:
        return "Hedef gerekli (target is required)"
    if len(t) > 253:
        return "Hedef çok uzun (target too long)"
    if "://" in t or "/" in t:
        return ("Zincirleme recon tek bir host bekler (IP veya domain); "
                "URL veya CIDR verilemez — örn. 10.0.0.5 veya example.com")
    if _HOST_RE.match(t) or (":" in t and _IPV6_RE.match(t)):
        return None
    return "Geçersiz hedef formatı (invalid host)"


def validate_args(value: str, field: str) -> Optional[str]:
    if value and not _ARGS_RE.match(value):
        return f"'{field}' izin verilmeyen karakter içeriyor (; | & > < ` $ tırnak vb.)"
    if value and len(value) > 300:
        return f"'{field}' çok uzun"
    return None


def validate_path(value: str, field: str) -> Optional[str]:
    if value and not _PATH_RE.match(value):
        return f"'{field}' geçerli bir dosya yolu değil"
    return None


def normalize_options(data: Dict[str, Any], default_timeout: Optional[int] = None) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Turn a request body into a clean options dict.
    Returns (options, error_message).
    """
    data = data or {}
    target = (data.get("target") or "").strip()
    err = validate_host(target)
    if err:
        return {}, err

    def _str(key, default):
        v = data.get(key)
        return default if v is None else str(v).strip()

    opts = {
        "target": target,
        "nmap_scan_type": _str("nmap_scan_type", DEFAULT_NMAP_SCAN_TYPE) or DEFAULT_NMAP_SCAN_TYPE,
        "nmap_args": _str("nmap_args", DEFAULT_NMAP_ARGS),
        "ports": _str("ports", ""),
        "run_gobuster": bool(data.get("run_gobuster", True)),
        "run_nikto": bool(data.get("run_nikto", True)),
        "wordlist": _str("wordlist", DEFAULT_WORDLIST) or DEFAULT_WORDLIST,
        "gobuster_args": _str("gobuster_args", DEFAULT_GOBUSTER_ARGS),
        "nikto_args": _str("nikto_args", DEFAULT_NIKTO_ARGS),
    }

    for field in ("nmap_scan_type", "nmap_args", "gobuster_args", "nikto_args"):
        err = validate_args(opts[field], field)
        if err:
            return {}, err
    if opts["ports"] and not _PORTS_RE.match(opts["ports"]):
        return {}, "'ports' yalnızca rakam, virgül ve tire içerebilir (örn. 1-1000,8080)"
    err = validate_path(opts["wordlist"], "wordlist")
    if err:
        return {}, err

    try:
        mwt = int(data.get("max_web_targets", DEFAULT_MAX_WEB_TARGETS))
    except (TypeError, ValueError):
        return {}, "'max_web_targets' bir sayı olmalı"
    opts["max_web_targets"] = max(1, min(mwt, HARD_MAX_WEB_TARGETS))

    # step_timeout: one value for every step. Empty/0/missing → None, and each
    # step uses its tool's own default (nmap 15 min, gobuster/nikto 30 min...).
    raw_st = data.get("step_timeout", default_timeout)
    if raw_st in (None, "", 0, "0"):
        opts["step_timeout"] = None
    else:
        try:
            st = int(raw_st)
        except (TypeError, ValueError):
            return {}, "'step_timeout' bir sayı olmalı (saniye)"
        opts["step_timeout"] = max(MIN_STEP_TIMEOUT, min(st, MAX_STEP_TIMEOUT))

    return opts, None


# ---------------------------------------------------------------------------
# Web target discovery from parsed nmap ports
# ---------------------------------------------------------------------------
def _is_web(service: str, port: str) -> bool:
    s = (service or "").lower().rstrip("?")
    if s in NON_WEB_HTTP_SERVICES:
        return False
    if "http" in s or s in ("www", "ssl/www"):
        return True
    # nmap couldn't name it, but the port is a classic web port
    return s in ("", "unknown", "tcpwrapped") and port in COMMON_WEB_PORTS


def _is_https(service: str, port: str) -> bool:
    s = (service or "").lower().rstrip("?")
    if s.startswith("ssl/") or s.startswith("https") or s == "http-ssl":
        return True
    if s.startswith("http"):
        return False          # explicit plain http on any port
    return port in HTTPS_PORTS


def _url_host(host: str) -> str:
    h = host.strip("[]")
    return f"[{h}]" if ":" in h else h


def web_targets_from_ports(ports: List[Dict[str, Any]], host: str,
                           limit: int = DEFAULT_MAX_WEB_TARGETS) -> List[Dict[str, Any]]:
    """
    From findings.parse_nmap()["ports"], pick the web services and build URLs.

    Returns e.g. [{"port": "80", "scheme": "http", "service": "http",
                   "url": "http://10.0.0.5"}]
    """
    out, seen = [], set()
    for p in ports or []:
        if p.get("proto", "tcp") != "tcp" or "open" not in p.get("state", "open"):
            continue
        port, service = str(p.get("port", "")), p.get("service", "")
        if not port or port in seen or not _is_web(service, port):
            continue
        seen.add(port)
        scheme = "https" if _is_https(service, port) else "http"
        default = (scheme == "http" and port == "80") or (scheme == "https" and port == "443")
        url = f"{scheme}://{_url_host(host)}" + ("" if default else f":{port}")
        out.append({"port": port, "scheme": scheme, "service": service, "url": url})
    return out[:max(0, limit)]


# ---------------------------------------------------------------------------
# Command builders (one place, so the UI/API/MCP all run the same thing)
# ---------------------------------------------------------------------------
def _join(*parts: str) -> str:
    return " ".join(p for p in parts if p)


def build_nmap_command(opts: Dict[str, Any]) -> str:
    ports = f"-p {opts['ports']}" if opts.get("ports") else ""
    return _join("nmap", opts["nmap_scan_type"], ports, opts.get("nmap_args", ""), opts["target"])


def build_gobuster_command(web: Dict[str, Any], opts: Dict[str, Any]) -> str:
    # -k: skip TLS verification (self-signed certs are the norm in labs)
    insecure = "-k" if web["scheme"] == "https" else ""
    return _join("gobuster dir", f"-u {web['url']}", f"-w {opts['wordlist']}",
                 insecure, opts.get("gobuster_args", ""))


def build_nikto_command(web: Dict[str, Any], opts: Dict[str, Any]) -> str:
    return _join("nikto", f"-h {web['url']}", opts.get("nikto_args", ""))


def plan_web_steps(web_targets: List[Dict[str, Any]], opts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build the follow-up steps (gobuster then nikto, per web target)."""
    steps = []
    for w in web_targets:
        if opts.get("run_gobuster"):
            steps.append({"tool": "gobuster", "target": w["url"],
                          "command": build_gobuster_command(w, opts)})
        if opts.get("run_nikto"):
            steps.append({"tool": "nikto", "target": w["url"],
                          "command": build_nikto_command(w, opts)})
    return steps


def new_step(index: int, tool: str, target: str, command: str) -> Dict[str, Any]:
    return {"index": index, "tool": tool, "target": target, "command": command,
            "status": "pending", "scan_id": None, "history_id": None,
            "started_at": None, "finished_at": None, "duration": 0.0,
            "return_code": None, "timed_out": False, "note": "",
            "summary": None, "findings": [], "ports": []}


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
MAX_FINDINGS_PER_STEP = 50
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def trim_findings(findings: List[Dict[str, Any]], limit: int = MAX_FINDINGS_PER_STEP) -> List[Dict[str, Any]]:
    """Keep the most severe findings first so big gobuster runs don't bloat the DB."""
    return sorted(findings or [], key=lambda f: _SEV_ORDER.get(f.get("severity"), 9))[:limit]


def summarize(steps: List[Dict[str, Any]], web_targets: List[Dict[str, Any]]) -> Dict[str, Any]:
    s = {"open_ports": 0, "web_targets": len(web_targets or []),
         "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0,
         "steps_total": len(steps), "steps_done": 0, "steps_failed": 0}
    for st in steps:
        if st["status"] == "done":
            s["steps_done"] += 1
        elif st["status"] == "failed":
            s["steps_failed"] += 1
        sm = st.get("summary") or {}
        if st["tool"] == "nmap":
            s["open_ports"] = sm.get("open_ports", 0)
        for k in ("high", "medium", "low", "info", "total"):
            s[k] += sm.get(k, 0)
    return s


def combined_findings(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """All findings across steps, tagged with their source, most severe first."""
    out = []
    for st in steps:
        for f in st.get("findings") or []:
            out.append({**f, "tool": st["tool"], "source": st["target"],
                        "step": st["index"]})
    out.sort(key=lambda f: _SEV_ORDER.get(f.get("severity"), 9))
    return out
