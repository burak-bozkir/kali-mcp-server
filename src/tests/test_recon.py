#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for the chained recon workflow helpers (src/backend/recon.py).
No server, no Kali tools needed.

    python3 src/tests/test_recon.py
"""

import sys
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import findings  # noqa: E402
import recon     # noqa: E402

passed, failed = [], []


def check(name, cond, info=""):
    (passed if cond else failed).append(name)
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"  {mark} {name}" + ("" if cond else f" — {info}"))


NMAP_OUT = """\
Starting Nmap 7.94 ( https://nmap.org )
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.3.4
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open  ssl/http nginx 1.18.0
593/tcp  open  ncacn_http Microsoft Windows RPC over HTTP 1.0
3306/tcp open  mysql    MySQL 5.7.33
8080/tcp open  http-proxy
8443/tcp open  unknown
9000/tcp closed http
Nmap done: 1 IP address (1 host up)
"""


def test_web_targets():
    print("\nweb_targets_from_ports")
    ports = findings.parse_nmap(NMAP_OUT)["ports"]
    web = recon.web_targets_from_ports(ports, "10.0.0.5", limit=20)
    urls = [w["url"] for w in web]
    check("http on 80 → no port in URL", "http://10.0.0.5" in urls, urls)
    check("ssl/http on 443 → https, no port", "https://10.0.0.5" in urls, urls)
    check("http-proxy on 8080", "http://10.0.0.5:8080" in urls, urls)
    check("unknown on 8443 → https by port hint", "https://10.0.0.5:8443" in urls, urls)
    check("ncacn_http (RPC) is not web", not any(":593" in u for u in urls), urls)
    check("ssh / mysql / ftp not web", len(web) == 4, urls)
    check("closed port ignored", not any(":9000" in u for u in urls), urls)
    check("limit respected", len(recon.web_targets_from_ports(ports, "h", limit=2)) == 2)
    v6 = recon.web_targets_from_ports([{"port": "80", "proto": "tcp", "state": "open",
                                        "service": "http"}], "fe80::1")
    check("IPv6 host is bracketed", v6 and v6[0]["url"] == "http://[fe80::1]", v6)
    check("empty ports → []", recon.web_targets_from_ports([], "h") == [])


def test_validation():
    print("\nvalidate / normalize_options")
    check("IPv4 ok", recon.validate_host("192.168.1.10") is None)
    check("hostname ok", recon.validate_host("scanme.nmap.org") is None)
    check("IPv6 ok", recon.validate_host("fe80::1") is None)
    for bad in ["", "10.0.0.0/24", "http://x.com", "a;rm -rf /", "x y", "$(id)"]:
        check(f"reject host {bad!r}", recon.validate_host(bad) is not None)

    opts, err = recon.normalize_options({"target": "10.0.0.5"})
    check("defaults applied (per-tool timeouts)", err is None and opts["nmap_args"] == "-T4 -Pn"
          and opts["run_gobuster"] and opts["run_nikto"] and opts["step_timeout"] is None, err)
    opts, _ = recon.normalize_options({"target": "10.0.0.5", "step_timeout": ""})
    check("empty step_timeout → tool default", opts["step_timeout"] is None)
    opts, _ = recon.normalize_options({"target": "10.0.0.5", "step_timeout": 2400})
    check("explicit step_timeout kept", opts["step_timeout"] == 2400)
    for field, val in [("nmap_args", "-T4; id"), ("gobuster_args", "-t 5 | nc"),
                       ("nikto_args", "`id`"), ("nmap_args", "-oN >/tmp/x"),
                       ("wordlist", "/tmp/a b.txt"), ("ports", "80;id")]:
        _, err = recon.normalize_options({"target": "10.0.0.5", field: val}, 180)
        check(f"reject {field}={val!r}", err is not None)
    opts, _ = recon.normalize_options({"target": "h", "max_web_targets": 999, "step_timeout": 1}, 180)
    check("max_web_targets clamped", opts["max_web_targets"] == recon.HARD_MAX_WEB_TARGETS)
    check("step_timeout clamped", opts["step_timeout"] == recon.MIN_STEP_TIMEOUT)
    _, err = recon.normalize_options({"target": "h", "step_timeout": "abc"}, 180)
    check("non-numeric timeout rejected", err is not None)


def test_commands_and_plan():
    print("\ncommand builders / plan")
    opts, _ = recon.normalize_options({"target": "10.0.0.5", "ports": "1-1000"}, 180)
    check("nmap command", recon.build_nmap_command(opts) == "nmap -sV -p 1-1000 -T4 -Pn 10.0.0.5",
          recon.build_nmap_command(opts))
    https = {"url": "https://10.0.0.5", "scheme": "https"}
    http = {"url": "http://10.0.0.5:8080", "scheme": "http"}
    g = recon.build_gobuster_command(https, opts)
    check("gobuster https gets -k", " -k" in g and g.startswith("gobuster dir -u https://10.0.0.5"), g)
    check("gobuster http has no -k", " -k" not in recon.build_gobuster_command(http, opts))
    check("nikto command", recon.build_nikto_command(http, opts) == "nikto -h http://10.0.0.5:8080")

    plan = recon.plan_web_steps([https, http], opts)
    check("plan: 2 targets × 2 tools", [s["tool"] for s in plan] == ["gobuster", "nikto", "gobuster", "nikto"])
    opts["run_nikto"] = False
    check("plan: nikto off", [s["tool"] for s in recon.plan_web_steps([http], opts)] == ["gobuster"])


def test_aggregation():
    print("\nsummarize / combined_findings")
    steps = [recon.new_step(0, "nmap", "h", "nmap h"), recon.new_step(1, "nikto", "http://h", "nikto")]
    steps[0].update(status="done", summary={"open_ports": 3, "high": 1, "medium": 1, "low": 0, "info": 0, "total": 2},
                    findings=[{"title": "a", "severity": "medium"}, {"title": "b", "severity": "high"}])
    steps[1].update(status="failed", summary={"open_ports": 0, "high": 0, "medium": 0, "low": 1, "info": 0, "total": 1},
                    findings=[{"title": "c", "severity": "low"}])
    s = recon.summarize(steps, [{"url": "http://h"}])
    check("summary totals", s["open_ports"] == 3 and s["high"] == 1 and s["total"] == 3
          and s["web_targets"] == 1 and s["steps_done"] == 1 and s["steps_failed"] == 1, s)
    comb = recon.combined_findings(steps)
    check("combined sorted by severity", [f["title"] for f in comb] == ["b", "a", "c"], comb)
    check("combined tagged with tool", comb[0]["tool"] == "nmap" and comb[2]["tool"] == "nikto")
    many = [{"title": str(i), "severity": "info"} for i in range(80)] + [{"title": "x", "severity": "high"}]
    t = recon.trim_findings(many)
    check("trim keeps most severe first", len(t) == recon.MAX_FINDINGS_PER_STEP and t[0]["title"] == "x")


def main():
    print("=" * 60 + "\n  Recon workflow — unit tests\n" + "=" * 60)
    test_web_targets()
    test_validation()
    test_commands_and_plan()
    test_aggregation()
    print(f"\n  Passed: {len(passed)}   Failed: {len(failed)}")
    for f in failed:
        print(f"    - {f}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
