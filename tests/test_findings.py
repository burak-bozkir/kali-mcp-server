"""Unit tests for src/backend/findings.py (tool output -> risk-rated findings)."""
import pytest

import findings

NMAP_OUTPUT = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-11-24 10:00 UTC
Nmap scan report for 10.0.0.5
Host is up (0.00040s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE    SERVICE     VERSION
21/tcp   open     ftp         vsftpd 2.3.4
22/tcp   open     ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp   open     http        Apache httpd 2.4.52 ((Ubuntu))
139/tcp  filtered netbios-ssn
3306/tcp open     mysql       MySQL 5.7.33
8443/tcp closed   https-alt
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""

NIKTO_OUTPUT = """\
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.0.5
+ Target Hostname:    10.0.0.5
+ Target Port:        80
+ Start Time:         2026-11-24 10:00:00 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /phpinfo.php: Output from the phpinfo() function was found.
+ /index.php?page=../../../../etc/passwd: Directory traversal possible. CVE-2002-1234
+ Some unrelated note without keywords.
+ 8102 requests: 0 error(s) and 4 item(s) reported on remote host
"""

GOBUSTER_OUTPUT = """\
===============================================================
Gobuster v3.6
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://10.0.0.5/admin/]
/.htaccess            (Status: 403) [Size: 277]
/login                (Status: 401) [Size: 50]
/index.php            (Status: 200) [Size: 1234]
/old                  (Status: 404)
Progress: 4614 / 4615 (99.98%)
"""

DIRB_OUTPUT = """\
---- Scanning URL: http://10.0.0.5/ ----
+ http://10.0.0.5/index.php (CODE:200|SIZE:1234)
+ http://10.0.0.5/server-status (CODE:403|SIZE:277)
==> DIRECTORY: http://10.0.0.5/uploads/
"""

SQLMAP_OUTPUT = """\
[INFO] testing connection to the target URL
[INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based' injectable
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
---
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
available databases [3]:
[*] information_schema
[*] dvwa
[*] mysql
"""


def _titles(result):
    return [f["title"] for f in result["findings"]]


def _by_port(result):
    return {p["port"]: p for p in result["ports"]}


# --------------------------------------------------------------------------- nmap
class TestNmap:
    def test_only_open_ports_are_listed(self):
        res = findings.parse_nmap(NMAP_OUTPUT)
        assert sorted(_by_port(res)) == ["21", "22", "3306", "80"]
        assert res["summary"]["open_ports"] == 4

    def test_port_fields(self):
        p = _by_port(findings.parse_nmap(NMAP_OUTPUT))["22"]
        assert p == {"port": "22", "proto": "tcp", "state": "open", "service": "ssh",
                     "version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.1", "risk": "low"}

    def test_service_risk_levels(self):
        ports = _by_port(findings.parse_nmap(NMAP_OUTPUT))
        assert ports["3306"]["risk"] == "high"     # database exposed
        assert ports["80"]["risk"] == "medium"     # cleartext web
        assert ports["22"]["risk"] == "low"

    def test_known_backdoor_version_is_high(self):
        res = findings.parse_nmap(NMAP_OUTPUT)
        assert any("vsftpd 2.3.4" in t for t in _titles(res))
        # the ports table is raised to match the finding
        assert _by_port(res)["21"]["risk"] == "high"

    def test_exposed_database_is_a_high_finding(self):
        res = findings.parse_nmap(NMAP_OUTPUT)
        high = [f for f in res["findings"] if f["severity"] == "high"]
        assert any("mysql (3306/tcp)" in f["title"] for f in high)

    def test_ftp_port_not_reported_twice(self):
        res = findings.parse_nmap(NMAP_OUTPUT)
        assert sum("(21/tcp)" in t for t in _titles(res)) == 1

    def test_summary_counts_match_findings(self):
        res = findings.parse_nmap(NMAP_OUTPUT)
        s = res["summary"]
        assert s["total"] == len(res["findings"])
        assert s["high"] + s["medium"] + s["low"] + s["info"] == s["total"]

    def test_port_hint_when_service_unknown(self):
        res = findings.parse_nmap("6379/tcp open  unknown\n")
        assert res["ports"][0]["risk"] == "high"

    def test_only_low_risk_ports_gives_info_finding(self):
        res = findings.parse_nmap("22/tcp open ssh OpenSSH 9.6\n443/tcp open https\n")
        assert [f["severity"] for f in res["findings"]] == ["info"]
        assert "2 açık port" in res["findings"][0]["title"]

    def test_old_openssh_is_medium(self):
        res = findings.parse_nmap("22/tcp open ssh OpenSSH 5.3p1 Debian\n")
        assert res["ports"][0]["risk"] == "medium"
        assert res["summary"]["medium"] == 1

    def test_no_ports(self):
        res = findings.parse_nmap("Note: Host seems down.\n")
        assert res["ports"] == [] and res["findings"] == []
        assert res["summary"]["total"] == 0


# --------------------------------------------------------------------------- nikto
class TestNikto:
    def test_only_plus_lines_are_findings(self):
        res = findings.parse_nikto(NIKTO_OUTPUT)
        assert all(not t.startswith("-") for t in _titles(res))
        assert len(res["findings"]) == 10

    @pytest.mark.parametrize("needle,severity", [
        ("Target IP", "info"),
        ("Server: Apache", "info"),
        ("Directory traversal", "high"),
        ("phpinfo", "medium"),
        ("X-Frame-Options", "low"),
        ("unrelated note", "low"),
    ])
    def test_severity(self, needle, severity):
        res = findings.parse_nikto(NIKTO_OUTPUT)
        match = [f for f in res["findings"] if needle in f["title"]]
        assert match, needle
        assert match[0]["severity"] == severity

    def test_long_line_is_truncated_with_detail(self):
        line = "+ /x: " + "A" * 200
        f = findings.parse_nikto(line)["findings"][0]
        assert len(f["title"]) == 120
        assert f["detail"].endswith("A" * 10)


# --------------------------------------------------------------------------- gobuster / dirb
class TestGobuster:
    def test_paths_and_status_severity(self):
        res = findings.parse_gobuster(GOBUSTER_OUTPUT)
        sev = {f["title"].split()[0]: f["severity"] for f in res["findings"]}
        assert sev == {"/admin": "medium", "/.htaccess": "low", "/login": "medium",
                       "/index.php": "medium", "/old": "info"}

    def test_size_in_detail(self):
        res = findings.parse_gobuster(GOBUSTER_OUTPUT)
        admin = next(f for f in res["findings"] if f["title"].startswith("/admin"))
        assert admin["detail"] == "Boyut: 312 bayt"
        old = next(f for f in res["findings"] if f["title"].startswith("/old"))
        assert old["detail"] == ""

    def test_banner_lines_ignored(self):
        assert findings.parse_gobuster("Gobuster v3.6\nProgress: 1 / 2\n")["findings"] == []


class TestDirb:
    def test_urls_and_directories(self):
        res = findings.parse_dirb(DIRB_OUTPUT)
        assert _titles(res) == [
            "http://10.0.0.5/index.php  →  HTTP 200",
            "http://10.0.0.5/server-status  →  HTTP 403",
            "Dizin bulundu: http://10.0.0.5/uploads/",
        ]
        assert [f["severity"] for f in res["findings"]] == ["medium", "low", "medium"]


# --------------------------------------------------------------------------- sqlmap
class TestSqlmap:
    def test_vulnerable_target(self):
        res = findings.parse_sqlmap(SQLMAP_OUTPUT)
        titles = _titles(res)
        assert "SQL Injection açığı tespit edildi" in titles
        assert "Savunmasız parametre: id (GET)" in titles
        assert "Injection tekniği: boolean-based blind" in titles
        assert "Injection tekniği: UNION query" in titles
        assert "Veritabanı: MySQL >= 5.0" in titles

    def test_database_list(self):
        res = findings.parse_sqlmap(SQLMAP_OUTPUT)
        dbs = next(f for f in res["findings"] if "veritabanı listelendi" in f["title"])
        assert dbs["title"].startswith("3 ")
        assert dbs["detail"] == "information_schema, dvwa, mysql"

    def test_clean_target_has_no_findings(self):
        out = "[WARNING] GET parameter 'id' does not seem to be injectable\n"
        assert findings.parse_sqlmap(out)["findings"] == []


# --------------------------------------------------------------------------- dispatcher
class TestParseFindings:
    def test_registered_parsers(self):
        assert set(findings.PARSERS) == {"nmap", "nikto", "gobuster", "dirb", "sqlmap",
                                         "hydra", "wpscan", "enum4linux"}

    def test_dispatch_by_tool_name_is_case_insensitive(self):
        res = findings.parse_findings(" NMAP ", "", NMAP_OUTPUT)
        assert res["tool"] == "nmap" and res["supported"] is True
        assert res["summary"]["open_ports"] == 4

    def test_dispatch_from_command_when_tool_missing(self):
        res = findings.parse_findings("", "gobuster dir -u http://x", GOBUSTER_OUTPUT)
        assert res["tool"] == "gobuster" and len(res["findings"]) == 5

    def test_unsupported_tool(self):
        res = findings.parse_findings("john", "john hashes.txt", "whatever")
        assert res["supported"] is False and res["findings"] == []

    def test_none_output_is_safe(self):
        res = findings.parse_findings("nikto", None, None)
        assert res["supported"] is True and res["findings"] == []

    def test_parser_crash_becomes_info_finding(self, monkeypatch):
        def boom(stdout, command=""):
            raise RuntimeError("bad input")
        monkeypatch.setitem(findings.PARSERS, "nmap", boom)
        res = findings.parse_findings("nmap", "nmap x", "x")
        assert res["findings"] == [{"title": "Ayrıştırma hatası", "detail": "bad input",
                                    "severity": "info"}]
        assert res["summary"]["info"] == 1
