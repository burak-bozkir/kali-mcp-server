#!/usr/bin/env python3
"""
Findings parsers for hydra, wpscan and enum4linux (no server, no tools needed).

Each check feeds a realistic sample of the tool's output to findings.py and
looks at the risk-rated findings it returns.

    python3 src/tests/test_findings_parsers.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "backend"))

import findings  # noqa: E402

results = []


def check(name, cond, info=""):
    results.append(bool(cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  ({info})" if info and not cond else ""))


def titles(res, sev=None):
    return [f["title"] for f in res["findings"] if sev is None or f["severity"] == sev]


# ---------------------------------------------------------------- hydra
HYDRA_OK = """Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] max 4 tasks per 1 server, overall 4 tasks, 20 login tries (l:2/p:10)
[DATA] attacking ssh://10.0.0.5:22/
[22][ssh] host: 10.0.0.5   login: msfadmin   password: msfadmin
[22][ssh] host: 10.0.0.5   login: user   password: user123
[80][http-post-form] host: 10.0.0.5   login: admin   password: 
1 of 1 target successfully completed, 3 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-11-24 10:00:00
"""
HYDRA_NONE = """Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] attacking ftp://10.0.0.5:21/
1 of 1 target completed, 0 valid password found
"""
r = findings.parse_findings("hydra", "hydra -L u.txt -P p.txt ssh://10.0.0.5", HYDRA_OK)
check("hydra: supported", r["supported"])
check("hydra: 3 credentials, all high", r["summary"]["high"] == 3, r["summary"])
check("hydra: same login/password noted", any("kullanıcı adıyla aynı" in f["detail"] for f in r["findings"]))
check("hydra: empty password noted", any("Boş parola" in f["detail"] for f in r["findings"]))
check("hydra: service and port in title", "Geçerli kimlik bilgisi: ssh (10.0.0.5:22)" in titles(r))
r = findings.parse_findings("hydra", "", HYDRA_NONE)
check("hydra: no credentials -> one info finding",
      r["summary"]["total"] == 1 and r["summary"]["info"] == 1, r["findings"])

# ---------------------------------------------------------------- wpscan text
WPSCAN = """_______________________________________________________________
[+] URL: http://10.0.0.7/ [10.0.0.7]
[+] Started: Tue Nov 24 10:00:00 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.0.0.7/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)

[+] WordPress readme found: http://10.0.0.7/readme.html

[+] Upload directory has listing enabled: http://10.0.0.7/wp-content/uploads/

[+] The external WP-Cron seems to be enabled: http://10.0.0.7/wp-cron.php

[+] WordPress version 5.2.1 identified (Insecure, released on 2019-05-21).
 | Found By: Rss Generator (Passive Detection)
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 5.2.3
 |     References:
 |      - https://wpscan.com/vulnerability/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |
 | [!] Title: WordPress 5.0-5.2.2 - Authenticated Remote Code Execution
 |     Fixed in: 5.2.3

[+] WordPress theme in use: twentynineteen
 | Location: http://10.0.0.7/wp-content/themes/twentynineteen/
 | [!] The version is out of date, the latest version is 2.1

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] contact-form-7
 | Location: http://10.0.0.7/wp-content/plugins/contact-form-7/
 | [!] The version is out of date, the latest version is 5.3
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Contact Form 7 < 5.0.4 - Privilege Escalation
 |     Fixed in: 5.0.4

[+] Enumerating Users (via Passive and Aggressive Methods)

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)

[+] editor
 | Found By: Wp Json Api (Aggressive Detection)

[+] Performing password attack on Xmlrpc against 2 user/s
[SUCCESS] - admin / password123

[!] Valid Combinations Found:
 | Username: admin, Password: password123

[+] Finished: Tue Nov 24 10:05:00 2026
"""
r = findings.parse_findings("wpscan", "wpscan --url http://10.0.0.7/", WPSCAN)
t = titles(r)
check("wpscan: supported", r["supported"])
check("wpscan: insecure core version (medium)", "WordPress 5.2.1 güvensiz sürüm" in titles(r, "medium"), t)
check("wpscan: XSS vuln medium with CVE",
      any("Cross-Site Scripting" in f["title"] and f["severity"] == "medium" and "CVE-2019-16222" in f["detail"]
          for f in r["findings"]), r["findings"])
check("wpscan: RCE vuln high", any("Remote Code Execution" in x for x in titles(r, "high")), t)
check("wpscan: plugin vuln tagged with plugin name",
      any(x.startswith("Eklenti contact-form-7: ") for x in titles(r, "high")), t)
check("wpscan: outdated theme (low)", "Tema twentynineteen güncel değil" in titles(r, "low"), t)
check("wpscan: outdated plugin (low)", "Eklenti contact-form-7 güncel değil" in titles(r, "low"), t)
check("wpscan: XML-RPC (medium)", "XML-RPC etkin" in titles(r, "medium"), t)
check("wpscan: upload listing (medium)", "Dizin listeleme açık" in titles(r, "medium"), t)
check("wpscan: readme (low)", "WordPress readme dosyası erişilebilir" in titles(r, "low"), t)
check("wpscan: 2 users listed", "2 WordPress kullanıcısı listelendi" in t, t)
check("wpscan: cracked login (high)", "Geçerli WordPress girişi: admin" in titles(r, "high"), t)
check("wpscan: no helper keys left", all(set(f) == {"title", "detail", "severity"} for f in r["findings"]))

# ---------------------------------------------------------------- wpscan json
WPSCAN_JSON = json.dumps({
    "interesting_findings": [
        {"url": "http://10.0.0.7/xmlrpc.php", "to_s": "XML-RPC seems to be enabled: http://10.0.0.7/xmlrpc.php",
         "type": "xmlrpc"}],
    "version": {"number": "5.2.1", "status": "insecure", "vulnerabilities": [
        {"title": "WordPress 5.0-5.2.2 - Authenticated Remote Code Execution", "fixed_in": "5.2.3",
         "references": {"cve": ["2019-8942"]}}]},
    "plugins": {"contact-form-7": {"outdated": True, "latest_version": "5.3", "version": {"number": "5.0.3"},
                                   "vulnerabilities": [{"title": "Contact Form 7 - Stored XSS"}]}},
    "users": {"admin": {}, "editor": {}},
    "password_attack": {"admin": {"password": "password123"}},
})
r = findings.parse_findings("wpscan", "wpscan --format json", WPSCAN_JSON)
t = titles(r)
check("wpscan json: RCE high with CVE",
      any("Remote Code Execution" in f["title"] and f["severity"] == "high" and "CVE-2019-8942" in f["detail"]
          for f in r["findings"]), r["findings"])
check("wpscan json: plugin XSS medium", "Eklenti contact-form-7: Contact Form 7 - Stored XSS" in titles(r, "medium"), t)
check("wpscan json: outdated plugin", "Eklenti güncel değil: contact-form-7 5.0.3" in titles(r, "low"), t)
check("wpscan json: users + cracked login",
      "2 WordPress kullanıcısı listelendi" in t and "Geçerli WordPress girişi: admin" in t, t)

# ---------------------------------------------------------------- enum4linux
E4L = """Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ )

 =========================================( Target Information )=========================================
Target ........... 10.0.0.5

 ===========================( Enumerating Workgroup/Domain on 10.0.0.5 )===========================
[+] Got domain/workgroup name: WORKGROUP

 ===================================( Session Check on 10.0.0.5 )===================================
[+] Server 10.0.0.5 allows sessions using username '', password ''

 ================================( OS information on 10.0.0.5 )================================
[+] Got OS info for 10.0.0.5 from srvinfo:
	METASPLOITABLE Wk Sv PrQ Unx NT SNT metasploitable server (Samba 3.0.20-Debian)

 ========================================( Users on 10.0.0.5 )========================================
index: 0x1 RID: 0x3f2 acb: 0x00000011 Account: games	Name: games	Desc: (null)
index: 0x2 RID: 0x1f5 acb: 0x00000011 Account: nobody	Name: nobody	Desc: (null)
user:[games] rid:[0x3f2]
user:[nobody] rid:[0x1f5]
user:[msfadmin] rid:[0xbb8]

 ==================================( Share Enumeration on 10.0.0.5 )==================================
	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk
	IPC$            IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))

[+] Attempting to map shares on 10.0.0.5
//10.0.0.5/print$	Mapping: DENIED Listing: N/A Writing: N/A
//10.0.0.5/tmp	Mapping: OK Listing: OK Writing: N/A
//10.0.0.5/opt	Mapping: OK, Listing: OK, Writing: OK
//10.0.0.5/IPC$	Mapping: N/A Listing: N/A Writing: N/A

 =============================( Password Policy Information for 10.0.0.5 )=============================
[+] Password Info for Domain: METASPLOITABLE
	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000000
	[+] Account Lockout Threshold: None

 =======================================( Groups on 10.0.0.5 )=======================================
group:[Domain Admins] rid:[0x200]

 ==================( Users on 10.0.0.5 via RID cycling (RIDS: 500-550,1000-1050) )==================
S-1-22-1-1000 Unix User\\msfadmin (Local User)
S-1-22-1-1001 Unix User\\user (Local User)
S-1-5-21-1042354039-2475377354-766472396-500 METASPLOITABLE\\Administrator (Local User)
enum4linux complete on Tue Nov 24 10:00:00 2026
"""
r = findings.parse_findings("enum4linux", "enum4linux -a 10.0.0.5", E4L)
t = titles(r)
check("enum4linux: supported", r["supported"])
check("enum4linux: null session (high)", "Null session (anonim SMB oturumu) açık" in titles(r, "high"), t)
check("enum4linux: Samba 3.0.20 usermap_script (high)",
      any(f["title"] == "Samba 3.0.20" and "CVE-2007-2447" in f["detail"] and f["severity"] == "high"
          for f in r["findings"]), r["findings"])
check("enum4linux: writable share (high)", "Anonim yazılabilir paylaşım: opt" in titles(r, "high"), t)
check("enum4linux: readable share (medium)", "Anonim erişilebilir paylaşım: tmp" in titles(r, "medium"), t)
check("enum4linux: denied share not flagged", not any("print$" in x for x in titles(r, "medium")), t)
users = next((f for f in r["findings"] if "kullanıcı hesabı listelendi" in f["title"]), None)
check("enum4linux: users deduplicated (games, nobody, msfadmin, user, Administrator)",
      users and users["title"].startswith("5 ") and "Administrator" in users["detail"], users)
check("enum4linux: 4 shares listed", "4 SMB paylaşımı bulundu" in t, t)
check("enum4linux: weak min length (medium)", "Zayıf parola politikası: minimum uzunluk 5" in titles(r, "medium"), t)
check("enum4linux: no lockout (medium)", "Hesap kilitleme eşiği yok" in titles(r, "medium"), t)
check("enum4linux: domain info", "Domain/Workgroup: WORKGROUP" in titles(r, "info"), t)

# ---------------------------------------------------------------- dispatch
check("dispatch by command name", findings.parse_findings("", "hydra -l a -p b ftp://x", HYDRA_OK)["tool"] == "hydra")
check("empty output does not crash", all(findings.parse_findings(x, "", "")["supported"]
                                         for x in ("hydra", "wpscan", "enum4linux")))
check("john still unsupported", findings.parse_findings("john", "", "x")["supported"] is False)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
