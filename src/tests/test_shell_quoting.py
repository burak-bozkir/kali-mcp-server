#!/usr/bin/env python3
"""
Shell quoting of user values in tool commands (no server, no tools needed).

Tools run with shell=True, so a value like http://host/item.php?id=1&cat=2 must
reach the tool as ONE argument: an unquoted "&" sends the command to the
background and cuts the URL. Each check builds the command through the real
Flask endpoint (run_tool is replaced so nothing is executed) and splits it the
way a POSIX shell would (shlex.split).

    python3 src/tests/test_shell_quoting.py
"""
import os
import shlex
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "backend"))
os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(), "quoting_test.db")

import logging
logging.disable(logging.CRITICAL)
import kali_server  # noqa: E402
from flask import jsonify  # noqa: E402

captured = {}


def fake_run_tool(params, command, tool_name, target, scan_id, on_done=None):
    captured["command"] = command
    if on_done:
        on_done()
    return jsonify({"command": command})


kali_server.run_tool = fake_run_tool
client = kali_server.app.test_client()

results = []


def check(name, cond, info=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {info}"))


def build(tool, body):
    captured.clear()
    r = client.post(f"/api/tools/{tool}", json=body)
    cmd = captured.get("command", "")
    return r.status_code, cmd, (shlex.split(cmd) if cmd else [])


def arg_after(argv, flag):
    return argv[argv.index(flag) + 1] if flag in argv else None


SQL_URL = "http://10.10.10.5/item.php?id=1&cat=2"

# --- shell_arg itself
q = kali_server.shell_arg
check("plain IP unchanged", q("10.0.0.5") == "10.0.0.5", q("10.0.0.5"))
check("simple URL unchanged", q("http://10.0.0.5:8000/") == "http://10.0.0.5:8000/")
check("URL with ?/& becomes one argument", shlex.split(q(SQL_URL)) == [SQL_URL], q(SQL_URL))
check("user's own double quotes not doubled", shlex.split(q(f'"{SQL_URL}"')) == [SQL_URL], q(f'"{SQL_URL}"'))
check("user's own single quotes not doubled", shlex.split(q(f"'{SQL_URL}'")) == [SQL_URL])
check("surrounding spaces trimmed", shlex.split(q(f"  {SQL_URL} ")) == [SQL_URL])
check("value containing a single quote survives", shlex.split(q("id=1' OR '1'='1")) == ["id=1' OR '1'='1"])
check("command chars are literal (no injection)", shlex.split(q("x; id")) == ["x; id"])

# --- sqlmap (the reported bug)
code, cmd, argv = build("sqlmap", {"url": SQL_URL, "additional_args": "--dbs --level=3"})
check("sqlmap: 200 + command built", code == 200 and cmd, (code, cmd))
check("sqlmap: URL reaches -u intact", arg_after(argv, "-u") == SQL_URL, cmd)
check("sqlmap: no bare '&' left in command", "&" not in [a for a in argv], argv)
check("sqlmap: additional args still separate flags", "--dbs" in argv and "--level=3" in argv, argv)
code, cmd, argv = build("sqlmap", {"url": f'"{SQL_URL}"'})
check("sqlmap: URL typed with quotes still works", arg_after(argv, "-u") == SQL_URL, cmd)
code, cmd, argv = build("sqlmap", {"url": "http://10.10.10.5/login.php", "data": "user=admin&pass=x"})
check("sqlmap: POST data kept whole", "--data=user=admin&pass=x" in argv, cmd)

# --- other tools that take a URL / value
code, cmd, argv = build("gobuster", {"url": "http://10.10.10.5/app?x=1&y=2", "wordlist": "/usr/share/wordlists/dirb/common.txt"})
check("gobuster: URL intact", arg_after(argv, "-u") == "http://10.10.10.5/app?x=1&y=2", cmd)
check("gobuster: plain wordlist path unchanged in command", "-w /usr/share/wordlists/dirb/common.txt" in cmd, cmd)
code, cmd, argv = build("dirb", {"url": "http://10.10.10.5/?a=1&b=2"})
check("dirb: URL intact", argv[1] == "http://10.10.10.5/?a=1&b=2", cmd)
code, cmd, argv = build("nikto", {"target": "http://10.10.10.5/?a=1&b=2"})
check("nikto: target intact", arg_after(argv, "-h") == "http://10.10.10.5/?a=1&b=2", cmd)
code, cmd, argv = build("wpscan", {"url": "http://10.10.10.5/blog/?p=1&q=2"})
check("wpscan: URL intact", arg_after(argv, "--url") == "http://10.10.10.5/blog/?p=1&q=2", cmd)
code, cmd, argv = build("hydra", {"target": "10.10.10.5", "service": "ssh", "username": "admin", "password": "p@ss&word!"})
check("hydra: password with & kept whole", arg_after(argv, "-p") == "p@ss&word!", cmd)
check("hydra: target and service last", argv[-2:] == ["10.10.10.5", "ssh"], argv)
code, cmd, argv = build("nmap", {"target": "10.10.10.5", "ports": "22,80,8000"})
check("nmap: unchanged for plain values", cmd.endswith("-p 22,80,8000 -T4 -Pn 10.10.10.5"), cmd)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
