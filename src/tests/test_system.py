#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kali MCP Server - System Test Suite

Checks environment, project structure, dependencies, and (if the server is
running) the live API: health, tools, history, templates, scan, findings.

Usage:
    # static checks only
    python3 src/tests/test_system.py

    # include live checks (start the server first)
    python3 src/backend/kali_server.py --port 5001 &
    python3 src/tests/test_system.py
"""

import os
import sys
from pathlib import Path

# UTF-8 output so emoji/box chars don't crash legacy Windows consoles (cp1254)
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

try:
    import requests
except ImportError:
    requests = None

BASE_URL = os.environ.get("KALI_API_SERVER", "http://127.0.0.1:5001")
ROOT = Path(__file__).resolve().parent.parent.parent

passed, failed, skipped = [], [], []


def ok(name):      passed.append(name);  print(f"  \033[92mPASS\033[0m {name}")
def fail(name, e=""): failed.append(name); print(f"  \033[91mFAIL\033[0m {name}" + (f" — {e}" if e else ""))
def skip(name, e=""): skipped.append(name); print(f"  \033[93mSKIP\033[0m {name}" + (f" — {e}" if e else ""))
def header(t):     print(f"\n\033[94m{'='*66}\n  {t}\n{'='*66}\033[0m")


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------
def test_environment():
    header("1. Environment")
    v = sys.version_info
    (ok if (v.major, v.minor) >= (3, 8) else fail)(f"Python {v.major}.{v.minor}.{v.micro}")


def test_structure():
    header("2. Project structure & files")
    for d in ['src/backend', 'src/backend/static', 'src/tests', 'scripts', 'docs']:
        (ok if (ROOT / d).is_dir() else fail)(f"dir  {d}")
    for f in ['src/backend/kali_server.py', 'src/backend/findings.py',
              'src/backend/mcp_server.py', 'src/backend/static/dashboard.html',
              'src/backend/static/socket.io.min.js', 'requirements.txt', 'README.md']:
        (ok if (ROOT / f).is_file() else fail)(f"file {f}")


def test_dependencies():
    header("3. Dependencies")
    for pkg in ['flask', 'flask_sqlalchemy', 'flask_socketio', 'requests']:
        try:
            __import__(pkg); ok(f"import {pkg}")
        except ImportError as e:
            fail(f"import {pkg}", str(e))
    # reportlab is optional (PDF export)
    try:
        __import__('reportlab'); ok("import reportlab (PDF export)")
    except ImportError:
        skip("import reportlab (PDF export)", "optional — pip install reportlab")


def test_backend_import():
    header("4. Backend imports")
    sys.path.insert(0, str(ROOT / 'src' / 'backend'))
    os.environ.setdefault('DATABASE_PATH', str(ROOT / 'src' / 'tests' / '_test.db'))
    try:
        import kali_server  # noqa
        ok("import kali_server")
        for attr in ['app', 'TOOL_MODEL_MAPPING', 'ScanTemplate', 'CommandExecutor']:
            (ok if hasattr(kali_server, attr) else fail)(f"kali_server.{attr}")
    except Exception as e:
        fail("import kali_server", str(e))
    try:
        import findings
        r = findings.parse_findings('nmap', 'nmap', '22/tcp open ssh OpenSSH 7.6p1')
        (ok if r.get('supported') else fail)("findings.parse_findings")
    except Exception as e:
        fail("import findings", str(e))


# ---------------------------------------------------------------------------
# Live checks (only if the server is reachable)
# ---------------------------------------------------------------------------
def _get(path):
    return requests.get(BASE_URL + path, timeout=5)


def test_live():
    header("5. Live API  (" + BASE_URL + ")")
    if requests is None:
        skip("live API", "requests not installed"); return
    try:
        r = _get("/health")
    except Exception:
        skip("live API", "server not running — start kali_server.py to run these")
        return

    (ok if r.status_code == 200 else fail)("GET /health")
    for path, key in [("/", None), ("/api/tools/available", "success"),
                      ("/api/history", "success"), ("/api/templates", "templates")]:
        try:
            r = _get(path)
            good = r.status_code == 200 and (key is None or key in r.json())
            (ok if good else fail)(f"GET {path}")
        except Exception as e:
            fail(f"GET {path}", str(e))

    # built-in templates seeded?
    try:
        tpls = _get("/api/templates").json().get("templates", [])
        (ok if any(t.get("builtin") for t in tpls) else fail)("built-in templates seeded")
    except Exception as e:
        fail("built-in templates seeded", str(e))

    # static socket.io served
    try:
        r = _get("/static/socket.io.min.js")
        (ok if r.status_code == 200 else fail)("GET /static/socket.io.min.js")
    except Exception as e:
        fail("GET /static/socket.io.min.js", str(e))


def main():
    print("\n" + "=" * 66 + "\n  Kali MCP Server — System Tests\n" + "=" * 66)
    test_environment()
    test_structure()
    test_dependencies()
    test_backend_import()
    test_live()

    header("Summary")
    print(f"  Passed: {len(passed)}   Failed: {len(failed)}   Skipped: {len(skipped)}")
    if failed:
        print("\n  Failed tests:")
        for f in failed:
            print(f"    - {f}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
