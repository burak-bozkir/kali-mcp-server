#!/usr/bin/env python3
"""
Quick Test Script - Fast checks without running the server.
"""

import sys
from pathlib import Path

# UTF-8 output (Windows legacy consoles)
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

print("\n" + "=" * 60)
print("  QUICK SYSTEM CHECK")
print("=" * 60 + "\n")

# 1. Python
print("[1/5] Python version...", end=" ")
v = sys.version_info
print(f"OK {v.major}.{v.minor}.{v.micro}" if (v.major, v.minor) >= (3, 8)
      else f"FAIL {v.major}.{v.minor} (need 3.8+)")

# 2. venv
print("[2/5] Virtual environment...", end=" ")
in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
print("OK active" if in_venv else "optional (not active)")

# 3. structure
print("[3/5] Project structure...", end=" ")
base = Path(__file__).parent.parent.parent  # src/tests -> src -> root
dirs = ['src/backend', 'src/backend/static', 'src/tests', 'scripts', 'docs']
missing = [d for d in dirs if not (base / d).exists()]
print("OK" if not missing else f"FAIL missing: {missing}")

# 4. files
print("[4/5] Required files...", end=" ")
files = ['src/backend/kali_server.py', 'src/backend/findings.py',
         'src/backend/static/dashboard.html', 'requirements.txt', 'README.md']
missing = [f for f in files if not (base / f).exists()]
print("OK" if not missing else f"FAIL missing: {missing}")

# 5. dependencies
print("[5/5] Python packages...", end=" ")
missing_pkgs = []
for pkg in ['flask', 'flask_sqlalchemy', 'flask_socketio', 'requests']:
    try:
        __import__(pkg)
    except ImportError:
        missing_pkgs.append(pkg)
print("OK all installed" if not missing_pkgs else f"FAIL missing: {missing_pkgs}")
if missing_pkgs:
    print("      Run: python3 -m pip install -r requirements.txt")

print("\n" + "=" * 60)
print("Quick check complete!  For full tests: python3 src/tests/test_system.py")
print("=" * 60 + "\n")
