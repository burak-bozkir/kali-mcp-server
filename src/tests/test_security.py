#!/usr/bin/env python3
"""
Security defaults (no server, no Kali tools needed).

- /api/command is off unless KALI_ENABLE_COMMAND=1
- CORS is off by default (no Access-Control-Allow-Origin header for other sites)
- Socket.IO refuses cross-origin connections by default
- SECRET_KEY is never the old public default

    python3 src/tests/test_security.py
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "backend"))
os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(), "security_test.db")
for var in ("KALI_ENABLE_COMMAND", "CORS_ORIGINS", "SECRET_KEY"):
    os.environ.pop(var, None)

import logging
logging.disable(logging.CRITICAL)
import kali_server  # noqa: E402

results = []


def check(name, cond, info=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {info}"))


client = kali_server.app.test_client()

# --- generic command endpoint
r = client.post("/api/command", json={"command": "id"})
check("/api/command disabled by default -> 403", r.status_code == 403, r.status_code)
check("403 body says how to enable it", "KALI_ENABLE_COMMAND" in (r.get_json() or {}).get("error", ""))
kali_server.ENABLE_COMMAND_ENDPOINT = True
kali_server.execute_command = lambda command, **kw: {"success": True, "stdout": "ran:" + command}
r = client.post("/api/command", json={"command": "id"})
check("/api/command works when enabled", r.status_code == 200 and "ran:id" in r.get_data(as_text=True), r.status_code)
kali_server.ENABLE_COMMAND_ENDPOINT = False

kali_server.get_all_tools_status = lambda force_refresh=False: {}
r = client.get("/health")
check("/health reports command_endpoint_enabled=false", (r.get_json() or {}).get("command_endpoint_enabled") is False)

# --- CORS off by default
r = client.get("/api/history", headers={"Origin": "http://evil.example"})
check("no Access-Control-Allow-Origin for other sites", "Access-Control-Allow-Origin" not in r.headers,
      r.headers.get("Access-Control-Allow-Origin"))
r = client.open("/api/tools/nmap", method="OPTIONS", headers={
    "Origin": "http://evil.example", "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "content-type"})
check("CORS preflight from another site is not allowed", "Access-Control-Allow-Origin" not in r.headers)

# --- Socket.IO same-origin only
if kali_server.SOCKETIO_AVAILABLE and kali_server.socketio:
    sio = kali_server.socketio
    check("Socket.IO cors_allowed_origins is same-origin only",
          sio.server.eio.cors_allowed_origins is None, sio.server.eio.cors_allowed_origins)
    c = sio.test_client(kali_server.app)
    check("Socket.IO same-origin client connects", c.is_connected())
    c.disconnect()
else:
    print("SKIP Socket.IO checks (flask-socketio not installed)")

# --- SECRET_KEY
key = kali_server.app.config["SECRET_KEY"]
check("SECRET_KEY is not the old public default", key != "dev-secret-key-change-in-production")
check("generated SECRET_KEY is long and random", len(key) >= 32, len(key))

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
