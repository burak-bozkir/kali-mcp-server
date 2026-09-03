# Development Guide

## Project Layout

```
src/backend/
  kali_server.py   # unified server: REST API + WebSocket + serves the dashboard
  mcp_server.py    # MCP integration (exposes tools to AI agents)
  findings.py      # parses raw tool output into structured findings
  migration.py     # one-off DB schema migration helper
  static/          # dashboard UI (dashboard.html + local socket.io.min.js)
src/tests/         # test suite
scripts/           # start_api.sh / start_api.bat launchers
docs/              # documentation
```

> There is **one** server. The old separate dashboard (port 5002) has been removed —
> `kali_server.py` serves the UI itself so the UI and the WebSocket share one origin.

## Running Locally

```bash
# create a venv (recommended) and install deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# run the server (serves API + WebSocket + dashboard on one port)
python3 src/backend/kali_server.py --port 5001 --ip 0.0.0.0
```

Open **http://127.0.0.1:5001/**. Or use the launcher: `scripts/start_api.sh` (Linux) / `scripts\start_api.bat` (Windows).

## Making Changes

- **Backend:** edit `src/backend/kali_server.py`, restart the server, test with curl.
- **UI:** edit `src/backend/static/dashboard.html`, then hard-refresh the browser (Ctrl+F5).
- **New parser:** add a `parse_<tool>` function in `findings.py` and register it in `PARSERS`.

## Testing

```bash
# fast environment/structure check (no server needed)
python3 src/tests/quick_test.py

# database model tests
python3 src/tests/test_db_schema.py

# full system test (start the server first for the live checks)
python3 src/tests/test_system.py
```

Manual endpoint test:
```bash
curl -X POST http://127.0.0.1:5001/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","scan_type":"-sV"}'
```

## Configuration

Everything is configurable via environment variables (see [`.env.example`](../.env.example))
or CLI flags (`--ip`, `--port`). Key values: `API_PORT`, `API_IP`, `DATABASE_PATH`,
`COMMAND_TIMEOUT`, `TOOL_STATUS_CACHE_TTL`, `SECRET_KEY`, `CORS_ORIGINS`.

## Troubleshooting

**Port already in use**
```bash
# Linux
sudo lsof -i :5001 && sudo kill -9 <PID>
# Windows
netstat -ano | findstr :5001 && taskkill /PID <PID> /F
```

**Module not found** — install into the *Python 3* interpreter:
```bash
python3 -m pip install -r requirements.txt
```

**PDF export returns 503** — `python3 -m pip install reportlab`, then restart.

**Live output not streaming** — always open the server's own page (`http://host:5001/`),
and make sure `src/backend/static/socket.io.min.js` exists.
