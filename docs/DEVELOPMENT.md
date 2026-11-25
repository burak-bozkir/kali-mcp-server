# Development Guide

## Project Layout

```
src/backend/
  kali_server.py   # unified server: REST API + WebSocket + serves the dashboard
  mcp_server.py    # MCP integration (exposes tools to AI agents)
  findings.py      # parses raw tool output into structured findings
  migration.py     # one-off DB schema migration helper
  static/          # dashboard UI (dashboard.html + local socket.io.min.js)
src/tests/         # plain-script tests (also run by pytest)
tests/             # pytest suite: parsers, API routes, wrapper for src/tests
.github/workflows/ # CI (pytest on Python 3.11-3.13)
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
- **Recon workflow:** the pure logic (which ports count as web, command builders, input validation,
  aggregation) lives in `recon.py` and is unit-tested by `test_recon.py`. The runner (`ReconRunner`)
  and the `/api/workflows/*` endpoints are in `kali_server.py`. To add a follow-up tool, extend
  `recon.plan_web_steps` and give the tool a parser in `findings.py`.

## Testing

The pytest suite needs no Kali tools and no running server. `tests/conftest.py`
replaces `CommandExecutor.execute`, so a tool endpoint builds its real command and
records history, but nothing is executed.

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest                      # everything
python3 -m pytest tests/test_findings.py -v   # only the parsers
```

When you add a parser to `findings.py`, add sample output and cases to
`tests/test_findings.py`. When you add an endpoint, add a route test to
`tests/test_api.py`. CI (`.github/workflows/tests.yml`) runs the suite on every push
to `main` and on pull requests.

The older plain scripts still run on their own:

```bash
# fast environment/structure check (no server needed)
python3 src/tests/quick_test.py

# database model tests
python3 src/tests/test_db_schema.py

# recon workflow logic (web-port detection, validation, commands)
python3 src/tests/test_recon.py

# shell quoting of user values in tool commands (no server, nothing executed)
python3 src/tests/test_shell_quoting.py

# security defaults: CORS off, /api/command off, SECRET_KEY (no server)
python3 src/tests/test_security.py

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
`COMMAND_TIMEOUT`, `TOOL_STATUS_CACHE_TTL`, `SECRET_KEY`, `CORS_ORIGINS`, `KALI_ENABLE_COMMAND`.

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
