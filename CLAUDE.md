# CLAUDE.md — Kali MCP Server

Context for Claude Code sessions working in this repo.

## Working with the owner
- Communicate in **Turkish**. The owner (Burak) is a cybersecurity learner and this is a **portfolio project**.
- Explain changes step by step. He is fine reading Python but prefers ready-to-run code and exact commands.
- Give **PowerShell** commands for the Windows repo copy and **bash** commands for Kali.
- Don't commit or push unless asked. When asked, use clear conventional messages (`fix:`, `feat:`, `docs:`).

## What this is
A pentest dashboard plus an MCP server that wrap Kali tools (nmap, gobuster, dirb, nikto, sqlmap, enum4linux, wpscan, hydra, john, metasploit) behind a web UI and an AI-agent API.

## Architecture (single server)
- `src/backend/kali_server.py` is **the** server (port 5001). It serves the REST API, the Socket.IO WebSocket and the dashboard UI from one origin. There is no separate frontend server. The old 5002 dashboard was removed on purpose; don't bring it back.
- `src/backend/static/dashboard.html` is the UI: vanilla JS, light/dark theme, Turkish labels. `socket.io.min.js` is vendored locally so the UI works offline.
- `src/backend/findings.py` parses raw tool output into structured, risk-rated findings (`high/medium/low/info`). It covers nmap, nikto, gobuster, dirb and sqlmap. To add a tool, write `parse_<tool>` and register it in `PARSERS`.
- `src/backend/recon.py` holds the chained recon logic (web-port detection, command builders, strict arg validation). `ReconRunner` in `kali_server.py` runs it in a background thread. Workflows are stored in `recon_workflows` (steps as JSON). Endpoints: `/api/workflows/*`. MCP tools: `recon_workflow`, `recon_status`, `recon_cancel`.
- `src/backend/mcp_server.py` is a stdio MCP server (FastMCP). It does **not** run tools; it forwards calls over HTTP to `kali_server.py` (`--server` / `KALI_API_SERVER`).
- Storage is SQLite with one table per tool (`<tool>_history`) plus `scan_templates`. The 8 built-in templates are seeded on first run and protected from edit and delete.
- Long scans: each tool has its own default timeout (`TOOL_TIMEOUTS`, env `TIMEOUT_<TOOL>`); requests can pass `timeout`. Tool endpoints go through `run_tool()`. `"async": true` returns 202, and the output is buffered per scan (`scan_registry`) and read with `GET /api/scans/<id>?since=N`. The dashboard and the recon UI **pull** output by offset; WebSocket events only nudge a pull. Don't go back to WS-only streaming: missed events lost the output. MCP tools use `run_scan()` (async + bounded wait) and return a `scan_id` for `scan_status` when a scan outlasts the MCP request.
- Socket.IO is forced to `async_mode="threading"` (real threads + blocking subprocess). The client uses default transports (polling first), because socket.io-client 4.7 has no fallback from websocket-only.
- Because of `shell=True`, every single user value put into a tool command (url, target, wordlist, data, username, password...) goes through `shell_arg()` (`shlex.quote`). Otherwise a URL like `?id=1&cat=2` is cut at `&`. Free-form `additional_args` / nmap `scan_type` stay unquoted on purpose (they hold several flags).
- Scans run via `CommandExecutor` with `shell=True` in a **new process group**. Cancel and timeout kill the whole group with `os.killpg`. Keep it that way, or the tool keeps running after "cancel".
- Security defaults: CORS is off unless `CORS_ORIGINS` is set (Socket.IO too: `cors_allowed_origins=None` = same-origin). `SECRET_KEY` is random per run if unset, and known placeholder values are ignored. `/api/command` returns 403 unless `KALI_ENABLE_COMMAND=1`; `mcp_server.py` only registers `execute_command` with `--enable-command`. There is no API auth on purpose: the owner will add a login system later instead of a token.
- PDFs come from ReportLab with a registered DejaVu font, so Turkish characters render. Without reportlab, the endpoints return 503.

## Run
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 src/backend/kali_server.py --port 5001 --ip 0.0.0.0
# open http://127.0.0.1:5001/
```

## Test
Main entry point is pytest (`pytest.ini` limits it to `tests/`). No Kali tools or server needed: `tests/conftest.py` fakes `CommandExecutor.execute`.
```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
```
- `tests/test_findings.py`: parsers. `tests/test_api.py`: REST routes. `tests/test_scripts.py`: runs the plain scripts in `src/tests/` as subprocesses.
- CI: `.github/workflows/tests.yml` (push to main, PRs; Python 3.11-3.13).
- The scripts in `src/tests/` run checks at import time, so pytest must not collect them directly.

The plain scripts also run on their own:
```bash
python3 src/tests/quick_test.py       # env/structure, no server needed
python3 src/tests/test_db_schema.py   # DB models
python3 src/tests/test_recon.py       # recon workflow logic, no server
python3 src/tests/test_shell_quoting.py  # user values (URLs with ?/&) quoted in tool commands
python3 src/tests/test_security.py    # CORS off, /api/command off, SECRET_KEY
python3 src/tests/test_system.py      # full suite; live checks need the server running
```
For end-to-end checks without Kali, put fake `nmap`/`nikto`/`gobuster`/`sqlmap` scripts on `PATH`. Start the server with `subprocess.Popen` inside the test process so it doesn't outlive the test.

## Environment gotchas
- `mcp` is pinned `<2`: mcp 2.x removed `mcp.server.fastmcp` (renamed to `MCPServer`).
- On the owner's Kali VM, bare `pip` points to **Python 2.7**. Always use `python3 -m pip` or a venv.
- Two copies exist: the Windows repo (`C:\Users\bzkr_\OneDrive\Masaüstü\kalimcp`, git remote `burak-bozkir/kali-mcp-server`) and a separate copy on the Kali VM (`~/Desktop/kalimcp`). Edits on Windows reach Kali only through git push and pull, or by copying.
- Claude Desktop runs on Windows and the tools run in a Kali VM (VirtualBox). The MCP link is HTTP to `<vm-ip>:5001`, not SSH.
- Never commit `*.db`, `instance/`, `.env` or `.venv/` (already in `.gitignore`).

## Docs to keep in sync
`README.md` (features, MCP config, roadmap), `docs/API.md` (every endpoint), `docs/DEVELOPMENT.md`, `docs/KALI_DEPLOYMENT.md`. When you add or change an endpoint, update `docs/API.md`.

## Roadmap (next candidates)
1. ~~Chained recon workflow (nmap → gobuster/nikto)~~ — done.
2. More parsers: hydra, wpscan, enum4linux.
3. Docker / `docker compose up`.
4. Scope allowlist guardrail for MCP and UI (AI-security angle).
5. RBAC, scheduled scans, alerting.

The owner already declined analytics charts for now. He plans to add a login system later (2026-11-24) and declined a shared API token in the meantime.

## Legal
Authorized testing only. Keep the legal notice in the README.
