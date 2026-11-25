# AGENTS.md — Kali MCP Server

Notes for contributors and AI coding agents working in this repo: how the code is laid out, the rules that keep it working, and how to test it.

## Conventions
- Commit messages follow Conventional Commits (`fix:`, `feat:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Explain non-obvious changes in the PR description, and keep the docs listed below in sync.
- Keep personal or machine-specific data (local paths, IPs, hostnames, names, emails) out of the repo. Use placeholders such as `<kali-ip>` or `/path/to/kali-mcp-server`.

## What this is
A pentest dashboard plus an MCP server that wrap Kali tools (nmap, gobuster, dirb, nikto, sqlmap, enum4linux, wpscan, hydra, john, metasploit) behind a web UI and an AI-agent API.

## Architecture (single server)
- `src/backend/kali_server.py` is **the** server (port 5001). It serves the REST API, the Socket.IO WebSocket and the dashboard UI from one origin. There is no separate frontend server. The old 5002 dashboard was removed on purpose; don't bring it back.
- `src/backend/static/dashboard.html` is the UI: vanilla JS, light/dark theme, Turkish labels. `socket.io.min.js` is vendored locally so the UI works offline.
- `src/backend/findings.py` parses raw tool output into structured, risk-rated findings (`high/medium/low/info`). It covers nmap, nikto, gobuster, dirb, sqlmap, hydra, wpscan (text and `--format json`) and enum4linux. To add a tool, write `parse_<tool>` and register it in `PARSERS`.
- `src/backend/recon.py` holds the chained recon logic (web-port detection, command builders, strict arg validation). `ReconRunner` in `kali_server.py` runs it in a background thread. Workflows are stored in `recon_workflows` (steps as JSON). Endpoints: `/api/workflows/*`. MCP tools: `recon_workflow`, `recon_status`, `recon_cancel`.
- `src/backend/mcp_server.py` is a stdio MCP server (FastMCP). It does **not** run tools; it forwards calls over HTTP to `kali_server.py` (`--server` / `KALI_API_SERVER`).
- Storage is SQLite with one table per tool (`<tool>_history`) plus `scan_templates`. The 8 built-in templates are seeded on first run and protected from edit and delete.
- Long scans: each tool has its own default timeout (`TOOL_TIMEOUTS`, env `TIMEOUT_<TOOL>`); requests can pass `timeout`. Tool endpoints go through `run_tool()`. `"async": true` returns 202, and the output is buffered per scan (`scan_registry`) and read with `GET /api/scans/<id>?since=N`. The dashboard and the recon UI **pull** output by offset; WebSocket events only nudge a pull. Don't go back to WS-only streaming: missed events lost the output. MCP tools use `run_scan()` (async + bounded wait) and return a `scan_id` for `scan_status` when a scan outlasts the MCP request.
- Socket.IO is forced to `async_mode="threading"` (real threads + blocking subprocess). The client uses default transports (polling first), because socket.io-client 4.7 has no fallback from websocket-only.
- Route helpers in `kali_server.py`: `@api_errors(label)` turns an exception into a logged 500 JSON error, `@tool_route(tool)` registers `POST /api/tools/<tool>` with it. Tool availability uses `shutil.which` (`TOOL_BINARIES` maps metasploit to `msfconsole`). History models are generated from one list in `TOOL_MODEL_MAPPING`.
- Because of `shell=True`, every single user value put into a tool command (url, target, wordlist, data, username, password...) goes through `shell_arg()` (`shlex.quote`). Otherwise a URL like `?id=1&cat=2` is cut at `&`. Free-form `additional_args` / nmap `scan_type` stay unquoted on purpose (they hold several flags).
- Scans run via `CommandExecutor` with `shell=True` in a **new process group**. Cancel and timeout kill the whole group with `os.killpg`. Keep it that way, or the tool keeps running after "cancel".
- Security defaults: CORS is off unless `CORS_ORIGINS` is set (Socket.IO too: `cors_allowed_origins=None` = same-origin). `SECRET_KEY` is random per run if unset, and known placeholder values are ignored. `/api/command` returns 403 unless `KALI_ENABLE_COMMAND=1`; `mcp_server.py` only registers `execute_command` with `--enable-command`. There is no API auth yet: run the server on localhost or a trusted lab network (see *Roadmap*).
- PDFs come from ReportLab with a registered DejaVu font, so Turkish characters render. Without reportlab, the endpoints return 503.

## Run
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 src/backend/kali_server.py --port 5001 --ip 0.0.0.0
# open http://127.0.0.1:5001/
```
Docker: `docker compose up -d --build` (Kali base image with the tools, DB in the `kali-data` volume at `/data`, port published on `KALI_BIND`, default `127.0.0.1`; Metasploit only with `INSTALL_METASPLOIT=true`). MCP inside the container: `docker exec -i kali-mcp python3 src/backend/mcp_server.py --server http://127.0.0.1:5001`.

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
python3 src/tests/test_db_schema.py   # DB models
python3 src/tests/test_recon.py       # recon workflow logic, no server
python3 src/tests/test_shell_quoting.py  # user values (URLs with ?/&) quoted in tool commands
python3 src/tests/test_findings_parsers.py  # hydra/wpscan/enum4linux parsers on sample output
python3 src/tests/test_security.py    # CORS off, /api/command off, SECRET_KEY
python3 src/tests/test_system.py      # full suite; live checks need the server running
```
For end-to-end checks without Kali, put fake `nmap`/`nikto`/`gobuster`/`sqlmap` scripts on `PATH`. Start the server with `subprocess.Popen` inside the test process so it doesn't outlive the test.

## Environment gotchas
- `mcp` is pinned `<2`: mcp 2.x removed `mcp.server.fastmcp` (renamed to `MCPServer`).
- On some Kali installs, bare `pip` still points to **Python 2.7**. Always use `python3 -m pip` or a venv.
- A common setup is an MCP client on the host OS (e.g. Windows) and the tools in a Kali VM. The MCP link is HTTP to `<kali-ip>:5001`, not SSH. If you edit the code on the host, the VM only sees the change after a git push/pull or a copy.
- Never commit `*.db`, `instance/`, `.env` or `.venv/` (already in `.gitignore`).

## Docs to keep in sync
`README.md` (features, MCP config, roadmap), `docs/API.md` (every endpoint), `docs/DEVELOPMENT.md`, `docs/KALI_DEPLOYMENT.md`. When you add or change an endpoint, update `docs/API.md`.

## Roadmap (next candidates)
1. ~~Chained recon workflow (nmap → gobuster/nikto)~~ — done.
2. ~~More parsers: hydra, wpscan, enum4linux~~ — done.
3. ~~Docker / `docker compose up`~~ — done.
4. Scope allowlist guardrail for MCP and UI (AI-security angle).
5. Authentication (login) and RBAC, scheduled scans, alerting.

## Legal
Authorized testing only. Keep the legal notice in the README.
