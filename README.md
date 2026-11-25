# 🛡️ Kali MCP Server

[![tests](https://github.com/burak-bozkir/kali-mcp-server/actions/workflows/tests.yml/badge.svg)](https://github.com/burak-bozkir/kali-mcp-server/actions/workflows/tests.yml)

> An interactive penetration-testing dashboard and **Model Context Protocol (MCP)** server that wraps common Kali Linux security tools behind a clean web UI and an AI-agent-ready API.

<p align="center">
  <img src="docs/screenshot-dashboard.png" alt="Kali MCP Server dashboard" width="900">
</p>

Kali MCP Server turns a set of command-line security tools (nmap, sqlmap, gobuster, nikto, hydra, and more) into a single, modern application. You can drive scans from a real-time web dashboard **or** expose the same tools to an AI assistant through MCP — the raw tool output is parsed into structured, risk-rated findings and can be exported to a professional PDF report.

---

## ✨ Features

- **Unified single-server architecture** — the backend serves the REST API, the WebSocket stream, and the dashboard UI from one origin (port `5001`).
- **Real-time scan streaming that survives long scans** — scans start asynchronously and their output is buffered on the server. The dashboard pulls it by offset, with WebSocket pushes for low latency, so a 30-minute gobuster run keeps streaming even if the socket drops or you reload the page. Gobuster shows a real % progress bar. A working **cancel** button kills the whole process group (not just the shell).
- **Per-tool timeouts** — sensible defaults per tool (nmap 15 min, gobuster/nikto/sqlmap 30 min, hydra 1 h), overridable per scan from the UI/API/MCP or via `TIMEOUT_<TOOL>` env vars. A timeout keeps the partial output.
- **Chained recon workflow** — one click (or one MCP call) runs nmap, detects every web port (http/https, 8080, 8443, ...) and follows up with gobuster and nikto automatically. In the dashboard it is the first card under Scan Templates, and each step (nmap, gobuster, nikto) takes its own parameters. You get live per-step progress, combined risk-rated findings and one PDF report for the whole run.
- **Structured findings** — raw output from nmap / nikto / gobuster / dirb / sqlmap is parsed into open ports and risk-rated findings (high / medium / low / info), filterable by category in the dashboard.
- **Scan templates** — 8 built-in templates plus your own saved configurations, with one-click launch.
- **PDF reports** — per-scan and summary reports with a branded layout, findings section, and full Unicode (Turkish) support.
- **Modern UI** — responsive dashboard with a light/dark theme toggle and a live tool-availability panel.
- **MCP integration** — the same tools are exposed to AI agents (e.g. Claude Desktop) via the Model Context Protocol.
- **Per-tool scan history** — every scan is stored in SQLite, searchable and re-openable.
- **Safer defaults** — CORS is off (other websites can't call the API from your browser), the Flask `SECRET_KEY` is never a public default, and the arbitrary-command endpoint (`/api/command` / MCP `execute_command`) is disabled unless you turn it on.

## 🧰 Supported Tools

| Category | Tools |
|----------|-------|
| Reconnaissance | Nmap, Enum4linux |
| Web | Gobuster, Dirb, Nikto, SQLmap, WPScan |
| Exploitation | Metasploit |
| Credential attacks | Hydra, John the Ripper |

## 🚀 Quick Start

> Requires **Python 3.8+** running on **Kali Linux** (or any host with the tools installed). Use `python3` / `pip3` — not the legacy Python 2 `pip`.

```bash
# 1. (recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. install dependencies
pip install -r requirements.txt
# on newer Kali without a venv, use: pip install -r requirements.txt --break-system-packages

# 3. run the server (serves API + WebSocket + dashboard)
python3 src/backend/kali_server.py --port 5001 --ip 0.0.0.0
```

Then open the dashboard at **http://127.0.0.1:5001/**

## ⚙️ Configuration

Set via environment variables (see [`.env.example`](.env.example)):

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `5001` | Server port |
| `API_IP` | `127.0.0.1` | Bind address (`0.0.0.0` for LAN access) |
| `DATABASE_PATH` | `scan_history.db` | SQLite scan-history database |
| `COMMAND_TIMEOUT` | `180` | Timeout for `/api/command` and tools without their own default |
| `TIMEOUT_<TOOL>` | per tool | e.g. `TIMEOUT_GOBUSTER=3600` (defaults: nmap 900, gobuster/dirb/nikto/sqlmap 1800, wpscan 1200, enum4linux 600, hydra/john 3600, metasploit 900) |
| `MAX_COMMAND_TIMEOUT` | `14400` | Upper limit for any requested timeout |
| `MAX_CONCURRENT_WORKFLOWS` | `2` | Recon workflows allowed to run at the same time |
| `TOOL_STATUS_CACHE_TTL` | `60` | Tool-availability cache lifetime (s) |
| `KALI_ENABLE_COMMAND` | `0` | `1` enables `/api/command` (any shell command). Off by default |
| `CORS_ORIGINS` | *(empty = off)* | Comma-separated origins allowed to call the API from a browser |
| `SECRET_KEY` | *(random per run)* | Flask secret. Public placeholder values are ignored |

## 🏗️ Architecture

```
┌──────────────────────────────────────────────┐
│         kali_server.py  (port 5001)           │
│  ┌────────────┐  ┌───────────┐  ┌──────────┐  │
│  │  REST API  │  │ WebSocket │  │  Static  │  │
│  │  /api/...  │  │ (Socket.IO)│ │   UI     │  │
│  └─────┬──────┘  └─────┬─────┘  └────┬─────┘  │
│        │  CommandExecutor (streams)  │        │
│        └───────────┬─────────────────┘        │
│         SQLite (per-tool scan history)        │
│         findings.py (output → findings)       │
│   recon.py + ReconRunner (nmap → web tools)   │
└──────────────────────┬───────────────────────┘
                       │  runs
              Kali Linux tools (nmap, sqlmap, …)

   mcp_server.py  ── exposes the same tools to AI agents (MCP)
```

## 📁 Project Structure

```
kali-mcp-server/
├── src/
│   ├── backend/
│   │   ├── kali_server.py      # Main unified server (run this)
│   │   ├── mcp_server.py       # MCP integration for AI agents
│   │   ├── findings.py         # Parses raw output → structured findings
│   │   ├── recon.py            # Chained recon logic (web-port detection, commands)
│   │   ├── migration.py        # DB schema migration helper
│   │   └── static/             # Dashboard UI (HTML + local Socket.IO)
│   └── tests/                  # Plain-script tests (run by pytest too)
├── tests/                      # pytest suite (parsers, API routes)
├── .github/workflows/tests.yml # CI: pytest on Python 3.11–3.13
├── docs/                       # Documentation & screenshots
├── scripts/                    # Startup scripts
├── requirements.txt
├── .env.example
└── LICENSE
```

## 🤖 MCP Integration (Claude Desktop)

`src/backend/mcp_server.py` is a stdio MCP server that exposes each tool as an MCP tool (`nmap_scan`, `sqlmap_scan`, `gobuster_scan`, `hydra_attack`, …), plus the chained workflow tools `recon_workflow`, `recon_status` and `recon_cancel`. Every scan tool takes an optional `timeout`. If a scan outlasts one MCP request (~5 min), the tool returns `status: "running"` with a `scan_id` while the scan keeps going on Kali. The agent then calls `scan_status(scan_id, wait=…)` for the output and parsed findings, or `scan_cancel(scan_id)`. With `recon_workflow` an agent runs a full first-pass recon of a host in one call. It gets back a compact result (open ports, web targets, per-step status, top findings) instead of raw tool output. It does **not** run the tools itself — it forwards them over HTTP to the REST API (`kali_server.py`). Two processes cooperate:

1. **On Kali** — run the API server, bound so the VM is reachable:
   ```bash
   python3 src/backend/kali_server.py --port 5001 --ip 0.0.0.0
   ```
2. **On your desktop** — your MCP client (Claude Desktop) launches `mcp_server.py` and points it at the Kali API with `--server`.

**How Windows ↔ Kali VM connect:** when Claude Desktop runs on Windows and the tools live in a Kali VM, the MCP server process starts **on Windows** (via the config below) and reaches Kali over plain **HTTP** at the VM's IP on port 5001 — no SSH required. Give the VM a reachable address (VirtualBox *Bridged* or *Host-only* adapter), start the API with `--ip 0.0.0.0`, find the VM's IP with `ip a` on Kali, and use that IP in `--server`. (If you run everything on one machine, use `http://localhost:5001`.)

Add this to `claude_desktop_config.json` (Windows: `%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "kali": {
      "command": "C:\\path\\to\\python.exe",
      "args": [
        "C:\\path\\to\\kali-mcp-server\\src\\backend\\mcp_server.py",
        "--server", "http://192.168.1.50:5001"
      ]
    }
  }
}
```

Replace the **Python path**, the **repo path**, and the **Kali VM IP**. The `execute_command` tool (any shell command) is only exposed when you add `"--enable-command"` to `args` **and** start the server with `KALI_ENABLE_COMMAND=1`. The Python you point to must have the MCP deps installed (`pip install mcp requests`). Restart Claude Desktop and the `kali` tools appear.

## 🧪 Testing

Run everything with pytest (no Kali tools or running server needed; tool runs are faked):

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
```

`tests/test_findings.py` checks the output parsers, `tests/test_api.py` the REST routes, and `tests/test_scripts.py` runs the plain scripts below. GitHub Actions runs the same suite on every push to `main` and every pull request.

The plain scripts still work on their own:

```bash
python3 src/tests/quick_test.py       # fast environment & structure checks (no server)
python3 src/tests/test_db_schema.py   # database model tests
python3 src/tests/test_recon.py       # recon workflow logic (no server, no Kali tools)
python3 src/tests/test_shell_quoting.py  # URLs with ?/& reach the tools as one argument
python3 src/tests/test_security.py    # CORS off, /api/command off, SECRET_KEY not a public default
# then start the server and run the full suite (incl. live API checks):
python3 src/tests/test_system.py
```

Developed and tested on **Kali Linux (rolling)** with **Python 3.11+**.

## 🗺️ Roadmap

The project is feature-complete but built to grow. Planned next:

- **User management & RBAC** — authentication and role-based access to scans and reports.
- **Scheduled scans** — cron-style recurring scans with result diffing.
- **Alerting** — notify on new high-risk findings (webhook / email / Discord).
- **More parsers** — extend structured findings to Hydra, WPScan and Enum4linux.
- **Scope allowlist** — only allow scans (UI and MCP) against approved targets/CIDRs.

## ⚠️ Legal & Ethical Notice

This project is intended for **authorized security testing and educational purposes only**. Scanning or attacking systems you do not own or have explicit written permission to test is illegal in most jurisdictions. The authors accept no liability for misuse. Always operate within a controlled lab or an engagement with a signed scope.

## 🛠️ Tech Stack

Python · Flask · Flask-SocketIO · SQLAlchemy (SQLite) · ReportLab · vanilla JS + Socket.IO

## 📄 License

Released under the terms in [LICENSE](LICENSE).
