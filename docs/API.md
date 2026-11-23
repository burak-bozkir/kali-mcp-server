# API Documentation

All endpoints are served by the unified server (`kali_server.py`).

## Base URL

```
http://127.0.0.1:5001
```

Use `--ip 0.0.0.0` to expose it on the network (e.g. `http://<kali-ip>:5001`).

A successful **scan** response has this shape:

```json
{
  "success": true,
  "scan_id": "scan_1730000000_ab12c",
  "command": "nmap -sV -T4 -Pn 10.0.0.5",
  "return_code": 0,
  "timed_out": false,
  "stdout": "...",
  "stderr": "",
  "partial_results": false
}
```

---

## Tool Execution

`POST /api/tools/<tool>` — every tool also accepts these optional fields:

| Field | Meaning |
|-------|---------|
| `scan_id` | ID for the live WebSocket room and `/api/scans/<id>` (generated if omitted) |
| `timeout` | Max run time in seconds (10 – `MAX_COMMAND_TIMEOUT`). Omitted = the tool's default (table below) |
| `async` | `true` → respond **202** at once and run in the background. Poll `GET /api/scans/<scan_id>`. Without it the request blocks until the scan ends (old behaviour) |

Default timeouts per tool (override with env `TIMEOUT_<TOOL>`, e.g. `TIMEOUT_GOBUSTER=3600`):

| nmap | gobuster | dirb | nikto | sqlmap | wpscan | enum4linux | hydra | john | metasploit |
|------|----------|------|-------|--------|--------|------------|-------|------|------------|
| 900 | 1800 | 1800 | 1800 | 1800 | 1200 | 600 | 3600 | 3600 | 900 |

When a scan hits its timeout the process group is killed, the output collected so far is saved
to history and the status is `timeout` (`success: true`, `partial_results: true`).

Async start response (**202**):
```json
{ "success": true, "async": true, "scan_id": "scan_1730000000_ab12c", "status": "running",
  "command": "gobuster dir -u http://10.0.0.5 -w ...", "timeout": 1800,
  "status_url": "/api/scans/scan_1730000000_ab12c" }
```

### Nmap
```
POST /api/tools/nmap
{
  "target": "10.0.0.5",
  "scan_type": "-sV",             // optional (default -sCV)
  "ports": "1-1000",              // optional
  "additional_args": "-T4 -Pn"    // optional
}
```

### Gobuster
```
POST /api/tools/gobuster
{
  "url": "http://10.0.0.5",
  "mode": "dir",                  // dir | dns | fuzz | vhost
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "additional_args": "-t 50"
}
```

### Dirb
```
POST /api/tools/dirb
{ "url": "http://10.0.0.5", "wordlist": "/usr/share/wordlists/dirb/common.txt", "additional_args": "" }
```

### Nikto
```
POST /api/tools/nikto
{ "target": "http://10.0.0.5", "additional_args": "" }
```

### SQLmap
```
POST /api/tools/sqlmap
{ "url": "http://10.0.0.5/page?id=1", "data": "", "additional_args": "--batch --dbs" }
```

### Enum4linux
```
POST /api/tools/enum4linux
{ "target": "10.0.0.5", "additional_args": "-a" }
```

### WPScan
```
POST /api/tools/wpscan
{ "url": "http://wordpress-site.com", "additional_args": "--enumerate vp" }
```

### Hydra
```
POST /api/tools/hydra
{
  "target": "10.0.0.5",
  "service": "ssh",
  "username": "admin",            // or "username_file": "/path/users.txt"
  "password_file": "/path/passwords.txt",
  "additional_args": "-t 4 -f"
}
```

### John the Ripper
```
POST /api/tools/john
{ "hash_file": "/root/hashes.txt", "wordlist": "/usr/share/wordlists/rockyou.txt", "format": "raw-md5" }
```

### Metasploit
```
POST /api/tools/metasploit
{ "module": "exploit/windows/smb/ms17_010_eternalblue", "options": { "RHOSTS": "10.0.0.5" } }
```

### Generic command
```
POST /api/command
{ "command": "whoami" }     // basic injection guard applied
```

### Live scan state & buffered output
```
GET /api/scans/<scan_id>?since=0     # state + output lines from absolute index `since`
GET /api/scans/<scan_id>?lines=0     # state only
GET /api/scans/active                # scans still running (to re-attach after a page reload)
```
The server keeps each scan's output in memory (last 5000 lines, the 200 most recent scans).
Pass the previous response's `next` as `since` to get only the new lines. This works even if
WebSocket events were missed or the socket never connected.
```json
{
  "scan_id": "scan_…", "tool": "gobuster", "status": "running",
  "elapsed": 412.3, "timeout": 1800,
  "progress": {"done": 1840, "total": 4614, "percent": 39.88},
  "lines": [{"n": 5, "type": "stdout", "line": "/admin (Status: 301) [Size: 312]"}],
  "next": 6, "total_lines": 6, "skipped": 0, "more": false,
  "return_code": null, "timed_out": false, "history_id": null
}
```
- `status`: `starting` · `running` · `completed` · `failed` · `timeout` · `cancelled`
- `progress` is only set for tools that report it (gobuster's `Progress: x / y (p%)` ticker).
  Those ticker lines are not stored as output.
- ANSI escape codes (e.g. gobuster's line-clear prefix) are stripped from output and history.
- `history_id` is set once the scan is saved; then use `/api/history/<history_id>`.
- `404` = unknown or expired scan ID; use `/api/history` instead.

### Cancel a running scan
```
POST /api/scans/cancel/<scan_id>
```

---

## Chained Recon Workflow

Runs nmap on **one host**, then automatically runs gobuster and/or nikto on every
web port it finds (http/https: `80`, `443`, `8080`, `8443`, `ssl/http`, `http-proxy`, ...).
Steps run one at a time in a background thread. Every step is a normal scan:
it is saved in `<tool>_history`, streams over Socket.IO and can be cancelled.

### Start
```
POST /api/workflows/recon
{
  "target": "10.0.0.5",          // required: single IP or hostname (no CIDR, no URL)
  "workflow_id": "<uuid>",       // optional: pick the ID to join its Socket.IO room first
  "nmap_scan_type": "-sV",       // optional
  "nmap_args": "-T4 -Pn",        // optional
  "ports": "1-1000,8080",        // optional nmap port spec
  "run_gobuster": true,          // optional (default true)
  "run_nikto": true,             // optional (default true)
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "gobuster_args": "-t 30",      // optional (https targets also get -k)
  "nikto_args": "",              // optional
  "max_web_targets": 5,          // optional, 1-20
  "step_timeout": 2400           // optional, one timeout for every step (10-14400);
                                 // omitted = each tool's default (nmap 900, gobuster/nikto 1800)
}
```
Returns **202** right away:
```json
{ "success": true, "workflow_id": "3f1c...", "workflow": { "status": "running", "steps": [ ... ] } }
```
Argument fields only accept letters, digits, spaces and `- _ = . , : / +`.
Shell metacharacters (`;`, `|`, `&`, `>`, `<`, backtick, `$`, quotes) are rejected with **400**.
At most `MAX_CONCURRENT_WORKFLOWS` (default 2) run at once; more return **429**.
A duplicate `workflow_id` returns **409**.

### Read / list / cancel / report
```
GET  /api/workflows?limit=20            # recent workflows (light step view)
GET  /api/workflows/<id>                # full state: steps, web targets, summary, findings
POST /api/workflows/<id>/cancel         # kill the running step, skip the rest (404 if not running)
GET  /api/workflows/<id>/report         # PDF report of the whole workflow
```

`GET /api/workflows/<id>` response (shortened):
```json
{
  "success": true,
  "workflow": {
    "id": "3f1c...", "target": "10.0.0.5", "status": "completed",
    "web_targets": [
      {"port": "80",  "scheme": "http",  "service": "http",     "url": "http://10.0.0.5"},
      {"port": "443", "scheme": "https", "service": "ssl/http", "url": "https://10.0.0.5"}
    ],
    "steps": [
      {"index": 0, "tool": "nmap", "target": "10.0.0.5", "status": "done",
       "command": "nmap -sV -T4 -Pn 10.0.0.5", "history_id": "...", "duration": 41.2,
       "note": "", "summary": {"open_ports": 7, "high": 2}, "ports": [], "findings": []},
      {"index": 1, "tool": "gobuster", "target": "http://10.0.0.5", "status": "done"}
    ],
    "summary": {"open_ports": 7, "web_targets": 2, "high": 2, "medium": 10, "low": 4,
                "info": 2, "total": 18, "steps_total": 5, "steps_done": 5, "steps_failed": 0},
    "findings": [ {"severity": "high", "title": "...", "tool": "nmap", "source": "10.0.0.5", "step": 0} ]
  }
}
```

- Workflow `status`: `running` / `completed` / `failed` (nmap failed or server restarted) / `cancelled`
- Step `status`: `pending` / `running` / `done` / `failed` / `skipped` (tool not installed) / `cancelled`
- A step that exits non-zero but produced parseable findings (common with nikto) is `done`, with a `note`.
- Each step keeps at most 50 findings (most severe first). Use `history_id` with
  `/api/history/<id>` for the full raw output.

---

## Tools & Health

```
GET /health                    # server status + per-tool availability
GET /api/tools/available       # tools grouped by category, with availability
```

---

## Scan History

```
GET  /api/history?limit=50&tool=nmap      # list (optionally filter by tool)
GET  /api/history/<id>                     # single scan (id = UUID) or tool history (id = tool name)
GET  /api/history/detail/<id>              # single scan detail
GET  /api/history/stats?tool=nmap          # statistics
DELETE /api/history?tool=nmap              # clear all, or one tool
```

---

## Findings (parsed results)

```
GET /api/history/<id>/findings
```
Returns structured, risk-rated findings parsed from the scan output
(supported: nmap, nikto, gobuster, dirb, sqlmap):

```json
{
  "tool": "nmap",
  "supported": true,
  "ports": [
    {"port": "3306", "proto": "tcp", "state": "open",
     "service": "mysql", "version": "MySQL 5.7.33", "risk": "high"}
  ],
  "findings": [
    {"title": "mysql (3306/tcp) exposed", "detail": "...", "severity": "high"}
  ],
  "summary": {"open_ports": 4, "high": 1, "medium": 2, "low": 1, "info": 0, "total": 3}
}
```

---

## PDF Reports

```
GET /api/history/<id>/report      # per-scan PDF (includes findings)
GET /api/report/summary?limit=50  # summary PDF of recent scans
```
Returns `application/pdf` as a download. Requires `reportlab`
(`pip install reportlab`); otherwise responds `503`.

---

## Scan Templates

```
GET    /api/templates             # list (built-in + user)
POST   /api/templates             # create  { name, tool, target?, params?, wordlist?, description? }
GET    /api/templates/<id>        # read
PUT    /api/templates/<id>        # update (user templates only)
DELETE /api/templates/<id>        # delete (user templates only)
```

---

## WebSocket (Socket.IO)

Connect to the same origin (`http://<host>:5001`). Events:

| Direction | Event | Payload |
|-----------|-------|---------|
| client → server | `join_scan` | `{ scan_id }` |
| client → server | `cancel_scan` | `{ scan_id }` |
| server → client | `scan_started` | `{ scan_id, command }` |
| server → client | `scan_output` | `{ scan_id, type, line, line_count, elapsed }` |
| server → client | `scan_progress` | `{ scan_id, done, total, percent, elapsed }` (gobuster) |
| server → client | `scan_completed` | `{ scan_id, return_code, line_count, elapsed }` |
| server → client | `scan_timeout` / `scan_cancelled` | `{ scan_id, ... }` |
| server → client | `workflow_update` | light workflow (status, steps, summary) + `workflow_id` |
| server → client | `workflow_step_started` | `{ workflow_id, index, tool, target, command, scan_id }` |
| server → client | `workflow_finished` | `{ workflow_id, status }` |

For a recon workflow, send `join_scan` with the **workflow ID** as `scan_id`. That room receives the
workflow events **and** every step's `scan_started` / `scan_output` / `scan_completed`
(each step's own `scan_id` is `<workflow_id>_s<index>`).

---

## Errors

```json
{ "error": "Target parameter is required" }        // 400
{ "error": "Scan not found in history" }            // 404
{ "error": "workflow_id already exists" }           // 409
{ "error": "Aynı anda en fazla 2 recon akışı ..." } // 429
{ "error": "PDF support not installed..." }         // 503
{ "error": "Server error: ..." }                    // 500
```

## Example (cURL)

```bash
# Health
curl http://127.0.0.1:5001/health

# Run an nmap scan
curl -X POST http://127.0.0.1:5001/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{"target":"10.0.0.5","scan_type":"-sV"}'

# History + findings + report
curl "http://127.0.0.1:5001/api/history?limit=10"
curl http://127.0.0.1:5001/api/history/<scan-id>/findings
curl -OJ http://127.0.0.1:5001/api/history/<scan-id>/report

# Chained recon: nmap -> gobuster + nikto on every web port
curl -X POST http://127.0.0.1:5001/api/workflows/recon \
  -H "Content-Type: application/json" \
  -d '{"target":"10.0.0.5","max_web_targets":3}'
curl http://127.0.0.1:5001/api/workflows/<workflow-id>
curl -OJ http://127.0.0.1:5001/api/workflows/<workflow-id>/report
```

## Notes

- **No authentication** is implemented — run on a trusted network only.
- Each tool has its own default timeout (see *Tool Execution*); `COMMAND_TIMEOUT` (180 s) only
  applies to `/api/command` and unknown tools. `MAX_COMMAND_TIMEOUT` (14400 s) caps any request.
- For long scans prefer `"async": true` + `GET /api/scans/<id>`: a blocking HTTP request that stays
  open for 30 minutes is easily cut by browsers, proxies or the MCP client.
