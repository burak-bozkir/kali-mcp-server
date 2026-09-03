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

`POST /api/tools/<tool>` — every tool accepts an optional `scan_id` (used to join the
live WebSocket room; one is generated if omitted).

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

### Cancel a running scan
```
POST /api/scans/cancel/<scan_id>
```

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
| server → client | `scan_output` | `{ scan_id, type, line, line_count, elapsed, eta }` |
| server → client | `scan_completed` | `{ scan_id, return_code, line_count, elapsed }` |
| server → client | `scan_timeout` / `scan_cancelled` | `{ scan_id, ... }` |

---

## Errors

```json
{ "error": "Target parameter is required" }        // 400
{ "error": "Scan not found in history" }            // 404
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
```

## Notes

- **No authentication** is implemented — run on a trusted network only.
- Long scans are streamed live; `COMMAND_TIMEOUT` (default 180 s) bounds each command.
