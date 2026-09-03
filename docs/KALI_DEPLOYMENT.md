# Kali Deployment Guide

How to run Kali MCP Server on a Kali Linux machine. The whole app is a single
server — no separate dashboard process.

## 1. Get the code onto Kali

**Option A — git (recommended):**
```bash
cd ~
git clone https://github.com/<your-user>/<your-repo>.git kalimcp
cd kalimcp
```

**Option B — copy from another machine (scp):**
```bash
scp -r ./kalimcp kali@<kali-ip>:/home/kali/
```

**Option C — VirtualBox/VMware shared folder:**
```bash
cp -r /media/sf_kalimcp ~/kalimcp
```

## 2. Install dependencies

Always use the **Python 3** interpreter (`python3` / `python3 -m pip`), never the
legacy Python 2 `pip`:

```bash
cd ~/kalimcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> On newer Kali without a venv you may need:
> `python3 -m pip install -r requirements.txt --break-system-packages`

## 3. Run the server

```bash
python3 src/backend/kali_server.py --port 5001 --ip 0.0.0.0
```

- `--ip 0.0.0.0` makes it reachable from other machines on the network.
- Runs in the foreground; add `&` (or use `tmux`/`systemd`) to keep it running.

To stop a background instance:
```bash
pkill -f kali_server.py
```

## 4. Open the dashboard

From the Kali machine: **http://127.0.0.1:5001/**
From another machine on the LAN: **http://<kali-ip>:5001/**

## Persisting the database

Scan history is stored in SQLite (`DATABASE_PATH`, default `scan_history.db`, created
next to the app). Set an absolute path to keep it in a fixed location:

```bash
export DATABASE_PATH=/home/kali/scan_history.db
python3 src/backend/kali_server.py --port 5001 --ip 0.0.0.0
```

## Run as a service (optional)

`/etc/systemd/system/kalimcp.service`:
```ini
[Unit]
Description=Kali MCP Server
After=network.target

[Service]
User=kali
WorkingDirectory=/home/kali/kalimcp
ExecStart=/home/kali/kalimcp/.venv/bin/python src/backend/kali_server.py --port 5001 --ip 0.0.0.0
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable --now kalimcp
```

## Troubleshooting

```bash
# is it up?
curl http://localhost:5001/health

# which process holds the port?
sudo lsof -i :5001

# PDF export 503 -> reportlab missing
python3 -m pip install reportlab
```

## Security note

There is no authentication. Bind to `127.0.0.1` for local-only use, or restrict
network access with a firewall. Only scan systems you are authorized to test.
