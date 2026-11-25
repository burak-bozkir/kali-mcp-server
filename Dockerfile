# Kali MCP Server - all-in-one image
# Kali tools + the unified server (REST API, WebSocket, dashboard) on port 5001.
# mcp_server.py is included too, so an MCP client can start it with `docker exec -i`.
FROM kalilinux/kali-rolling

# Metasploit adds ~1.5 GB, so it is optional:
#   docker compose build --build-arg INSTALL_METASPLOIT=true
ARG INSTALL_METASPLOIT=false

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-venv ca-certificates curl fonts-dejavu-core \
        nmap gobuster dirb nikto sqlmap enum4linux wpscan hydra john wordlists \
    && if [ "$INSTALL_METASPLOIT" = "true" ]; then \
        apt-get install -y --no-install-recommends metasploit-framework; fi \
    && if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip /usr/share/wordlists/rockyou.txt.gz; fi \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so code changes don't re-run pip
COPY requirements.txt .
RUN python3 -m venv /opt/venv \
    && pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Scan history lives on a volume so it survives `docker compose down`
ENV API_IP=0.0.0.0 \
    API_PORT=5001 \
    DATABASE_PATH=/data/scan_history.db
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5001/health > /dev/null || exit 1

CMD ["python3", "src/backend/kali_server.py"]
