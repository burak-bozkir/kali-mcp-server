#!/bin/bash
# Kali MCP API Server Launcher for Linux/Mac

cd "$(dirname "$0")/.."

API_PORT=${1:-5001}
API_IP=${2:-0.0.0.0}

python3 src/backend/kali_server.py --ip "$API_IP" --port "$API_PORT"
