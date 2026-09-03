@echo off
REM Kali MCP API Server Launcher for Windows

setlocal
set API_PORT=%1
if "%API_PORT%"=="" set API_PORT=5001

set API_IP=%2
if "%API_IP%"=="" set API_IP=0.0.0.0

cd /d "%~dp0\.."
python src\backend\kali_server.py --ip %API_IP% --port %API_PORT%
