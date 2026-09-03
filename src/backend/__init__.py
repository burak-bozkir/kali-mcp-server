#!/usr/bin/env python3
"""
Kali MCP Server — backend package.

Contains:
- kali_server.py : the unified Flask server (REST API + WebSocket + dashboard UI)
- mcp_server.py  : Model Context Protocol integration for AI agents
- findings.py    : parses raw tool output into structured, risk-rated findings
- migration.py   : one-off database schema migration helper
"""
