#!/usr/bin/env python3
"""
Kali MCP Server: REST API + Socket.IO + dashboard UI on one port (default 5001).

Some of the code here was inspired by https://github.com/whit3rabbit0/project_astro
"""

import argparse
import functools
import io
import json
import logging
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as _xesc

from flask import Flask, jsonify, request, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import case, func
from sqlalchemy.orm import DeclarativeBase

try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system environment variables

import findings as findings_parser  # raw tool output -> structured findings
import recon                         # chained recon logic (web ports, commands)

# PDF report support (optional)
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, Preformatted)
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Register a Unicode TTF font so Turkish characters (ı, ş, ğ, ç...) render in
# PDFs. Falls back to the built-in Helvetica/Courier if no TTF is found.
FONT_NORMAL, FONT_BOLD, FONT_MONO = "Helvetica", "Helvetica-Bold", "Courier"
if REPORTLAB_AVAILABLE:
    def _find_fonts(*names) -> Dict[str, str]:
        """One walk over the font folders; the first folder that has a font wins."""
        dirs = ["/usr/share/fonts", "/usr/local/share/fonts", "/Library/Fonts",
                os.path.expanduser("~/.fonts"), os.path.join(os.path.dirname(pdfmetrics.__file__), "fonts")]
        found: Dict[str, str] = {}
        for d in dirs:
            for root, _, files in os.walk(d):
                for name in names:
                    if name in files and name not in found:
                        found[name] = os.path.join(root, name)
            if len(found) == len(names):
                break
        return found

    try:
        _fonts = _find_fonts("DejaVuSans.ttf", "DejaVuSans-Bold.ttf", "DejaVuSansMono.ttf")
        if "DejaVuSans.ttf" in _fonts:
            pdfmetrics.registerFont(TTFont("KaliSans", _fonts["DejaVuSans.ttf"]))
            FONT_NORMAL = FONT_BOLD = "KaliSans"
            if "DejaVuSans-Bold.ttf" in _fonts:
                pdfmetrics.registerFont(TTFont("KaliSans-Bold", _fonts["DejaVuSans-Bold.ttf"]))
                FONT_BOLD = "KaliSans-Bold"
            if "DejaVuSansMono.ttf" in _fonts:
                pdfmetrics.registerFont(TTFont("KaliMono", _fonts["DejaVuSansMono.ttf"]))
                FONT_MONO = "KaliMono"
            # Map <b> tags to the bold face
            pdfmetrics.registerFontFamily("KaliSans", normal="KaliSans", bold=FONT_BOLD,
                                          italic="KaliSans", boldItalic=FONT_BOLD)
    except Exception:
        pass  # keep Helvetica fallback

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

def _env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


API_PORT = int(os.environ.get("API_PORT", 5001))
DEBUG_MODE = _env_flag("DEBUG_MODE")
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 180))  # Fallback timeout (generic /api/command, unknown tools)
MAX_COMMAND_TIMEOUT = int(os.environ.get("MAX_COMMAND_TIMEOUT", 14400))  # Hard cap for any requested timeout (4 h)
MIN_COMMAND_TIMEOUT = 10
DATABASE_PATH = os.environ.get("DATABASE_PATH", "scan_history.db")
# How long (seconds) to cache tool-availability results
TOOL_STATUS_CACHE_TTL = int(os.environ.get("TOOL_STATUS_CACHE_TTL", 60))

# Per-tool default timeouts (seconds). Directory brute-forcing, nikto and
# sqlmap routinely need far more than 3 minutes on a real target, so one
# global value either kills them early or lets a stuck nmap hang forever.
# Override any of them with an env var, e.g. TIMEOUT_GOBUSTER=3600, or per
# request with the "timeout" field.
_DEFAULT_TOOL_TIMEOUTS = {
    "nmap": 900, "gobuster": 1800, "dirb": 1800, "nikto": 1800, "sqlmap": 1800,
    "wpscan": 1200, "enum4linux": 600, "hydra": 3600, "john": 3600, "metasploit": 900,
}
TOOL_TIMEOUTS = {t: int(os.environ.get(f"TIMEOUT_{t.upper()}", v))
                 for t, v in _DEFAULT_TOOL_TIMEOUTS.items()}


def resolve_timeout(tool_name: Optional[str], requested: Any = None) -> int:
    """Timeout for one run: the request's value (clamped) or the tool's default.

    Raises ValueError if `requested` is not a number.
    """
    base = TOOL_TIMEOUTS.get((tool_name or "").lower(), COMMAND_TIMEOUT)
    if requested in (None, "", 0, "0"):
        return base
    return max(MIN_COMMAND_TIMEOUT, min(int(requested), MAX_COMMAND_TIMEOUT))


# tool -> (display name, description, category). The key is also the binary
# looked up on PATH, except where TOOL_BINARIES says otherwise.
KALI_TOOLS = {
    "nmap": ("Nmap", "Network mapper - port scanning and service discovery", "reconnaissance"),
    "gobuster": ("Gobuster", "Directory, DNS, and virtual host enumeration tool", "web"),
    "dirb": ("Dirb", "Web content scanner", "web"),
    "nikto": ("Nikto", "Web server scanner", "web"),
    "sqlmap": ("SQLmap", "SQL injection detection and exploitation tool", "web"),
    "metasploit": ("Metasploit", "Penetration testing framework", "exploitation"),
    "hydra": ("Hydra", "Password cracking tool", "cracking"),
    "john": ("John the Ripper", "Hash cracking tool", "cracking"),
    "wpscan": ("WPScan", "WordPress vulnerability scanner", "web"),
    "enum4linux": ("Enum4linux", "Windows/Samba enumeration tool", "reconnaissance"),
}
TOOL_BINARIES = {"metasploit": "msfconsole"}


class Base(DeclarativeBase):
    pass


app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app, model_class=Base)


# ============================================================================
# Security settings: SECRET_KEY, CORS, generic command endpoint
# ============================================================================

# SECRET_KEY signs Flask cookies/sessions. Never fall back to a fixed, public
# value: without SECRET_KEY a random key is generated for this run.
_PUBLIC_SECRET_KEYS = {"dev-secret-key-change-in-production", "change-me-in-production",
                       "changeme", "secret", "dev"}
_secret_key = os.environ.get("SECRET_KEY", "").strip()
if _secret_key in _PUBLIC_SECRET_KEYS:
    logger.warning("SECRET_KEY is a well-known placeholder value; ignoring it.")
    _secret_key = ""
if not _secret_key:
    _secret_key = secrets.token_hex(32)
    logger.warning("SECRET_KEY is not set: using a random key for this run. "
                   "Set SECRET_KEY to keep it stable across restarts.")
app.config['SECRET_KEY'] = _secret_key

# CORS: the dashboard is served from this same origin, so no other site needs
# access. Default: CORS off. Set CORS_ORIGINS="http://a,http://b" to allow
# specific origins ("*" is accepted but not recommended).
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]

# /api/command runs any shell command. Off unless KALI_ENABLE_COMMAND=1.
ENABLE_COMMAND_ENDPOINT = _env_flag("KALI_ENABLE_COMMAND", False)

socketio = None
if SOCKETIO_AVAILABLE:
    # Force "threading": scans use real OS threads and blocking subprocess calls.
    # If eventlet/gevent happen to be installed, auto-detection would pick them
    # and (without monkey patching) live events would never leave the server.
    # cors_allowed_origins=None -> python-socketio only accepts same-origin connections.
    _sio_origins = None if not CORS_ORIGINS else ("*" if CORS_ORIGINS == ["*"] else CORS_ORIGINS)
    socketio = SocketIO(app, cors_allowed_origins=_sio_origins, async_mode="threading")
    logger.info(f"Flask-SocketIO initialized (async_mode={socketio.async_mode})")
else:
    logger.warning("Flask-SocketIO not installed. Real-time streaming disabled. "
                   "Install with: python3 -m pip install flask-socketio")

if CORS_ORIGINS:
    try:
        from flask_cors import CORS
        CORS(app, resources={r"/api/*": {"origins": CORS_ORIGINS}})
        logger.info(f"CORS enabled for origins: {', '.join(CORS_ORIGINS)}")
        if "*" in CORS_ORIGINS:
            logger.warning("CORS_ORIGINS='*' lets any website call this API from a browser")
    except ImportError:
        logger.warning("Flask-CORS not installed. CORS support disabled. Install with: pip install flask-cors")
else:
    logger.info("CORS disabled (same-origin only). Set CORS_ORIGINS to allow other origins.")


def socket_emit(event: str, data: Dict[str, Any], room: str):
    """Send a Socket.IO event to one room (no-op without Flask-SocketIO)."""
    if socketio:
        try:
            socketio.emit(event, data, room=room)
        except Exception as e:
            logger.debug(f"Error emitting {event}: {e}")


def api_errors(label: str):
    """Turn an unexpected exception in a route into a logged 500 JSON error."""
    def wrap(fn):
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in {fn.__name__}: {e}")
                logger.error(traceback.format_exc())
                return jsonify({"error": f"{label}: {e}"}), 500
        return inner
    return wrap


# ============================================================================
# SQLAlchemy models: one history table per tool, templates, recon workflows
# ============================================================================

class BaseScanRecord(db.Model):
    """Columns shared by every <tool>_history table."""
    __abstract__ = True

    id = db.Column(db.String(36), primary_key=True)
    command = db.Column(db.String(500), nullable=False)
    target = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    duration = db.Column(db.Float, nullable=False, default=0.0)
    success = db.Column(db.Boolean, nullable=False, default=False)
    return_code = db.Column(db.Integer, nullable=False, default=-1)
    timed_out = db.Column(db.Boolean, nullable=False, default=False)
    stdout = db.Column(db.Text, nullable=True)
    stderr = db.Column(db.Text, nullable=True)
    stdout_length = db.Column(db.Integer, nullable=False, default=0)
    stderr_length = db.Column(db.Integer, nullable=False, default=0)

    def to_dict(self, include_output=False):
        data = {
            "id": self.id,
            "command": self.command,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "duration": self.duration,
            "success": self.success,
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "stdout_length": self.stdout_length,
            "stderr_length": self.stderr_length,
        }
        if include_output:
            data["stdout"] = self.stdout
            data["stderr"] = self.stderr
        return data


# One model (and table "<tool>_history") per tool, e.g. NmapHistory -> nmap_history
TOOL_MODEL_MAPPING = {
    tool: type(f"{tool.capitalize()}History", (BaseScanRecord,), {"__tablename__": f"{tool}_history"})
    for tool in ("nmap", "gobuster", "dirb", "nikto", "sqlmap", "enum4linux",
                 "metasploit", "hydra", "john", "wpscan")
}
VALID_TOOLS = set(TOOL_MODEL_MAPPING)


class ScanTemplate(db.Model):
    """A saved, reusable scan configuration (tool + params + optional target)."""
    __tablename__ = 'scan_templates'

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    tool = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=True)
    params = db.Column(db.String(1000), nullable=True)
    wordlist = db.Column(db.String(500), nullable=True)
    description = db.Column(db.String(500), nullable=True)
    builtin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "tool": self.tool,
            "target": self.target or "",
            "params": self.params or "",
            "wordlist": self.wordlist or "",
            "description": self.description or "",
            "builtin": self.builtin,
            "created_at": self.created_at.isoformat(),
        }


class ReconWorkflow(db.Model):
    """One chained recon run (nmap → gobuster/nikto). Steps/options are JSON text."""
    __tablename__ = 'recon_workflows'

    id = db.Column(db.String(36), primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="running")
    options = db.Column(db.Text, nullable=True)
    steps = db.Column(db.Text, nullable=True)
    web_targets = db.Column(db.Text, nullable=True)
    error = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self, include_findings: bool = False):
        steps = json.loads(self.steps or "[]")
        web = json.loads(self.web_targets or "[]")
        data = {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "options": json.loads(self.options or "{}"),
            "web_targets": web,
            "error": self.error or "",
            "created_at": self.created_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "summary": recon.summarize(steps, web),
        }
        if include_findings:
            data["steps"] = steps
            data["findings"] = recon.combined_findings(steps)
        else:
            # light step view for lists
            data["steps"] = [{k: s.get(k) for k in ("index", "tool", "target", "status")}
                             for s in steps]
        return data


# Built-in templates seeded on first run
DEFAULT_TEMPLATES = [
    {"name": "Hızlı Port Taraması", "tool": "nmap", "params": "-T4 -F",
     "description": "En yaygın 100 portu hızlıca tarar"},
    {"name": "Tam Port + Servis Tespiti", "tool": "nmap", "params": "-p- -sV -T4",
     "description": "Tüm portlar + servis/sürüm tespiti (yavaş)"},
    {"name": "Agresif Tarama", "tool": "nmap", "params": "-A -T4",
     "description": "OS, servis, script ve traceroute birlikte"},
    {"name": "Web Dizin Keşfi", "tool": "gobuster", "wordlist": "/usr/share/wordlists/dirb/common.txt",
     "params": "-t 50", "description": "Gizli dizin ve dosyaları arar"},
    {"name": "Web Sunucu Zafiyet Taraması", "tool": "nikto", "params": "",
     "description": "Bilinen web sunucu açıklarını tarar"},
    {"name": "SQL Injection Testi", "tool": "sqlmap", "params": "--batch --dbs",
     "description": "URL üzerinde SQL injection ve veritabanı tespiti"},
    {"name": "SMB/Samba Enumeration", "tool": "enum4linux", "params": "-a",
     "description": "Windows/Samba paylaşım ve kullanıcı bilgisi toplar"},
    {"name": "WordPress Zafiyet Taraması", "tool": "wpscan", "params": "--enumerate vp",
     "description": "WordPress plugin ve tema açıklarını tarar"},
]


def seed_default_templates():
    """Insert built-in templates once (idempotent by name+builtin flag)."""
    try:
        with app.app_context():
            existing = {t.name for t in ScanTemplate.query.filter_by(builtin=True).all()}
            new = [ScanTemplate(id=str(uuid.uuid4()), builtin=True, **tpl)
                   for tpl in DEFAULT_TEMPLATES if tpl["name"] not in existing]
            if new:
                db.session.add_all(new)
                db.session.commit()
                logger.info(f"Seeded {len(new)} built-in scan templates")
    except Exception as e:
        logger.error(f"Error seeding templates: {e}")


class CommandHistory:
    """Scan history in SQLite, one table per tool (see TOOL_MODEL_MAPPING)."""

    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self.lock = threading.Lock()
        with app.app_context():
            db.create_all()
        logger.info(f"Database initialized at {DATABASE_PATH}")

    @staticmethod
    def _model(tool_name: Optional[str]):
        """Model for a tool (unknown tools are stored with nmap, as before)."""
        return TOOL_MODEL_MAPPING.get((tool_name or "").lower(), TOOL_MODEL_MAPPING["nmap"])

    def _models(self, tool_name: Optional[str]):
        return [self._model(tool_name)] if tool_name else list(TOOL_MODEL_MAPPING.values())

    def add_command(self, command: str, result: Dict[str, Any], duration: float = 0.0,
                    tool_name: str = None, target: str = None) -> str:
        """Store one finished scan and return its ID ("" on error)."""
        with self.lock:
            try:
                model = self._model(tool_name)
                stdout, stderr = result.get("stdout", ""), result.get("stderr", "")
                record = model(
                    id=str(uuid.uuid4()), command=command, target=target, duration=duration,
                    success=result.get("success", False), return_code=result.get("return_code", -1),
                    timed_out=result.get("timed_out", False), stdout=stdout, stderr=stderr,
                    stdout_length=len(stdout), stderr_length=len(stderr))
                with app.app_context():
                    db.session.add(record)
                    db.session.commit()
                    logger.info(f"Scan recorded in {model.__tablename__} with ID: {record.id} (tool: {tool_name})")
                    self._cleanup_old_records(model)
                    return record.id
            except Exception as e:
                logger.error(f"Error adding command to history: {e}")
                logger.error(traceback.format_exc())
                return ""

    def get_all(self, limit: int = 50, tool_name: str = None) -> List[Dict[str, Any]]:
        """Newest scans first (one tool, or merged across all tools)."""
        with self.lock:
            try:
                with app.app_context():
                    records = []
                    for model in self._models(tool_name):
                        records += model.query.order_by(model.timestamp.desc()).limit(limit).all()
                    records.sort(key=lambda r: r.timestamp, reverse=True)
                    return [r.to_dict() for r in records[:limit]]
            except Exception as e:
                logger.error(f"Error getting history: {e}")
                return []

    def get_by_id(self, command_id: str, tool_name: str = None) -> Optional[Dict[str, Any]]:
        """One scan with its full output, or None."""
        with self.lock:
            try:
                with app.app_context():
                    for model in self._models(tool_name):
                        record = db.session.get(model, command_id)
                        if record:
                            return record.to_dict(include_output=True)
                    return None
            except Exception as e:
                logger.error(f"Error getting command by ID: {e}")
                return None

    def clear(self, tool_name: str = None):
        """Clear history (all tools or one tool)."""
        with self.lock:
            try:
                with app.app_context():
                    for model in self._models(tool_name):
                        model.query.delete()
                    db.session.commit()
                    logger.info(f"History cleared ({tool_name or 'all tools'})")
            except Exception as e:
                logger.error(f"Error clearing history: {e}")

    def _cleanup_old_records(self, model):
        """Keep only the newest max_history rows of one table."""
        try:
            excess = model.query.count() - self.max_history
            if excess > 0:
                old = db.session.query(model.id).order_by(model.timestamp.asc()).limit(excess)
                model.query.filter(model.id.in_(old.scalar_subquery())).delete(synchronize_session=False)
                db.session.commit()
                logger.info(f"Cleaned up {excess} old scan records from {model.__tablename__}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def get_stats(self, tool_name: str = None) -> Dict[str, Any]:
        """Totals for one tool or all tools (one aggregate query per table)."""
        stats = {"total": 0, "successful": 0, "failed": 0, "timed_out": 0}
        try:
            with app.app_context():
                for model in self._models(tool_name):
                    total, ok, timed_out = db.session.query(
                        func.count(model.id),
                        func.sum(case((model.success.is_(True), 1), else_=0)),
                        func.sum(case((model.timed_out.is_(True), 1), else_=0))).one()
                    stats["total"] += total
                    stats["successful"] += ok or 0
                    stats["failed"] += total - (ok or 0)
                    stats["timed_out"] += timed_out or 0
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {"total": 0, "successful": 0, "failed": 0, "timed_out": 0}
        return stats


command_history = CommandHistory(max_history=100)  # Keep last 100 scans per tool
seed_default_templates()  # Insert built-in scan templates on first run

# ============================================================================
# Scan execution: live output buffer, cancel/timeout, polling registry
# ============================================================================

# Running scans by scan_id (used for cancel)
active_scans: Dict[str, "CommandExecutor"] = {}

# Every recent scan (running or finished) by scan_id, so clients can poll the
# buffered output even if they missed WebSocket events or reloaded the page.
scan_registry: "OrderedDict[str, CommandExecutor]" = OrderedDict()
_scan_registry_lock = threading.Lock()
MAX_REGISTRY_SCANS = 200        # finished scans kept for polling (oldest dropped first)
MAX_BUFFER_LINES = 5000         # live-output lines kept in memory per scan
MAX_LINES_PER_POLL = 2000

# ANSI escape codes (gobuster prefixes results with "\r\x1b[2K" to clear the line)
_ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')
# gobuster: "Progress: 1234 / 4615 (26.74%)"
_PROGRESS_RE = re.compile(r'^Progress:\s*([\d,]+)\s*/\s*([\d,]+)\s*\((\d+(?:\.\d+)?)%\)')

SCAN_FINAL_STATUSES = ("completed", "failed", "timeout", "cancelled")


def _register_scan(executor):
    with _scan_registry_lock:
        scan_registry[executor.scan_id] = executor
        scan_registry.move_to_end(executor.scan_id)
        for sid in list(scan_registry):
            if len(scan_registry) <= MAX_REGISTRY_SCANS:
                break
            if scan_registry[sid].status in SCAN_FINAL_STATUSES:
                del scan_registry[sid]


class CommandExecutor:
    """Runs one shell command, buffers and streams its output, handles timeout/cancel."""

    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT, scan_id: str = None,
                 extra_rooms: Optional[List[str]] = None, tool_name: str = None, target: str = None):
        self.command = command
        self.timeout = timeout
        self.scan_id = scan_id or str(uuid.uuid4())
        self.tool_name = tool_name
        self.target = target
        # Socket.IO rooms that receive this scan's events: its own room plus
        # extras (e.g. a recon workflow room, so the UI follows every step live)
        self.rooms = [self.scan_id] + [r for r in (extra_rooms or []) if r]
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.return_code = None
        self.timed_out = False
        self.cancelled = False
        self.start_time = None
        self.end_time: Optional[float] = None
        self.line_count = 0
        # Buffered live output: [{"n": abs_index, "type": "stdout"|"stderr", "line": str}]
        self.lines: List[Dict[str, Any]] = []
        self.line_base = 0              # absolute index of self.lines[0]
        self.buffer_lock = threading.Lock()
        self.progress: Optional[Dict[str, Any]] = None   # {"done", "total", "percent"}
        self._last_progress_emit = 0.0
        self.status = "starting"        # starting|running|completed|failed|timeout|cancelled
        self.final_status: Optional[str] = None
        self.history_id: Optional[str] = None

    def _emit_event(self, event_name: str, data: dict):
        payload = {**data, "scan_id": self.scan_id}
        for room in self.rooms:
            socket_emit(event_name, payload, room)

    def _elapsed(self) -> float:
        return time.time() - self.start_time

    def terminate(self, grace: int = 5) -> bool:
        """
        Stop the running scan by killing its ENTIRE process group.

        With shell=True the direct child is the shell; the actual tool (nmap,
        sqlmap, hydra...) is a grandchild. Killing only self.process leaves the
        tool running, so we signal the whole group created via start_new_session.

        Returns True if a termination signal was sent.
        """
        self.cancelled = True
        if not self.process or self.process.poll() is not None:
            return False
        try:
            if os.name == 'posix':
                pgid = os.getpgid(self.process.pid)
                os.killpg(pgid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Scan {self.scan_id} ignored SIGTERM; sending SIGKILL")
                    os.killpg(pgid, signal.SIGKILL)
            else:
                # Windows fallback
                self.process.send_signal(signal.CTRL_BREAK_EVENT)
                try:
                    self.process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            return True
        except ProcessLookupError:
            return False
        except Exception as e:
            logger.error(f"Error terminating scan {self.scan_id}: {e}")
            try:
                self.process.kill()
            except Exception:
                pass
            return False

    def _buffer_line(self, kind: str, line: str):
        with self.buffer_lock:
            self.lines.append({"n": self.line_base + len(self.lines), "type": kind, "line": line})
            if len(self.lines) > MAX_BUFFER_LINES:
                drop = len(self.lines) - MAX_BUFFER_LINES
                del self.lines[:drop]
                self.line_base += drop

    def _handle_line(self, kind: str, raw: str):
        """Clean one output line, buffer it and stream it."""
        clean = _ANSI_RE.sub('', raw)
        text = clean.rstrip('\r\n')
        m = _PROGRESS_RE.match(text.strip())
        if m:
            # progress ticker (gobuster): update the % instead of flooding the console/DB
            done, total, pct = m.groups()
            self.progress = {"done": int(done.replace(',', '')), "total": int(total.replace(',', '')),
                             "percent": float(pct)}
            now = time.time()
            if now - self._last_progress_emit >= 1:
                self._last_progress_emit = now
                self._emit_event('scan_progress', {**self.progress, 'elapsed': self._elapsed()})
            return
        if kind == 'stdout':
            self.stdout_data += clean
            self.line_count += 1
        else:
            self.stderr_data += clean
        if not text.strip():
            return      # blank line left over from a "\r" line-clear
        self._buffer_line(kind, text)
        self._emit_event('scan_output', {
            'type': kind,
            'line': text,
            'line_count': self.line_count,
            'elapsed': self._elapsed(),
            'is_error': kind == 'stderr',
        })

    def _read(self, kind: str, stream):
        """Reader thread: stream one pipe line by line."""
        for line in iter(stream.readline, ''):
            self._handle_line(kind, line)

    def snapshot(self, since: int = 0, include_lines: bool = True) -> Dict[str, Any]:
        """State + buffered output from absolute line `since` (for polling clients)."""
        since = max(0, int(since or 0))
        with self.buffer_lock:
            total = self.line_base + len(self.lines)
            start = max(since, self.line_base)
            chunk = self.lines[start - self.line_base:] if include_lines else []
            more = len(chunk) > MAX_LINES_PER_POLL
            chunk = chunk[:MAX_LINES_PER_POLL]
        end = (self.end_time or time.time()) if self.start_time else None
        return {
            "success": True,
            "scan_id": self.scan_id,
            "tool": self.tool_name,
            "target": self.target,
            "command": self.command,
            "status": self.status,
            "elapsed": round(end - self.start_time, 1) if end else 0.0,
            "timeout": self.timeout,
            "progress": self.progress,
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "history_id": self.history_id,
            "lines": chunk,
            "next": (start + len(chunk)) if include_lines else total,
            "total_lines": total,
            "skipped": max(0, self.line_base - since) if include_lines else 0,
            "more": more,
        }

    def execute(self) -> Dict[str, Any]:
        """Run the command to completion (or timeout/cancel) while streaming output."""
        logger.info(f"Executing command: {self.command} [scan_id: {self.scan_id}]")
        self.start_time = time.time()
        active_scans[self.scan_id] = self
        _register_scan(self)
        self.status = "running"
        try:
            self._emit_event('scan_started', {'command': self.command})

            # Launch in its OWN process group/session so that cancelling or a
            # timeout can kill the whole tree (the shell AND the actual tool such
            # as nmap/sqlmap). Terminating just the shell leaves the tool running.
            popen_kwargs = dict(
                shell=True,
                # Nobody can type into a scan, so give it a closed stdin: a tool that
                # still asks "[Y/n]?" gets EOF at once (and takes its default or
                # exits) instead of waiting silently until the timeout.
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )
            if os.name == 'posix':
                popen_kwargs['start_new_session'] = True  # setsid -> new process group
            else:
                # Windows: allow sending CTRL_BREAK to the whole group
                popen_kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
            self.process = subprocess.Popen(self.command, **popen_kwargs)

            readers = [threading.Thread(target=self._read, args=(kind, stream), daemon=True)
                       for kind, stream in (("stdout", self.process.stdout), ("stderr", self.process.stderr))]
            for t in readers:
                t.start()

            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                for t in readers:
                    t.join(timeout=2)
                if not self.cancelled:
                    self._emit_event('scan_completed', {
                        'status': 'completed', 'return_code': self.return_code,
                        'line_count': self.line_count, 'elapsed': self._elapsed()})
            except subprocess.TimeoutExpired:
                # Timed out: keep the partial output and kill the whole process group
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                self._emit_event('scan_timeout', {
                    'status': 'timeout', 'elapsed': self._elapsed(), 'line_count': self.line_count})
                self.terminate()
                self.return_code = -1

            has_output = bool(self.stdout_data or self.stderr_data)
            if self.timed_out:
                self.final_status = "timeout"
            elif self.cancelled:
                self.final_status = "cancelled"
            else:
                self.final_status = "completed" if self.return_code == 0 else "failed"
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                # A timed-out scan with output still counts as a (partial) success
                "success": has_output if self.timed_out else self.return_code == 0,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and has_output,
            }
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            logger.error(traceback.format_exc())
            self.final_status = "failed"
            self._buffer_line('stderr', f"Error executing command: {e}")
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {e}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
            }
        finally:
            active_scans.pop(self.scan_id, None)


def create_executor(command: str, tool_name: str = None, target: str = None, scan_id: str = None,
                    timeout: int = None, extra_rooms: Optional[List[str]] = None) -> CommandExecutor:
    """Build an executor and register it (status "starting") so it can be polled right away."""
    executor = CommandExecutor(command, timeout=timeout or COMMAND_TIMEOUT, scan_id=scan_id,
                               extra_rooms=extra_rooms, tool_name=tool_name, target=target)
    _register_scan(executor)
    return executor


def run_executor(executor: CommandExecutor, record_history: bool = True) -> Dict[str, Any]:
    """Run a created executor to completion, record it, and finalize its status."""
    start_time = time.time()
    result = executor.execute()
    duration = time.time() - start_time

    if record_history:
        executor.history_id = command_history.add_command(
            executor.command, result, duration, tool_name=executor.tool_name,
            target=executor.target) or None
        result['history_id'] = executor.history_id

    result.update(scan_id=executor.scan_id, duration=duration,
                  cancelled=executor.cancelled and not executor.timed_out,
                  status=executor.final_status or "failed", timeout=executor.timeout)

    # Final status only now, so a poller that sees it can also see history_id
    executor.end_time = time.time()
    executor.status = result['status']
    return result


def execute_command(command: str, record_history: bool = True, tool_name: str = None,
                    target: str = None, scan_id: str = None, timeout: int = None,
                    extra_rooms: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run one command synchronously and return stdout, stderr, status and history_id."""
    executor = create_executor(command, tool_name=tool_name, target=target, scan_id=scan_id,
                               timeout=timeout, extra_rooms=extra_rooms)
    return run_executor(executor, record_history=record_history)


def run_tool(params: Dict[str, Any], command: str, tool_name: str, target: str,
             scan_id: str, on_done=None):
    """
    Shared runner for the /api/tools/<tool> endpoints.

    - "timeout" (seconds) overrides the tool's default timeout.
    - "async": true returns 202 immediately; poll GET /api/scans/<scan_id>
      for live output and the final status. Without it the request blocks
      until the scan finishes (the original behaviour).
    """
    try:
        timeout = resolve_timeout(tool_name, params.get("timeout"))
    except (TypeError, ValueError):
        return jsonify({"error": "'timeout' must be a number of seconds"}), 400

    executor = create_executor(command, tool_name=tool_name, target=target,
                               scan_id=scan_id, timeout=timeout)

    def _run():
        try:
            return run_executor(executor)
        finally:
            if on_done:
                try:
                    on_done()
                except Exception as e:
                    logger.warning(f"Cleanup after {tool_name} failed: {e}")

    if params.get("async"):
        threading.Thread(target=_run, name=f"scan-{executor.scan_id[:16]}", daemon=True).start()
        return jsonify({"success": True, "async": True, "scan_id": executor.scan_id,
                        "status": "running", "command": command, "timeout": timeout,
                        "status_url": f"/api/scans/{executor.scan_id}"}), 202
    return jsonify(_run())


# ============================================================================
# Input validation and quoting
# ============================================================================

_TARGET_RE = re.compile(r'^[a-zA-Z0-9\.\-/:_\[\]%]+$')
# Blocked in /api/command: command substitution, chaining, "; rm"
_DANGEROUS_COMMAND_RE = re.compile(r'[`$]|&&|\|\||;\s*rm\s')
_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)


def validate_target(target: str, max_length: int = 255) -> bool:
    """IP, hostname, CIDR or URL made only of safe characters."""
    return bool(target) and len(target) <= max_length and bool(_TARGET_RE.match(target))


def validate_command(command: str, max_length: int = 1000) -> bool:
    """Reject empty/overlong commands and obvious shell tricks."""
    if not command or len(command) > max_length:
        return False
    if _DANGEROUS_COMMAND_RE.search(command):
        logger.warning(f"Potentially dangerous command detected: {command}")
        return False
    return True


def shell_arg(value: Any) -> str:
    """Quote ONE user-supplied value for the shell (tools run with shell=True).

    A URL such as http://host/item.php?id=1&cat=2 contains characters the shell
    interprets: "&" sends the command to the background and cuts the URL, "?"
    and "*" are glob patterns. shlex.quote turns the value into one literal
    argument. A single pair of quotes the user already typed around the value
    is dropped first so it isn't quoted twice. Plain values (IPs, simple URLs,
    paths) come back unchanged.

    Only for single values (target, url, wordlist, data...). Free-form flag
    strings such as additional_args are left as typed on purpose.
    """
    s = str(value).strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        s = s[1:-1]
    return shlex.quote(s)


# Cache for tool-availability checks
_tool_status_cache = {"data": None, "timestamp": 0.0}
_tool_status_lock = threading.Lock()


def check_tool_availability(tool_name: str) -> bool:
    """True if the tool's binary is on PATH."""
    return shutil.which(TOOL_BINARIES.get(tool_name, tool_name)) is not None


def get_all_tools_status(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """Availability of every Kali tool (cached for TOOL_STATUS_CACHE_TTL seconds)."""
    with _tool_status_lock:
        now = time.time()
        cached = _tool_status_cache["data"]
        if (not force_refresh and cached is not None
                and (now - _tool_status_cache["timestamp"]) < TOOL_STATUS_CACHE_TTL):
            return cached
        status = {tool: {"available": check_tool_availability(tool), "name": name,
                         "description": desc, "category": category}
                  for tool, (name, desc, category) in KALI_TOOLS.items()}
        _tool_status_cache.update(data=status, timestamp=now)
        return status

# ============================================================================
# Tool endpoints: build the command, then run_tool() runs it
# ============================================================================

def _params() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _bad(message: str):
    return jsonify({"error": message}), 400


def _scan_id(params: Dict[str, Any]) -> str:
    return params.get("scan_id") or str(uuid.uuid4())


def _cmd(*parts: str) -> str:
    """Join command parts, skipping empty ones."""
    return " ".join(p for p in parts if p)


def tool_route(tool: str):
    """POST /api/tools/<tool> with the shared error handling."""
    def wrap(fn):
        return app.route(f"/api/tools/{tool}", methods=["POST"])(api_errors("Server error")(fn))
    return wrap


DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


@app.route("/api/command", methods=["POST"])
@api_errors("Server error")
def generic_command():
    """Execute any command provided in the request (only if KALI_ENABLE_COMMAND=1)."""
    if not ENABLE_COMMAND_ENDPOINT:
        logger.warning(f"/api/command is disabled; rejected request from {request.remote_addr}")
        return jsonify({
            "error": "The generic command endpoint is disabled. Start the server with "
                     "KALI_ENABLE_COMMAND=1 to enable it."
        }), 403
    command = _params().get("command", "")
    if not command:
        return _bad("Command parameter is required")
    if not validate_command(command):
        logger.warning(f"Invalid or potentially dangerous command rejected: {command}")
        return _bad("Command contains invalid or dangerous characters/patterns")
    return jsonify(execute_command(command))


@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Serve the dashboard page."""
    return app.send_static_file("dashboard.html")


@tool_route("nmap")
def nmap():
    p = _params()
    target = p.get("target", "")
    if not target:
        return _bad("Target parameter is required")
    if not validate_target(target):
        logger.warning(f"Invalid target for nmap: {target}")
        return _bad("Invalid target format. Use IP address, hostname, or CIDR notation.")
    ports = p.get("ports", "")
    # scan_type / additional_args hold several flags, so they stay unquoted
    command = _cmd("nmap", p.get("scan_type", "-sCV"), ports and f"-p {shell_arg(ports)}",
                   p.get("additional_args", "-T4 -Pn"), shell_arg(target))
    return run_tool(p, command, "nmap", target, _scan_id(p))


@tool_route("gobuster")
def gobuster():
    p = _params()
    url, mode = p.get("url", ""), p.get("mode", "dir")
    if not url:
        return _bad("URL parameter is required")
    if mode not in ("dir", "dns", "fuzz", "vhost"):
        return _bad(f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost")
    wordlist = p.get("wordlist") or DEFAULT_WORDLIST
    command = _cmd(f"gobuster {mode} -u {shell_arg(url)} -w {shell_arg(wordlist)}",
                   p.get("additional_args", ""))
    return run_tool(p, command, "gobuster", url, _scan_id(p))


@tool_route("dirb")
def dirb():
    p = _params()
    url = p.get("url", "")
    if not url:
        return _bad("URL parameter is required")
    command = _cmd(f"dirb {shell_arg(url)} {shell_arg(p.get('wordlist', DEFAULT_WORDLIST))}",
                   p.get("additional_args", ""))
    return run_tool(p, command, "dirb", url, _scan_id(p))


@tool_route("nikto")
def nikto():
    p = _params()
    target = p.get("target", "")
    if not target:
        return _bad("Target parameter is required")
    command = _cmd(f"nikto -h {shell_arg(target)}", p.get("additional_args", ""))
    return run_tool(p, command, "nikto", target, _scan_id(p))


@tool_route("sqlmap")
def sqlmap():
    p = _params()
    url, data = p.get("url", ""), p.get("data", "")
    if not url:
        return _bad("URL parameter is required")
    # The URL almost always carries a query string (?id=1&cat=2) -> must be quoted
    command = _cmd(f"sqlmap -u {shell_arg(url)} --batch", data and f"--data={shell_arg(data)}",
                   p.get("additional_args", ""))
    return run_tool(p, command, "sqlmap", url, _scan_id(p))


@tool_route("metasploit")
def metasploit():
    p = _params()
    module, options = p.get("module", ""), p.get("options") or {}
    if not module:
        return _bad("Module parameter is required")
    # msfconsole reads the module + options from a resource script. Each run
    # gets its own temp file, so two runs at once don't overwrite each other.
    script = f"use {module}\n" + "".join(f"set {k} {v}\n" for k, v in options.items()) + "exploit\n"
    fd, resource_file = tempfile.mkstemp(prefix="mcp_msf_", suffix=".rc")
    with os.fdopen(fd, "w") as f:
        f.write(script)
    return run_tool(p, f"msfconsole -q -r {resource_file}", "metasploit", module, _scan_id(p),
                    on_done=lambda: os.path.exists(resource_file) and os.remove(resource_file))


@tool_route("hydra")
def hydra():
    p = _params()
    target, service = p.get("target", ""), p.get("service", "")
    username, username_file = p.get("username", ""), p.get("username_file", "")
    password, password_file = p.get("password", ""), p.get("password_file", "")
    if not target or not service:
        return _bad("Target and service parameters are required")
    if not (username or username_file) or not (password or password_file):
        return _bad("Username/username_file and password/password_file are required")
    command = _cmd("hydra -t 4",
                   f"-l {shell_arg(username)}" if username else f"-L {shell_arg(username_file)}",
                   f"-p {shell_arg(password)}" if password else f"-P {shell_arg(password_file)}",
                   p.get("additional_args", ""), shell_arg(target), shell_arg(service))
    return run_tool(p, command, "hydra", target, _scan_id(p))


@tool_route("john")
def john():
    p = _params()
    hash_file = p.get("hash_file", "")
    if not hash_file:
        return _bad("Hash file parameter is required")
    fmt, wordlist = p.get("format", ""), p.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    command = _cmd("john", fmt and f"--format={shell_arg(fmt)}",
                   wordlist and f"--wordlist={shell_arg(wordlist)}",
                   p.get("additional_args", ""), shell_arg(hash_file))
    return run_tool(p, command, "john", hash_file, _scan_id(p))


@tool_route("wpscan")
def wpscan():
    p = _params()
    url = p.get("url", "")
    if not url:
        return _bad("URL parameter is required")
    command = _cmd(f"wpscan --url {shell_arg(url)}", p.get("additional_args", ""))
    return run_tool(p, command, "wpscan", url, _scan_id(p))


@tool_route("enum4linux")
def enum4linux():
    p = _params()
    target = p.get("target", "")
    if not target:
        return _bad("Target parameter is required")
    command = _cmd("enum4linux", p.get("additional_args", "-a"), shell_arg(target))
    return run_tool(p, command, "enum4linux", target, _scan_id(p))


@app.route("/health", methods=["GET"])
def health_check():
    tools_status = get_all_tools_status()
    available_count = sum(1 for t in tools_status.values() if t["available"])
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": {tool: info["available"] for tool, info in tools_status.items()},
        "available_tools_count": available_count,
        "total_tools_count": len(tools_status),
        "all_essential_tools_available": available_count >= 4,
        "command_endpoint_enabled": ENABLE_COMMAND_ENDPOINT,
    })


@app.route("/api/tools/available", methods=["GET"])
@api_errors("Server error")
def list_available_tools():
    """All Kali tools with availability, grouped by category, plus the timeouts."""
    tools_status = get_all_tools_status()
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for cmd, info in tools_status.items():
        by_category.setdefault(info["category"], []).append({
            "command": cmd, "name": info["name"], "description": info["description"],
            "available": info["available"]})
    available_count = sum(1 for t in tools_status.values() if t["available"])
    return jsonify({
        "success": True,
        "total_tools": len(tools_status),
        "available_tools": available_count,
        "unavailable_tools": len(tools_status) - available_count,
        "tools_by_category": by_category,
        "all_tools": tools_status,
        "timeouts": {**TOOL_TIMEOUTS, "default": COMMAND_TIMEOUT, "max": MAX_COMMAND_TIMEOUT},
    })


# ============================================================================
# History endpoints
# ============================================================================

def _unknown_tool(tool_name: str):
    return jsonify({"error": f"Unknown tool: {tool_name}. "
                             f"Available tools: {', '.join(TOOL_MODEL_MAPPING)}"}), 404


def _history_page(tool_name: Optional[str]) -> Dict[str, Any]:
    limit = min(request.args.get("limit", 50, type=int), 500)
    history = command_history.get_all(limit=limit, tool_name=tool_name)
    stats = command_history.get_stats(tool_name=tool_name)
    return {"success": True, "total_count": stats["total"], "returned_count": len(history),
            "stats": stats, "history": history}


@app.route("/api/history", methods=["GET"])
@api_errors("Server error")
def get_history():
    """Scan history. Query: limit (default 50, max 500), tool (one tool only)."""
    tool_name = request.args.get("tool")
    data = _history_page(tool_name)
    if tool_name:
        data["filtered_by_tool"] = tool_name
    return jsonify(data)


@app.route("/api/history/stats", methods=["GET"])
@api_errors("Server error")
def get_history_stats():
    tool_name = request.args.get("tool")
    if tool_name and tool_name.lower() not in TOOL_MODEL_MAPPING:
        return _unknown_tool(tool_name)
    return jsonify({"success": True, "stats": command_history.get_stats(tool_name=tool_name)})


@app.route("/api/history/detail/<command_id>", methods=["GET"])
@api_errors("Server error")
def get_history_detail(command_id):
    """One scan with full output. Query: tool (search only that tool's table)."""
    tool_name = request.args.get("tool")
    cmd = command_history.get_by_id(command_id, tool_name=tool_name)
    if cmd is None:
        return jsonify({"error": "Command not found in history" + (f" in {tool_name}" if tool_name else "")}), 404
    return jsonify({"success": True, "command": cmd})


@app.route("/api/history/<command_id>", methods=["GET"])
@api_errors("Server error")
def get_history_by_id_or_tool(command_id):
    """A UUID returns that scan (like /detail); a tool name returns that tool's history."""
    if _UUID_RE.match(command_id):
        return get_history_detail(command_id)
    if command_id.lower() not in TOOL_MODEL_MAPPING:
        return _unknown_tool(command_id)
    return jsonify({"tool": command_id, **_history_page(command_id)})


@app.route("/api/history", methods=["DELETE"])
@api_errors("Server error")
def clear_history():
    """Clear history. Query: tool (only that tool's history)."""
    tool_name = request.args.get("tool")
    if tool_name and tool_name.lower() not in TOOL_MODEL_MAPPING:
        return _unknown_tool(tool_name)
    command_history.clear(tool_name=tool_name)
    return jsonify({"success": True,
                    "message": f"History cleared for {tool_name}" if tool_name else "All history cleared"})


# ============================================================================
# Scan template endpoints (CRUD)
# ============================================================================

# Optional template fields and their max length
_TEMPLATE_FIELDS = {"target": 255, "params": 1000, "wordlist": 500, "description": 500}


def _get_template(template_id: str) -> Optional[ScanTemplate]:
    return db.session.get(ScanTemplate, template_id)


@app.route("/api/templates", methods=["GET"])
@api_errors("Server error")
def list_templates():
    """All scan templates (built-in first, then user templates)."""
    templates = ScanTemplate.query.order_by(ScanTemplate.builtin.desc(), ScanTemplate.created_at.asc()).all()
    return jsonify({"success": True, "count": len(templates), "templates": [t.to_dict() for t in templates]})


@app.route("/api/templates", methods=["POST"])
@api_errors("Server error")
def create_template():
    data = _params()
    name = (data.get("name") or "").strip()
    tool = (data.get("tool") or "").strip().lower()
    if not name:
        return _bad("Template name is required")
    if tool not in VALID_TOOLS:
        return _bad(f"Invalid tool. Must be one of: {', '.join(sorted(VALID_TOOLS))}")
    template = ScanTemplate(id=str(uuid.uuid4()), name=name[:120], tool=tool, builtin=False,
                            **{k: (data.get(k) or "").strip()[:n] or None for k, n in _TEMPLATE_FIELDS.items()})
    db.session.add(template)
    db.session.commit()
    logger.info(f"Created scan template: {name} ({tool})")
    return jsonify({"success": True, "template": template.to_dict()}), 201


@app.route("/api/templates/<template_id>", methods=["GET"])
@api_errors("Server error")
def get_template(template_id):
    template = _get_template(template_id)
    if not template:
        return jsonify({"error": "Template not found"}), 404
    return jsonify({"success": True, "template": template.to_dict()})


@app.route("/api/templates/<template_id>", methods=["PUT"])
@api_errors("Server error")
def update_template(template_id):
    """Update a user template (built-in templates cannot be edited)."""
    template = _get_template(template_id)
    if not template:
        return jsonify({"error": "Template not found"}), 404
    if template.builtin:
        return jsonify({"error": "Built-in templates cannot be edited"}), 403
    data = _params()
    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return _bad("Template name cannot be empty")
        template.name = name[:120]
    if "tool" in data:
        tool = (data.get("tool") or "").strip().lower()
        if tool not in VALID_TOOLS:
            return _bad("Invalid tool")
        template.tool = tool
    for key, limit in _TEMPLATE_FIELDS.items():
        if key in data:
            setattr(template, key, (data.get(key) or "").strip()[:limit] or None)
    db.session.commit()
    return jsonify({"success": True, "template": template.to_dict()})


@app.route("/api/templates/<template_id>", methods=["DELETE"])
@api_errors("Server error")
def delete_template(template_id):
    """Delete a user template (built-in templates cannot be deleted)."""
    template = _get_template(template_id)
    if not template:
        return jsonify({"error": "Template not found"}), 404
    if template.builtin:
        return jsonify({"error": "Built-in templates cannot be deleted"}), 403
    db.session.delete(template)
    db.session.commit()
    logger.info(f"Deleted scan template: {template.name}")
    return jsonify({"success": True, "message": "Template deleted"})

# ============================================================================
# PDF reports
# ============================================================================

BRAND = colors.HexColor("#0891b2") if REPORTLAB_AVAILABLE else None
BRAND_DARK = colors.HexColor("#16233f") if REPORTLAB_AVAILABLE else None
MAX_PDF_OUTPUT_CHARS = 40000  # keep report size sane for huge scan outputs
SEV_COLORS = {"high": "#ef4444", "medium": "#f59e0b", "low": "#22c55e", "info": "#0891b2"}
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _report_styles():
    styles = getSampleStyleSheet()
    # Make the base body text use the Unicode font so Turkish renders
    styles['BodyText'].fontName = FONT_NORMAL
    styles.add(ParagraphStyle(name='KTitle', fontName=FONT_BOLD, fontSize=20,
                              leading=24, textColor=BRAND_DARK, spaceAfter=8))
    styles.add(ParagraphStyle(name='KSub', fontName=FONT_NORMAL, fontSize=9,
                              leading=12, textColor=colors.HexColor("#55627d"), spaceAfter=14))
    styles.add(ParagraphStyle(name='KSection', fontName=FONT_BOLD, fontSize=12,
                              textColor=BRAND, spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle(name='KMono', fontName=FONT_MONO, fontSize=7.5,
                              textColor=colors.HexColor("#1a1a1a"), leading=9))
    return styles


def _header_footer(canvas, doc):
    canvas.saveState()
    # top brand bar
    canvas.setFillColor(BRAND_DARK)
    canvas.rect(0, A4[1] - 16 * mm, A4[0], 16 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont(FONT_BOLD, 12)
    canvas.drawString(18 * mm, A4[1] - 11 * mm, "Kali MCP Server  —  Scan Report")
    # footer
    canvas.setFillColor(colors.HexColor("#93a0b8"))
    canvas.setFont(FONT_NORMAL, 8)
    canvas.drawString(18 * mm, 10 * mm, "Generated by Kali MCP Server")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(colors.HexColor("#dbe2ee"))
    canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
    canvas.restoreState()


def _build_pdf(title: str, story_fn) -> bytes:
    """Shared page setup: title + timestamp, then story_fn(story, styles) adds the rest."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=22 * mm, bottomMargin=18 * mm,
                            leftMargin=18 * mm, rightMargin=18 * mm)
    styles = _report_styles()
    story = [Paragraph(title, styles['KTitle']),
             Paragraph(f"Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
                       styles['KSub'])]
    story_fn(story, styles)
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()


def _cells(values, styles, bold: bool = False):
    fmt = "<b>{}</b>" if bold else "{}"
    return [Paragraph(fmt.format(v), styles['BodyText']) for v in values]


def _meta_table(rows, styles):
    """Two-column key/value table."""
    t = Table([_cells([f"<b>{k}</b>", v], styles) for k, v in rows], colWidths=[38 * mm, 130 * mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f0f4fa")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#dbe2ee")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    return t


def _data_table(header, rows, widths_mm, styles, zebra: bool = True, extra_style=()):
    """Table with a dark header row (repeated on each page)."""
    t = Table([_cells(header, styles, bold=True)] + rows,
              colWidths=[w * mm for w in widths_mm], repeatRows=1)
    style = [
        ('BACKGROUND', (0, 0), (-1, 0), BRAND_DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#dbe2ee")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]
    if zebra:
        style.append(('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f9fd")]))
    t.setStyle(TableStyle(style + list(extra_style)))
    return t


def _findings_section(story, styles, findings_data, show_overview: bool = True):
    """Append parsed findings (ports table + findings list) to the PDF story."""
    if not findings_data or not findings_data.get("supported"):
        return
    s = findings_data.get("summary", {})

    if show_overview:
        story.append(Paragraph("Findings Overview", styles['KSection']))
        story.append(_meta_table([
            ("Open ports", s.get("open_ports", 0)),
            ("High risk", s.get("high", 0)),
            ("Medium risk", s.get("medium", 0)),
            ("Low / Info", s.get("low", 0) + s.get("info", 0)),
        ], styles))

    ports = findings_data.get("ports", [])
    if ports:
        story.append(Paragraph("Open Ports &amp; Services", styles['KSection']))
        rows = [_cells([f"{p['port']}/{p['proto']}", p.get("service", ""), p.get("version", "") or "-",
                        f"<b>{p['risk'].upper()}</b>"], styles) for p in ports]
        risk_colors = [('TEXTCOLOR', (3, i), (3, i), colors.HexColor(SEV_COLORS.get(p['risk'], "#333333")))
                       for i, p in enumerate(ports, start=1)]
        story.append(_data_table(("Port", "Service", "Version", "Risk"), rows, (22, 30, 86, 24),
                                 styles, zebra=False, extra_style=risk_colors))

    flist = findings_data.get("findings", [])
    if flist:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Highlighted Findings", styles['KSection']))
        for f in sorted(flist, key=lambda x: _SEV_ORDER.get(x.get("severity"), 9)):
            sev = f.get("severity", "info")
            html = (f'<font color="{SEV_COLORS.get(sev, "#333333")}"><b>[{sev.upper()}]</b></font> '
                    f'<b>{f.get("title", "")}</b>')
            if f.get("detail"):
                html += f'<br/><font size="8" color="#55627d">{f["detail"]}</font>'
            story.append(Paragraph(html, styles['BodyText']))
            story.append(Spacer(1, 5))


def _clip(text: str, limit: int, note: str) -> str:
    return text[:limit] + (f"\n\n... [{note}] ..." if len(text) > limit else "")


def _tool_of(cmd: Dict[str, Any]) -> str:
    """Tool name = first word of the stored command."""
    return (cmd.get("command") or "").strip().split(" ")[0]


def _short_time(iso: Optional[str]) -> str:
    return (iso or "-")[:19].replace("T", " ")


def build_scan_pdf(cmd: Dict[str, Any], findings_data: Dict[str, Any] = None) -> bytes:
    """Build a one-scan PDF report and return the bytes."""
    tool = _tool_of(cmd) or "scan"

    def story_fn(story, styles):
        status = "SUCCESS" if cmd.get("success") else "FAILED"
        story.append(Paragraph("Scan Summary", styles['KSection']))
        story.append(_meta_table([
            ("Tool", tool),
            ("Target", cmd.get("target") or "-"),
            ("Command", cmd.get("command") or "-"),
            ("Status", f"{status} (return code {cmd.get('return_code')})"),
            ("Timed out", "Yes" if cmd.get("timed_out") else "No"),
            ("Duration", f"{cmd.get('duration', 0):.2f} s"),
            ("Timestamp", cmd.get("timestamp") or "-"),
            ("Scan ID", cmd.get("id") or "-"),
        ], styles))
        _findings_section(story, styles, findings_data)

        stdout, stderr = cmd.get("stdout") or "", cmd.get("stderr") or ""
        if stdout:
            story.append(Paragraph("Output (stdout)", styles['KSection']))
            story.append(Preformatted(_clip(stdout, MAX_PDF_OUTPUT_CHARS, "output truncated"), styles['KMono']))
        if stderr:
            story.append(Spacer(1, 6))
            story.append(Paragraph("Errors (stderr)", styles['KSection']))
            story.append(Preformatted(_clip(stderr, MAX_PDF_OUTPUT_CHARS // 2, "truncated"), styles['KMono']))
        if not stdout and not stderr:
            story.append(Paragraph("No output was captured for this scan.", styles['BodyText']))

    return _build_pdf(f"{tool.capitalize()} Scan Report", story_fn)


def build_summary_pdf(history: List[Dict[str, Any]], stats: Dict[str, Any]) -> bytes:
    """Build a summary PDF of recent scans."""
    def story_fn(story, styles):
        story.append(Paragraph("Statistics", styles['KSection']))
        story.append(_meta_table([
            ("Total scans", stats.get("total", 0)),
            ("Successful", stats.get("successful", 0)),
            ("Failed", stats.get("failed", 0)),
            ("Timed out", stats.get("timed_out", 0)),
        ], styles))
        story.append(Paragraph("Recent Scans", styles['KSection']))
        rows = [_cells([_tool_of(c), str(c.get("target") or "-")[:40], "OK" if c.get("success") else "FAIL",
                        f"{c.get('duration', 0):.1f}s", _short_time(c.get("timestamp") or "")], styles)
                for c in history]
        story.append(_data_table(("Tool", "Target", "Status", "Duration", "Time"), rows,
                                 (24, 55, 18, 20, 41), styles))

    return _build_pdf("Scan Activity Summary", story_fn)


def build_workflow_pdf(wf: Dict[str, Any]) -> bytes:
    """PDF report for one recon workflow: overview, steps, findings per step."""
    def story_fn(story, styles):
        s = wf.get("summary", {})
        story.append(Paragraph("Workflow Summary", styles['KSection']))
        web_urls = ", ".join(w.get("url", "") for w in wf.get("web_targets", [])) or "-"
        story.append(_meta_table([
            ("Target", wf.get("target") or "-"),
            ("Status", (wf.get("status") or "-").upper()),
            ("Started", _short_time(wf.get("created_at"))),
            ("Finished", _short_time(wf.get("finished_at"))),
            ("Open ports", s.get("open_ports", 0)),
            ("Web targets", _xesc(web_urls)),
            ("Steps", f"{s.get('steps_done', 0)} done / {s.get('steps_failed', 0)} failed / "
                      f"{s.get('steps_total', 0)} total"),
            ("High / Medium", f"{s.get('high', 0)} / {s.get('medium', 0)}"),
            ("Low / Info", f"{s.get('low', 0)} / {s.get('info', 0)}"),
            ("Workflow ID", wf.get("id") or "-"),
        ], styles))
        if wf.get("error"):
            story.append(Spacer(1, 4))
            story.append(Paragraph(f'<font color="#ef4444"><b>Error:</b></font> {_xesc(wf["error"])}',
                                   styles['BodyText']))

        steps = wf.get("steps", [])
        story.append(Paragraph("Steps", styles['KSection']))
        rows = [_cells([st.get("index", 0) + 1, st.get("tool", ""), _xesc(st.get("target", "")),
                        st.get("status", ""), f"{st.get('duration') or 0:.1f}s",
                        (st.get("summary") or {}).get("total", 0)], styles) for st in steps]
        story.append(_data_table(("#", "Tool", "Target", "Status", "Time", "Findings"), rows,
                                 (10, 22, 66, 22, 18, 24), styles))

        for st in steps:
            if not st.get("summary"):
                continue
            story.append(Spacer(1, 6))
            story.append(Paragraph(_xesc(f"Step {st['index'] + 1}: {st['tool']} — {st['target']}"),
                                   styles['KSection']))
            story.append(Paragraph(f'<font face="{FONT_MONO}" size="8">{_xesc(st.get("command", ""))}</font>',
                                   styles['BodyText']))
            if st.get("note"):
                story.append(Paragraph(f'<font size="8" color="#55627d">{_xesc(st["note"])}</font>',
                                       styles['BodyText']))
            _findings_section(story, styles, {"supported": True, "summary": st["summary"],
                                              "ports": st.get("ports", []),
                                              "findings": st.get("findings", [])},
                              show_overview=False)

    return _build_pdf("Chained Recon Report", story_fn)


def _safe_filename(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]', '_', name)[:60]


def _pdf_response(pdf_bytes: bytes, filename: str):
    return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf",
                     as_attachment=True, download_name=_safe_filename(filename))


_NO_PDF = ({"error": "PDF support not installed. Run: pip install reportlab"}, 503)


def _parse_scan(cmd: Dict[str, Any]) -> Dict[str, Any]:
    return findings_parser.parse_findings(tool_name=_tool_of(cmd), command=cmd.get("command") or "",
                                          stdout=cmd.get("stdout") or "", stderr=cmd.get("stderr") or "")


@app.route("/api/history/<command_id>/findings", methods=["GET"])
@api_errors("Findings error")
def scan_findings(command_id):
    """Structured, risk-rated findings parsed from a scan's raw output."""
    cmd = command_history.get_by_id(command_id, tool_name=request.args.get("tool"))
    if cmd is None:
        return jsonify({"error": "Scan not found in history"}), 404
    return jsonify({**_parse_scan(cmd), "success": True, "scan_id": command_id})


@app.route("/api/history/<command_id>/report", methods=["GET"])
@api_errors("Report error")
def scan_report(command_id):
    """Download a PDF report for a single scan."""
    if not REPORTLAB_AVAILABLE:
        return _NO_PDF
    cmd = command_history.get_by_id(command_id, tool_name=request.args.get("tool"))
    if cmd is None:
        return jsonify({"error": "Scan not found in history"}), 404
    try:
        findings_data = _parse_scan(cmd)
    except Exception:
        findings_data = None
    tool = _tool_of(cmd) or "scan"
    return _pdf_response(build_scan_pdf(cmd, findings_data=findings_data),
                         f"kali_report_{tool}_{command_id[:8]}.pdf")


@app.route("/api/report/summary", methods=["GET"])
@api_errors("Report error")
def summary_report():
    """Download a PDF summary report of recent scans."""
    if not REPORTLAB_AVAILABLE:
        return _NO_PDF
    history = command_history.get_all(limit=min(request.args.get("limit", 50, type=int), 200))
    if not history:
        return jsonify({"error": "No scans to report yet"}), 404
    return _pdf_response(build_summary_pdf(history, command_history.get_stats()),
                         f"kali_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf")

# ============================================================================
# Chained Recon Workflow  (nmap → gobuster / nikto on every web port found)
# ============================================================================
#
# POST /api/workflows/recon starts a background thread (ReconRunner) and
# returns 202 immediately. The runner:
#   1. runs nmap on the host,
#   2. parses the open ports (findings.parse_nmap) and picks the web ones
#      (recon.web_targets_from_ports),
#   3. runs gobuster and/or nikto on each web URL, one step at a time.
# Every step is a normal scan: it lands in <tool>_history, streams over
# Socket.IO (to its own scan room AND the workflow room) and can be cancelled.
# The workflow itself (steps, statuses, trimmed findings) is persisted in
# recon_workflows so it survives a page reload.

MAX_CONCURRENT_WORKFLOWS = int(os.environ.get("MAX_CONCURRENT_WORKFLOWS", 2))
active_workflows: Dict[str, "ReconRunner"] = {}
_workflow_db_lock = threading.Lock()


def _utc_iso() -> str:
    return datetime.utcnow().isoformat()


class ReconRunner:
    """Runs one chained recon workflow in a background thread."""

    def __init__(self, workflow_id: str, opts: Dict[str, Any]):
        self.id = workflow_id
        self.opts = opts
        self.target = opts["target"]
        self.steps: List[Dict[str, Any]] = []
        self.web_targets: List[Dict[str, Any]] = []
        self.status = "running"
        self.error = ""
        self.cancelled = False
        self.current_scan_id: Optional[str] = None

    # ---- persistence / events ------------------------------------------
    def _emit(self, event: str, data: Dict[str, Any]):
        socket_emit(event, {**data, "workflow_id": self.id}, self.id)

    def save(self, finished: bool = False):
        with _workflow_db_lock, app.app_context():
            wf = db.session.get(ReconWorkflow, self.id)
            if wf is None:
                wf = ReconWorkflow(id=self.id, target=self.target,
                                   options=json.dumps(self.opts, ensure_ascii=False))
                db.session.add(wf)
            wf.status = self.status
            wf.steps = json.dumps(self.steps, ensure_ascii=False)
            wf.web_targets = json.dumps(self.web_targets, ensure_ascii=False)
            wf.error = self.error[:500] if self.error else None
            if finished:
                wf.finished_at = datetime.utcnow()
            db.session.commit()
            payload = wf.to_dict()
        self._emit("workflow_update", payload)

    # ---- control --------------------------------------------------------
    def cancel(self):
        """Stop the workflow: kill the running step and skip the rest."""
        self.cancelled = True
        # The step may be a split second away from registering its executor
        deadline = time.time() + 2
        while time.time() < deadline:
            sid = self.current_scan_id
            if sid is None:
                return
            executor = active_scans.get(sid)
            if executor is not None:
                executor.terminate()
                return
            time.sleep(0.1)

    # ---- execution ------------------------------------------------------
    def _run_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Run one step in place. Returns the parsed findings dict."""
        empty = {"ports": [], "findings": [], "summary": None}
        if self.cancelled:
            step["status"] = "cancelled"
            return empty
        if not shutil.which(step["tool"]):
            step["status"] = "failed" if step["tool"] == "nmap" else "skipped"
            step["note"] = f"{step['tool']} kurulu değil / PATH'te bulunamadı"
            self.save()
            return empty

        # Per-tool default (gobuster/nikto: 30 min) unless the user set step_timeout
        timeout = resolve_timeout(step["tool"], self.opts.get("step_timeout"))
        step.update(status="running", scan_id=f"{self.id}_s{step['index']}",
                    started_at=_utc_iso(), timeout=timeout)
        # Register the executor BEFORE announcing the step, so a client polling
        # /api/scans/<scan_id> never gets a 404 for a step marked "running".
        executor = create_executor(step["command"], tool_name=step["tool"], target=step["target"],
                                   scan_id=step["scan_id"], timeout=timeout, extra_rooms=[self.id])
        self.current_scan_id = step["scan_id"]
        self.save()
        self._emit("workflow_step_started", {k: step[k] for k in
                                             ("index", "tool", "target", "command", "scan_id")})

        result = run_executor(executor)
        self.current_scan_id = None

        stdout = result.get("stdout") or ""
        stderr = result.get("stderr") or ""
        parsed = findings_parser.parse_findings(step["tool"], step["command"], stdout, stderr)
        rc = result.get("return_code")
        step.update(history_id=result.get("history_id"), finished_at=_utc_iso(),
                    duration=round(result.get("duration", 0.0), 2), return_code=rc,
                    timed_out=bool(result.get("timed_out")),
                    summary=parsed.get("summary"),
                    findings=recon.trim_findings(parsed.get("findings", [])),
                    ports=parsed.get("ports", []))

        if self.cancelled or result.get("cancelled"):
            step["status"] = "cancelled"
            step["note"] = "İptal edildi"
        elif result.get("timed_out"):
            step["status"] = "done"
            step["note"] = f"Zaman aşımı ({timeout}s) — kısmi sonuç"
        elif result.get("success"):
            step["status"] = "done"
        elif stdout.strip() and parsed.get("findings"):
            # some tools (nikto, gobuster) exit non-zero even with useful output
            step["status"] = "done"
            step["note"] = f"Çıkış kodu {rc} — çıktı yine de ayrıştırıldı"
        else:
            step["status"] = "failed"
            first_err = next((l.strip() for l in stderr.splitlines() if l.strip()), "")
            step["note"] = (first_err[:200] or f"Çıkış kodu {rc}")
        self.save()
        return parsed

    def _finish(self, status: str):
        for s in self.steps:
            if s["status"] in ("pending", "running"):
                s["status"] = "cancelled" if status == "cancelled" else "skipped"
        self.status = status
        self.save(finished=True)
        self._emit("workflow_finished", {"status": status})
        logger.info(f"Recon workflow {self.id} finished: {status}")

    def run(self):
        try:
            nmap_step = recon.new_step(0, "nmap", self.target, recon.build_nmap_command(self.opts))
            self.steps.append(nmap_step)
            self.save()

            parsed = self._run_step(nmap_step)
            if self.cancelled:
                return self._finish("cancelled")
            if nmap_step["status"] != "done":
                self.error = "Nmap adımı başarısız — zincir devam ettirilmedi. " + nmap_step["note"]
                return self._finish("failed")

            found = recon.web_targets_from_ports(parsed.get("ports", []), self.target,
                                                 limit=recon.HARD_MAX_WEB_TARGETS)
            self.web_targets = found[:self.opts["max_web_targets"]]
            notes = []
            if len(found) > len(self.web_targets):
                notes.append(f"{len(found)} web portu bulundu, ilk {len(self.web_targets)} tanesi "
                             f"taranacak (max_web_targets)")
            if not self.web_targets:
                notes.append("Web portu bulunamadı — gobuster/nikto adımları yok.")
            elif not (self.opts["run_gobuster"] or self.opts["run_nikto"]):
                notes.append("Gobuster ve Nikto kapalı — yalnızca nmap çalıştı.")
            nmap_step["note"] = " ".join(filter(None, [nmap_step["note"]] + notes))

            for i, s in enumerate(recon.plan_web_steps(self.web_targets, self.opts), start=1):
                self.steps.append(recon.new_step(i, s["tool"], s["target"], s["command"]))
            self.save()

            for step in self.steps[1:]:
                if self.cancelled:
                    break
                self._run_step(step)

            self._finish("cancelled" if self.cancelled else "completed")
        except Exception as e:
            logger.error(f"Recon workflow {self.id} crashed: {e}")
            logger.error(traceback.format_exc())
            self.error = f"Beklenmeyen hata: {e}"
            try:
                self._finish("failed")
            except Exception:
                pass
        finally:
            active_workflows.pop(self.id, None)


def _recover_interrupted_workflows():
    """Workflows left 'running' by a previous server process can never finish."""
    try:
        with app.app_context():
            stale = ReconWorkflow.query.filter_by(status="running").all()
            for wf in stale:
                steps = json.loads(wf.steps or "[]")
                for s in steps:
                    if s.get("status") in ("pending", "running"):
                        s["status"] = "cancelled"
                wf.steps = json.dumps(steps, ensure_ascii=False)
                wf.status = "failed"
                wf.error = "Sunucu yeniden başlatıldı — akış yarıda kaldı"
                wf.finished_at = datetime.utcnow()
            if stale:
                db.session.commit()
                logger.info(f"Marked {len(stale)} interrupted recon workflow(s) as failed")
    except Exception as e:
        logger.error(f"Error recovering workflows: {e}")


_recover_interrupted_workflows()


@app.route("/api/workflows/recon", methods=["POST"])
@api_errors("Server error")
def start_recon_workflow():
    """Start a chained recon workflow (nmap → gobuster/nikto) in the background."""
    body = _params()
    opts, err = recon.normalize_options(body)
    if err:
        return _bad(err)
    if len(active_workflows) >= MAX_CONCURRENT_WORKFLOWS:
        return jsonify({"error": f"Aynı anda en fazla {MAX_CONCURRENT_WORKFLOWS} recon akışı "
                                 f"çalışabilir — birinin bitmesini bekleyin veya iptal edin"}), 429

    # The client may pick the ID (a UUID) so it can join the Socket.IO room
    # BEFORE the first nmap line is emitted — same idea as scan_id.
    workflow_id = str(body.get("workflow_id") or "").strip().lower()
    if workflow_id:
        try:
            workflow_id = str(uuid.UUID(workflow_id))
        except ValueError:
            return _bad("workflow_id must be a UUID")
        if workflow_id in active_workflows or db.session.get(ReconWorkflow, workflow_id):
            return jsonify({"error": "workflow_id already exists"}), 409
    else:
        workflow_id = str(uuid.uuid4())
    runner = ReconRunner(workflow_id, opts)
    runner.save()  # persist before returning so GET works right away
    active_workflows[workflow_id] = runner
    threading.Thread(target=runner.run, name=f"recon-{workflow_id[:8]}", daemon=True).start()
    logger.info(f"Started recon workflow {workflow_id} on {opts['target']}")

    with app.app_context():
        data = db.session.get(ReconWorkflow, workflow_id).to_dict(include_findings=True)
    return jsonify({"success": True, "workflow_id": workflow_id, "workflow": data}), 202


@app.route("/api/workflows", methods=["GET"])
@api_errors("Server error")
def list_workflows():
    """Recent recon workflows (newest first, light step view)."""
    limit = min(request.args.get("limit", 20, type=int), 100)
    rows = ReconWorkflow.query.order_by(ReconWorkflow.created_at.desc()).limit(limit).all()
    return jsonify({"success": True, "count": len(rows), "active": len(active_workflows),
                    "workflows": [w.to_dict() for w in rows]})


@app.route("/api/workflows/<workflow_id>", methods=["GET"])
@api_errors("Server error")
def get_workflow(workflow_id):
    """Full workflow state: steps, web targets, summary and combined findings."""
    wf = db.session.get(ReconWorkflow, workflow_id)
    if not wf:
        return jsonify({"error": "Workflow not found"}), 404
    return jsonify({"success": True, "workflow": wf.to_dict(include_findings=True)})


@app.route("/api/workflows/<workflow_id>/cancel", methods=["POST"])
def cancel_workflow(workflow_id):
    """Cancel a running workflow (kills the current step, skips the rest)."""
    runner = active_workflows.get(workflow_id)
    if runner is None:
        return jsonify({"error": "Workflow is not running"}), 404
    logger.info(f"Cancelling recon workflow {workflow_id}")
    runner.cancel()
    return jsonify({"success": True, "message": f"Workflow {workflow_id} cancelling"})


@app.route("/api/workflows/<workflow_id>/report", methods=["GET"])
@api_errors("Report error")
def workflow_report(workflow_id):
    """Download a PDF report for a recon workflow."""
    if not REPORTLAB_AVAILABLE:
        return _NO_PDF
    wf = db.session.get(ReconWorkflow, workflow_id)
    if not wf:
        return jsonify({"error": "Workflow not found"}), 404
    return _pdf_response(build_workflow_pdf(wf.to_dict(include_findings=True)),
                         f"kali_recon_{wf.target}_{workflow_id[:8]}.pdf")


# ============================================================================
# Live scans: WebSocket rooms, polling, cancel
# ============================================================================

def _cancel(scan_id: str) -> bool:
    """Kill a running scan and tell its room. False if it isn't running."""
    executor = active_scans.get(scan_id)
    if executor is None:
        return False
    logger.info(f"Cancelling scan {scan_id}")
    executor.terminate()
    socket_emit('scan_cancelled', {'scan_id': scan_id, 'message': 'Scan cancelled by user'}, scan_id)
    return True


if socketio:
    @socketio.on('connect')
    def handle_connect():
        logger.info(f"Client connected: {request.sid}")
        emit('connected', {'message': 'Connected to Kali scan server'})

    @socketio.on('disconnect')
    def handle_disconnect(*_):
        logger.info(f"Client disconnected: {request.sid}")

    @socketio.on('join_scan')
    def handle_join_scan(data):
        """Join a scan (or workflow) room to receive its live events."""
        scan_id = (data or {}).get('scan_id')
        if scan_id:
            join_room(scan_id)
            emit('room_joined', {'scan_id': scan_id})

    @socketio.on('leave_scan')
    def handle_leave_scan(data):
        scan_id = (data or {}).get('scan_id')
        if scan_id:
            leave_room(scan_id)

    @socketio.on('cancel_scan')
    def handle_cancel_scan(data):
        scan_id = (data or {}).get('scan_id')
        try:
            if scan_id:
                _cancel(scan_id)
        except Exception as e:
            logger.error(f"Error cancelling scan: {e}")
            emit('cancel_error', {'scan_id': scan_id, 'error': str(e)}, room=scan_id)


@app.route("/api/scans/active", methods=["GET"])
def list_active_scans():
    """Scans that are still running (no output lines) — lets a reloaded page re-attach."""
    with _scan_registry_lock:
        running = [e for e in scan_registry.values() if e.status in ("starting", "running")]
    return jsonify({"success": True, "count": len(running),
                    "scans": [e.snapshot(include_lines=False) for e in running]})


@app.route("/api/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    """
    Live state of a scan + its buffered output.

    Query: since=<n>  return output lines from absolute index n (use the
                      previous response's "next"), lines=0 to omit lines.
    Works while the scan runs and for a while after it finishes; afterwards
    use /api/history/<history_id>.
    """
    executor = scan_registry.get(scan_id)
    if executor is None:
        return jsonify({"error": "Scan not found (unknown or expired) — see /api/history"}), 404
    since = request.args.get("since", 0, type=int)
    include = request.args.get("lines", "1") not in ("0", "false", "no")
    return jsonify(executor.snapshot(since=since, include_lines=include))


@app.route("/api/scans/cancel/<scan_id>", methods=["POST"])
@api_errors("Server error")
def cancel_scan(scan_id):
    """REST endpoint to cancel a scan."""
    if not _cancel(scan_id):
        return jsonify({'error': f'Scan {scan_id} not found'}), 404
    return jsonify({'success': True, 'message': f'Scan {scan_id} cancelled'})


def parse_args():
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    default_ip = os.environ.get("API_IP", "127.0.0.1")
    parser.add_argument("--ip", type=str, default=default_ip,
                        help=f"IP address to bind the server to (default: {default_ip}). Use 0.0.0.0 for network access")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    debug = DEBUG_MODE or args.debug
    if debug:
        logger.setLevel(logging.DEBUG)
    logger.info(f"Starting Kali Linux Tools API Server on {args.ip}:{args.port}")
    if socketio:
        socketio.run(app, host=args.ip, port=args.port, debug=debug, allow_unsafe_werkzeug=True)
    else:
        app.run(host=args.ip, port=args.port, debug=debug)
