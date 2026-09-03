#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import traceback
import threading
import uuid
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# WebSocket support
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
    logger_warning = "Flask-SocketIO not installed. Real-time streaming disabled. Install with: pip install flask-socketio python-socketio"

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system environment variables

# Findings parser (structured results from raw tool output)
try:
    import findings as findings_parser
except ImportError:
    import os as _os_imp, sys as _sys_imp
    _sys_imp.path.insert(0, _os_imp.path.dirname(_os_imp.path.abspath(__file__)))
    import findings as findings_parser

# PDF report support (optional)
import io as _io
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, Preformatted)
    from reportlab.lib.enums import TA_LEFT
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Register a Unicode TTF font so Turkish characters (ı, ş, ğ, ç...) render in
# PDFs. Falls back to the built-in Helvetica/Courier if no TTF is found.
FONT_NORMAL, FONT_BOLD, FONT_MONO = "Helvetica", "Helvetica-Bold", "Courier"
if REPORTLAB_AVAILABLE:
    import glob as _glob

    def _find_font(*names):
        search_dirs = ["/usr/share/fonts", "/usr/local/share/fonts",
                       "/Library/Fonts", os.path.expanduser("~/.fonts"),
                       os.path.join(os.path.dirname(pdfmetrics.__file__), "fonts")]
        for name in names:
            for d in search_dirs:
                hits = _glob.glob(os.path.join(d, "**", name), recursive=True)
                if hits:
                    return hits[0]
        return None

    try:
        _reg = _find_font("DejaVuSans.ttf")
        _reg_b = _find_font("DejaVuSans-Bold.ttf")
        _reg_m = _find_font("DejaVuSansMono.ttf")
        if _reg:
            pdfmetrics.registerFont(TTFont("KaliSans", _reg))
            FONT_NORMAL = "KaliSans"
            if _reg_b:
                pdfmetrics.registerFont(TTFont("KaliSans-Bold", _reg_b))
                FONT_BOLD = "KaliSans-Bold"
            else:
                FONT_BOLD = "KaliSans"
            if _reg_m:
                pdfmetrics.registerFont(TTFont("KaliMono", _reg_m))
                FONT_MONO = "KaliMono"
            # Map <b> tags to the bold face
            from reportlab.pdfbase.pdfmetrics import registerFontFamily
            registerFontFamily("KaliSans", normal="KaliSans", bold=FONT_BOLD,
                               italic="KaliSans", boldItalic=FONT_BOLD)
    except Exception:
        pass  # keep Helvetica fallback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5001))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 180))  # Default per-command timeout in seconds (3 minutes)
DATABASE_PATH = os.environ.get("DATABASE_PATH", "scan_history.db")
# How long (seconds) to cache tool-availability results before re-checking with `which`
TOOL_STATUS_CACHE_TTL = int(os.environ.get("TOOL_STATUS_CACHE_TTL", 60))

# Kali Tools Database
KALI_TOOLS = {
    "nmap": {
        "name": "Nmap",
        "description": "Network mapper - port scanning and service discovery",
        "category": "reconnaissance"
    },
    "gobuster": {
        "name": "Gobuster",
        "description": "Directory, DNS, and virtual host enumeration tool",
        "category": "web"
    },
    "dirb": {
        "name": "Dirb",
        "description": "Web content scanner",
        "category": "web"
    },
    "nikto": {
        "name": "Nikto",
        "description": "Web server scanner",
        "category": "web"
    },
    "sqlmap": {
        "name": "SQLmap",
        "description": "SQL injection detection and exploitation tool",
        "category": "web"
    },
    "metasploit": {
        "name": "Metasploit",
        "description": "Penetration testing framework",
        "category": "exploitation"
    },
    "hydra": {
        "name": "Hydra",
        "description": "Password cracking tool",
        "category": "cracking"
    },
    "john": {
        "name": "John the Ripper",
        "description": "Hash cracking tool",
        "category": "cracking"
    },
    "wpscan": {
        "name": "WPScan",
        "description": "WordPress vulnerability scanner",
        "category": "web"
    },
    "enum4linux": {
        "name": "Enum4linux",
        "description": "Windows/Samba enumeration tool",
        "category": "reconnaissance"
    }
}

# Configure Flask with SQLite database
class Base(DeclarativeBase):
    pass

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
db = SQLAlchemy(app, model_class=Base)

# Initialize SocketIO for real-time communication
socketio = None
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*")
    logger.info("Flask-SocketIO initialized for real-time scanning")
else:
    logger.warning(logger_warning)

# Enable CORS - Cross-Origin Resource Sharing
try:
    from flask_cors import CORS
    cors_origins = os.environ.get("CORS_ORIGINS", "*")
    CORS(app, resources={r"/api/*": {"origins": cors_origins}})
    logger.info(f"CORS enabled for origins: {cors_origins}")
except ImportError:
    logger.warning("Flask-CORS not installed. CORS support disabled. Install with: pip install flask-cors")


# ============================================================================
# SQLAlchemy Models - Tool-Specific Tables with Base Class (Inheritance)
# ============================================================================

class BaseScanRecord(db.Model):
    """Base model for all scan records (abstract base class)"""
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
        """Convert to dictionary"""
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
            "stderr_length": self.stderr_length
        }
        if include_output:
            data["stdout"] = self.stdout
            data["stderr"] = self.stderr
        return data


# Backward compatibility: Keep ScanRecord for migration
class ScanRecord(db.Model):
    """Legacy model - used for migration from old single-table schema"""
    __tablename__ = 'scan_history'
    
    id = db.Column(db.String(36), primary_key=True)
    command = db.Column(db.String(500), nullable=False)
    tool_name = db.Column(db.String(50), nullable=True)
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


# ============================================================================
# Tool-Specific Models (10 Kali Tools)
# ============================================================================

class NmapHistory(BaseScanRecord):
    """Nmap scan records"""
    __tablename__ = 'nmap_history'


class GobusterHistory(BaseScanRecord):
    """Gobuster scan records"""
    __tablename__ = 'gobuster_history'


class DirbHistory(BaseScanRecord):
    """Dirb scan records"""
    __tablename__ = 'dirb_history'


class NiktoHistory(BaseScanRecord):
    """Nikto scan records"""
    __tablename__ = 'nikto_history'


class SqlmapHistory(BaseScanRecord):
    """SQLmap scan records"""
    __tablename__ = 'sqlmap_history'


class Enum4linuxHistory(BaseScanRecord):
    """Enum4linux scan records"""
    __tablename__ = 'enum4linux_history'


class MetasploitHistory(BaseScanRecord):
    """Metasploit scan records"""
    __tablename__ = 'metasploit_history'


class HydraHistory(BaseScanRecord):
    """Hydra scan records"""
    __tablename__ = 'hydra_history'


class JohnHistory(BaseScanRecord):
    """John the Ripper scan records"""
    __tablename__ = 'john_history'


class WpscanHistory(BaseScanRecord):
    """WPScan scan records"""
    __tablename__ = 'wpscan_history'


# Mapping tool names to their models
TOOL_MODEL_MAPPING = {
    'nmap': NmapHistory,
    'gobuster': GobusterHistory,
    'dirb': DirbHistory,
    'nikto': NiktoHistory,
    'sqlmap': SqlmapHistory,
    'enum4linux': Enum4linuxHistory,
    'metasploit': MetasploitHistory,
    'hydra': HydraHistory,
    'john': JohnHistory,
    'wpscan': WpscanHistory,
}


# ============================================================================
# Scan Template Model - reusable saved scan configurations
# ============================================================================

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
            added = 0
            for tpl in DEFAULT_TEMPLATES:
                if tpl["name"] in existing:
                    continue
                db.session.add(ScanTemplate(
                    id=str(uuid.uuid4()),
                    name=tpl["name"], tool=tpl["tool"],
                    target=tpl.get("target"), params=tpl.get("params"),
                    wordlist=tpl.get("wordlist"), description=tpl.get("description"),
                    builtin=True,
                ))
                added += 1
            if added:
                db.session.commit()
                logger.info(f"Seeded {added} built-in scan templates")
    except Exception as e:
        logger.error(f"Error seeding templates: {e}")


class CommandHistory:
    """Class to manage command execution history with SQLite backend (tool-specific tables)"""
    
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self.lock = threading.Lock()
        # Initialize database tables
        with app.app_context():
            db.create_all()
            logger.info(f"Database initialized at {DATABASE_PATH}")
            logger.info(f"Tool-specific tables: {', '.join(TOOL_MODEL_MAPPING.keys())}")
    
    def _get_model_for_tool(self, tool_name: str):
        """Get the appropriate model class for a tool"""
        return TOOL_MODEL_MAPPING.get(tool_name.lower() if tool_name else None, NmapHistory)
    
    def add_command(self, command: str, result: Dict[str, Any], duration: float = 0.0, 
                   tool_name: str = None, target: str = None) -> str:
        """
        Add a command to the history (SQLite) in the appropriate tool-specific table
        
        Args:
            command: The command that was executed
            result: The result of the command execution
            duration: How long the command took to execute
            tool_name: Name of the tool used
            target: Target being scanned
            
        Returns:
            The ID of the recorded command
        """
        # Skip recording 'which' commands - these are just tool availability checks
        if command.strip().startswith('which '):
            logger.debug(f"Skipped recording 'which' command: {command}")
            return ""
        
        with self.lock:
            try:
                command_id = str(uuid.uuid4())
                
                # Get the correct model for this tool
                model_class = self._get_model_for_tool(tool_name)
                
                record = model_class(
                    id=command_id,
                    command=command,
                    target=target,
                    duration=duration,
                    success=result.get("success", False),
                    return_code=result.get("return_code", -1),
                    timed_out=result.get("timed_out", False),
                    stdout=result.get("stdout", ""),
                    stderr=result.get("stderr", ""),
                    stdout_length=len(result.get("stdout", "")),
                    stderr_length=len(result.get("stderr", ""))
                )
                
                with app.app_context():
                    db.session.add(record)
                    db.session.commit()
                
                logger.info(f"Scan recorded in {model_class.__tablename__} with ID: {command_id} (tool: {tool_name})")
                
                # Cleanup old records (keep only max_history per tool)
                self._cleanup_old_records(tool_name)
                
                return command_id
            except Exception as e:
                logger.error(f"Error adding command to history: {e}")
                logger.error(traceback.format_exc())
                return ""
    
    def get_all(self, limit: int = 50, tool_name: str = None) -> List[Dict[str, Any]]:
        """
        Get all or recent commands from history
        
        Args:
            limit: Maximum number of commands to return
            tool_name: Filter by specific tool (if None, returns from all tools)
            
        Returns:
            List of commands
        """
        with self.lock:
            try:
                with app.app_context():
                    if tool_name:
                        # Get from specific tool table
                        model_class = self._get_model_for_tool(tool_name)
                        records = model_class.query.order_by(model_class.timestamp.desc()).limit(limit).all()
                    else:
                        # Get from all tool tables (union query)
                        all_records = []
                        for model_class in TOOL_MODEL_MAPPING.values():
                            records = model_class.query.order_by(model_class.timestamp.desc()).limit(limit).all()
                            all_records.extend(records)
                        
                        # Sort by timestamp descending and limit
                        all_records.sort(key=lambda x: x.timestamp, reverse=True)
                        records = all_records[:limit]
                    
                    return [record.to_dict(include_output=False) for record in records]
            except Exception as e:
                logger.error(f"Error getting history: {e}")
                logger.error(traceback.format_exc())
                return []
    
    def get_by_id(self, command_id: str, tool_name: str = None) -> Optional[Dict[str, Any]]:
        """
        Get a specific command by ID
        
        Args:
            command_id: The ID of the command
            tool_name: Optional tool name to search in specific table
            
        Returns:
            The command entry or None if not found
        """
        with self.lock:
            try:
                with app.app_context():
                    if tool_name:
                        # Search in specific tool table
                        model_class = self._get_model_for_tool(tool_name)
                        record = model_class.query.filter_by(id=command_id).first()
                    else:
                        # Search in all tool tables
                        record = None
                        for model_class in TOOL_MODEL_MAPPING.values():
                            record = model_class.query.filter_by(id=command_id).first()
                            if record:
                                break
                    
                    if record:
                        return record.to_dict(include_output=True)
                    return None
            except Exception as e:
                logger.error(f"Error getting command by ID: {e}")
                logger.error(traceback.format_exc())
                return None
    
    def clear(self, tool_name: str = None):
        """Clear history (all tools or specific tool)"""
        with self.lock:
            try:
                with app.app_context():
                    if tool_name:
                        # Clear specific tool table
                        model_class = self._get_model_for_tool(tool_name)
                        model_class.query.delete()
                        logger.info(f"Cleared history for {tool_name}")
                    else:
                        # Clear all tool tables
                        for model_class in TOOL_MODEL_MAPPING.values():
                            model_class.query.delete()
                        logger.info("All scan history cleared from all tool tables")
                    
                    db.session.commit()
            except Exception as e:
                logger.error(f"Error clearing history: {e}")
                logger.error(traceback.format_exc())
    
    def _cleanup_old_records(self, tool_name: str = None):
        """Remove old records keeping only max_history items per tool"""
        try:
            with app.app_context():
                if tool_name:
                    # Cleanup specific tool table
                    model_class = self._get_model_for_tool(tool_name)
                    count = model_class.query.count()
                    if count > self.max_history:
                        excess = count - self.max_history
                        old_records = model_class.query.order_by(model_class.timestamp.asc()).limit(excess).all()
                        for record in old_records:
                            db.session.delete(record)
                        db.session.commit()
                        logger.info(f"Cleaned up {excess} old scan records from {tool_name}")
                else:
                    # Cleanup all tool tables
                    for model_class in TOOL_MODEL_MAPPING.values():
                        count = model_class.query.count()
                        if count > self.max_history:
                            excess = count - self.max_history
                            old_records = model_class.query.order_by(model_class.timestamp.asc()).limit(excess).all()
                            for record in old_records:
                                db.session.delete(record)
                            db.session.commit()
                            logger.info(f"Cleaned up {excess} old scan records from {model_class.__tablename__}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            logger.error(traceback.format_exc())
    
    def get_stats(self, tool_name: str = None) -> Dict[str, Any]:
        """Get statistics about scans (all tools or specific tool)"""
        try:
            with app.app_context():
                if tool_name:
                    # Get stats for specific tool
                    model_class = self._get_model_for_tool(tool_name)
                    total = model_class.query.count()
                    successful = model_class.query.filter_by(success=True).count()
                    failed = model_class.query.filter_by(success=False).count()
                    timed_out = model_class.query.filter_by(timed_out=True).count()
                else:
                    # Get stats for all tools
                    total = 0
                    successful = 0
                    failed = 0
                    timed_out = 0
                    
                    for model_class in TOOL_MODEL_MAPPING.values():
                        total += model_class.query.count()
                        successful += model_class.query.filter_by(success=True).count()
                        failed += model_class.query.filter_by(success=False).count()
                        timed_out += model_class.query.filter_by(timed_out=True).count()
                
                return {
                    "total": total,
                    "successful": successful,
                    "failed": failed,
                    "timed_out": timed_out
                }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            logger.error(traceback.format_exc())
            return {"total": 0, "successful": 0, "failed": 0, "timed_out": 0}


command_history = CommandHistory(max_history=100)  # Keep last 100 scans in database
seed_default_templates()  # Insert built-in scan templates on first run

# Global dictionary to track active scans
active_scans = {}


class CommandExecutor:
    """Class to handle command execution with real-time streaming support"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT, scan_id: str = None, socketio_obj=None):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
        self.scan_id = scan_id or str(uuid.uuid4())
        self.cancelled = False
        self.socketio_obj = socketio_obj
        self.start_time = None
        self.line_count = 0
    
    def _emit_event(self, event_name: str, data: dict):
        """Emit WebSocket event if socketio is available"""
        if self.socketio_obj and SOCKETIO_AVAILABLE:
            try:
                self.socketio_obj.emit(event_name, {**data, "scan_id": self.scan_id}, room=self.scan_id)
            except Exception as e:
                logger.debug(f"Error emitting event {event_name}: {e}")

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
    
    def _read_stdout(self):
        """Thread function to continuously read and stream stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
            self.line_count += 1
            
            # Emit real-time output
            elapsed = time.time() - self.start_time
            eta = self._calculate_eta(self.line_count, elapsed) if self.line_count > 0 else 0
            
            self._emit_event('scan_output', {
                'type': 'stdout',
                'line': line.rstrip('\n'),
                'line_count': self.line_count,
                'elapsed': elapsed,
                'eta': eta
            })
    
    def _read_stderr(self):
        """Thread function to continuously read and stream stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
            self._emit_event('scan_output', {
                'type': 'stderr',
                'line': line.rstrip('\n'),
                'is_error': True
            })
    
    def _calculate_eta(self, lines_so_far: int, elapsed_seconds: float) -> int:
        """Estimate time to completion based on line processing rate"""
        if lines_so_far == 0 or elapsed_seconds == 0:
            return 0
        
        # Estimate based on average lines per second
        avg_line_time = elapsed_seconds / lines_so_far
        # Assume typical scan produces 100-1000 lines (conservative estimate: 500)
        estimated_total_lines = max(lines_so_far + 100, min(lines_so_far * 2, self.timeout * 10))
        remaining_lines = max(0, estimated_total_lines - lines_so_far)
        
        return int(remaining_lines * avg_line_time)
    
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command with real-time streaming and timeout handling"""
        logger.info(f"Executing command: {self.command} [scan_id: {self.scan_id}]")
        
        try:
            self.start_time = time.time()
            
            # Register this scan in active scans
            active_scans[self.scan_id] = self
            
            self._emit_event('scan_started', {'command': self.command})
            
            # Launch in its OWN process group/session so that cancelling or a
            # timeout can kill the whole tree (the shell AND the actual tool such
            # as nmap/sqlmap). Terminating just the shell leaves the tool running.
            popen_kwargs = dict(
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            if os.name == 'posix':
                popen_kwargs['start_new_session'] = True  # setsid -> new process group
            else:
                # Windows: allow sending CTRL_BREAK to the whole group
                popen_kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP

            self.process = subprocess.Popen(self.command, **popen_kwargs)
            
            # Start threads to read and stream output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join(timeout=2)
                self.stderr_thread.join(timeout=2)
                
                if not self.cancelled:
                    self._emit_event('scan_completed', {
                        'status': 'completed',
                        'return_code': self.return_code,
                        'line_count': self.line_count,
                        'elapsed': time.time() - self.start_time
                    })
                
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                self._emit_event('scan_timeout', {
                    'status': 'timeout',
                    'elapsed': time.time() - self.start_time,
                    'line_count': self.line_count
                })
                
                # Terminate the whole process group (shell + tool)
                self.terminate()

                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            result = {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
            
            # Remove from active scans
            if self.scan_id in active_scans:
                del active_scans[self.scan_id]
            
            return result
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Remove from active scans
            if self.scan_id in active_scans:
                del active_scans[self.scan_id]
            
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str, record_history: bool = True, tool_name: str = None, 
                   target: str = None, scan_id: str = None) -> Dict[str, Any]:
    """
    Execute a shell command with real-time streaming support
    
    Args:
        command: The command to execute
        record_history: Whether to record this command in history
        tool_name: Name of the tool being executed (for history)
        target: Target being scanned (for history)
        scan_id: Unique scan ID for WebSocket streaming
        
    Returns:
        A dictionary containing the stdout, stderr, return code, and streaming info
    """
    start_time = time.time()
    executor = CommandExecutor(command, scan_id=scan_id, socketio_obj=socketio if SOCKETIO_AVAILABLE else None)
    result = executor.execute()
    duration = time.time() - start_time
    
    # Record in history if requested
    if record_history:
        command_history.add_command(command, result, duration, tool_name=tool_name, target=target)
    
    # Add scan ID to result
    result['scan_id'] = executor.scan_id
    
    return result


def check_tool_availability(tool_name: str) -> bool:
    """
    Check if a tool is installed and available
    
    Args:
        tool_name: Name of the tool to check
        
    Returns:
        True if tool is available, False otherwise
    """
    try:
        result = execute_command(f"which {tool_name}")
        return result.get("success", False)
    except Exception as e:
        logger.warning(f"Error checking tool {tool_name}: {str(e)}")
        return False


def validate_target(target: str, max_length: int = 255) -> bool:
    """
    Validate target parameter to prevent injection attacks
    
    Args:
        target: Target string (IP, hostname, URL)
        max_length: Maximum allowed length
        
    Returns:
        True if valid, False otherwise
    """
    if not target or len(target) > max_length:
        return False
    
    # Allow alphanumeric, dots, hyphens, slashes, colons, underscores (for URLs and IPs)
    import re
    pattern = r'^[a-zA-Z0-9\.\-/:_\[\]%]+$'
    return bool(re.match(pattern, target))


def validate_command(command: str, max_length: int = 1000) -> bool:
    """
    Validate command string to prevent injection attacks
    
    Args:
        command: Command string to validate
        max_length: Maximum allowed length
        
    Returns:
        True if valid, False otherwise
    """
    if not command or len(command) > max_length:
        return False
    
    # Blacklist dangerous characters/patterns
    dangerous_patterns = [
        r'[`$]|\$\(',  # Command substitution
        r'&&|\|\|',     # Command chaining
        r';\s*rm\s',    # File deletion
    ]
    
    for pattern in dangerous_patterns:
        import re
        if re.search(pattern, command):
            logger.warning(f"Potentially dangerous command detected: {command}")
            return False
    
    return True


# Cache for tool-availability checks (avoids running `which` 10x on every request)
_tool_status_cache = {"data": None, "timestamp": 0.0}
_tool_status_lock = threading.Lock()


def get_all_tools_status(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Get availability status of all Kali tools (cached for TOOL_STATUS_CACHE_TTL seconds).

    Args:
        force_refresh: Bypass the cache and re-check every tool.

    Returns:
        Dictionary with tool status information
    """
    with _tool_status_lock:
        now = time.time()
        cached = _tool_status_cache["data"]
        if (not force_refresh and cached is not None
                and (now - _tool_status_cache["timestamp"]) < TOOL_STATUS_CACHE_TTL):
            return cached

        tools_status = {}
        for tool_cmd, tool_info in KALI_TOOLS.items():
            is_available = check_tool_availability(tool_cmd)
            tools_status[tool_cmd] = {
                "available": is_available,
                "name": tool_info["name"],
                "description": tool_info["description"],
                "category": tool_info["category"]
            }

        _tool_status_cache["data"] = tools_status
        _tool_status_cache["timestamp"] = now
        return tools_status


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        # Validate command for security
        if not validate_command(command):
            logger.warning(f"Invalid or potentially dangerous command rejected: {command}")
            return jsonify({
                "error": "Command contains invalid or dangerous characters/patterns"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Serve the dashboard page."""
    # Use absolute path to find the dashboard file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dashboard_path = os.path.join(current_dir, 'static', 'dashboard.html')
    
    try:
        with open(dashboard_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError as e:
        logger.error(f"Dashboard file not found at {dashboard_path}")
        return f"Dashboard file not found at {dashboard_path}", 404
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        return f"Error loading dashboard: {str(e)}", 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        scan_id = params.get("scan_id", str(uuid.uuid4()))  # Generate scan ID if not provided
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        # Validate target
        if not validate_target(target):
            logger.warning(f"Invalid target for nmap: {target}")
            return jsonify({
                "error": "Invalid target format. Use IP address, hostname, or CIDR notation."
            }), 400        
        
        command = f"nmap {scan_type}"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            # Basic validation for additional args - more sophisticated validation would be better
            command += f" {additional_args}"
        
        command += f" {target}"
        
        result = execute_command(command, tool_name="nmap", target=target, scan_id=scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "")
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        scan_id = params.get("scan_id", str(uuid.uuid4()))
        result = execute_command(command, tool_name="gobuster", target=url, scan_id=scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        scan_id = params.get("scan_id", str(uuid.uuid4()))
        result = execute_command(command, tool_name="dirb", target=url, scan_id=scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        scan_id = params.get("scan_id", str(uuid.uuid4()))
        result = execute_command(command, tool_name="nikto", target=target, scan_id=scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        scan_id = params.get("scan_id", str(uuid.uuid4()))
        result = execute_command(command, tool_name="sqlmap", target=url, scan_id=scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        scan_id = params.get("scan_id", str(uuid.uuid4()))
        result = execute_command(command, tool_name="metasploit", target=module, scan_id=scan_id)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        scan_id = params.get("scan_id", str(uuid.uuid4()))
        result = execute_command(command, tool_name="hydra", target=target, scan_id=scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"john"
        
        if format_type:
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        scan_id = params.get("scan_id", str(uuid.uuid4()))
        result = execute_command(command, tool_name="john", target=hash_file, scan_id=scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        scan_id = params.get("scan_id", str(uuid.uuid4()))
        result = execute_command(command, tool_name="wpscan", target=url, scan_id=scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        scan_id = params.get("scan_id", str(uuid.uuid4()))
        result = execute_command(command, tool_name="enum4linux", target=target, scan_id=scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    tools_status = get_all_tools_status()
    
    # Count available tools
    available_count = sum(1 for tool in tools_status.values() if tool["available"])
    total_count = len(tools_status)
    
    # Convert to simple boolean status for essential tools
    simple_status = {tool: info["available"] for tool, info in tools_status.items()}
    
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": simple_status,
        "available_tools_count": available_count,
        "total_tools_count": total_count,
        "all_essential_tools_available": available_count >= 4
    })


# API Proxy endpoint - for frontend dashboard to access backend tools
@app.route("/api/proxy/<path:endpoint>", methods=["POST", "GET"])
def api_proxy(endpoint):
    """
    Proxy endpoint for frontend dashboard.
    Frontend sends requests to /api/proxy/<endpoint> which forwards to /api/<endpoint>
    This allows the dashboard to call API endpoints through the same server.
    """
    try:
        if request.method == "POST":
            data = request.get_json() if request.is_json else {}
            # Construct the internal route
            if endpoint.startswith("tools/"):
                tool_name = endpoint.replace("tools/", "")
                # Direct function call approach - simpler and more efficient
                if tool_name == "available":
                    return list_available_tools()
                else:
                    # For other tools, route to the tool endpoint
                    return jsonify({"error": f"Tool {tool_name} not found"}), 404
            elif endpoint == "history":
                return get_history()
            elif endpoint.startswith("history/"):
                command_id = endpoint.replace("history/", "")
                return get_history_detail(command_id)
            else:
                return jsonify({"error": f"Endpoint {endpoint} not found"}), 404
        else:  # GET request
            if endpoint == "tools/available":
                return list_available_tools()
            elif endpoint == "history":
                return get_history()
            elif endpoint.startswith("history/"):
                command_id = endpoint.replace("history/", "")
                return get_history_detail(command_id)
            elif endpoint == "health":
                return health_check()
            else:
                return jsonify({"error": f"Endpoint {endpoint} not found"}), 404
    except Exception as e:
        logger.error(f"Error in proxy endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Proxy error: {str(e)}"}), 500


@app.route("/api/tools/available", methods=["GET"])
def list_available_tools():
    """Get list of all available Kali tools with their details."""
    try:
        tools_status = get_all_tools_status()
        
        # Group tools by category
        tools_by_category = {}
        for tool_cmd, tool_info in tools_status.items():
            category = tool_info["category"]
            if category not in tools_by_category:
                tools_by_category[category] = []
            tools_by_category[category].append({
                "command": tool_cmd,
                "name": tool_info["name"],
                "description": tool_info["description"],
                "available": tool_info["available"]
            })
        
        # Count statistics
        available_count = sum(1 for tool in tools_status.values() if tool["available"])
        total_count = len(tools_status)
        
        return jsonify({
            "success": True,
            "total_tools": total_count,
            "available_tools": available_count,
            "unavailable_tools": total_count - available_count,
            "tools_by_category": tools_by_category,
            "all_tools": tools_status
        })
    except Exception as e:
        logger.error(f"Error listing available tools: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/history", methods=["GET"])
def get_history():
    """
    Get command execution history (all tools or specific tool).
    
    Query parameters:
        - limit: Maximum number of records to return (default: 50, max: 500)
        - tool: Filter by specific tool name (nmap, gobuster, dirb, etc.)
    """
    try:
        limit = request.args.get("limit", 50, type=int)
        tool_name = request.args.get("tool", None, type=str)
        
        if limit > 500:
            limit = 500  # Max limit
        
        history = command_history.get_all(limit=limit, tool_name=tool_name)
        stats = command_history.get_stats(tool_name=tool_name)
        
        response_data = {
            "success": True,
            "total_count": stats["total"],
            "returned_count": len(history),
            "stats": stats,
            "history": history
        }
        
        if tool_name:
            response_data["filtered_by_tool"] = tool_name
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error getting history: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/history/stats", methods=["GET"])
def get_history_stats():
    """
    Get statistics about scans (all tools or specific tool).
    
    Query parameters:
        - tool: Optional tool name to get stats for specific tool
    """
    try:
        tool_name = request.args.get("tool", None, type=str)
        
        if tool_name and tool_name.lower() not in TOOL_MODEL_MAPPING:
            return jsonify({
                "error": f"Unknown tool: {tool_name}. Available tools: {', '.join(TOOL_MODEL_MAPPING.keys())}"
            }), 404
        
        stats = command_history.get_stats(tool_name=tool_name)
        return jsonify({
            "success": True,
            "stats": stats
        })
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/history/detail/<command_id>", methods=["GET"])
def get_history_detail(command_id):
    """
    Get detailed information about a specific command from history.
    
    URL parameters:
        - command_id: The UUID of the command
    
    Query parameters:
        - tool: Optional tool name to search in specific table
    """
    try:
        tool_name = request.args.get("tool", None, type=str)
        cmd = command_history.get_by_id(command_id, tool_name=tool_name)
        
        if cmd is None:
            search_info = f" in {tool_name}" if tool_name else ""
            return jsonify({
                "error": f"Command not found in history{search_info}"
            }), 404
        
        return jsonify({
            "success": True,
            "command": cmd
        })
    except Exception as e:
        logger.error(f"Error getting history detail: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/history/<command_id>", methods=["GET"])
def get_history_by_id_or_tool(command_id):
    """
    Get command execution history for a specific tool or by command ID.
    Automatically detects if command_id is a UUID or tool name.
    
    URL parameters:
        - command_id: Either a tool name (nmap, gobuster, etc.) or a UUID
    
    Query parameters:
        - limit: Maximum number of records to return for tool queries (default: 50, max: 500)
    """
    import re
    
    # UUID format: 8-4-4-4-12 hex digits
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    is_uuid = bool(re.match(uuid_pattern, command_id, re.IGNORECASE))
    
    if is_uuid:
        # Handle as UUID (command ID)
        try:
            tool_name = request.args.get("tool", None, type=str)
            cmd = command_history.get_by_id(command_id, tool_name=tool_name)
            
            if cmd is None:
                search_info = f" in {tool_name}" if tool_name else ""
                return jsonify({
                    "error": f"Command not found in history{search_info}"
                }), 404
            
            return jsonify({
                "success": True,
                "command": cmd
            })
        except Exception as e:
            logger.error(f"Error getting history detail: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": f"Server error: {str(e)}"
            }), 500
    else:
        # Handle as tool name
        try:
            tool_name = command_id
            
            # Validate tool name
            if tool_name.lower() not in TOOL_MODEL_MAPPING:
                return jsonify({
                    "error": f"Unknown tool: {tool_name}. Available tools: {', '.join(TOOL_MODEL_MAPPING.keys())}"
                }), 404
            
            limit = request.args.get("limit", 50, type=int)
            if limit > 500:
                limit = 500
            
            history = command_history.get_all(limit=limit, tool_name=tool_name)
            stats = command_history.get_stats(tool_name=tool_name)
            
            return jsonify({
                "success": True,
                "tool": tool_name,
                "total_count": stats["total"],
                "returned_count": len(history),
                "stats": stats,
                "history": history
            })
        except Exception as e:
            logger.error(f"Error getting history for {command_id}: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": f"Server error: {str(e)}"
            }), 500


@app.route("/api/history/id/<command_id>", methods=["GET"])
def get_history_detail_legacy(command_id):
    """
    Legacy endpoint for backward compatibility.
    Use /api/history/<command_id> or /api/history/detail/<command_id> instead.
    """
    return get_history_by_id_or_tool(command_id)


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    """
    Clear command history (all tools or specific tool).
    
    Query parameters:
        - tool: Optional tool name to clear only that tool's history. If not specified, clears all.
    """
    try:
        tool_name = request.args.get("tool", None, type=str)
        
        if tool_name and tool_name.lower() not in TOOL_MODEL_MAPPING:
            return jsonify({
                "error": f"Unknown tool: {tool_name}. Available tools: {', '.join(TOOL_MODEL_MAPPING.keys())}"
            }), 404
        
        command_history.clear(tool_name=tool_name)
        
        message = f"History cleared for {tool_name}" if tool_name else "All history cleared"
        return jsonify({
            "success": True,
            "message": message
        })
    except Exception as e:
        logger.error(f"Error clearing history: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# ============================================================================
# Scan Template Endpoints (CRUD)
# ============================================================================

VALID_TOOLS = set(TOOL_MODEL_MAPPING.keys())


@app.route("/api/templates", methods=["GET"])
def list_templates():
    """List all scan templates (built-in first, then user templates)."""
    try:
        templates = ScanTemplate.query.order_by(
            ScanTemplate.builtin.desc(), ScanTemplate.created_at.asc()
        ).all()
        return jsonify({"success": True, "count": len(templates),
                        "templates": [t.to_dict() for t in templates]})
    except Exception as e:
        logger.error(f"Error listing templates: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/templates", methods=["POST"])
def create_template():
    """Create a new user scan template."""
    try:
        data = request.get_json() or {}
        name = (data.get("name") or "").strip()
        tool = (data.get("tool") or "").strip().lower()

        if not name:
            return jsonify({"error": "Template name is required"}), 400
        if tool not in VALID_TOOLS:
            return jsonify({"error": f"Invalid tool. Must be one of: {', '.join(sorted(VALID_TOOLS))}"}), 400

        template = ScanTemplate(
            id=str(uuid.uuid4()),
            name=name[:120],
            tool=tool,
            target=(data.get("target") or "").strip()[:255] or None,
            params=(data.get("params") or "").strip()[:1000] or None,
            wordlist=(data.get("wordlist") or "").strip()[:500] or None,
            description=(data.get("description") or "").strip()[:500] or None,
            builtin=False,
        )
        db.session.add(template)
        db.session.commit()
        logger.info(f"Created scan template: {name} ({tool})")
        return jsonify({"success": True, "template": template.to_dict()}), 201
    except Exception as e:
        logger.error(f"Error creating template: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/templates/<template_id>", methods=["GET"])
def get_template(template_id):
    """Get a single template by ID."""
    try:
        template = ScanTemplate.query.filter_by(id=template_id).first()
        if not template:
            return jsonify({"error": "Template not found"}), 404
        return jsonify({"success": True, "template": template.to_dict()})
    except Exception as e:
        logger.error(f"Error getting template: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/templates/<template_id>", methods=["PUT"])
def update_template(template_id):
    """Update a user template (built-in templates cannot be edited)."""
    try:
        template = ScanTemplate.query.filter_by(id=template_id).first()
        if not template:
            return jsonify({"error": "Template not found"}), 404
        if template.builtin:
            return jsonify({"error": "Built-in templates cannot be edited"}), 403

        data = request.get_json() or {}
        if "name" in data:
            name = (data.get("name") or "").strip()
            if not name:
                return jsonify({"error": "Template name cannot be empty"}), 400
            template.name = name[:120]
        if "tool" in data:
            tool = (data.get("tool") or "").strip().lower()
            if tool not in VALID_TOOLS:
                return jsonify({"error": "Invalid tool"}), 400
            template.tool = tool
        if "target" in data:
            template.target = (data.get("target") or "").strip()[:255] or None
        if "params" in data:
            template.params = (data.get("params") or "").strip()[:1000] or None
        if "wordlist" in data:
            template.wordlist = (data.get("wordlist") or "").strip()[:500] or None
        if "description" in data:
            template.description = (data.get("description") or "").strip()[:500] or None

        db.session.commit()
        return jsonify({"success": True, "template": template.to_dict()})
    except Exception as e:
        logger.error(f"Error updating template: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/templates/<template_id>", methods=["DELETE"])
def delete_template(template_id):
    """Delete a template (built-in templates cannot be deleted)."""
    try:
        template = ScanTemplate.query.filter_by(id=template_id).first()
        if not template:
            return jsonify({"error": "Template not found"}), 404
        if template.builtin:
            return jsonify({"error": "Built-in templates cannot be deleted"}), 403

        db.session.delete(template)
        db.session.commit()
        logger.info(f"Deleted scan template: {template.name}")
        return jsonify({"success": True, "message": "Template deleted"})
    except Exception as e:
        logger.error(f"Error deleting template: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# PDF Report Generation
# ============================================================================

BRAND = colors.HexColor("#0891b2") if REPORTLAB_AVAILABLE else None
BRAND_DARK = colors.HexColor("#16233f") if REPORTLAB_AVAILABLE else None


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


def _meta_table(rows, styles):
    data = [[Paragraph(f"<b>{k}</b>", styles['BodyText']), Paragraph(str(v), styles['BodyText'])]
            for k, v in rows]
    t = Table(data, colWidths=[38 * mm, 130 * mm])
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


MAX_PDF_OUTPUT_CHARS = 40000  # keep report size sane for huge scan outputs


SEV_COLORS = {
    "high": "#ef4444", "medium": "#f59e0b", "low": "#22c55e", "info": "#0891b2",
} if REPORTLAB_AVAILABLE else {}
SEV_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def _findings_section(story, styles, findings_data):
    """Append parsed findings (ports table + findings list) to the PDF story."""
    if not findings_data or not findings_data.get("supported"):
        return
    s = findings_data.get("summary", {})

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
        data = [[Paragraph(f"<b>{h}</b>", styles['BodyText']) for h in
                 ("Port", "Service", "Version", "Risk")]]
        for p in ports:
            data.append([
                Paragraph(f"{p['port']}/{p['proto']}", styles['BodyText']),
                Paragraph(p.get("service", ""), styles['BodyText']),
                Paragraph(p.get("version", "") or "-", styles['BodyText']),
                Paragraph(f"<b>{SEV_LABEL.get(p['risk'], p['risk']).upper()}</b>", styles['BodyText']),
            ])
        t = Table(data, colWidths=[22 * mm, 30 * mm, 86 * mm, 24 * mm], repeatRows=1)
        style = [
            ('BACKGROUND', (0, 0), (-1, 0), BRAND_DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#dbe2ee")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4), ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]
        for i, p in enumerate(ports, start=1):
            style.append(('TEXTCOLOR', (3, i), (3, i), colors.HexColor(SEV_COLORS.get(p['risk'], "#333333"))))
        t.setStyle(TableStyle(style))
        story.append(t)

    flist = findings_data.get("findings", [])
    if flist:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Highlighted Findings", styles['KSection']))
        # sort by severity
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        for f in sorted(flist, key=lambda x: order.get(x.get("severity"), 9)):
            sev = f.get("severity", "info")
            color = SEV_COLORS.get(sev, "#333333")
            title = f.get("title", "")
            detail = f.get("detail", "")
            html = (f'<font color="{color}"><b>[{SEV_LABEL.get(sev, sev).upper()}]</b></font> '
                    f'<b>{title}</b>')
            if detail:
                html += f'<br/><font size="8" color="#55627d">{detail}</font>'
            story.append(Paragraph(html, styles['BodyText']))
            story.append(Spacer(1, 5))


def build_scan_pdf(cmd: Dict[str, Any], findings_data: Dict[str, Any] = None) -> bytes:
    """Build a one-scan PDF report and return the bytes."""
    buf = _io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=22 * mm, bottomMargin=18 * mm,
                            leftMargin=18 * mm, rightMargin=18 * mm)
    styles = _report_styles()
    story = []

    tool = (cmd.get("command") or "").strip().split(" ")[0] or "scan"
    status = "SUCCESS" if cmd.get("success") else "FAILED"
    story.append(Paragraph(f"{tool.capitalize()} Scan Report", styles['KTitle']))
    story.append(Paragraph(f"Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
                           styles['KSub']))

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

    # Parsed findings (if available)
    _findings_section(story, styles, findings_data)

    stdout = cmd.get("stdout") or ""
    stderr = cmd.get("stderr") or ""

    if stdout:
        story.append(Paragraph("Output (stdout)", styles['KSection']))
        text = stdout[:MAX_PDF_OUTPUT_CHARS]
        if len(stdout) > MAX_PDF_OUTPUT_CHARS:
            text += "\n\n... [output truncated] ..."
        story.append(Preformatted(text, styles['KMono']))

    if stderr:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Errors (stderr)", styles['KSection']))
        text = stderr[:MAX_PDF_OUTPUT_CHARS // 2]
        if len(stderr) > MAX_PDF_OUTPUT_CHARS // 2:
            text += "\n\n... [truncated] ..."
        story.append(Preformatted(text, styles['KMono']))

    if not stdout and not stderr:
        story.append(Paragraph("No output was captured for this scan.", styles['BodyText']))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()


def build_summary_pdf(history: List[Dict[str, Any]], stats: Dict[str, Any]) -> bytes:
    """Build a summary PDF of recent scans."""
    buf = _io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=22 * mm, bottomMargin=18 * mm,
                            leftMargin=18 * mm, rightMargin=18 * mm)
    styles = _report_styles()
    story = [Paragraph("Scan Activity Summary", styles['KTitle']),
             Paragraph(f"Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
                       styles['KSub'])]

    story.append(Paragraph("Statistics", styles['KSection']))
    story.append(_meta_table([
        ("Total scans", stats.get("total", 0)),
        ("Successful", stats.get("successful", 0)),
        ("Failed", stats.get("failed", 0)),
        ("Timed out", stats.get("timed_out", 0)),
    ], styles))

    story.append(Paragraph("Recent Scans", styles['KSection']))
    header = [Paragraph(f"<b>{h}</b>", styles['BodyText']) for h in
              ("Tool", "Target", "Status", "Duration", "Time")]
    data = [header]
    for c in history:
        tool = (c.get("command") or "").split(" ")[0]
        data.append([
            Paragraph(tool, styles['BodyText']),
            Paragraph(str(c.get("target") or "-")[:40], styles['BodyText']),
            Paragraph("OK" if c.get("success") else "FAIL", styles['BodyText']),
            Paragraph(f"{c.get('duration', 0):.1f}s", styles['BodyText']),
            Paragraph((c.get("timestamp") or "")[:19].replace("T", " "), styles['BodyText']),
        ])
    t = Table(data, colWidths=[24 * mm, 55 * mm, 18 * mm, 20 * mm, 41 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BRAND_DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#dbe2ee")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f9fd")]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()


def _safe_filename(name: str) -> str:
    import re as _re
    return _re.sub(r'[^A-Za-z0-9._-]', '_', name)[:60]


@app.route("/api/history/<command_id>/findings", methods=["GET"])
def scan_findings(command_id):
    """Return structured, risk-rated findings parsed from a scan's raw output."""
    try:
        tool_name = request.args.get("tool", None, type=str)
        cmd = command_history.get_by_id(command_id, tool_name=tool_name)
        if cmd is None:
            return jsonify({"error": "Scan not found in history"}), 404

        result = findings_parser.parse_findings(
            tool_name=(cmd.get("command") or "").split(" ")[0],
            command=cmd.get("command") or "",
            stdout=cmd.get("stdout") or "",
            stderr=cmd.get("stderr") or "",
        )
        result["success"] = True
        result["scan_id"] = command_id
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error parsing findings: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Findings error: {str(e)}"}), 500


@app.route("/api/history/<command_id>/report", methods=["GET"])
def scan_report(command_id):
    """Download a PDF report for a single scan."""
    if not REPORTLAB_AVAILABLE:
        return jsonify({"error": "PDF support not installed. Run: pip install reportlab"}), 503
    try:
        tool_name = request.args.get("tool", None, type=str)
        cmd = command_history.get_by_id(command_id, tool_name=tool_name)
        if cmd is None:
            return jsonify({"error": "Scan not found in history"}), 404

        # Parse findings to enrich the report
        try:
            findings_data = findings_parser.parse_findings(
                tool_name=(cmd.get("command") or "").split(" ")[0],
                command=cmd.get("command") or "",
                stdout=cmd.get("stdout") or "", stderr=cmd.get("stderr") or "")
        except Exception:
            findings_data = None

        pdf_bytes = build_scan_pdf(cmd, findings_data=findings_data)
        tool = (cmd.get("command") or "scan").split(" ")[0]
        fname = _safe_filename(f"kali_report_{tool}_{command_id[:8]}.pdf")
        return send_file(_io.BytesIO(pdf_bytes), mimetype="application/pdf",
                         as_attachment=True, download_name=fname)
    except Exception as e:
        logger.error(f"Error generating scan report: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Report error: {str(e)}"}), 500


@app.route("/api/report/summary", methods=["GET"])
def summary_report():
    """Download a PDF summary report of recent scans."""
    if not REPORTLAB_AVAILABLE:
        return jsonify({"error": "PDF support not installed. Run: pip install reportlab"}), 503
    try:
        limit = request.args.get("limit", 50, type=int)
        limit = min(limit, 200)
        history = command_history.get_all(limit=limit)
        stats = command_history.get_stats()
        if not history:
            return jsonify({"error": "No scans to report yet"}), 404

        pdf_bytes = build_summary_pdf(history, stats)
        fname = _safe_filename(f"kali_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf")
        return send_file(_io.BytesIO(pdf_bytes), mimetype="application/pdf",
                         as_attachment=True, download_name=fname)
    except Exception as e:
        logger.error(f"Error generating summary report: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Report error: {str(e)}"}), 500


# ============================================================================
# WebSocket Event Handlers - Real-Time Scan Streaming
# ============================================================================

if SOCKETIO_AVAILABLE:
    @socketio.on('connect')
    def handle_connect():
        """Handle WebSocket connection"""
        logger.info(f"Client connected: {request.sid}")
        emit('connected', {'message': 'Connected to Kali scan server'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle WebSocket disconnection"""
        logger.info(f"Client disconnected: {request.sid}")
    
    @socketio.on('join_scan')
    def handle_join_scan(data):
        """Join a specific scan room"""
        scan_id = data.get('scan_id')
        if scan_id:
            join_room(scan_id)
            logger.debug(f"Client {request.sid} joined scan room: {scan_id}")
            emit('room_joined', {'scan_id': scan_id})
    
    @socketio.on('leave_scan')
    def handle_leave_scan(data):
        """Leave a specific scan room"""
        scan_id = data.get('scan_id')
        if scan_id:
            leave_room(scan_id)
            logger.debug(f"Client {request.sid} left scan room: {scan_id}")
    
    @socketio.on('cancel_scan')
    def handle_cancel_scan(data):
        """Cancel an active scan"""
        scan_id = data.get('scan_id')
        if scan_id and scan_id in active_scans:
            executor = active_scans[scan_id]
            try:
                logger.info(f"Cancelling scan {scan_id}")
                executor.terminate()
                emit('scan_cancelled', {'scan_id': scan_id, 'message': 'Scan cancelled by user'}, room=scan_id)
            except Exception as e:
                logger.error(f"Error cancelling scan: {e}")
                emit('cancel_error', {'scan_id': scan_id, 'error': str(e)}, room=scan_id)


@app.route("/api/scans/cancel/<scan_id>", methods=["POST"])
def cancel_scan(scan_id):
    """REST endpoint to cancel a scan"""
    if scan_id in active_scans:
        executor = active_scans[scan_id]
        try:
            logger.info(f"Cancelling scan {scan_id}")
            executor.terminate()

            if SOCKETIO_AVAILABLE and socketio:
                socketio.emit('scan_cancelled', {'scan_id': scan_id, 'message': 'Scan cancelled by user'}, room=scan_id)

            return jsonify({'success': True, 'message': f'Scan {scan_id} cancelled'})
        except Exception as e:
            logger.error(f"Error cancelling scan: {e}")
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': f'Scan {scan_id} not found'}), 404


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    
    # Get default IP from environment variable
    default_ip = os.environ.get("API_IP", "127.0.0.1")
    parser.add_argument("--ip", type=str, default=default_ip, help=f"IP address to bind the server to (default: {default_ip}). Use 0.0.0.0 for network access")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    logger.info(f"Starting Kali Linux Tools API Server on {args.ip}:{API_PORT}")
    
    if SOCKETIO_AVAILABLE and socketio:
        # Run with SocketIO for real-time streaming
        socketio.run(app, host=args.ip, port=API_PORT, debug=DEBUG_MODE, allow_unsafe_werkzeug=True)
    else:
        # Fallback to regular Flask
        app.run(host=args.ip, port=API_PORT, debug=DEBUG_MODE)
