"""
Shared pytest fixtures.

kali_server is imported once with a throwaway SQLite file and the security
env vars cleared. No Kali tool is ever run: `fake_exec` replaces
CommandExecutor.execute so a tool endpoint builds the real command, records
it in history and returns the canned output instead.
"""
import logging
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "src" / "backend"
sys.path.insert(0, str(BACKEND))

# Must happen before kali_server is imported (it reads them at import time)
os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(prefix="kalimcp-pytest-"), "test.db")
for _var in ("KALI_ENABLE_COMMAND", "CORS_ORIGINS", "SECRET_KEY"):
    os.environ.pop(_var, None)

logging.disable(logging.CRITICAL)

import kali_server  # noqa: E402


@pytest.fixture(scope="session")
def server():
    return kali_server


@pytest.fixture()
def client():
    return kali_server.app.test_client()


@pytest.fixture(autouse=True)
def _no_tool_checks(monkeypatch):
    """/health and /api/tools/available must not shell out to `which`."""
    status = {name: {"available": True, "path": f"/usr/bin/{name}"}
              for name in ("nmap", "gobuster", "dirb", "nikto", "sqlmap")}
    monkeypatch.setattr(kali_server, "get_all_tools_status",
                        lambda force_refresh=False: status)


@pytest.fixture()
def fake_exec(monkeypatch):
    """Replace process execution. Set `fake_exec.stdout` before the request;
    every executed command is appended to `fake_exec.commands`."""

    class Fake:
        stdout = ""
        return_code = 0
        commands = []

    fake = Fake()
    fake.commands = []

    def execute(self):
        fake.commands.append(self.command)
        self.start_time = kali_server.time.time()
        self.status = "running"
        for line in fake.stdout.splitlines():
            self._buffer_line("stdout", line)
        self.stdout_data = fake.stdout
        self.return_code = fake.return_code
        self.final_status = "completed" if fake.return_code == 0 else "failed"
        return {"stdout": fake.stdout, "stderr": "", "return_code": fake.return_code,
                "success": fake.return_code == 0, "timed_out": False,
                "partial_results": False}

    monkeypatch.setattr(kali_server.CommandExecutor, "execute", execute)
    return fake
