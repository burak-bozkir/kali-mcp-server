"""
Run the older plain-script tests in src/tests (security defaults, shell
quoting, recon logic, DB schema...) so CI covers them too. Each script prints
its own PASS/FAIL lines and exits non-zero on failure.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "src" / "tests"
SCRIPTS = ["quick_test.py", "test_db_schema.py", "test_recon.py",
           "test_shell_quoting.py", "test_findings_parsers.py", "test_security.py",
           "test_system.py"]


@pytest.mark.parametrize("script", SCRIPTS)
def test_script(script, tmp_path):
    env = dict(os.environ, PYTHONIOENCODING="utf-8",
               DATABASE_PATH=str(tmp_path / "script.db"))
    proc = subprocess.run([sys.executable, str(SCRIPTS_DIR / script)],
                          cwd=tmp_path, env=env, capture_output=True,
                          text=True, encoding="utf-8", timeout=300)
    assert proc.returncode == 0, f"{script} failed:\n{proc.stdout[-4000:]}\n{proc.stderr[-4000:]}"
