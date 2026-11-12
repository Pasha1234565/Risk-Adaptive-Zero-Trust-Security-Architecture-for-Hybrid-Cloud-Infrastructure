"""Regression tests for running the suite (Phase 2).

* Bug 6: ``python -m pytest`` puts the current directory on ``sys.path``; the
  ``pytest`` console script does not. ``python -P`` reproduces the
  console-script behaviour, so these tests fail if the project root is not
  configured through ``pytest.ini``.
* Test isolation: engine-level tests must not depend on another test module
  having started the application first.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run_pytest_without_cwd_on_path(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-P", "-m", "pytest", "-q", "-p", "no:cacheprovider", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_bare_pytest_can_import_app_package():
    completed = _run_pytest_without_cwd_on_path("--collect-only", "tests/test_risk.py")
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "ModuleNotFoundError" not in output
    assert "5 tests collected" in output


def test_engine_tests_pass_when_run_in_isolation():
    completed = _run_pytest_without_cwd_on_path("tests/test_risk.py")
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "5 passed" in output
