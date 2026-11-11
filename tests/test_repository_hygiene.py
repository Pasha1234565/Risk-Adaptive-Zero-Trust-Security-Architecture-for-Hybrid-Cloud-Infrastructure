"""Repository hygiene: secrets and runtime files stay out of Git (Phase 2, bug 7).

Before the fix, ``.env`` files were not ignored. These tests ask Git itself
(``git check-ignore``) so they reflect the real ignore rules; they are skipped
when Git or the repository metadata is unavailable (for example in an sdist).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / ".git").exists(),
    reason="requires a Git checkout",
)


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=60
    )


def _ignored(path: str) -> bool:
    # --no-index: evaluate the rules even for paths that are not on disk.
    result = _git("check-ignore", "-q", "--no-index", path)
    assert result.returncode in (0, 1), result.stderr
    return result.returncode == 0


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".env.local",
        ".env.production",
        "app/.env",
        "deploy/staging.env",
        ".venv/pyvenv.cfg",
        "data/zerotrust.db",
        "data/behaviour_model.joblib",
        "data/signing.key",
        ".secret_key",
    ],
)
def test_secret_and_runtime_files_are_ignored(path):
    assert _ignored(path), path


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        "app/main.py",
        "app/config.py",
        "app/security.py",
        "app/static/js/api-docs.js",
        "app/static/vendor/swagger-ui/swagger-ui-bundle.js",
        "app/templates/api_docs.html",
        "tests/conftest.py",
        "requirements.txt",
        "pytest.ini",
        "README.md",
    ],
)
def test_source_files_and_env_template_are_not_ignored(path):
    assert not _ignored(path), path


def test_no_tracked_file_matches_an_ignore_rule():
    result = _git("ls-files", "--cached", "--ignored", "--exclude-standard")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ""


def test_no_runtime_secret_or_database_is_tracked():
    result = _git("ls-files")
    assert result.returncode == 0, result.stderr
    risky_suffixes = (".db", ".sqlite", ".sqlite3", ".joblib", ".key", ".pem", ".env")
    tracked = [line for line in result.stdout.splitlines() if line]
    offenders = [
        name for name in tracked
        if name.lower().endswith(risky_suffixes)
        or name.startswith("data/")
        or Path(name).name.startswith(".env") and Path(name).name != ".env.example"
    ]
    assert offenders == []
