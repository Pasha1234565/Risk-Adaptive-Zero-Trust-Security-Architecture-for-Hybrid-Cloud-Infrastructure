"""Concurrent start-up on a new database file (final validation).

During final regression runs the two-worker test failed once in eight full
runs: a uvicorn worker exited during start-up with
``sqlite3.OperationalError: database is locked`` raised by
``PRAGMA journal_mode=WAL`` in ``database.get_db``. A stress run reproduced it
(6 failures in 60 processes opening one new file together; 2 in 100 on the
pre-fix code in a clean clone). SQLite can refuse the switch to WAL
immediately, without waiting for the busy timeout, while other processes are
opening the same new file. The switch is now retried with a short back-off,
and skipped once the file is already in WAL mode.
"""

from __future__ import annotations

import multiprocessing
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from app import database


class FakeConnection:
    """Answers PRAGMA journal_mode like SQLite, failing the first ``failures`` calls."""

    def __init__(self, failures: int, message: str = "database is locked", mode: str = "delete"):
        self.failures, self.message, self.mode, self.calls = failures, message, mode, []

    def execute(self, sql: str):
        self.calls.append(sql)
        if self.failures:
            self.failures -= 1
            raise sqlite3.OperationalError(self.message)
        if sql.endswith("=WAL"):
            self.mode = "wal"
        return self

    def fetchone(self):
        return (self.mode,)


def test_wal_switch_is_retried_while_the_file_is_locked(monkeypatch):
    monkeypatch.setattr(database.time, "sleep", lambda _: None)
    conn = FakeConnection(failures=3)
    database._enable_wal(conn)
    assert conn.mode == "wal"
    assert conn.calls.count("PRAGMA journal_mode=WAL") == 1


def test_wal_switch_is_skipped_when_already_enabled():
    conn = FakeConnection(failures=0, mode="wal")
    database._enable_wal(conn)
    assert conn.calls == ["PRAGMA journal_mode"]


def test_other_errors_are_not_retried(monkeypatch):
    monkeypatch.setattr(database.time, "sleep", lambda _: None)
    conn = FakeConnection(failures=5, message="disk I/O error")
    with pytest.raises(sqlite3.OperationalError, match="disk I/O"):
        database._enable_wal(conn)
    assert len(conn.calls) == 1


def test_retrying_stops_at_the_deadline(monkeypatch):
    monkeypatch.setattr(database, "WAL_RETRY_SECONDS", 0.0)
    conn = FakeConnection(failures=1000)
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        database._enable_wal(conn)


def _open_new_database(path: str, start: float, results) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from app import config
    from app import database as db

    # The child re-imports this module (and app.config) with the parent's
    # environment, so point the configuration at this round's file directly.
    config.DB_PATH = Path(path)
    config.DATA_DIR = Path(path).parent
    while time.time() < start:
        pass
    try:
        db.init_db()
        results.put("ok")
    except Exception as exc:  # noqa: BLE001 - reported to the parent
        results.put(repr(exc))


def test_processes_opening_a_new_database_together_all_succeed(tmp_path):
    """Statistical check: the pre-fix code failed about 2-10 % of these starts."""
    context = multiprocessing.get_context("spawn")
    outcomes = []
    for round_number in range(6):
        path = str(tmp_path / f"round-{round_number}.db")
        results = context.Queue()
        start = time.time() + 1.5
        processes = [context.Process(target=_open_new_database, args=(path, start, results)) for _ in range(4)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=60)
        outcomes += [results.get(timeout=10) for _ in processes]
        with sqlite3.connect(path) as conn:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert outcomes == ["ok"] * len(outcomes)
