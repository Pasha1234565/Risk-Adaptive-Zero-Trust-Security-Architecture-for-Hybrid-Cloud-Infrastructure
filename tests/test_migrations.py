"""Schema migration safety (Phase 2.1).

A database created before Phase 2.1 has no events.actor_user_id column and no
totp_counters / mfa_attempts tables. init_db() must add them without touching
existing rows, and must be safe to run repeatedly.
"""

from __future__ import annotations

import re
import sqlite3

from app import config, database


def _legacy_schema() -> str:
    legacy = re.sub(
        r",\s*--[^\n]*\n\s*--[^\n]*\n\s*actor_user_id\s+INTEGER REFERENCES users\(id\)",
        "",
        database.SCHEMA,
    )
    legacy = re.sub(r"-- TOTP replay protection.*", "", legacy, flags=re.S)
    assert "actor_user_id" not in legacy and "totp_counters" not in legacy
    return legacy


def test_init_db_migrates_a_pre_phase_2_1_database(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(db_path)
    legacy.executescript(_legacy_schema())
    legacy.execute(
        "INSERT INTO users (email, name, role, password_hash, created_at) "
        "VALUES ('old@example.test', 'Old', 'analyst', 'x', '2026-01-01T00:00:00+00:00')"
    )
    legacy.execute(
        "INSERT INTO events (ts, user_id, decision, risk_score) VALUES ('2026-01-01T00:00:00+00:00', 1, 'ALLOW', 5.0)"
    )
    legacy.commit()
    legacy.close()

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", db_path)

    applied = database.init_db()
    again = database.init_db()

    assert applied == ["events.actor_user_id"]
    assert again == []
    with database.get_db() as conn:
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(events)")]
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        event = database.row(conn, "SELECT user_id, decision, risk_score, actor_user_id FROM events")
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    assert columns[-1] == "actor_user_id"
    assert {"totp_counters", "mfa_attempts", "revoked_sessions"} <= tables
    assert event == {"user_id": 1, "decision": "ALLOW", "risk_score": 5.0, "actor_user_id": None}
    assert users == 1
    assert integrity == "ok"


def test_fresh_database_needs_no_migration(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "fresh.db")
    assert database.init_db() == []
