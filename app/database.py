"""SQLite persistence layer.

The prototype intentionally uses the Python standard library's sqlite3 module:
no external database is required to reproduce the experiments locally. A new
connection is opened per request (connections are cheap and thread-safe this
way) with WAL mode enabled for concurrent readers.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL,
    department    TEXT NOT NULL DEFAULT 'General',
    password_hash TEXT NOT NULL,
    mfa_enabled   INTEGER NOT NULL DEFAULT 1,
    mfa_secret    TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active',
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'laptop',
    os          TEXT NOT NULL DEFAULT 'Linux',
    managed     INTEGER NOT NULL DEFAULT 1,
    compliant   INTEGER NOT NULL DEFAULT 1,
    trust_score REAL NOT NULL DEFAULT 80,
    fingerprint TEXT NOT NULL DEFAULT '',
    last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    zone        TEXT NOT NULL CHECK (zone IN ('private', 'public')),
    service     TEXT NOT NULL,
    category    TEXT NOT NULL,
    sensitivity TEXT NOT NULL CHECK (sensitivity IN ('low', 'medium', 'high', 'critical')),
    owner       TEXT NOT NULL DEFAULT 'Platform',
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS policies (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT NOT NULL,
    description          TEXT NOT NULL DEFAULT '',
    resource_category    TEXT NOT NULL DEFAULT '*',
    required_device_trust REAL NOT NULL DEFAULT 40,
    mfa_required         INTEGER NOT NULL DEFAULT 1,
    allowed_roles        TEXT NOT NULL DEFAULT '',
    effect               TEXT NOT NULL DEFAULT 'enforce',
    enabled              INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    user_id        INTEGER REFERENCES users(id),
    device_id      INTEGER REFERENCES devices(id),
    resource_id    INTEGER REFERENCES resources(id),
    action         TEXT NOT NULL DEFAULT 'access',
    decision       TEXT NOT NULL,
    risk_score     REAL NOT NULL,
    anomaly_score  REAL NOT NULL DEFAULT 0,
    base_risk      REAL NOT NULL DEFAULT 0,
    signals        TEXT NOT NULL DEFAULT '{}',
    reasons        TEXT NOT NULL DEFAULT '[]',
    context        TEXT NOT NULL DEFAULT '{}',
    source_ip      TEXT NOT NULL DEFAULT '',
    geo            TEXT NOT NULL DEFAULT '',
    latency_ms     REAL NOT NULL DEFAULT 0,
    ground_truth   INTEGER NOT NULL DEFAULT 0,
    scenario       TEXT NOT NULL DEFAULT 'live',
    outcome        TEXT NOT NULL DEFAULT 'evaluated',
    -- Signed-in user who initiated the evaluation (NULL for system-generated
    -- traffic and for events recorded before this column existed).
    actor_user_id  INTEGER REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    severity TEXT NOT NULL,
    title    TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '',
    event_id INTEGER REFERENCES events(id),
    status   TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS eval_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    name        TEXT NOT NULL,
    samples     INTEGER NOT NULL,
    metrics     TEXT NOT NULL,
    config      TEXT NOT NULL DEFAULT '{}',
    duration_ms REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    email   TEXT NOT NULL,
    ts      TEXT NOT NULL,
    success INTEGER NOT NULL,
    source_ip TEXT NOT NULL DEFAULT ''
);

-- Server-side session revocation, keyed by the token's jti claim. A row only
-- needs to live until the token itself expires (expires_at, Unix seconds).
CREATE TABLE IF NOT EXISTS revoked_sessions (
    jti        TEXT PRIMARY KEY,
    user_id    INTEGER,
    revoked_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_sessions_expires ON revoked_sessions(expires_at);

-- TOTP replay protection: the last accepted 30-second time step per user. Only
-- the counter is stored, never a code.
CREATE TABLE IF NOT EXISTS totp_counters (
    user_id      INTEGER PRIMARY KEY REFERENCES users(id),
    last_counter INTEGER NOT NULL,
    updated_at   TEXT NOT NULL
);

-- Step-up MFA verification outcomes per identity, used for throttling and
-- audit. user_id is the identity whose code was checked; actor_user_id is the
-- signed-in user who submitted it (when known). Codes are never stored.
CREATE TABLE IF NOT EXISTS mfa_attempts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    actor_user_id INTEGER REFERENCES users(id),
    ts            TEXT NOT NULL,
    success       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mfa_attempts_user_ts ON mfa_attempts(user_id, ts);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Additive column migrations for databases created before a column existed.
# Each entry is applied only when the column is missing; existing rows keep
# their data and get NULL in the new column.
COLUMN_MIGRATIONS = [
    ("events", "actor_user_id", "INTEGER REFERENCES users(id)"),
]


def _migrate_columns(conn: sqlite3.Connection) -> list[str]:
    applied = []
    for table, column, ddl in COLUMN_MIGRATIONS:
        present = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in present:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            applied.append(f"{table}.{column}")
    return applied


def init_db() -> list[str]:
    """Create missing tables and apply additive migrations; returns the
    migrations applied (empty when the schema was already current)."""
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.executescript(SCHEMA)
        return _migrate_columns(conn)


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def rows(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def row(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> dict | None:
    found = conn.execute(sql, params).fetchone()
    return dict(found) if found else None


def get_setting(key: str, default: Any = None) -> Any:
    with get_db() as conn:
        found = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if not found:
        return default
    try:
        return json.loads(found["value"])
    except (TypeError, json.JSONDecodeError):
        return found["value"]


def set_setting(key: str, value: Any) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )


def engine_config() -> dict:
    """Thresholds and weights currently in force (DB overrides defaults)."""
    thresholds = get_setting("thresholds", config.DEFAULT_THRESHOLDS)
    weights = get_setting("weights", config.DEFAULT_WEIGHTS)
    clean_thresholds = {
        key: float(thresholds.get(key, value)) for key, value in config.DEFAULT_THRESHOLDS.items()
    }
    clean_weights = {
        key: float(weights.get(key, value)) for key, value in config.DEFAULT_WEIGHTS.items()
    }
    total = sum(clean_weights.values()) or 1.0
    # Keep the weighted score on a 0-100 scale.
    clean_weights = {k: round(v * 100.0 / total, 2) for k, v in clean_weights.items()}
    return {"thresholds": clean_thresholds, "weights": clean_weights}


def revoke_session(jti: str, user_id: int | None, expires_at: int) -> None:
    """Record a session id as revoked until its token expiry (idempotent)."""
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_sessions (jti, user_id, revoked_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (jti, user_id, utcnow(), int(expires_at)),
        )


def is_session_revoked(jti: str) -> bool:
    with get_db() as conn:
        found = conn.execute(
            "SELECT 1 FROM revoked_sessions WHERE jti = ?", (jti,)
        ).fetchone()
    return found is not None


def purge_expired_revocations(now: int | None = None) -> int:
    """Delete revocation rows whose tokens have expired; return rows removed.

    Safe because an expired token is already rejected by its ``exp`` claim, so
    the revocation record no longer protects anything.
    """
    cutoff = int(time.time()) if now is None else int(now)
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM revoked_sessions WHERE expires_at < ?", (cutoff,))
    return int(cursor.rowcount)


def advance_totp_counter(user_id: int, counter: int) -> bool:
    """Record ``counter`` as the user's last accepted TOTP step if it is newer.

    A single UPSERT with a conditional update runs under SQLite's write lock,
    so concurrent requests presenting the same code cannot both succeed.
    Returns True when the counter was accepted.
    """
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO totp_counters (user_id, last_counter, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE
                   SET last_counter = excluded.last_counter, updated_at = excluded.updated_at
                   WHERE excluded.last_counter > totp_counters.last_counter""",
            (int(user_id), int(counter), utcnow()),
        )
        return cursor.rowcount == 1


def record_mfa_attempt(user_id: int, success: bool, actor_user_id: int | None = None) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO mfa_attempts (user_id, actor_user_id, ts, success) VALUES (?, ?, ?, ?)",
            (int(user_id), actor_user_id, utcnow(), 1 if success else 0),
        )


def recent_mfa_failures(user_id: int, window_seconds: int) -> tuple[int, str | None]:
    """Failed verifications for ``user_id`` inside the window, counted only
    since the identity's last successful verification.

    Returns ``(count, oldest_counted_failure_ts)``.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat(timespec="seconds")
    with get_db() as conn:
        last_success = conn.execute(
            "SELECT MAX(ts) AS ts FROM mfa_attempts WHERE user_id = ? AND success = 1", (int(user_id),)
        ).fetchone()["ts"]
        since = max(cutoff, last_success) if last_success else cutoff
        found = conn.execute(
            "SELECT COUNT(*) AS n, MIN(ts) AS oldest FROM mfa_attempts "
            "WHERE user_id = ? AND success = 0 AND ts > ?",
            (int(user_id), since),
        ).fetchone()
    return int(found["n"]), found["oldest"]


def last_totp_counter(user_id: int) -> int | None:
    with get_db() as conn:
        found = conn.execute(
            "SELECT last_counter FROM totp_counters WHERE user_id = ?", (int(user_id),)
        ).fetchone()
    return int(found["last_counter"]) if found else None


def is_empty() -> bool:
    with get_db() as conn:
        found = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
    return int(found["n"]) == 0
