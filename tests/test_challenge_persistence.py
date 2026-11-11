"""Step-up challenges persisted in SQLite (Phase 2.2, Task C).

Before this change challenges lived in a Python dict guarded by a
threading.Lock, so a challenge issued by one worker process was unknown to
every other worker ("Challenge expired or already used"), and the single-use,
attempt-limit and TTL guarantees held only inside one process.

Challenges are now rows in mfa_challenges. Only a SHA-256 hash of the
challenge id and of the session id is stored. Every verification runs its
checks and updates in one BEGIN IMMEDIATE transaction, so consumption and
failure counting are atomic across threads and processes.
"""

from __future__ import annotations

import hashlib
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

from app import config, database, mfa_crypto, risk, security
from conftest import decrypted, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
CONTEXT = {"geo": "Bengaluru, IN", "hour": 13, "requests_last_5m": 4, "failed_attempts_24h": 0,
           "bytes_out_mb": 15, "session_minutes": 25, "concurrent_sessions": 1,
           "new_device": False, "mfa_verified": False, "threat_intel": "clean"}


def _finance() -> dict:
    with database.get_db() as conn:
        return decrypted(database.row(conn, "SELECT * FROM users WHERE email = ?", (FINANCE[0],)))


def _ids(user: dict) -> tuple[int, int, int]:
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (user["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    return user["id"], device["id"], resource["id"]


def _new_challenge(user: dict) -> str:
    result = risk.evaluate(*_ids(user), dict(CONTEXT), persist=True)
    assert result["decision"] == "CHALLENGE"
    return result["challenge"]["id"]


def _wrong(user: dict) -> str:
    now = int(time.time())
    valid = {security.totp_code(user["mfa_secret"], at=now + 30 * k) for k in range(-2, 3)}
    return next(f"{n:06d}" for n in range(1, 1_000_000) if f"{n:06d}" not in valid)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def test_only_hashes_of_the_challenge_and_session_ids_are_stored(make_client):
    browser = make_client()
    assert login(browser, *FINANCE).status_code == 200
    user_id, device_id, resource_id = _ids(_finance())
    response = browser.post("/api/access/evaluate", json={"device_id": device_id, "resource_id": resource_id,
                                                          "context": CONTEXT})
    token = response.json()["challenge"]["id"]
    jti = security.decode_token(browser.cookies[config.SESSION_COOKIE])["jti"]
    state = risk.challenge_state(token)
    assert state["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert state["session_hash"] not in (None, jti)
    assert (state["user_id"], state["device_id"], state["resource_id"], state["actor_user_id"]) == (
        user_id, device_id, resource_id, user_id)
    assert state["event_id"] == response.json()["event_id"]
    assert state["status"] == "pending" and state["failed_attempts"] == 0 and state["consumed_at"] is None
    assert state["expires_at"] - state["created_at"] == pytest.approx(config.CHALLENGE_TTL_SECONDS)
    raw = b"".join(p.read_bytes() for p in config.DB_PATH.parent.glob(config.DB_PATH.name + "*"))
    assert token.encode() not in raw
    assert jti.encode() not in raw


def test_successful_verification_consumes_the_row_once():
    user = _finance()
    token = _new_challenge(user)
    assert risk.verify_challenge(token, security.totp_code(user["mfa_secret"]))["step_up"] is True
    state = risk.challenge_state(token)
    assert state["status"] == "consumed" and state["consumed_at"] is not None
    with pytest.raises(risk.ChallengeError) as excinfo:
        risk.verify_challenge(token, security.totp_code(user["mfa_secret"], at=int(time.time()) + 30))
    assert str(excinfo.value) == risk.INVALID_CHALLENGE


def test_old_challenges_are_purged_after_the_retention_period():
    user = _finance()
    token = _new_challenge(user)
    with database.get_db() as conn:
        conn.execute("UPDATE mfa_challenges SET expires_at = ? WHERE token_hash = ?",
                     (time.time() - risk.CHALLENGE_RETENTION_SECONDS - 5, risk.token_hash(token)))
    assert risk.purge_old_challenges() >= 1
    assert risk.challenge_state(token) is None


def test_init_db_adds_the_challenge_table_to_an_existing_database(tmp_path, monkeypatch):
    db_path = tmp_path / "pre-2.2.db"
    legacy = sqlite3.connect(db_path)
    legacy.executescript(database.SCHEMA.split("-- Step-up MFA challenges.")[0])
    legacy.execute("INSERT INTO users (email, name, role, password_hash, created_at) "
                   "VALUES ('old@example.test', 'Old', 'analyst', 'x', '2026-01-01T00:00:00+00:00')")
    legacy.commit()
    legacy.close()
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", db_path)
    for _ in range(3):  # repeated start-ups
        database.init_db()
    with database.get_db() as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert "mfa_challenges" in tables


# ---------------------------------------------------------------------------
# Concurrency inside one process (thread pool)
# ---------------------------------------------------------------------------


def _race(target, count: int) -> list:
    barrier = threading.Barrier(count)
    results: list = [None] * count

    def run(index: int) -> None:
        barrier.wait()
        try:
            results[index] = target()
        except Exception as exc:  # noqa: BLE001 - outcome is asserted below
            results[index] = exc

    threads = [threading.Thread(target=run, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def test_concurrent_correct_codes_consume_the_challenge_exactly_once():
    user = _finance()
    token = _new_challenge(user)
    code = security.totp_code(user["mfa_secret"])
    results = _race(lambda: risk.verify_challenge(token, code), 8)
    successes = [r for r in results if isinstance(r, dict)]
    assert len(successes) == 1
    assert all(isinstance(r, risk.ChallengeError) for r in results if not isinstance(r, dict))
    assert risk.challenge_state(token)["status"] == "consumed"


def test_concurrent_wrong_codes_never_exceed_the_attempt_limit():
    user = _finance()
    token = _new_challenge(user)
    wrong = _wrong(user)
    results = _race(lambda: risk.verify_challenge(token, wrong), 10)
    assert all(isinstance(r, risk.ChallengeError) for r in results)
    assert sum(isinstance(r, risk.ChallengeLimitError) for r in results) == 1
    assert sum(str(r).startswith("Incorrect verification code") for r in results) == 2
    state = risk.challenge_state(token)
    assert state["status"] == "cancelled" and state["failed_attempts"] == config.MFA_MAX_ATTEMPTS_PER_CHALLENGE
    with database.get_db() as conn:
        failures = conn.execute("SELECT COUNT(*) FROM mfa_attempts WHERE user_id = ? AND success = 0",
                                (user["id"],)).fetchone()[0]
    assert failures == config.MFA_MAX_ATTEMPTS_PER_CHALLENGE


# ---------------------------------------------------------------------------
# Two worker processes sharing one database
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Worker:
    def __init__(self, data_dir: Path, log_name: str):
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = {k: v for k, v in os.environ.items() if not k.startswith("ZT_")}
        env.update({
            "ZT_DATA_DIR": str(data_dir),
            "ZT_DB_PATH": str(data_dir / "shared.db"),
            "ZT_MODEL_PATH": str(data_dir / "model.joblib"),
            "ZT_SECRET_PATH": str(data_dir / "signing.key"),
            "ZT_MFA_KEY_PATH": str(data_dir / "mfa.key"),
            "ZT_PBKDF2_ITERATIONS": "1000",
        })
        self.log = open(data_dir / log_name, "wb")
        self.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(self.port),
             "--log-level", "warning"],
            cwd=config.BASE_DIR, env=env, stdout=self.log, stderr=subprocess.STDOUT,
        )

    def wait_ready(self, timeout: float = 90) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"worker on {self.port} exited with {self.process.returncode}")
            try:
                if httpx.get(self.base + "/api/health", timeout=2).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        raise AssertionError(f"worker on {self.port} did not start")

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base, timeout=30)

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=20)
        self.log.close()


@pytest.fixture
def workers(tmp_path):
    started: list[Worker] = []

    def start(count: int) -> list[Worker]:
        batch = [Worker(tmp_path, f"worker-{len(started) + i}.log") for i in range(count)]
        started.extend(batch)
        for worker in batch:  # all of the batch start at the same time
            worker.wait_ready()
        return batch

    yield start, tmp_path
    for worker in started:
        if worker.process.poll() is None:
            worker.stop()


def _shared_secret(data_dir: Path) -> tuple[int, str]:
    key = mfa_crypto.parse_key((data_dir / "mfa.key").read_text(), source="test")
    db = sqlite3.connect(data_dir / "shared.db")
    try:
        user_id, stored = db.execute("SELECT id, mfa_secret FROM users WHERE email = ?", (FINANCE[0],)).fetchone()
    finally:
        db.close()
    return user_id, mfa_crypto.decrypt_secret(stored, user_id, key)


def _counts(data_dir: Path) -> dict[str, int]:
    db = sqlite3.connect(data_dir / "shared.db")
    try:
        return {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("users", "devices", "resources", "policies", "eval_runs")}
    finally:
        db.close()


def _challenge_over_http(client: httpx.Client) -> str:
    inventory = client.get("/api/context/inventory").json()
    me = inventory["users"][0]
    device = next(d for d in me["devices"] if d["name"] == "PRIYA-LT-03")
    resource = next(r for r in inventory["resources"] if r["name"] == "finance-db")
    response = client.post("/api/access/evaluate", json={"device_id": device["id"], "resource_id": resource["id"],
                                                         "context": CONTEXT})
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "CHALLENGE"
    return response.json()["challenge"]["id"]


def _copy_session(source: httpx.Client, target: httpx.Client) -> None:
    target.cookies.set(config.SESSION_COOKIE, source.cookies[config.SESSION_COOKIE])


def test_challenge_lifecycle_across_two_worker_processes(workers):
    start, data_dir = workers
    first, second = start(2)  # concurrent start-up on an empty data directory

    # Exactly one worker seeded, and both use the one MFA key file.
    assert _counts(data_dir)["users"] == 6
    _, secret = _shared_secret(data_dir)

    with first.client() as a, second.client() as b:
        assert login(a, *FINANCE).status_code == 200
        _copy_session(a, b)  # the same browser session, load-balanced to the other worker
        # The signing key created by worker 1 verifies the session on worker 2.
        assert b.get("/api/auth/me").status_code == 200
        assert sorted(p.name for p in data_dir.iterdir() if p.suffix == ".key") == ["mfa.key", "signing.key"]

        # Issued by worker 1, completed by worker 2, replay rejected by both.
        token = _challenge_over_http(a)
        response = b.post("/api/access/challenge", json={"challenge_id": token, "code": security.totp_code(secret)})
        assert response.status_code == 200, response.text
        assert response.json()["step_up"] is True
        for worker in (a, b):
            replay = worker.post("/api/access/challenge", json={"challenge_id": token, "code": "000000"})
            assert replay.status_code == 400 and replay.json()["detail"] == risk.INVALID_CHALLENGE

        # Failed attempts are shared: 2 on worker 1 + 1 on worker 2 cancel the challenge.
        token = _challenge_over_http(b)
        wrong = _wrong({"mfa_secret": secret})
        assert a.post("/api/access/challenge", json={"challenge_id": token, "code": wrong}).status_code == 400
        assert b.post("/api/access/challenge", json={"challenge_id": token, "code": wrong}).status_code == 400
        assert a.post("/api/access/challenge", json={"challenge_id": token, "code": wrong}).status_code == 429
        assert b.post("/api/access/challenge",
                      json={"challenge_id": token, "code": security.totp_code(secret, at=int(time.time()) + 30)}
                      ).status_code == 400

        # Sign-out on one worker revokes the session on the other.
        assert a.post("/api/auth/logout").status_code == 200
        assert b.get("/api/auth/me").status_code == 401


def test_concurrent_verification_on_two_workers_succeeds_once(workers):
    start, data_dir = workers
    first, second = start(2)
    _, secret = _shared_secret(data_dir)
    with first.client() as a, second.client() as b:
        assert login(a, *FINANCE).status_code == 200
        _copy_session(a, b)
        token = _challenge_over_http(a)
        code = security.totp_code(secret)
        clients = [a, b] * 4
        barrier = threading.Barrier(len(clients))
        statuses: list[int] = [0] * len(clients)

        def submit(index: int) -> None:
            barrier.wait()
            statuses[index] = clients[index].post(
                "/api/access/challenge", json={"challenge_id": token, "code": code}).status_code

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(len(clients))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(statuses) == [200] + [400] * (len(clients) - 1)


def test_repeated_startups_do_not_duplicate_data(workers):
    start, data_dir = workers
    for worker in start(2):
        worker.stop()
    before = _counts(data_dir)
    for worker in start(1):
        worker.stop()
    for worker in start(2):
        worker.stop()
    assert _counts(data_dir) == before
    assert before["users"] == 6 and before["eval_runs"] == 1
    db = sqlite3.connect(data_dir / "shared.db")
    try:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert all(mfa_crypto.is_encrypted(s) for (s,) in db.execute("SELECT mfa_secret FROM users"))
    finally:
        db.close()
