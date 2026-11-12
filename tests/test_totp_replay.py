"""TOTP replay protection (Phase 2.1, issue 3).

Before the fix a valid code could be reused for its whole tolerance window
(about 90 seconds), so one observed code could complete several challenges.
Now the matched 30-second step is recorded per user and must be newer than any
step previously accepted for that user.

Most tests pin the current time step so they never straddle a 30 s boundary.
"""

from __future__ import annotations

import threading

import pytest

from app import config, database, risk, security
from conftest import decrypted, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
ANALYST_EMAIL = "analyst@hybridcloud.io"
LOCAL = {"base_url": "http://127.0.0.1:8000", "client": ("127.0.0.1", 50000)}
CLEAN = {
    "geo": "Bengaluru, IN", "hour": 13, "requests_last_5m": 4, "failed_attempts_24h": 0,
    "bytes_out_mb": 15, "session_minutes": 25, "concurrent_sessions": 1,
    "new_device": False, "mfa_verified": False, "threat_intel": "clean",
}


def _user(email: str) -> dict:
    with database.get_db() as conn:
        return decrypted(database.row(conn, "SELECT * FROM users WHERE email = ?", (email,)))


@pytest.fixture
def step(monkeypatch):
    """Freeze the TOTP time step used for verification."""
    pinned = security.current_totp_counter()
    monkeypatch.setattr(security, "current_totp_counter", lambda at=None: pinned)
    return pinned


def _code(user: dict, counter: int) -> str:
    return security._hotp(user["mfa_secret"], counter)


# ---------------------------------------------------------------------------
# security.consume_totp
# ---------------------------------------------------------------------------


def test_valid_first_time_code_is_accepted_and_recorded(step):
    user = _user(FINANCE[0])
    assert database.last_totp_counter(user["id"]) is None

    assert security.consume_totp(user["id"], user["mfa_secret"], _code(user, step)) is True
    assert database.last_totp_counter(user["id"]) == step


def test_exact_same_code_cannot_be_reused(step):
    user = _user(FINANCE[0])
    code = _code(user, step)

    assert security.consume_totp(user["id"], user["mfa_secret"], code) is True
    assert security.consume_totp(user["id"], user["mfa_secret"], code) is False
    # The stateless check still recognises the code; only consumption is refused.
    assert security.verify_totp(user["mfa_secret"], code) is True


def test_older_step_inside_the_window_is_rejected_after_a_newer_one(step):
    user = _user(FINANCE[0])
    assert security.consume_totp(user["id"], user["mfa_secret"], _code(user, step)) is True

    assert security.consume_totp(user["id"], user["mfa_secret"], _code(user, step - 1)) is False
    assert database.last_totp_counter(user["id"]) == step


def test_adjacent_steps_are_accepted_in_order(step):
    user = _user(FINANCE[0])

    assert security.consume_totp(user["id"], user["mfa_secret"], _code(user, step - 1)) is True
    assert security.consume_totp(user["id"], user["mfa_secret"], _code(user, step)) is True
    assert security.consume_totp(user["id"], user["mfa_secret"], _code(user, step + 1)) is True
    assert database.last_totp_counter(user["id"]) == step + 1
    # Outside the +/-1 tolerance window is never accepted.
    assert security.consume_totp(user["id"], user["mfa_secret"], _code(user, step + 2)) is False


@pytest.mark.parametrize("bad", ["", "abcdef", "12345", "1234567"])
def test_invalid_code_never_updates_the_counter(step, bad):
    user = _user(FINANCE[0])
    valid = {_code(user, step + k) for k in (-1, 0, 1)}
    wrong = next(c for c in ("000000", "111111", "222222") if c not in valid)

    for code in (bad, wrong):
        assert security.consume_totp(user["id"], user["mfa_secret"], code) is False
    assert database.last_totp_counter(user["id"]) is None


def test_concurrent_duplicate_submissions_succeed_exactly_once(step):
    user = _user(FINANCE[0])
    code = _code(user, step)
    workers = 8
    barrier = threading.Barrier(workers)
    outcomes: list[bool] = []
    lock = threading.Lock()

    def submit():
        barrier.wait()
        accepted = security.consume_totp(user["id"], user["mfa_secret"], code)
        with lock:
            outcomes.append(accepted)

    threads = [threading.Thread(target=submit) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert len(outcomes) == workers
    assert outcomes.count(True) == 1


def test_users_have_independent_counters(step):
    finance, analyst = _user(FINANCE[0]), _user(ANALYST_EMAIL)

    assert security.consume_totp(finance["id"], finance["mfa_secret"], _code(finance, step)) is True
    assert security.consume_totp(analyst["id"], analyst["mfa_secret"], _code(analyst, step)) is True
    assert database.last_totp_counter(finance["id"]) == step
    assert database.last_totp_counter(analyst["id"]) == step


def test_counter_store_is_monotonic_and_holds_no_codes():
    user = _user(FINANCE[0])
    assert database.advance_totp_counter(user["id"], 1000) is True
    assert database.advance_totp_counter(user["id"], 1000) is False
    assert database.advance_totp_counter(user["id"], 999) is False
    assert database.advance_totp_counter(user["id"], 1001) is True

    with database.get_db() as conn:
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(totp_counters)")]
    assert columns == ["user_id", "last_counter", "updated_at"]


# ---------------------------------------------------------------------------
# Challenge flow
# ---------------------------------------------------------------------------


def _challenge(user: dict) -> str:
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (user["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    result = risk.evaluate(user["id"], device["id"], resource["id"], dict(CLEAN), persist=True)
    assert result["decision"] == "CHALLENGE"
    return result["challenge"]["id"]


def test_one_code_cannot_complete_two_challenges(step):
    user = _user(FINANCE[0])
    first, second = _challenge(user), _challenge(user)
    code = _code(user, step)

    assert risk.verify_challenge(first, code)["step_up"] is True
    with pytest.raises(ValueError, match="Incorrect verification code"):
        risk.verify_challenge(second, code)
    # The next time step is still accepted, so the legitimate user is not stuck.
    assert risk.verify_challenge(second, _code(user, step + 1))["step_up"] is True


def test_replayed_code_is_rejected_over_http(make_client, step):
    browser = make_client()
    assert login(browser, *FINANCE).status_code == 200
    user = _user(FINANCE[0])
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (user["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    body = {"user_id": user["id"], "device_id": device["id"], "resource_id": resource["id"],
            "context": {"hour": 13, "failed_attempts_24h": 0, "mfa_verified": False}}
    code = _code(user, step)

    first = browser.post("/api/access/evaluate", json=body).json()["challenge"]["id"]
    second = browser.post("/api/access/evaluate", json=body).json()["challenge"]["id"]

    ok = browser.post("/api/access/challenge", json={"challenge_id": first, "code": code})
    replay = browser.post("/api/access/challenge", json={"challenge_id": second, "code": code})
    assert ok.status_code == 200
    assert replay.status_code == 400
    assert replay.json()["detail"].startswith("Incorrect verification code")


def test_demo_helper_reports_a_spent_code(make_client, monkeypatch, step):
    monkeypatch.setattr(config, "DEMO_TOTP_ENABLED", True)
    browser = make_client(**LOCAL)
    login(browser, *FINANCE)
    user = _user(FINANCE[0])

    assert browser.get("/api/auth/totp").json()["already_used"] is False
    assert security.consume_totp(user["id"], user["mfa_secret"], _code(user, step)) is True
    assert browser.get("/api/auth/totp").json()["already_used"] is True
