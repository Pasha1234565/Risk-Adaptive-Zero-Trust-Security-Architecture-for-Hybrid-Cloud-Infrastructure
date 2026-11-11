"""Failed step-up MFA attempt limiting (Phase 2.1, issue 1).

Before the fix a wrong code left the challenge usable, so codes could be
guessed repeatedly for the full 180-second lifetime, and new challenges could
be requested without limit.

Policy under test (app/config.py):
* 3 incorrect codes cancel a challenge (HTTP 429), and it can never be reused;
* 6 incorrect codes for one identity within 15 minutes, across any number of
  challenges, pause verification for that identity (HTTP 429 + Retry-After);
* nothing locks permanently, and a successful verification starts a new window.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from app import config, database, risk, security
from conftest import decrypted, expire_challenge, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
CONTEXT = {"hour": 13, "failed_attempts_24h": 0, "mfa_verified": False}


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
    assert result["challenge"]["max_attempts"] == config.MFA_MAX_ATTEMPTS_PER_CHALLENGE
    return result["challenge"]["id"]


def _wrong(user: dict) -> str:
    now = int(time.time())
    valid = {security.totp_code(user["mfa_secret"], at=now + 30 * k) for k in range(-2, 3)}
    return next(code for code in ("000000", "111111", "222222", "333333") if code not in valid)


def _right(user: dict) -> str:
    return security.totp_code(user["mfa_secret"])


def _attempts(user: dict) -> list[dict]:
    with database.get_db() as conn:
        return database.rows(conn, "SELECT * FROM mfa_attempts WHERE user_id = ? ORDER BY id", (user["id"],))


def test_defaults_are_conservative():
    assert config.MFA_MAX_ATTEMPTS_PER_CHALLENGE == 3
    assert config.MFA_USER_MAX_FAILURES == 6
    assert config.MFA_USER_FAILURE_WINDOW_SECONDS == 900
    assert config.CHALLENGE_TTL_SECONDS == 180


# ---------------------------------------------------------------------------
# Per-challenge limit
# ---------------------------------------------------------------------------


def test_first_invalid_code_reports_remaining_attempts():
    user = _finance()
    token = _new_challenge(user)

    with pytest.raises(risk.ChallengeError) as excinfo:
        risk.verify_challenge(token, _wrong(user))

    assert excinfo.value.status_code == 400
    assert str(excinfo.value) == "Incorrect verification code. 2 attempt(s) remaining."
    assert risk.challenge_state(token)["failed_attempts"] == 1


def test_third_invalid_code_cancels_the_challenge():
    user = _finance()
    token = _new_challenge(user)
    messages = []
    for _ in range(2):
        with pytest.raises(risk.ChallengeError) as excinfo:
            risk.verify_challenge(token, _wrong(user))
        messages.append(str(excinfo.value))

    with pytest.raises(risk.ChallengeLimitError) as excinfo:
        risk.verify_challenge(token, _wrong(user))

    assert messages == [
        "Incorrect verification code. 2 attempt(s) remaining.",
        "Incorrect verification code. 1 attempt(s) remaining.",
    ]
    assert excinfo.value.status_code == 429
    assert "cancelled" in str(excinfo.value)
    assert risk.challenge_state(token)["status"] == "cancelled"


def test_cancelled_challenge_cannot_be_reused_even_with_the_right_code():
    user = _finance()
    token = _new_challenge(user)
    for _ in range(3):
        with pytest.raises(risk.ChallengeError):
            risk.verify_challenge(token, _wrong(user))

    with pytest.raises(risk.ChallengeError) as excinfo:
        risk.verify_challenge(token, _right(user))

    assert excinfo.value.status_code == 400
    assert str(excinfo.value) == risk.INVALID_CHALLENGE
    # The correct code was not spent on the dead challenge.
    assert database.last_totp_counter(user["id"]) is None


def test_expired_challenge_is_rejected_without_spending_the_code():
    user = _finance()
    token = _new_challenge(user)
    expire_challenge(token)

    with pytest.raises(risk.ChallengeError) as excinfo:
        risk.verify_challenge(token, _right(user))

    assert str(excinfo.value) == risk.INVALID_CHALLENGE
    assert risk.challenge_state(token)["status"] == "expired"
    assert database.last_totp_counter(user["id"]) is None


def test_challenge_lifetime_is_unchanged():
    user = _finance()
    before = time.time()
    token = _new_challenge(user)
    assert config.CHALLENGE_TTL_SECONDS - 2 <= risk.challenge_state(token)["expires_at"] - before <= config.CHALLENGE_TTL_SECONDS + 2


def test_success_after_earlier_wrong_codes():
    user = _finance()
    token = _new_challenge(user)
    for _ in range(2):
        with pytest.raises(risk.ChallengeError):
            risk.verify_challenge(token, _wrong(user))

    result = risk.verify_challenge(token, _right(user))

    assert result["step_up"] is True
    assert [row["success"] for row in _attempts(user)] == [0, 0, 1]


def test_unknown_and_malformed_challenge_ids_get_the_same_answer():
    user = _finance()
    for token in ("does-not-exist", "", None, 123):
        with pytest.raises(risk.ChallengeError) as excinfo:
            risk.verify_challenge(token, _right(user))
        assert str(excinfo.value) == risk.INVALID_CHALLENGE


# ---------------------------------------------------------------------------
# Per-identity throttle across new challenges
# ---------------------------------------------------------------------------


def _burn(user: dict, challenges: int) -> None:
    for _ in range(challenges):
        token = _new_challenge(user)
        for _ in range(config.MFA_MAX_ATTEMPTS_PER_CHALLENGE):
            with pytest.raises(risk.ChallengeError):
                risk.verify_challenge(token, _wrong(user))


def test_new_challenges_do_not_reset_the_identity_budget():
    user = _finance()
    _burn(user, 2)  # 6 failures in total
    token = _new_challenge(user)

    with pytest.raises(risk.ChallengeLimitError) as excinfo:
        risk.verify_challenge(token, _right(user))

    assert excinfo.value.status_code == 429
    assert "this identity" in str(excinfo.value)
    assert 1 <= excinfo.value.retry_after <= config.MFA_USER_FAILURE_WINDOW_SECONDS + 1
    # The throttled attempt neither spent the code nor consumed the challenge.
    assert database.last_totp_counter(user["id"]) is None
    assert risk.challenge_state(token)["status"] == "pending"
    assert sum(1 for row in _attempts(user) if row["success"] == 0) == 6


def test_throttle_is_temporary_not_a_permanent_lock(make_client):
    user = _finance()
    _burn(user, 2)
    token = _new_challenge(user)
    with pytest.raises(risk.ChallengeLimitError):
        risk.verify_challenge(token, _right(user))

    # Age the failures past the window: verification works again.
    old = (datetime.now(timezone.utc) - timedelta(seconds=config.MFA_USER_FAILURE_WINDOW_SECONDS + 5))
    with database.get_db() as conn:
        conn.execute("UPDATE mfa_attempts SET ts = ? WHERE user_id = ?", (old.isoformat(timespec="seconds"), user["id"]))
    assert risk.verify_challenge(token, _right(user))["step_up"] is True
    # Password login was never affected.
    assert login(make_client(), *FINANCE).status_code == 200


def test_successful_verification_starts_a_new_window():
    user = _finance()
    _burn(user, 1)  # 3 failures
    assert risk.verify_challenge(_new_challenge(user), _right(user))["step_up"] is True
    assert database.recent_mfa_failures(user["id"], config.MFA_USER_FAILURE_WINDOW_SECONDS)[0] == 0


def test_attempt_records_hold_no_codes():
    user = _finance()
    # A challenge owned by a signed-in actor and session, as the API creates it.
    token = risk.evaluate(*_ids(user), dict(CONTEXT), persist=True, actor_id=user["id"],
                          session_id="session-under-test")["challenge"]["id"]
    with pytest.raises(risk.ChallengeError):
        risk.verify_challenge(token, _wrong(user), actor_id=user["id"], session_id="session-under-test")

    with database.get_db() as conn:
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(mfa_attempts)")]
    assert columns == ["id", "user_id", "actor_user_id", "ts", "success"]
    assert _attempts(user)[-1]["actor_user_id"] == user["id"]


# ---------------------------------------------------------------------------
# HTTP behaviour
# ---------------------------------------------------------------------------


def _http_challenge(browser, user: dict) -> str:
    user_id, device_id, resource_id = _ids(user)
    body = {"user_id": user_id, "device_id": device_id, "resource_id": resource_id, "context": CONTEXT}
    response = browser.post("/api/access/evaluate", json=body)
    assert response.json()["decision"] == "CHALLENGE", response.text
    return response.json()["challenge"]["id"]


def test_http_status_codes_and_retry_after(make_client):
    user = _finance()
    browser = make_client()
    assert login(browser, *FINANCE).status_code == 200

    def submit(token, code):
        return browser.post("/api/access/challenge", json={"challenge_id": token, "code": code})

    statuses = []
    for _ in range(2):
        token = _http_challenge(browser, user)
        statuses += [submit(token, _wrong(user)).status_code for _ in range(3)]
        reuse = submit(token, _right(user))
        assert reuse.status_code == 400 and reuse.json()["detail"] == risk.INVALID_CHALLENGE

    throttled = submit(_http_challenge(browser, user), _right(user))

    assert statuses == [400, 400, 429, 400, 400, 429]
    assert throttled.status_code == 429
    assert int(throttled.headers["retry-after"]) >= 1
    assert "this identity" in throttled.json()["detail"]
    assert _attempts(user)[-1]["actor_user_id"] == user["id"]
