"""Step-up challenge ownership (Phase 2.1, issue 2).

Before the fix any signed-in user holding a challenge id could answer it.
Now every challenge is bound, on the server, to:
* the subject whose TOTP must be presented (user_id),
* the signed-in actor and the session (token jti) that requested it,
* the device, resource and stored event of the original request.

Session-binding policy: only the same user in the same session may answer.
A different user, a different session of the same user (including after
logout), or an administrator who learns the id all get the generic
"Challenge expired or already used" answer, and such attempts do not use up
the owner's attempts.
"""

from __future__ import annotations

import time

from app import database, risk, security
from conftest import ADMIN, ANALYST, decrypted, expire_challenge, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
CONTEXT = {"hour": 13, "failed_attempts_24h": 0, "mfa_verified": False}


def _finance() -> dict:
    with database.get_db() as conn:
        return decrypted(database.row(conn, "SELECT * FROM users WHERE email = ?", (FINANCE[0],)))


def _ids() -> tuple[int, int, int]:
    user = _finance()
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (user["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    return user["id"], device["id"], resource["id"]


def _signed_in(make_client, credentials):
    browser = make_client()
    assert login(browser, *credentials).status_code == 200
    return browser


def _challenge(browser, *, simulate: bool = False) -> str:
    user_id, device_id, resource_id = _ids()
    body = {"device_id": device_id, "resource_id": resource_id, "context": CONTEXT}
    if simulate:
        body["user_id"] = user_id
    response = browser.post("/api/access/evaluate", json=body)
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "CHALLENGE"
    return response.json()["challenge"]["id"]


def _submit(browser, token: str, code: str, **extra):
    return browser.post("/api/access/challenge", json={"challenge_id": token, "code": code, **extra})


def _code() -> str:
    return security.totp_code(_finance()["mfa_secret"])


def _wrong() -> str:
    secret, now = _finance()["mfa_secret"], int(time.time())
    valid = {security.totp_code(secret, at=now + 30 * k) for k in range(-2, 3)}
    return next(c for c in ("000000", "111111", "222222") if c not in valid)


def _attempt_rows() -> int:
    with database.get_db() as conn:
        return conn.execute("SELECT COUNT(*) FROM mfa_attempts").fetchone()[0]


def _jti(browser) -> str:
    return security.decode_token(browser.cookies.get("zt_session"))["jti"]


def test_challenge_records_its_binding_on_the_server(make_client):
    browser = _signed_in(make_client, FINANCE)
    token = _challenge(browser)
    user_id, device_id, resource_id = _ids()

    entry = risk.challenge_state(token)

    assert entry["user_id"] == user_id
    assert entry["actor_user_id"] == user_id
    assert entry["session_hash"] == risk._session_hash(_jti(browser))
    assert (entry["device_id"], entry["resource_id"]) == (device_id, resource_id)
    with database.get_db() as conn:
        event = database.row(conn, "SELECT user_id, device_id, resource_id FROM events WHERE id = ?", (entry["event_id"],))
    assert event == {"user_id": user_id, "device_id": device_id, "resource_id": resource_id}


def test_same_user_and_same_session_succeeds(make_client):
    browser = _signed_in(make_client, FINANCE)
    response = _submit(browser, _challenge(browser), _code())
    assert response.status_code == 200
    assert response.json()["step_up"] is True


def test_different_user_is_rejected_without_burning_attempts(make_client):
    owner = _signed_in(make_client, FINANCE)
    token = _challenge(owner)
    intruder = _signed_in(make_client, ANALYST)

    for code in (_wrong(), _wrong(), _wrong(), _wrong(), _code()):
        response = _submit(intruder, token, code)
        assert response.status_code == 400
        assert response.json()["detail"] == risk.INVALID_CHALLENGE

    assert risk.challenge_state(token)["failed_attempts"] == 0
    assert _attempt_rows() == 0
    assert database.last_totp_counter(_finance()["id"]) is None
    # The owner can still complete it.
    assert _submit(owner, token, _code()).status_code == 200


def test_administrator_cannot_complete_another_users_challenge(make_client):
    owner = _signed_in(make_client, FINANCE)
    token = _challenge(owner)
    admin = _signed_in(make_client, ADMIN)

    response = _submit(admin, token, _code())

    assert response.status_code == 400
    assert response.json()["detail"] == risk.INVALID_CHALLENGE
    assert risk.challenge_state(token)["status"] == "pending"


def test_ownership_cannot_be_claimed_through_the_request_body(make_client):
    owner = _signed_in(make_client, FINANCE)
    token = _challenge(owner)
    intruder = _signed_in(make_client, ANALYST)
    user_id = _finance()["id"]

    response = _submit(intruder, token, _code(), user_id=user_id, actor_id=user_id, session_id=_jti(owner))

    assert response.status_code == 400
    assert response.json()["detail"] == risk.INVALID_CHALLENGE


def test_same_user_in_another_session_is_rejected(make_client):
    first = _signed_in(make_client, FINANCE)
    token = _challenge(first)
    second = _signed_in(make_client, FINANCE)
    assert _jti(first) != _jti(second)

    assert _submit(second, token, _code()).status_code == 400
    assert _submit(first, token, _code()).status_code == 200


def test_challenge_dies_with_its_session(make_client):
    browser = _signed_in(make_client, FINANCE)
    token = _challenge(browser)
    old_cookie = browser.cookies.get("zt_session")
    assert browser.post("/api/auth/logout").status_code == 200

    stale = make_client(cookies={"zt_session": old_cookie})
    assert _submit(stale, token, _code()).status_code == 401
    fresh = _signed_in(make_client, FINANCE)
    assert _submit(fresh, token, _code()).status_code == 400


def test_expired_and_used_challenges_are_rejected(make_client):
    browser = _signed_in(make_client, FINANCE)
    expired = _challenge(browser)
    expire_challenge(expired)
    assert _submit(browser, expired, _code()).status_code == 400

    used = _challenge(browser)
    assert _submit(browser, used, _code()).status_code == 200
    replay = _submit(browser, used, security.totp_code(_finance()["mfa_secret"], at=int(time.time()) + 30))
    assert replay.status_code == 400
    assert replay.json()["detail"] == risk.INVALID_CHALLENGE


def test_tampered_original_request_invalidates_the_challenge(make_client):
    browser = _signed_in(make_client, FINANCE)
    token = _challenge(browser)
    with database.get_db() as conn:
        other_resource = database.row(conn, "SELECT id FROM resources WHERE name = 'internal-wiki'")["id"]
        conn.execute("UPDATE events SET resource_id = ? WHERE id = ?", (other_resource, risk.challenge_state(token)["event_id"]))

    response = _submit(browser, token, _code())

    assert response.status_code == 400
    assert risk.challenge_state(token)["status"] == "invalidated"
    assert database.last_totp_counter(_finance()["id"]) is None


def test_simulated_challenge_belongs_to_the_operator_session(make_client):
    admin = _signed_in(make_client, ADMIN)
    token = _challenge(admin, simulate=True)
    subject = _signed_in(make_client, FINANCE)

    entry = risk.challenge_state(token)
    assert entry["user_id"] == _finance()["id"]
    assert entry["actor_user_id"] != entry["user_id"]
    # The subject's own session did not request it, so it cannot answer it ...
    assert _submit(subject, token, _code()).status_code == 400
    # ... while the operator session can, with the subject's authenticator code.
    assert _submit(admin, token, _code()).status_code == 200


def test_engine_level_challenges_without_an_actor_are_not_answerable_over_http(make_client):
    user_id, device_id, resource_id = _ids()
    token = risk.evaluate(user_id, device_id, resource_id, dict(CONTEXT), persist=True)["challenge"]["id"]
    browser = _signed_in(make_client, FINANCE)

    assert _submit(browser, token, _code()).status_code == 400
    # In-process callers that pass the same (empty) binding still can.
    assert risk.verify_challenge(token, _code())["step_up"] is True
