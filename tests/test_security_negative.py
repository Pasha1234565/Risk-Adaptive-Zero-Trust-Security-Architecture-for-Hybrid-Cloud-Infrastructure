"""Cross-cutting negative security tests (Phase 2.1).

Each fix has its own test module. These tests check that the controls still
hold when combined: session revocation and expiry, MFA attempt limits,
challenge ownership, TOTP replay protection, the simulation-role boundary and
the existing admin-only APIs.
"""

from __future__ import annotations

import time

import pytest

from app import config, database, risk, security
from conftest import ADMIN, ANALYST, decrypted, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
CONTRACTOR = ("contractor@hybridcloud.io", "Guest#2026")
CONTEXT = {"hour": 13, "failed_attempts_24h": 0, "mfa_verified": False}


def _finance() -> dict:
    with database.get_db() as conn:
        return decrypted(database.row(conn, "SELECT * FROM users WHERE email = ?", (FINANCE[0],)))


def _body(simulate: bool = False) -> dict:
    user = _finance()
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (user["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    body = {"device_id": device["id"], "resource_id": resource["id"], "context": CONTEXT}
    if simulate:
        body["user_id"] = user["id"]
    return body


def _signed_in(make_client, credentials):
    browser = make_client()
    assert login(browser, *credentials).status_code == 200
    return browser


def _challenge(browser, simulate: bool = False) -> str:
    response = browser.post("/api/access/evaluate", json=_body(simulate))
    assert response.json()["decision"] == "CHALLENGE", response.text
    return response.json()["challenge"]["id"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Revoked and expired sessions against the new controls
# ---------------------------------------------------------------------------


def test_revoked_session_cannot_evaluate_answer_or_simulate(make_client):
    admin = _signed_in(make_client, ADMIN)
    token = admin.cookies.get(config.SESSION_COOKIE)
    challenge = _challenge(admin, simulate=True)
    admin.post("/api/auth/logout")
    stale = make_client()

    assert stale.post("/api/access/evaluate", json=_body(), headers=_bearer(token)).status_code == 401
    code = security.totp_code(_finance()["mfa_secret"])
    assert stale.post("/api/access/challenge", json={"challenge_id": challenge, "code": code},
                      headers=_bearer(token)).status_code == 401
    assert stale.post("/api/sim/scenario", json={"scenario_id": "impossible_travel", "variants": 1},
                      headers=_bearer(token)).status_code == 401
    assert database.last_totp_counter(_finance()["id"]) is None


def test_expired_session_cannot_evaluate_or_answer(make_client):
    finance = _finance()
    owner = _signed_in(make_client, FINANCE)
    challenge = _challenge(owner)
    expired = security.issue_token(finance["id"], ttl_seconds=-1)
    client = make_client()

    assert client.post("/api/access/evaluate", json=_body(), headers=_bearer(expired)).status_code == 401
    assert client.post("/api/access/challenge", json={"challenge_id": challenge, "code": "123456"},
                       headers=_bearer(expired)).status_code == 401
    assert risk.challenge_state(challenge)["failed_attempts"] == 0


# ---------------------------------------------------------------------------
# Attacker with a stolen password and an observed code
# ---------------------------------------------------------------------------


def test_stolen_password_plus_observed_code_is_not_enough(make_client):
    victim = _signed_in(make_client, FINANCE)
    attacker = _signed_in(make_client, FINANCE)  # same password, separate session
    secret = _finance()["mfa_secret"]

    victim_challenge = _challenge(victim)
    observed = security.totp_code(secret)
    assert victim.post("/api/access/challenge", json={"challenge_id": victim_challenge, "code": observed}).status_code == 200

    # The attacker cannot use the victim's challenge ...
    stolen = attacker.post("/api/access/challenge", json={"challenge_id": victim_challenge, "code": observed})
    # ... nor replay the observed code on their own challenge.
    own = attacker.post("/api/access/challenge", json={"challenge_id": _challenge(attacker), "code": observed})

    assert stolen.status_code == 400 and stolen.json()["detail"] == risk.INVALID_CHALLENGE
    assert own.status_code == 400 and own.json()["detail"].startswith("Incorrect verification code")


def test_guessing_across_sessions_hits_the_identity_budget(make_client):
    secret = _finance()["mfa_secret"]
    now = int(time.time())
    valid = {security.totp_code(secret, at=now + 30 * k) for k in range(-2, 3)}
    wrong = next(c for c in ("000000", "111111", "222222") if c not in valid)
    statuses = []
    for _ in range(3):  # three sessions, each with a fresh challenge
        session = _signed_in(make_client, FINANCE)
        token = _challenge(session)
        statuses += [session.post("/api/access/challenge", json={"challenge_id": token, "code": wrong}).status_code
                     for _ in range(3)]

    assert statuses[:6] == [400, 400, 429, 400, 400, 429]
    assert statuses[6:] == [429, 429, 429]  # identity budget exhausted, regardless of session


# ---------------------------------------------------------------------------
# Payload manipulation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code, status", [("12345", 422), ("1234567", 422), ("", 422), ("abcdef", 400), ("12 456", 400)])
def test_malformed_codes(make_client, code, status):
    browser = _signed_in(make_client, FINANCE)
    response = browser.post("/api/access/challenge", json={"challenge_id": _challenge(browser), "code": code})
    assert response.status_code == status


@pytest.mark.parametrize("challenge_id", ["short", "x" * 201])
def test_malformed_challenge_ids_are_rejected_by_validation(make_client, challenge_id):
    response = _signed_in(make_client, FINANCE).post(
        "/api/access/challenge", json={"challenge_id": challenge_id, "code": "123456"}
    )
    assert response.status_code == 422


def test_actor_fields_in_the_evaluate_body_are_ignored(make_client):
    finance = _finance()
    with database.get_db() as conn:
        admin_id = database.row(conn, "SELECT id FROM users WHERE email = ?", (ADMIN[0],))["id"]
    body = {**_body(), "actor_id": admin_id, "actor_user_id": admin_id, "simulated": True}

    response = _signed_in(make_client, FINANCE).post("/api/access/evaluate", json=body)

    assert response.status_code == 200
    with database.get_db() as conn:
        stored = database.row(conn, "SELECT user_id, actor_user_id FROM events WHERE id = ?", (response.json()["event_id"],))
    assert stored == {"user_id": finance["id"], "actor_user_id": finance["id"]}


# ---------------------------------------------------------------------------
# Role boundaries
# ---------------------------------------------------------------------------


ADMIN_CALLS = [
    ("get", "/api/admin/inventory", None),
    ("put", "/api/admin/settings", {"thresholds": {"allow_max": 40, "challenge_max": 60, "restrict_max": 80}}),
    ("post", "/api/admin/policies/1/toggle", None),
    ("post", "/api/admin/model/train", {"samples": 200}),
]


@pytest.mark.parametrize("credentials", [ANALYST, FINANCE, CONTRACTOR])
@pytest.mark.parametrize("method, path, body", ADMIN_CALLS)
def test_simulation_role_does_not_grant_administration(make_client, credentials, method, path, body):
    browser = _signed_in(make_client, credentials)
    kwargs = {"json": body} if body is not None else {}
    assert getattr(browser, method)(path, **kwargs).status_code == 403


def test_contractor_cannot_reach_admin_or_simulation_with_forged_bearer(make_client):
    forged = security.issue_token(1)[:-4] + "AAAA"  # tampered signature for user 1 (admin)
    client = make_client()
    assert client.get("/api/admin/inventory", headers=_bearer(forged)).status_code == 401
    assert client.post("/api/sim/normal", json={"count": 1}, headers=_bearer(forged)).status_code == 401


# ---------------------------------------------------------------------------
# Independent throttles
# ---------------------------------------------------------------------------


def test_mfa_throttle_and_login_throttle_are_independent(make_client):
    finance = _finance()
    for _ in range(config.MFA_USER_MAX_FAILURES):
        database.record_mfa_attempt(finance["id"], False)

    # Password login still works while MFA verification is throttled.
    browser = _signed_in(make_client, FINANCE)
    response = browser.post("/api/access/challenge", json={"challenge_id": _challenge(browser),
                                                           "code": security.totp_code(finance["mfa_secret"])})
    assert response.status_code == 429
    # A different identity is unaffected.
    analyst = _signed_in(make_client, ANALYST)
    assert analyst.get("/api/auth/me").status_code == 200
